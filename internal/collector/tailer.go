package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
)

// Tailer reads lines from a file with support for rotation detection.
type Tailer struct {
	source   SourceConfig
	parser   Parser
	sincedb  *SinceDB
	eventCh  chan<- *LogEvent
	logger   zerolog.Logger
	tenantID string
	hostname string

	// File state
	file   *os.File
	reader *bufio.Reader
	inode  uint64
	device uint64
	offset int64

	// Configuration
	pollInterval time.Duration
	startFromEnd bool
}

// NewTailer creates a new file tailer.
func NewTailer(
	source SourceConfig,
	parser Parser,
	sincedb *SinceDB,
	eventCh chan<- *LogEvent,
	logger zerolog.Logger,
	tenantID string,
	startFromEnd bool,
) (*Tailer, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return &Tailer{
		source:       source,
		parser:       parser,
		sincedb:      sincedb,
		eventCh:      eventCh,
		logger:       logger.With().Str("source", source.Name).Str("path", source.Path).Logger(),
		tenantID:     tenantID,
		hostname:     hostname,
		pollInterval: 1 * time.Second,
		startFromEnd: startFromEnd,
	}, nil
}

// Run starts the tailer and reads lines until context is cancelled.
func (t *Tailer) Run(ctx context.Context) error {
	t.logger.Info().Msg("Starting tailer")
	defer t.logger.Info().Msg("Tailer stopped")

	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.close()
			return ctx.Err()
		case <-ticker.C:
			if err := t.poll(ctx); err != nil {
				t.logger.Error().Err(err).Msg("Poll error")
			}
		}
	}
}

// poll checks for new data and reads available lines.
func (t *Tailer) poll(ctx context.Context) error {
	// Check if file exists
	info, err := os.Stat(t.source.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, close if open and wait
			if t.file != nil {
				t.close()
			}
			return nil
		}
		return fmt.Errorf("stat file: %w", err)
	}

	// Temporary diagnostic logging at info level
	if info.Size() != t.offset {
		t.logger.Info().
			Int64("file_size", info.Size()).
			Int64("current_offset", t.offset).
			Msg("New data detected")
	}

	// Get file identity
	inode, device, err := GetFileIdentity(t.source.Path)
	if err != nil {
		return fmt.Errorf("get file identity: %w", err)
	}

	// Check for rotation (inode/device changed)
	if t.file != nil && (inode != t.inode || device != t.device) {
		t.logger.Info().
			Uint64("old_inode", t.inode).
			Uint64("new_inode", inode).
			Msg("File rotation detected")
		t.close()
	}

	// Open file if needed
	if t.file == nil {
		if err := t.open(inode, device, info.Size()); err != nil {
			return fmt.Errorf("open file: %w", err)
		}
	}

	// Check for truncation (size smaller than offset)
	if info.Size() < t.offset {
		t.logger.Info().
			Int64("old_offset", t.offset).
			Int64("new_size", info.Size()).
			Msg("File truncation detected")
		t.offset = 0
		if _, err := t.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek to start: %w", err)
		}
		t.reader.Reset(t.file)
	}

	// Read available lines
	err = t.readLines(ctx)
	if DebugCollector && err != nil {
		t.logger.Debug().Err(err).Msg("readLines returned error")
	}
	return err
}

// open opens the file and positions to the correct offset.
func (t *Tailer) open(inode, device uint64, size int64) error {
	file, err := os.Open(t.source.Path)
	if err != nil {
		return err
	}

	// Determine starting position
	var offset int64
	storedOffset := t.sincedb.GetOffset(t.source.Path, inode, device)

	if storedOffset >= 0 {
		// Resume from stored position
		offset = storedOffset
		t.logger.Debug().Int64("offset", offset).Msg("Resuming from stored position")
	} else if t.startFromEnd {
		// Start from end of file
		offset = size
		t.logger.Debug().Int64("offset", offset).Msg("Starting from end of file")
	} else {
		// Start from beginning
		offset = 0
		t.logger.Debug().Msg("Starting from beginning of file")
	}

	// Seek to position
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			file.Close()
			return fmt.Errorf("seek: %w", err)
		}
	}

	t.file = file
	t.reader = bufio.NewReaderSize(file, 64*1024) // 64KB buffer
	t.inode = inode
	t.device = device
	t.offset = offset

	t.logger.Info().
		Uint64("inode", inode).
		Uint64("device", device).
		Int64("offset", offset).
		Msg("File opened")

	return nil
}

// readLines reads all available lines from the file.
func (t *Tailer) readLines(ctx context.Context) error {
	linesRead := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := t.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No more data available
				if linesRead > 0 {
					if DebugCollector {
						t.logger.Debug().Int("lines_read", linesRead).Msg("Read batch complete (EOF)")
					}
					// Save position periodically
					t.sincedb.SetOffset(t.source.Path, t.inode, t.device, t.offset)
				}
				return nil
			}
			return fmt.Errorf("read line: %w", err)
		}

		// Update offset
		t.offset += int64(len(line))

		// Parse line
		event, err := t.parser.Parse(line)
		if err != nil {
			t.logger.Debug().Err(err).Str("line", truncate(line, 100)).Msg("Parse error")
			continue
		}

		if event == nil {
			continue // Parser returned nil (e.g., empty line)
		}

		// Enrich event
		event.Source = t.source.Name
		event.TenantID = t.tenantID
		event.Host = t.hostname
		event.Tags = append(event.Tags, t.source.Tags...)

		// Send to channel (non-blocking with timeout)
		select {
		case t.eventCh <- event:
			linesRead++
		case <-time.After(100 * time.Millisecond):
			t.logger.Warn().Msg("Event channel full, dropping event")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// close closes the file handle.
func (t *Tailer) close() {
	if t.file != nil {
		// Save final position
		t.sincedb.SetOffset(t.source.Path, t.inode, t.device, t.offset)
		t.file.Close()
		t.file = nil
		t.reader = nil
		t.logger.Debug().Int64("final_offset", t.offset).Msg("File closed")
	}
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ExpandPath expands glob patterns in a path.
func ExpandPath(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	return matches, nil
}
