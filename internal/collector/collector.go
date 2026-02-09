// Package collector provides log collection and forwarding capabilities.
package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	// DefaultEventChannelSize is the default size of the event channel.
	DefaultEventChannelSize = 1000
	// SinceDBSaveInterval is how often to save sincedb to disk.
	SinceDBSaveInterval = 30 * time.Second
	// SinceDBStaleAge is the maximum age of sincedb entries before cleanup.
	SinceDBStaleAge = 7 * 24 * time.Hour
)

// Collector is the main log collection component.
type Collector struct {
	cfg     Config
	logger  zerolog.Logger
	sincedb *SinceDB
	output  Output
	batcher *Batcher
	tailers []*Tailer
	eventCh chan *LogEvent

	mu      sync.RWMutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New creates a new Collector.
func New(cfg Config, logger zerolog.Logger) (*Collector, error) {
	l := logger.With().Str("component", "collector").Logger()

	// Create sincedb
	sincedb, err := NewSinceDB(cfg.File.SinceDBPath)
	if err != nil {
		return nil, fmt.Errorf("creating sincedb: %w", err)
	}

	// Load sincedb state
	if err := sincedb.Load(); err != nil {
		l.Warn().Err(err).Msg("Failed to load sincedb, starting fresh")
	}

	// Create output
	output, err := NewOutput(cfg.Output, logger)
	if err != nil {
		return nil, fmt.Errorf("creating output: %w", err)
	}

	return &Collector{
		cfg:     cfg,
		logger:  l,
		sincedb: sincedb,
		output:  output,
		eventCh: make(chan *LogEvent, DefaultEventChannelSize),
	}, nil
}

// Start starts the collector.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("collector already running")
	}
	c.running = true
	c.mu.Unlock()

	c.logger.Info().
		Int("sources", len(c.cfg.Sources)).
		Str("output", c.cfg.Output.Type).
		Msg("Starting collector")

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	// Create batcher
	c.batcher = NewBatcher(
		c.eventCh,
		c.output.Send,
		c.logger,
		c.cfg.Batch.Size,
		c.cfg.Batch.Interval,
	)

	// Start batcher
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.batcher.Run(ctx); err != nil && err != context.Canceled {
			c.logger.Error().Err(err).Msg("Batcher error")
		}
	}()

	// Start tailers for each source
	startFromEnd := c.cfg.File.StartPosition == "end"
	for _, source := range c.cfg.Sources {
		// Get parser for source
		parser, err := GetParser(source.Parser)
		if err != nil {
			c.logger.Error().
				Err(err).
				Str("source", source.Name).
				Str("parser", source.Parser).
				Msg("Failed to create parser, skipping source")
			continue
		}

		// Expand path (supports glob patterns)
		paths, err := ExpandPath(source.Path)
		if err != nil {
			c.logger.Error().
				Err(err).
				Str("source", source.Name).
				Str("path", source.Path).
				Msg("Failed to expand path, skipping source")
			continue
		}

		if len(paths) == 0 {
			c.logger.Warn().
				Str("source", source.Name).
				Str("path", source.Path).
				Msg("No files match path pattern")
		}

		// Create tailer for each matching file
		for _, path := range paths {
			// Create source config with expanded path
			srcCfg := source
			srcCfg.Path = path

			tailer, err := NewTailer(
				srcCfg,
				parser,
				c.sincedb,
				c.eventCh,
				c.logger,
				c.cfg.TenantID,
				startFromEnd,
			)
			if err != nil {
				c.logger.Error().
					Err(err).
					Str("source", source.Name).
					Str("path", path).
					Msg("Failed to create tailer")
				continue
			}

			c.tailers = append(c.tailers, tailer)

			// Start tailer
			c.wg.Add(1)
			go func(t *Tailer) {
				defer c.wg.Done()
				if err := t.Run(ctx); err != nil && err != context.Canceled {
					c.logger.Error().Err(err).Msg("Tailer error")
				}
			}(tailer)
		}
	}

	c.logger.Info().
		Int("tailers", len(c.tailers)).
		Msg("Collector started")

	// Start sincedb saver
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.sincedbSaver(ctx)
	}()

	return nil
}

// Stop stops the collector gracefully.
func (c *Collector) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	c.mu.Unlock()

	c.logger.Info().Msg("Stopping collector")

	// Cancel context to stop all goroutines
	if c.cancel != nil {
		c.cancel()
	}

	// Wait for all goroutines to finish
	c.wg.Wait()

	// Close event channel
	close(c.eventCh)

	// Final sincedb save
	if err := c.sincedb.Save(); err != nil {
		c.logger.Error().Err(err).Msg("Failed to save sincedb")
	}

	// Close output
	if err := c.output.Close(); err != nil {
		c.logger.Error().Err(err).Msg("Failed to close output")
	}

	c.logger.Info().Msg("Collector stopped")
	return nil
}

// sincedbSaver periodically saves sincedb to disk.
func (c *Collector) sincedbSaver(ctx context.Context) {
	ticker := time.NewTicker(SinceDBSaveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.sincedb.Save(); err != nil {
				c.logger.Error().Err(err).Msg("Failed to save sincedb")
			}
			// Cleanup stale entries
			c.sincedb.RemoveStale(SinceDBStaleAge)
		}
	}
}

// Stats returns collector statistics.
func (c *Collector) Stats() CollectorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := CollectorStats{
		Running:      c.running,
		TailerCount:  len(c.tailers),
		SourceCount:  len(c.cfg.Sources),
		ChannelUsage: len(c.eventCh),
		ChannelSize:  cap(c.eventCh),
	}

	if c.batcher != nil {
		stats.Batcher = c.batcher.Stats()
	}

	if httpOut, ok := c.output.(*HTTPOutput); ok {
		stats.Output = httpOut.Stats()
	}

	return stats
}

// CollectorStats contains collector statistics.
type CollectorStats struct {
	Running      bool             `json:"running"`
	TailerCount  int              `json:"tailer_count"`
	SourceCount  int              `json:"source_count"`
	ChannelUsage int              `json:"channel_usage"`
	ChannelSize  int              `json:"channel_size"`
	Batcher      BatcherStats     `json:"batcher"`
	Output       HTTPOutputStats  `json:"output"`
}
