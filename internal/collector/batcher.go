package collector

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Batcher collects events and flushes them in batches.
type Batcher struct {
	eventCh       <-chan *LogEvent
	flushCallback func(ctx context.Context, events []*LogEvent) error
	logger        zerolog.Logger

	// Configuration
	batchSize     int
	flushInterval time.Duration

	// State
	mu     sync.Mutex
	buffer []*LogEvent
}

// NewBatcher creates a new event batcher.
func NewBatcher(
	eventCh <-chan *LogEvent,
	flushCallback func(ctx context.Context, events []*LogEvent) error,
	logger zerolog.Logger,
	batchSize int,
	flushInterval time.Duration,
) *Batcher {
	return &Batcher{
		eventCh:       eventCh,
		flushCallback: flushCallback,
		logger:        logger.With().Str("component", "batcher").Logger(),
		batchSize:     batchSize,
		flushInterval: flushInterval,
		buffer:        make([]*LogEvent, 0, batchSize),
	}
}

// Run starts the batcher and processes events until context is cancelled.
func (b *Batcher) Run(ctx context.Context) error {
	b.logger.Info().
		Int("batch_size", b.batchSize).
		Dur("flush_interval", b.flushInterval).
		Msg("Starting batcher")
	defer b.logger.Info().Msg("Batcher stopped")

	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown
			b.flush(context.Background()) // Use background context for final flush
			return ctx.Err()

		case event, ok := <-b.eventCh:
			if !ok {
				// Channel closed
				b.flush(ctx)
				return nil
			}
			b.addEvent(ctx, event)

		case <-ticker.C:
			b.flush(ctx)
		}
	}
}

// addEvent adds an event to the buffer and flushes if batch size reached.
func (b *Batcher) addEvent(ctx context.Context, event *LogEvent) {
	b.mu.Lock()
	b.buffer = append(b.buffer, event)
	shouldFlush := len(b.buffer) >= b.batchSize
	b.mu.Unlock()

	if shouldFlush {
		b.flush(ctx)
	}
}

// flush sends buffered events to the output.
func (b *Batcher) flush(ctx context.Context) {
	b.mu.Lock()
	if len(b.buffer) == 0 {
		b.mu.Unlock()
		return
	}

	// Take ownership of buffer and create new one
	events := b.buffer
	b.buffer = make([]*LogEvent, 0, b.batchSize)
	b.mu.Unlock()

	// Send events
	b.logger.Debug().Int("count", len(events)).Msg("Flushing batch")

	if err := b.flushCallback(ctx, events); err != nil {
		b.logger.Error().Err(err).Int("count", len(events)).Msg("Flush failed")
		// Events are lost on failure - could implement retry queue if needed
	}
}

// Stats returns current batcher statistics.
func (b *Batcher) Stats() BatcherStats {
	b.mu.Lock()
	defer b.mu.Unlock()

	return BatcherStats{
		BufferedEvents: len(b.buffer),
		BatchSize:      b.batchSize,
		FlushInterval:  b.flushInterval,
	}
}

// BatcherStats contains batcher statistics.
type BatcherStats struct {
	BufferedEvents int           `json:"buffered_events"`
	BatchSize      int           `json:"batch_size"`
	FlushInterval  time.Duration `json:"flush_interval"`
}
