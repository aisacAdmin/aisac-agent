package collector

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestBatcher(t *testing.T) {
	logger := zerolog.Nop()
	eventCh := make(chan *LogEvent, 100)

	var mu sync.Mutex
	var flushedEvents [][]*LogEvent

	flushCallback := func(ctx context.Context, events []*LogEvent) error {
		mu.Lock()
		flushedEvents = append(flushedEvents, events)
		mu.Unlock()
		return nil
	}

	batcher := NewBatcher(eventCh, flushCallback, logger, 5, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start batcher
	go batcher.Run(ctx)

	// Send 12 events (should trigger 2 flushes of 5 + 1 flush of 2 on shutdown)
	for i := 0; i < 12; i++ {
		eventCh <- &LogEvent{Message: "test event"}
	}

	// Wait for batch size flush (5 events)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	flushCount := len(flushedEvents)
	mu.Unlock()

	if flushCount < 2 {
		t.Errorf("Expected at least 2 flushes from batch size, got %d", flushCount)
	}

	// Stop batcher
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Check stats
	stats := batcher.Stats()
	if stats.BatchSize != 5 {
		t.Errorf("BatchSize = %d, want 5", stats.BatchSize)
	}
}

func TestBatcherTimeBasedFlush(t *testing.T) {
	logger := zerolog.Nop()
	eventCh := make(chan *LogEvent, 100)

	var mu sync.Mutex
	var flushedEvents [][]*LogEvent

	flushCallback := func(ctx context.Context, events []*LogEvent) error {
		mu.Lock()
		flushedEvents = append(flushedEvents, events)
		mu.Unlock()
		return nil
	}

	// Batch size 100, interval 50ms - should flush on interval
	batcher := NewBatcher(eventCh, flushCallback, logger, 100, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go batcher.Run(ctx)

	// Send 3 events (less than batch size)
	for i := 0; i < 3; i++ {
		eventCh <- &LogEvent{Message: "test event"}
	}

	// Wait for interval flush
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	flushCount := len(flushedEvents)
	totalEvents := 0
	for _, batch := range flushedEvents {
		totalEvents += len(batch)
	}
	mu.Unlock()

	if flushCount < 1 {
		t.Errorf("Expected at least 1 interval-based flush, got %d", flushCount)
	}

	if totalEvents != 3 {
		t.Errorf("Expected 3 total events flushed, got %d", totalEvents)
	}
}

func TestBatcherShutdownFlush(t *testing.T) {
	logger := zerolog.Nop()
	eventCh := make(chan *LogEvent, 100)

	var mu sync.Mutex
	var flushedEvents [][]*LogEvent

	flushCallback := func(ctx context.Context, events []*LogEvent) error {
		mu.Lock()
		flushedEvents = append(flushedEvents, events)
		mu.Unlock()
		return nil
	}

	// Large batch size and interval so only shutdown triggers flush
	batcher := NewBatcher(eventCh, flushCallback, logger, 1000, 10*time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		batcher.Run(ctx)
		close(done)
	}()

	// Send 5 events
	for i := 0; i < 5; i++ {
		eventCh <- &LogEvent{Message: "test event"}
	}

	// Small wait to ensure events are received
	time.Sleep(10 * time.Millisecond)

	// Cancel to trigger shutdown
	cancel()
	<-done

	mu.Lock()
	totalEvents := 0
	for _, batch := range flushedEvents {
		totalEvents += len(batch)
	}
	mu.Unlock()

	if totalEvents != 5 {
		t.Errorf("Expected 5 events flushed on shutdown, got %d", totalEvents)
	}
}

func TestBatcherStats(t *testing.T) {
	logger := zerolog.Nop()
	eventCh := make(chan *LogEvent, 100)

	flushCallback := func(ctx context.Context, events []*LogEvent) error {
		return nil
	}

	batcher := NewBatcher(eventCh, flushCallback, logger, 50, 5*time.Second)

	stats := batcher.Stats()
	if stats.BatchSize != 50 {
		t.Errorf("BatchSize = %d, want 50", stats.BatchSize)
	}
	if stats.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", stats.FlushInterval)
	}
	if stats.BufferedEvents != 0 {
		t.Errorf("BufferedEvents = %d, want 0", stats.BufferedEvents)
	}
}
