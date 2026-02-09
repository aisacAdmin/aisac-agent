package collector

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

// Output defines the interface for sending log events to a destination.
type Output interface {
	// Name returns the output name for logging.
	Name() string
	// Send sends a batch of events to the destination.
	Send(ctx context.Context, events []*LogEvent) error
	// Close closes the output and releases resources.
	Close() error
}

// NewOutput creates an output based on configuration.
func NewOutput(cfg OutputConfig, logger zerolog.Logger) (Output, error) {
	switch cfg.Type {
	case "http":
		return NewHTTPOutput(cfg, logger)
	default:
		return nil, fmt.Errorf("unknown output type: %s", cfg.Type)
	}
}
