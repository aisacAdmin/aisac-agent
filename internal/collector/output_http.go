package collector

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// DebugCollector enables detailed logging when set via environment variable
var DebugCollector = os.Getenv("AISAC_DEBUG_COLLECTOR") == "true"

// HTTPOutput sends events via HTTP POST to an ingest endpoint.
type HTTPOutput struct {
	cfg        OutputConfig
	httpClient *http.Client
	logger     zerolog.Logger

	// Statistics
	mu            sync.RWMutex
	sentBatches   int64
	sentEvents    int64
	failedBatches int64
}

// NewHTTPOutput creates a new HTTP output.
func NewHTTPOutput(cfg OutputConfig, logger zerolog.Logger) (*HTTPOutput, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("HTTP output URL is required")
	}

	l := logger.With().Str("component", "http_output").Logger()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if DebugCollector {
		l.Debug().
			Str("url", cfg.URL).
			Dur("timeout", cfg.Timeout).
			Int("retry_attempts", cfg.RetryAttempts).
			Msg("HTTPOutput initialized")
	}

	return &HTTPOutput{
		cfg:    cfg,
		logger: l,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}, nil
}

// Name returns the output name.
func (o *HTTPOutput) Name() string {
	return "http"
}

// Send sends a batch of events to the HTTP endpoint with retry logic.
func (o *HTTPOutput) Send(ctx context.Context, events []*LogEvent) error {
	if len(events) == 0 {
		return nil
	}

	if DebugCollector {
		o.logger.Debug().
			Int("event_count", len(events)).
			Str("url", o.cfg.URL).
			Msg("Sending events")
		// Log first event as sample
		if len(events) > 0 {
			sample, _ := json.MarshalIndent(events[0], "", "  ")
			o.logger.Debug().
				Str("sample_event", string(sample)).
				Msg("Sample event")
		}
	}

	// Prepare payload
	payload, err := o.preparePayload(events)
	if err != nil {
		return fmt.Errorf("preparing payload: %w", err)
	}

	if DebugCollector {
		o.logger.Debug().
			Int("payload_size", len(payload)).
			Msg("Payload prepared")
		// Log raw payload (first 500 chars)
		if len(payload) > 500 {
			o.logger.Debug().
				Str("payload_preview", string(payload[:500])+"...").
				Msg("Payload preview")
		} else {
			o.logger.Debug().
				Str("payload", string(payload)).
				Msg("Full payload")
		}
	}

	// Compress payload
	compressed, err := o.compress(payload)
	if err != nil {
		return fmt.Errorf("compressing payload: %w", err)
	}

	if DebugCollector {
		compressionRatio := float64(len(compressed)) / float64(len(payload)) * 100
		o.logger.Debug().
			Int("compressed_size", len(compressed)).
			Float64("compression_ratio", compressionRatio).
			Msg("Payload compressed")
	}

	// Send with retries
	var lastErr error
	for attempt := 0; attempt <= o.cfg.RetryAttempts; attempt++ {
		if attempt > 0 {
			if DebugCollector {
				o.logger.Debug().
					Int("attempt", attempt).
					Int("max_attempts", o.cfg.RetryAttempts).
					Msg("Retry attempt")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.cfg.RetryDelay):
			}
		}

		err := o.doRequest(ctx, compressed)
		if err == nil {
			o.recordSuccess(len(events))
			if DebugCollector {
				o.logger.Debug().
					Int("event_count", len(events)).
					Msg("SUCCESS - events sent")
			}
			return nil
		}

		lastErr = err
		if DebugCollector {
			o.logger.Debug().
				Int("attempt", attempt+1).
				Err(err).
				Msg("Attempt failed")
		}
	}

	o.recordFailure()
	return fmt.Errorf("failed after %d attempts: %w", o.cfg.RetryAttempts+1, lastErr)
}

// IngestPayload is the JSON structure expected by the AISAC /v1/logs endpoint.
type IngestPayload struct {
	AssetID  string   `json:"asset_id"`
	Messages []string `json:"messages"`
}

// preparePayload creates the JSON payload for the events.
func (o *HTTPOutput) preparePayload(events []*LogEvent) ([]byte, error) {
	// Convert each LogEvent to a JSON string (API expects array of strings)
	messages := make([]string, 0, len(events))
	for _, event := range events {
		eventJSON, err := json.Marshal(event)
		if err != nil {
			return nil, fmt.Errorf("marshaling event: %w", err)
		}
		messages = append(messages, string(eventJSON))
	}

	payload := IngestPayload{
		AssetID:  o.cfg.AssetID,
		Messages: messages,
	}

	return json.Marshal(payload)
}

// compress compresses the payload using gzip.
func (o *HTTPOutput) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// doRequest performs the HTTP request.
func (o *HTTPOutput) doRequest(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "AISAC-Collector/1.0")

	if o.cfg.APIKey != "" {
		// Use X-API-Key header as expected by AISAC platform
		req.Header.Set("X-API-Key", o.cfg.APIKey)
	}

	if DebugCollector {
		o.logger.Debug().
			Str("method", "POST").
			Str("url", o.cfg.URL).
			Str("content_type", req.Header.Get("Content-Type")).
			Str("content_encoding", req.Header.Get("Content-Encoding")).
			Bool("has_api_key", o.cfg.APIKey != "").
			Int("api_key_length", len(o.cfg.APIKey)).
			Str("x_api_key_header", req.Header.Get("X-API-Key")).
			Msg("Making HTTP request")
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error messages
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	if DebugCollector {
		o.logger.Debug().
			Int("status_code", resp.StatusCode).
			Str("response_body", string(body)).
			Msg("HTTP response received")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// recordSuccess records a successful batch send.
func (o *HTTPOutput) recordSuccess(eventCount int) {
	o.mu.Lock()
	o.sentBatches++
	o.sentEvents += int64(eventCount)
	o.mu.Unlock()
}

// recordFailure records a failed batch send.
func (o *HTTPOutput) recordFailure() {
	o.mu.Lock()
	o.failedBatches++
	o.mu.Unlock()
}

// Stats returns output statistics.
func (o *HTTPOutput) Stats() HTTPOutputStats {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return HTTPOutputStats{
		SentBatches:   o.sentBatches,
		SentEvents:    o.sentEvents,
		FailedBatches: o.failedBatches,
	}
}

// Close closes the HTTP output.
func (o *HTTPOutput) Close() error {
	o.httpClient.CloseIdleConnections()
	return nil
}

// HTTPOutputStats contains HTTP output statistics.
type HTTPOutputStats struct {
	SentBatches   int64 `json:"sent_batches"`
	SentEvents    int64 `json:"sent_events"`
	FailedBatches int64 `json:"failed_batches"`
}
