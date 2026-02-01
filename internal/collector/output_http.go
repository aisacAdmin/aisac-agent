package collector

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// DebugCollector enables detailed logging when set via environment variable
var DebugCollector = os.Getenv("AISAC_DEBUG_COLLECTOR") == "true"

// HTTPOutput sends events via HTTP POST to an ingest endpoint.
type HTTPOutput struct {
	cfg        OutputConfig
	httpClient *http.Client

	// Statistics
	mu            sync.RWMutex
	sentBatches   int64
	sentEvents    int64
	failedBatches int64
}

// NewHTTPOutput creates a new HTTP output.
func NewHTTPOutput(cfg OutputConfig) (*HTTPOutput, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("HTTP output URL is required")
	}

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
		log.Printf("[DEBUG] HTTPOutput: URL=%s, Timeout=%v, RetryAttempts=%d",
			cfg.URL, cfg.Timeout, cfg.RetryAttempts)
	}

	return &HTTPOutput{
		cfg: cfg,
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
		log.Printf("[DEBUG] HTTPOutput.Send: Sending %d events to %s", len(events), o.cfg.URL)
		// Log first event as sample
		if len(events) > 0 {
			sample, _ := json.MarshalIndent(events[0], "", "  ")
			log.Printf("[DEBUG] HTTPOutput.Send: Sample event:\n%s", string(sample))
		}
	}

	// Prepare payload
	payload, err := o.preparePayload(events)
	if err != nil {
		return fmt.Errorf("preparing payload: %w", err)
	}

	if DebugCollector {
		log.Printf("[DEBUG] HTTPOutput.Send: Payload size (uncompressed): %d bytes", len(payload))
		// Log raw payload (first 500 chars)
		if len(payload) > 500 {
			log.Printf("[DEBUG] HTTPOutput.Send: Payload preview:\n%s...", string(payload[:500]))
		} else {
			log.Printf("[DEBUG] HTTPOutput.Send: Full payload:\n%s", string(payload))
		}
	}

	// Compress payload
	compressed, err := o.compress(payload)
	if err != nil {
		return fmt.Errorf("compressing payload: %w", err)
	}

	if DebugCollector {
		log.Printf("[DEBUG] HTTPOutput.Send: Compressed size: %d bytes (%.1f%% compression)",
			len(compressed), float64(len(compressed))/float64(len(payload))*100)
	}

	// Send with retries
	var lastErr error
	for attempt := 0; attempt <= o.cfg.RetryAttempts; attempt++ {
		if attempt > 0 {
			if DebugCollector {
				log.Printf("[DEBUG] HTTPOutput.Send: Retry attempt %d/%d", attempt, o.cfg.RetryAttempts)
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
				log.Printf("[DEBUG] HTTPOutput.Send: SUCCESS - sent %d events", len(events))
			}
			return nil
		}

		lastErr = err
		if DebugCollector {
			log.Printf("[DEBUG] HTTPOutput.Send: Attempt %d failed: %v", attempt+1, err)
		}
	}

	o.recordFailure()
	return fmt.Errorf("failed after %d attempts: %w", o.cfg.RetryAttempts+1, lastErr)
}

// IngestPayload is the JSON structure expected by the syslog-ingest Edge Function.
type IngestPayload struct {
	Events []*LogEvent `json:"events"`
}

// preparePayload creates the JSON payload for the events.
func (o *HTTPOutput) preparePayload(events []*LogEvent) ([]byte, error) {
	// Create JSON payload with "events" array (format expected by AISAC platform)
	payload := IngestPayload{
		Events: events,
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
		log.Printf("[DEBUG] HTTPOutput.doRequest: POST %s", o.cfg.URL)
		log.Printf("[DEBUG] HTTPOutput.doRequest: Headers: Content-Type=%s, Content-Encoding=%s, Auth=%v",
			req.Header.Get("Content-Type"),
			req.Header.Get("Content-Encoding"),
			o.cfg.APIKey != "")
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error messages
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	if DebugCollector {
		log.Printf("[DEBUG] HTTPOutput.doRequest: Response status=%d, body=%s",
			resp.StatusCode, string(body))
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
