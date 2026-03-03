// Package heartbeat provides agent heartbeat functionality to report status to the AISAC platform.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Config holds the heartbeat configuration.
type Config struct {
	Enabled       bool          `yaml:"enabled"`
	URL           string        `yaml:"url"`
	APIKey        string        `yaml:"api_key"`
	AssetID       string        `yaml:"asset_id"`
	Interval      time.Duration `yaml:"interval"`
	Timeout       time.Duration `yaml:"timeout"`
	SkipTLSVerify bool          `yaml:"skip_tls_verify"`
	AuthToken     string        `yaml:"auth_token"` // Supabase anon key for Authorization header

	// Safety: auto-recovery on consecutive failures
	FailureThreshold int      `yaml:"failure_threshold"` // Number of consecutive failures before triggering recovery
	RecoveryActions  []string `yaml:"recovery_actions"`  // Actions to trigger on recovery (e.g., "unisolate_host")
}

// RecoveryCallback is called when consecutive heartbeat failures exceed the threshold.
type RecoveryCallback func(ctx context.Context, actions []string)

// DefaultConfig returns default heartbeat configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:  false,
		URL:      "https://api.aisac.cisec.es/v1/heartbeat",
		Interval: 120 * time.Second,
		Timeout:  10 * time.Second,
	}
}

// Validate validates the heartbeat configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.APIKey == "" {
		return fmt.Errorf("heartbeat.api_key is required when heartbeat is enabled")
	}

	if c.AssetID == "" {
		return fmt.Errorf("heartbeat.asset_id is required when heartbeat is enabled")
	}

	if c.URL == "" {
		return fmt.Errorf("heartbeat.url is required")
	}

	if c.Interval < 10*time.Second {
		return fmt.Errorf("heartbeat.interval must be at least 10 seconds")
	}

	return nil
}

// Payload represents the heartbeat request payload.
type Payload struct {
	AssetID      string    `json:"asset_id"`
	Timestamp    time.Time `json:"timestamp"`
	AgentVersion string    `json:"agent_version"`
	Metrics      Metrics   `json:"metrics"`
}

// Metrics contains system metrics.
type Metrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

// Response represents the heartbeat response from the server.
type Response struct {
	Success         bool   `json:"success"`
	NextHeartbeatIn int    `json:"next_heartbeat_in"` // seconds
	Message         string `json:"message,omitempty"`
}

// Client handles heartbeat communication with the AISAC platform.
type Client struct {
	cfg        Config
	logger     zerolog.Logger
	httpClient *http.Client
	version    string

	mu       sync.RWMutex
	running  bool
	interval time.Duration
	lastSent time.Time
	lastErr  error

	// Stats
	totalSent   int64
	totalFailed int64

	// Auto-recovery
	consecutiveFailures int
	recoveryTriggered   bool
	recoveryCallback    RecoveryCallback
}

// NewClient creates a new heartbeat client.
func NewClient(cfg Config, version string, logger zerolog.Logger) *Client {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		cfg:    cfg,
		logger: logger.With().Str("component", "heartbeat").Logger(),
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		version:  version,
		interval: cfg.Interval,
	}
}

// SetRecoveryCallback sets the callback function for auto-recovery.
func (c *Client) SetRecoveryCallback(cb RecoveryCallback) {
	c.mu.Lock()
	c.recoveryCallback = cb
	c.mu.Unlock()
}

// Start begins the heartbeat loop.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("heartbeat already running")
	}
	c.running = true
	c.mu.Unlock()

	c.logger.Info().
		Str("url", c.cfg.URL).
		Str("asset_id", c.cfg.AssetID).
		Dur("interval", c.interval).
		Msg("Starting heartbeat")

	// Send initial heartbeat immediately
	c.sendHeartbeat(ctx)

	// Start heartbeat loop
	go c.run(ctx)

	return nil
}

// run is the main heartbeat loop.
func (c *Client) run(ctx context.Context) {
	for {
		c.mu.RLock()
		interval := c.interval
		c.mu.RUnlock()

		select {
		case <-ctx.Done():
			c.logger.Info().Msg("Heartbeat stopped")
			c.mu.Lock()
			c.running = false
			c.mu.Unlock()
			return
		case <-time.After(interval):
			c.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat sends a single heartbeat to the server.
func (c *Client) sendHeartbeat(ctx context.Context) {
	c.logger.Debug().Str("url", c.cfg.URL).Msg("Sending heartbeat")
	metrics := CollectMetrics()

	payload := Payload{
		AssetID:      c.cfg.AssetID,
		Timestamp:    time.Now().UTC(),
		AgentVersion: c.version,
		Metrics:      metrics,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to marshal heartbeat payload")
		c.recordError(ctx, err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to create heartbeat request")
		c.recordError(ctx, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.cfg.APIKey)
	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	req.Header.Set("User-Agent", "AISAC-Agent/"+c.version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Warn().Err(err).Msg("Heartbeat request failed, will retry")
		c.recordError(ctx, err)
		// On network error, retry sooner
		c.mu.Lock()
		c.interval = 60 * time.Second
		c.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		c.logger.Error().
			Int("status", resp.StatusCode).
			Msg("Heartbeat unauthorized - invalid API Key, stopping heartbeat")
		c.recordError(ctx, fmt.Errorf("unauthorized: invalid API Key"))
		// Stop heartbeat on auth failure
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		return
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.Warn().
			Int("status", resp.StatusCode).
			Str("body", string(respBody)).
			Msg("Heartbeat failed")
		c.recordError(ctx, fmt.Errorf("status %d", resp.StatusCode))
		return
	}

	var response Response
	if err := json.Unmarshal(respBody, &response); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to parse heartbeat response")
		c.recordError(ctx, err)
		return
	}

	// Update interval from server response
	if response.NextHeartbeatIn > 0 {
		newInterval := time.Duration(response.NextHeartbeatIn) * time.Second
		c.mu.Lock()
		if c.interval != newInterval {
			c.logger.Debug().
				Dur("old_interval", c.interval).
				Dur("new_interval", newInterval).
				Msg("Heartbeat interval updated")
		}
		c.interval = newInterval
		c.mu.Unlock()
	}

	c.mu.Lock()
	c.lastSent = time.Now()
	c.lastErr = nil
	c.totalSent++
	// Reset failure tracking on successful heartbeat
	if c.consecutiveFailures > 0 {
		c.logger.Info().
			Int("previous_consecutive_failures", c.consecutiveFailures).
			Msg("Heartbeat recovered, resetting failure counter")
	}
	c.consecutiveFailures = 0
	c.recoveryTriggered = false
	c.mu.Unlock()

	c.logger.Info().
		Float64("cpu", metrics.CPUPercent).
		Float64("memory", metrics.MemoryPercent).
		Float64("disk", metrics.DiskPercent).
		Msg("Heartbeat sent successfully")
}

// recordError records a heartbeat error and checks for recovery trigger.
func (c *Client) recordError(ctx context.Context, err error) {
	c.mu.Lock()
	c.lastErr = err
	c.totalFailed++
	c.consecutiveFailures++

	shouldTriggerRecovery := false
	if c.cfg.FailureThreshold > 0 &&
		c.consecutiveFailures >= c.cfg.FailureThreshold &&
		!c.recoveryTriggered &&
		c.recoveryCallback != nil &&
		len(c.cfg.RecoveryActions) > 0 {
		shouldTriggerRecovery = true
		c.recoveryTriggered = true
	}

	failures := c.consecutiveFailures
	threshold := c.cfg.FailureThreshold
	actions := c.cfg.RecoveryActions
	callback := c.recoveryCallback
	c.mu.Unlock()

	if shouldTriggerRecovery {
		c.logger.Warn().
			Int("consecutive_failures", failures).
			Int("threshold", threshold).
			Strs("recovery_actions", actions).
			Msg("Heartbeat failure threshold exceeded, triggering auto-recovery")

		// Trigger recovery in a goroutine to avoid blocking
		go callback(ctx, actions)
	}
}

// Stats returns heartbeat statistics.
func (c *Client) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Stats{
		Running:             c.running,
		Interval:            c.interval,
		LastSent:            c.lastSent,
		LastError:           c.lastErr,
		TotalSent:           c.totalSent,
		TotalFailed:         c.totalFailed,
		ConsecutiveFailures: c.consecutiveFailures,
		RecoveryTriggered:   c.recoveryTriggered,
	}
}

// Stats contains heartbeat statistics.
type Stats struct {
	Running             bool          `json:"running"`
	Interval            time.Duration `json:"interval"`
	LastSent            time.Time     `json:"last_sent"`
	LastError           error         `json:"last_error,omitempty"`
	TotalSent           int64         `json:"total_sent"`
	TotalFailed         int64         `json:"total_failed"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	RecoveryTriggered   bool          `json:"recovery_triggered"`
}
