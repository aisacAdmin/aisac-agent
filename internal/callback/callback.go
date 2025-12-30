// Package callback handles notifications to external SOAR systems.
package callback

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/pkg/protocol"
	"github.com/cisec/aisac-agent/pkg/types"
)

// CallbackConfig holds callback configuration.
type CallbackConfig struct {
	// Enabled enables/disables callbacks
	Enabled bool `yaml:"enabled"`
	// URL is the webhook endpoint (n8n, SOAR, etc.)
	URL string `yaml:"url"`
	// AuthToken is the bearer token for authentication
	AuthToken string `yaml:"auth_token"`
	// Timeout for HTTP requests
	Timeout time.Duration `yaml:"timeout"`
	// RetryAttempts number of retry attempts on failure
	RetryAttempts int `yaml:"retry_attempts"`
	// RetryDelay between retry attempts
	RetryDelay time.Duration `yaml:"retry_delay"`
	// SkipTLSVerify skips TLS certificate verification
	SkipTLSVerify bool `yaml:"skip_tls_verify"`
}

// DefaultCallbackConfig returns default callback configuration.
func DefaultCallbackConfig() *CallbackConfig {
	return &CallbackConfig{
		Enabled:       false,
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    5 * time.Second,
	}
}

// CallbackPayload is the payload sent to SOAR systems.
type CallbackPayload struct {
	// Event type
	Event string `json:"event"`
	// Timestamp of the event
	Timestamp time.Time `json:"timestamp"`
	// AgentID that generated the event
	AgentID string `json:"agent_id"`
	// ExecutionID from SOAR
	ExecutionID string `json:"execution_id"`
	// CommandID of the command
	CommandID string `json:"command_id"`
	// Action that was executed
	Action string `json:"action"`
	// Status of the execution
	Status string `json:"status"`
	// Result details
	Result types.ActionResult `json:"result"`
	// ExecutionTimeMs in milliseconds
	ExecutionTimeMs int64 `json:"execution_time_ms"`
}

// Client handles callbacks to SOAR systems.
type Client struct {
	cfg        *CallbackConfig
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewClient creates a new callback client.
func NewClient(cfg *CallbackConfig, logger zerolog.Logger) *Client {
	l := logger.With().Str("component", "callback").Logger()

	// SECURITY: Warn about InsecureSkipVerify - should never be used in production
	if cfg.SkipTLSVerify && cfg.Enabled {
		l.Warn().Msg("SECURITY WARNING: TLS certificate verification disabled for callbacks (skip_tls_verify=true). This is vulnerable to MITM attacks. Only use for development/testing!")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
	}

	return &Client{
		cfg:    cfg,
		logger: l,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}
}

// SendCommandResult sends command execution result to SOAR.
func (c *Client) SendCommandResult(ctx context.Context, agentID string, cmd *protocol.Command, resp *protocol.Response) error {
	if !c.cfg.Enabled {
		return nil
	}

	payload := CallbackPayload{
		Event:           "command_result",
		Timestamp:       time.Now().UTC(),
		AgentID:         agentID,
		ExecutionID:     cmd.ExecutionID,
		CommandID:       cmd.ID,
		Action:          string(cmd.Action),
		Status:          string(resp.Status),
		Result:          resp.Result,
		ExecutionTimeMs: resp.ExecutionTimeMs,
	}

	return c.send(ctx, payload)
}

// SendAgentStatus sends agent status update to SOAR.
func (c *Client) SendAgentStatus(ctx context.Context, agentID string, status string, details map[string]interface{}) error {
	if !c.cfg.Enabled {
		return nil
	}

	payload := CallbackPayload{
		Event:     "agent_status",
		Timestamp: time.Now().UTC(),
		AgentID:   agentID,
		Status:    status,
		Result: types.ActionResult{
			Success: true,
			Details: details,
		},
	}

	return c.send(ctx, payload)
}

// send sends a payload to the callback URL with retries.
func (c *Client) send(ctx context.Context, payload CallbackPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.cfg.RetryAttempts; attempt++ {
		if attempt > 0 {
			c.logger.Debug().
				Int("attempt", attempt).
				Dur("delay", c.cfg.RetryDelay).
				Msg("Retrying callback")

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.cfg.RetryDelay):
			}
		}

		err := c.doRequest(ctx, data)
		if err == nil {
			c.logger.Debug().
				Str("event", payload.Event).
				Str("execution_id", payload.ExecutionID).
				Msg("Callback sent successfully")
			return nil
		}

		lastErr = err
		c.logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_attempts", c.cfg.RetryAttempts+1).
			Msg("Callback failed")
	}

	return fmt.Errorf("callback failed after %d attempts: %w", c.cfg.RetryAttempts+1, lastErr)
}

// doRequest performs the HTTP request.
func (c *Client) doRequest(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AISAC-Agent/1.0")

	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
