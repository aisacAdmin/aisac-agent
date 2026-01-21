// Package agent implements the main AISAC agent logic.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/actions"
	"github.com/cisec/aisac-agent/internal/callback"
	"github.com/cisec/aisac-agent/internal/collector"
	"github.com/cisec/aisac-agent/internal/config"
	"github.com/cisec/aisac-agent/pkg/protocol"
	"github.com/cisec/aisac-agent/pkg/types"
)

// Version is set at build time.
var Version = "dev"

// Agent represents the AISAC agent.
type Agent struct {
	cfg        *config.AgentConfig
	logger     zerolog.Logger
	conn       *websocket.Conn
	connMu     sync.Mutex
	executor   *actions.Executor
	callback   *callback.Client
	collector  *collector.Collector
	info       types.AgentInfo
	infoMu     sync.RWMutex // Protects info.Status

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	activeTasks      map[string]context.CancelFunc
	activeTasksMu    sync.Mutex
	reconnectAttempt int // Track reconnection attempts for exponential backoff
}

// New creates a new Agent instance.
func New(cfg *config.AgentConfig, logger zerolog.Logger) (*Agent, error) {
	ctx, cancel := context.WithCancel(context.Background())

	agentID := cfg.Agent.ID
	if agentID == "" {
		hostname, _ := os.Hostname()
		agentID = fmt.Sprintf("%s-%d", hostname, time.Now().Unix())
	}

	hostname, _ := os.Hostname()

	agent := &Agent{
		cfg:         cfg,
		logger:      logger.With().Str("component", "agent").Logger(),
		ctx:         ctx,
		cancel:      cancel,
		activeTasks: make(map[string]context.CancelFunc),
		info: types.AgentInfo{
			ID:       agentID,
			Hostname: hostname,
			Platform: types.Platform(runtime.GOOS),
			Version:  Version,
			Status:   "starting",
		},
	}

	executor, err := actions.NewExecutor(cfg, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating action executor: %w", err)
	}
	agent.executor = executor

	// Initialize callback client
	callbackCfg := &callback.CallbackConfig{
		Enabled:       cfg.Callback.Enabled,
		URL:           cfg.Callback.URL,
		AuthToken:     cfg.Callback.AuthToken,
		Timeout:       cfg.Callback.Timeout,
		RetryAttempts: cfg.Callback.RetryAttempts,
		RetryDelay:    cfg.Callback.RetryDelay,
		SkipTLSVerify: cfg.Callback.SkipTLSVerify,
	}
	agent.callback = callback.NewClient(callbackCfg, logger)

	// Initialize log collector if enabled
	if cfg.Collector.Enabled {
		col, err := collector.New(cfg.Collector, logger)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("creating collector: %w", err)
		}
		agent.collector = col
		logger.Info().Msg("Log collector initialized")
	}

	return agent, nil
}

// Run starts the agent and blocks until shutdown.
func (a *Agent) Run() error {
	a.logger.Info().
		Str("agent_id", a.info.ID).
		Str("version", Version).
		Msg("Starting AISAC agent")

	// Start collector if enabled (runs independently of server connection)
	if a.collector != nil {
		if err := a.collector.Start(a.ctx); err != nil {
			a.logger.Error().Err(err).Msg("Failed to start collector")
		}
	}

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info().Msg("Agent shutdown requested")
			return nil
		default:
		}

		if err := a.connect(); err != nil {
			a.logger.Error().Err(err).Msg("Connection failed")
			a.waitReconnect()
			continue
		}

		if err := a.register(); err != nil {
			a.logger.Error().Err(err).Msg("Registration failed")
			a.closeConn()
			a.waitReconnect()
			continue
		}

		a.setStatus("connected")
		a.reconnectAttempt = 0 // Reset on successful connection
		a.logger.Info().Msg("Connected and registered with server")

		// Start heartbeat
		a.wg.Add(1)
		go a.heartbeatLoop()

		// Process messages
		if err := a.messageLoop(); err != nil {
			a.logger.Error().Err(err).Msg("Message loop error")
		}

		a.closeConn()
		a.setStatus("disconnected")

		select {
		case <-a.ctx.Done():
			return nil
		default:
			a.waitReconnect()
		}
	}
}

// Shutdown gracefully shuts down the agent.
func (a *Agent) Shutdown() {
	a.logger.Info().Msg("Shutting down agent")
	a.cancel()

	// Cancel all active tasks
	a.activeTasksMu.Lock()
	for id, cancel := range a.activeTasks {
		a.logger.Debug().Str("task_id", id).Msg("Cancelling active task")
		cancel()
	}
	a.activeTasksMu.Unlock()

	// Stop collector if running
	if a.collector != nil {
		if err := a.collector.Stop(); err != nil {
			a.logger.Error().Err(err).Msg("Failed to stop collector")
		}
	}

	a.closeConn()
	a.wg.Wait()
}

func (a *Agent) connect() error {
	dialer := websocket.Dialer{
		HandshakeTimeout: a.cfg.Server.ConnectTimeout,
	}

	if a.cfg.TLS.Enabled {
		tlsConfig, err := a.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("building TLS config: %w", err)
		}
		dialer.TLSClientConfig = tlsConfig
	}

	headers := http.Header{}
	headers.Set("X-Agent-ID", a.info.ID)
	headers.Set("X-Agent-Version", Version)

	conn, resp, err := dialer.DialContext(a.ctx, a.cfg.Server.URL, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("websocket dial failed with status %d: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("websocket dial: %w", err)
	}

	a.connMu.Lock()
	a.conn = conn
	a.connMu.Unlock()

	return nil
}

func (a *Agent) buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	caCert, err := os.ReadFile(a.cfg.TLS.CAFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// SECURITY: Warn about InsecureSkipVerify - this should never be used in production
	if a.cfg.TLS.SkipVerify {
		a.logger.Warn().Msg("SECURITY WARNING: TLS certificate verification is disabled (skip_verify=true). This makes the connection vulnerable to MITM attacks. Only use this for development/testing!")
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: a.cfg.TLS.SkipVerify,
	}, nil
}

func (a *Agent) register() error {
	req := protocol.RegisterRequest{
		AgentInfo:    a.info,
		Capabilities: a.executor.ListActions(),
		Version:      Version,
	}

	msg, err := protocol.NewMessage(protocol.MessageTypeRegister, req)
	if err != nil {
		return fmt.Errorf("creating register message: %w", err)
	}

	if err := a.sendMessage(msg); err != nil {
		return fmt.Errorf("sending register message: %w", err)
	}

	// Wait for response
	a.conn.SetReadDeadline(time.Now().Add(a.cfg.Server.ReadTimeout))
	_, data, err := a.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("reading register response: %w", err)
	}

	var respMsg protocol.Message
	if err := json.Unmarshal(data, &respMsg); err != nil {
		return fmt.Errorf("parsing register response: %w", err)
	}

	var resp protocol.RegisterResponse
	if err := respMsg.ParsePayload(&resp); err != nil {
		return fmt.Errorf("parsing register response payload: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}

	return nil
}

func (a *Agent) messageLoop() error {
	for {
		select {
		case <-a.ctx.Done():
			return nil
		default:
		}

		a.conn.SetReadDeadline(time.Now().Add(a.cfg.Server.ReadTimeout))
		_, data, err := a.conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("reading message: %w", err)
		}

		var msg protocol.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			a.logger.Error().Err(err).Msg("Failed to parse message")
			continue
		}

		a.handleMessage(&msg)
	}
}

func (a *Agent) handleMessage(msg *protocol.Message) {
	switch msg.Type {
	case protocol.MessageTypeCommand:
		var cmd protocol.Command
		if err := msg.ParsePayload(&cmd); err != nil {
			a.logger.Error().Err(err).Msg("Failed to parse command")
			return
		}
		go a.executeCommand(&cmd)

	case protocol.MessageTypePing:
		a.sendPong()

	case protocol.MessageTypeCancel:
		var cancel protocol.CancelCommand
		if err := msg.ParsePayload(&cancel); err != nil {
			a.logger.Error().Err(err).Msg("Failed to parse cancel command")
			return
		}
		a.cancelTask(cancel.CommandID)

	default:
		a.logger.Warn().Str("type", string(msg.Type)).Msg("Unknown message type")
	}
}

func (a *Agent) executeCommand(cmd *protocol.Command) {
	logger := a.logger.With().
		Str("command_id", cmd.ID).
		Str("action", string(cmd.Action)).
		Str("execution_id", cmd.ExecutionID).
		Logger()

	logger.Info().Msg("Executing command")

	// Check if action is enabled
	if !a.cfg.IsActionEnabled(string(cmd.Action)) {
		logger.Warn().Msg("Action not enabled")
		a.sendResponse(cmd, types.StatusFailed, types.ActionResult{
			Success: false,
			Error:   "action not enabled",
		}, 0)
		return
	}

	// Create cancellable context
	timeout := time.Duration(cmd.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = a.cfg.Actions.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	// Track active task
	a.activeTasksMu.Lock()
	a.activeTasks[cmd.ID] = cancel
	a.activeTasksMu.Unlock()

	defer func() {
		a.activeTasksMu.Lock()
		delete(a.activeTasks, cmd.ID)
		a.activeTasksMu.Unlock()
	}()

	// Execute action
	start := time.Now()
	actCtx := types.ActionContext{
		ExecutionID: cmd.ExecutionID,
		CommandID:   cmd.ID,
		AgentID:     a.info.ID,
		Timeout:     timeout,
	}

	result, err := a.executor.Execute(ctx, cmd.Action, cmd.Parameters, actCtx)
	elapsed := time.Since(start).Milliseconds()

	status := types.StatusSuccess
	if err != nil {
		status = types.StatusFailed
		if ctx.Err() == context.DeadlineExceeded {
			status = types.StatusTimeout
		} else if ctx.Err() == context.Canceled {
			status = types.StatusCancelled
		}
		result.Success = false
		result.Error = err.Error()
		logger.Error().Err(err).Msg("Command execution failed")
	} else {
		logger.Info().Int64("duration_ms", elapsed).Msg("Command execution completed")
	}

	a.sendResponse(cmd, status, result, elapsed)
}

func (a *Agent) sendResponse(cmd *protocol.Command, status types.ActionStatus, result types.ActionResult, durationMs int64) {
	resp := protocol.Response{
		ID:              fmt.Sprintf("resp-%s", cmd.ID),
		CommandID:       cmd.ID,
		Status:          status,
		Result:          result,
		ExecutionTimeMs: durationMs,
		Timestamp:       time.Now().UTC(),
	}

	msg, err := protocol.NewMessage(protocol.MessageTypeResponse, resp)
	if err != nil {
		a.logger.Error().Err(err).Msg("Failed to create response message")
		return
	}

	if err := a.sendMessage(msg); err != nil {
		a.logger.Error().Err(err).Msg("Failed to send response")
	}

	// Send callback to SOAR system (async, don't block response)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.callback.SendCommandResult(ctx, a.info.ID, cmd, &resp); err != nil {
			a.logger.Warn().Err(err).Msg("Failed to send callback to SOAR")
		}
	}()
}

func (a *Agent) heartbeatLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.Agent.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

func (a *Agent) sendHeartbeat() {
	a.activeTasksMu.Lock()
	activeTasks := make([]string, 0, len(a.activeTasks))
	for id := range a.activeTasks {
		activeTasks = append(activeTasks, id)
	}
	a.activeTasksMu.Unlock()

	hb := protocol.Heartbeat{
		AgentID:     a.info.ID,
		Timestamp:   time.Now().UTC(),
		Status:      a.getStatus(),
		ActiveTasks: activeTasks,
	}

	msg, err := protocol.NewMessage(protocol.MessageTypeHeartbeat, hb)
	if err != nil {
		a.logger.Error().Err(err).Msg("Failed to create heartbeat message")
		return
	}

	if err := a.sendMessage(msg); err != nil {
		a.logger.Debug().Err(err).Msg("Failed to send heartbeat")
	}
}

func (a *Agent) sendPong() {
	msg, err := protocol.NewMessage(protocol.MessageTypePong, nil)
	if err != nil {
		a.logger.Error().Err(err).Msg("Failed to create pong message")
		return
	}
	if err := a.sendMessage(msg); err != nil {
		a.logger.Debug().Err(err).Msg("Failed to send pong")
	}
}

// setStatus safely sets the agent status with mutex protection.
func (a *Agent) setStatus(status string) {
	a.infoMu.Lock()
	a.info.Status = status
	a.infoMu.Unlock()
}

// getStatus safely gets the agent status with mutex protection.
func (a *Agent) getStatus() string {
	a.infoMu.RLock()
	defer a.infoMu.RUnlock()
	return a.info.Status
}

func (a *Agent) cancelTask(cmdID string) {
	a.activeTasksMu.Lock()
	defer a.activeTasksMu.Unlock()

	if cancel, ok := a.activeTasks[cmdID]; ok {
		a.logger.Info().Str("command_id", cmdID).Msg("Cancelling task")
		cancel()
	}
}

func (a *Agent) sendMessage(msg *protocol.Message) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.conn == nil {
		return fmt.Errorf("not connected")
	}

	a.conn.SetWriteDeadline(time.Now().Add(a.cfg.Server.WriteTimeout))
	return a.conn.WriteJSON(msg)
}

func (a *Agent) closeConn() {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
}

func (a *Agent) waitReconnect() {
	// Exponential backoff: delay = base * 2^attempt, capped at max
	base := a.cfg.Agent.ReconnectDelay
	maxDelay := a.cfg.Agent.MaxReconnectDelay

	delay := base
	for i := 0; i < a.reconnectAttempt && delay < maxDelay; i++ {
		delay *= 2
	}
	if delay > maxDelay {
		delay = maxDelay
	}

	a.reconnectAttempt++
	a.logger.Info().
		Dur("delay", delay).
		Int("attempt", a.reconnectAttempt).
		Msg("Waiting before reconnect (exponential backoff)")

	select {
	case <-a.ctx.Done():
	case <-time.After(delay):
	}
}
