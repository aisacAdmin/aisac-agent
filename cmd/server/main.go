// Package main is the entry point for the AISAC command server.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/cisec/aisac-agent/pkg/protocol"
	"github.com/cisec/aisac-agent/pkg/types"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

var (
	listenAddr         string
	certFile           string
	keyFile            string
	caFile             string
	logLevel           string
	apiToken           string
	allowedOrigins     string
	apiMTLS            bool
	platformWebhookURL string
	platformAPIKey     string
	serverURL          string
)

// Server represents the command server.
type Server struct {
	logger             zerolog.Logger
	upgrader           websocket.Upgrader
	agents             map[string]*AgentConn
	agentsMu           sync.RWMutex
	apiToken           string
	allowedOrigins     map[string]bool
	platformWebhookURL string
	platformAPIKey     string
	serverURL          string
	httpClient         *http.Client
}

// AgentConn represents a connected agent.
type AgentConn struct {
	ID          string
	Info        types.AgentInfo
	Conn        *websocket.Conn
	ConnMu      sync.Mutex
	LastSeen    time.Time
	msgCount    int64     // Message count for rate limiting
	msgResetAt  time.Time // When to reset message count
	stopPing    chan struct{} // Signal to stop ping loop
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "aisac-server",
		Short:   "AISAC Command Server",
		Long:    `AISAC Command Server receives commands from SOAR and dispatches them to agents.`,
		Version: version,
		RunE:    run,
	}

	rootCmd.Flags().StringVarP(&listenAddr, "listen", "a", ":8443", "listen address")
	rootCmd.Flags().StringVar(&certFile, "cert", "", "TLS certificate file")
	rootCmd.Flags().StringVar(&keyFile, "key", "", "TLS key file")
	rootCmd.Flags().StringVar(&caFile, "ca", "", "CA certificate for client auth")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "log level")
	rootCmd.Flags().StringVar(&apiToken, "api-token", "", "API bearer token for REST API authentication (required)")
	rootCmd.Flags().StringVar(&allowedOrigins, "allowed-origins", "", "Comma-separated list of allowed WebSocket origins")
	rootCmd.Flags().BoolVar(&apiMTLS, "api-mtls", true, "Require mTLS for API REST (disable for SOAR/n8n clients)")
	rootCmd.Flags().StringVar(&platformWebhookURL, "platform-webhook", "", "AISAC platform webhook URL for agent registration notifications")
	rootCmd.Flags().StringVar(&platformAPIKey, "platform-api-key", "", "AISAC platform API key for webhook authentication")
	rootCmd.Flags().StringVar(&serverURL, "server-url", "", "Command Server public URL (e.g., https://IP:8443) for SOAR webhook notification")

	rootCmd.SetVersionTemplate(`{{.Name}} {{.Version}}
Commit: ` + commit + `
Build Date: ` + buildDate + "\n")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	logger := setupLogger(logLevel)

	logger.Info().
		Str("version", version).
		Str("listen", listenAddr).
		Msg("Starting AISAC Command Server")

	// Parse allowed origins
	originsMap := make(map[string]bool)
	if allowedOrigins != "" {
		for _, origin := range strings.Split(allowedOrigins, ",") {
			originsMap[strings.TrimSpace(origin)] = true
		}
	}

	// Log platform webhook configuration (if enabled)
	if platformWebhookURL != "" {
		logger.Info().
			Str("webhook_url", platformWebhookURL).
			Bool("has_api_key", platformAPIKey != "").
			Msg("Platform webhook notifications enabled")
	}

	server := &Server{
		logger:             logger,
		agents:             make(map[string]*AgentConn),
		apiToken:           apiToken,
		allowedOrigins:     originsMap,
		platformWebhookURL: platformWebhookURL,
		platformAPIKey:     platformAPIKey,
		serverURL:          serverURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}

	// Configure WebSocket upgrader with origin checking
	server.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     server.checkOrigin,
	}

	router := mux.NewRouter()

	// WebSocket endpoint for agents
	router.HandleFunc("/ws", server.handleWebSocket)

	// REST API endpoints with authentication middleware
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(server.apiAuthMiddleware)
	api.HandleFunc("/agents", server.handleListAgents).Methods("GET")
	api.HandleFunc("/agents/{id}", server.handleGetAgent).Methods("GET")
	api.HandleFunc("/agents/{id}/command", server.handleSendCommand).Methods("POST")
	api.HandleFunc("/health", server.handleHealth).Methods("GET")
	api.HandleFunc("/status", server.handleStatus).Methods("GET") // Detailed status (requires auth)

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Configure TLS if certificates provided
	if certFile != "" && keyFile != "" {
		tlsConfig, err := server.buildTLSConfig()
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to configure TLS")
		}
		httpServer.TLSConfig = tlsConfig
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info().Msg("Shutting down server")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		httpServer.Shutdown(ctx)
	}()

	// Start server
	var err error
	if certFile != "" && keyFile != "" {
		logger.Info().Msg("Starting HTTPS server with mTLS")
		err = httpServer.ListenAndServeTLS(certFile, keyFile)
	} else {
		// SECURITY: Check if running in production mode (via environment variable)
		if os.Getenv("AISAC_PRODUCTION") == "true" || os.Getenv("AISAC_REQUIRE_TLS") == "true" {
			logger.Fatal().Msg("TLS is required in production mode. Set AISAC_PRODUCTION=false or provide --cert and --key flags")
		}
		logger.Warn().Msg("SECURITY WARNING: Starting HTTP server without TLS - NOT RECOMMENDED FOR PRODUCTION. Set AISAC_PRODUCTION=true to enforce TLS.")
		err = httpServer.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if caFile == "" {
		return &tls.Config{}, nil
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA file: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// If apiMTLS is disabled, request client cert but don't require it
	// This allows agents to use mTLS while API clients use only bearer token
	clientAuth := tls.RequireAndVerifyClientCert
	if !apiMTLS {
		clientAuth = tls.VerifyClientCertIfGiven
		s.logger.Info().Msg("API mTLS disabled - REST API will accept connections without client certificates")
	}

	return &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: clientAuth,
	}, nil
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Agents MUST always use mTLS, even if apiMTLS is disabled
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.logger.Warn().Str("remote", r.RemoteAddr).Msg("WebSocket connection rejected: client certificate required for agents")
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	defer conn.Close() // Ensure connection is always closed

	// Extract client IP from RemoteAddr (format: "IP:port")
	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	// Remove brackets from IPv6 addresses
	clientIP = strings.Trim(clientIP, "[]")

	agentID := r.Header.Get("X-Agent-ID")
	s.logger.Info().Str("agent_id", agentID).Str("remote", r.RemoteAddr).Str("client_ip", clientIP).Msg("Agent connected")

	// Wait for registration
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to read registration")
		return
	}

	var msg protocol.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		s.logger.Error().Err(err).Msg("Failed to parse registration message")
		return
	}

	if msg.Type != protocol.MessageTypeRegister {
		s.logger.Error().Str("type", string(msg.Type)).Msg("Expected register message")
		return
	}

	var req protocol.RegisterRequest
	if err := msg.ParsePayload(&req); err != nil {
		s.logger.Error().Err(err).Msg("Failed to parse registration payload")
		return
	}

	// Send registration response
	resp := protocol.RegisterResponse{
		Accepted:      true,
		ServerVersion: version,
	}
	respMsg, err := protocol.NewMessage(protocol.MessageTypeResponse, resp)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to create registration response")
		return
	}
	if err := conn.WriteJSON(respMsg); err != nil {
		s.logger.Error().Err(err).Msg("Failed to send registration response")
		return
	}

	// Register agent
	agent := &AgentConn{
		ID:       req.AgentInfo.ID,
		Info:     req.AgentInfo,
		Conn:     conn,
		LastSeen: time.Now(),
		stopPing: make(chan struct{}),
	}

	// Populate IP from WebSocket connection (override whatever agent sent)
	agent.Info.IP = clientIP

	s.agentsMu.Lock()
	s.agents[agent.ID] = agent
	s.agentsMu.Unlock()

	s.logger.Info().
		Str("agent_id", agent.ID).
		Str("hostname", agent.Info.Hostname).
		Str("platform", string(agent.Info.Platform)).
		Msg("Agent registered")

	// Notify platform about new agent connection (if configured)
	if s.platformWebhookURL != "" {
		go s.notifyPlatform(agent)
	}

	// Start ping loop to keep connection alive
	go s.startPingLoop(agent)

	// Handle messages (blocks until disconnect)
	s.handleAgentMessages(agent)

	// Stop ping loop
	close(agent.stopPing)

	// Cleanup on disconnect
	s.agentsMu.Lock()
	delete(s.agents, agent.ID)
	s.agentsMu.Unlock()

	s.logger.Info().Str("agent_id", agent.ID).Msg("Agent disconnected")
}

// SECURITY: Rate limiting constants for WebSocket messages
const (
	maxMessagesPerMinute = 120 // Maximum messages per minute per agent
	rateLimitWindow      = time.Minute
)

// Ping interval for keeping WebSocket connections alive
const pingInterval = 30 * time.Second

// startPingLoop sends periodic ping messages to keep the connection alive.
func (s *Server) startPingLoop(agent *AgentConn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-agent.stopPing:
			return
		case <-ticker.C:
			pingMsg, err := protocol.NewMessage(protocol.MessageTypePing, nil)
			if err != nil {
				s.logger.Error().Err(err).Str("agent_id", agent.ID).Msg("Failed to create ping message")
				continue
			}

			agent.ConnMu.Lock()
			err = agent.Conn.WriteJSON(pingMsg)
			agent.ConnMu.Unlock()

			if err != nil {
				s.logger.Debug().Err(err).Str("agent_id", agent.ID).Msg("Failed to send ping")
				return
			}
			s.logger.Debug().Str("agent_id", agent.ID).Msg("Ping sent")
		}
	}
}

func (s *Server) handleAgentMessages(agent *AgentConn) {
	// Initialize rate limiting
	agent.msgResetAt = time.Now().Add(rateLimitWindow)
	agent.msgCount = 0

	for {
		agent.Conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, data, err := agent.Conn.ReadMessage()
		if err != nil {
			s.logger.Debug().Err(err).Str("agent_id", agent.ID).Msg("Read error")
			return
		}

		// SECURITY: Rate limiting check
		now := time.Now()
		if now.After(agent.msgResetAt) {
			// Reset counter for new window
			agent.msgCount = 0
			agent.msgResetAt = now.Add(rateLimitWindow)
		}
		agent.msgCount++
		if agent.msgCount > maxMessagesPerMinute {
			s.logger.Warn().
				Str("agent_id", agent.ID).
				Int64("msg_count", agent.msgCount).
				Msg("Rate limit exceeded, dropping message")
			continue
		}

		agent.LastSeen = now

		var msg protocol.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			s.logger.Error().Err(err).Msg("Failed to parse message")
			continue
		}

		switch msg.Type {
		case protocol.MessageTypeHeartbeat:
			s.logger.Debug().Str("agent_id", agent.ID).Msg("Heartbeat received")

		case protocol.MessageTypeResponse:
			var resp protocol.Response
			if err := msg.ParsePayload(&resp); err != nil {
				s.logger.Error().Err(err).Msg("Failed to parse response")
				continue
			}
			s.logger.Info().
				Str("agent_id", agent.ID).
				Str("command_id", resp.CommandID).
				Str("status", string(resp.Status)).
				Int64("duration_ms", resp.ExecutionTimeMs).
				Msg("Command response received")

		case protocol.MessageTypePong:
			// Pong response, ignore

		default:
			s.logger.Warn().Str("type", string(msg.Type)).Msg("Unknown message type")
		}
	}
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	agents := make([]types.AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		info := a.Info
		info.LastSeen = a.LastSeen
		info.Status = "connected"
		agents = append(agents, info)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	s.agentsMu.RLock()
	agent, ok := s.agents[agentID]
	s.agentsMu.RUnlock()

	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	info := agent.Info
	info.LastSeen = agent.LastSeen
	info.Status = "connected"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) handleSendCommand(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	s.agentsMu.RLock()
	agent, ok := s.agents[agentID]
	s.agentsMu.RUnlock()

	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	// SECURITY: Limit request body size to prevent DoS attacks (1MB max)
	const maxBodySize = 1 << 20 // 1 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	var cmd protocol.Command
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "Request body too large (max 1MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate command ID if not provided
	if cmd.ID == "" {
		cmd.ID = fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	}

	msg, err := protocol.NewMessage(protocol.MessageTypeCommand, cmd)
	if err != nil {
		http.Error(w, "Failed to create message", http.StatusInternalServerError)
		return
	}

	agent.ConnMu.Lock()
	err = agent.Conn.WriteJSON(msg)
	agent.ConnMu.Unlock()

	if err != nil {
		s.logger.Error().Err(err).Str("agent_id", agentID).Msg("Failed to send command")
		http.Error(w, "Failed to send command", http.StatusInternalServerError)
		return
	}

	s.logger.Info().
		Str("agent_id", agentID).
		Str("command_id", cmd.ID).
		Str("action", string(cmd.Action)).
		Msg("Command sent to agent")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"command_id": cmd.ID,
		"status":     "sent",
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Health endpoint only returns status
	// Detailed metrics require authentication via /api/v1/status
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
	})
}

// handleStatus returns detailed server status (requires authentication).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.agentsMu.RLock()
	agentCount := len(s.agents)
	s.agentsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "healthy",
		"version":     version,
		"agent_count": agentCount,
	})
}

// checkOrigin validates WebSocket connection origins.
func (s *Server) checkOrigin(r *http.Request) bool {
	// If no origins specified, reject all (secure by default)
	// In production, always specify allowed origins
	if len(s.allowedOrigins) == 0 {
		// For agents connecting via mTLS, we allow the connection
		// since they're authenticated by client certificate
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			return true
		}
		s.logger.Warn().Msg("WebSocket connection rejected: no allowed origins configured and no mTLS")
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// No origin header (direct connection, not from browser)
		// Allow if mTLS authenticated
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			return true
		}
		return false
	}

	if s.allowedOrigins[origin] {
		return true
	}

	s.logger.Warn().Str("origin", origin).Msg("WebSocket connection rejected: origin not allowed")
	return false
}

// apiAuthMiddleware validates API requests with bearer token.
func (s *Server) apiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		// If no API token configured, reject all requests
		if s.apiToken == "" {
			s.logger.Error().Msg("API request rejected: no API token configured")
			http.Error(w, "API authentication not configured", http.StatusServiceUnavailable)
			return
		}

		// Validate bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		// SECURITY: Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.apiToken)) != 1 {
			s.logger.Warn().Str("remote", r.RemoteAddr).Msg("Invalid API token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// notifyPlatform sends a webhook to the AISAC platform when an agent connects.
// This allows the platform to register the agent and store the Command Server API token
// for future SOAR operations.
func (s *Server) notifyPlatform(agent *AgentConn) {
	if s.platformWebhookURL == "" {
		return
	}

	// Prepare webhook payload
	payload := map[string]interface{}{
		"event":      "agent_connected",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"agent_id":   agent.ID,
		"agent_info": map[string]interface{}{
			"hostname": agent.Info.Hostname,
			"platform": agent.Info.Platform,
			"version":  agent.Info.Version,
			"ip":       agent.Info.IP,
			"status":   agent.Info.Status,
			"labels":   agent.Info.Labels,
		},
		// SECURITY: Send Command Server API token so platform can store it
		// This is sent once per agent connection over HTTPS with authentication
		"command_server": map[string]interface{}{
			"api_token": s.apiToken,
			"url":       s.serverURL,
			"version":   version,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal webhook payload")
		return
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", s.platformWebhookURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to create webhook request")
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AISAC-Command-Server/"+version)

	// SECURITY: Authenticate with platform using API key
	if s.platformAPIKey != "" {
		req.Header.Set("X-API-Key", s.platformAPIKey)
	}

	// Send request with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Info().
		Str("agent_id", agent.ID).
		Str("webhook_url", s.platformWebhookURL).
		Msg("Sending agent registration webhook to platform")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("agent_id", agent.ID).
			Msg("Failed to send webhook to platform")
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body := make([]byte, 512)
		resp.Body.Read(body)
		s.logger.Error().
			Int("status_code", resp.StatusCode).
			Str("response", string(body)).
			Str("agent_id", agent.ID).
			Msg("Platform webhook failed")
		return
	}

	s.logger.Info().
		Str("agent_id", agent.ID).
		Int("status_code", resp.StatusCode).
		Msg("Platform notified successfully")
}

func setupLogger(level string) zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	var l zerolog.Level
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	default:
		l = zerolog.InfoLevel
	}

	return zerolog.New(os.Stdout).
		Level(l).
		With().
		Timestamp().
		Str("service", "aisac-server").
		Logger()
}
