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
	listenAddr     string
	certFile       string
	keyFile        string
	caFile         string
	logLevel       string
	apiToken       string
	allowedOrigins string
	apiMTLS        bool
)

// Server represents the command server.
type Server struct {
	logger         zerolog.Logger
	upgrader       websocket.Upgrader
	agents         map[string]*AgentConn
	agentsMu       sync.RWMutex
	apiToken       string
	allowedOrigins map[string]bool
}

// AgentConn represents a connected agent.
type AgentConn struct {
	ID       string
	Info     types.AgentInfo
	Conn     *websocket.Conn
	ConnMu   sync.Mutex
	LastSeen time.Time
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

	server := &Server{
		logger:         logger,
		agents:         make(map[string]*AgentConn),
		apiToken:       apiToken,
		allowedOrigins: originsMap,
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
		logger.Warn().Msg("Starting HTTP server (no TLS) - NOT RECOMMENDED FOR PRODUCTION")
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

	agentID := r.Header.Get("X-Agent-ID")
	s.logger.Info().Str("agent_id", agentID).Str("remote", r.RemoteAddr).Msg("Agent connected")

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
	}

	s.agentsMu.Lock()
	s.agents[agent.ID] = agent
	s.agentsMu.Unlock()

	s.logger.Info().
		Str("agent_id", agent.ID).
		Str("hostname", agent.Info.Hostname).
		Str("platform", string(agent.Info.Platform)).
		Msg("Agent registered")

	// Handle messages (blocks until disconnect)
	s.handleAgentMessages(agent)

	// Cleanup on disconnect
	s.agentsMu.Lock()
	delete(s.agents, agent.ID)
	s.agentsMu.Unlock()

	s.logger.Info().Str("agent_id", agent.ID).Msg("Agent disconnected")
}

func (s *Server) handleAgentMessages(agent *AgentConn) {
	for {
		agent.Conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, data, err := agent.Conn.ReadMessage()
		if err != nil {
			s.logger.Debug().Err(err).Str("agent_id", agent.ID).Msg("Read error")
			return
		}

		agent.LastSeen = time.Now()

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

	var cmd protocol.Command
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
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
	s.agentsMu.RLock()
	agentCount := len(s.agents)
	s.agentsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "healthy",
		"version":      version,
		"agent_count":  agentCount,
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
