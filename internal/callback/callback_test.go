package callback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/pkg/protocol"
	"github.com/cisec/aisac-agent/pkg/types"
)

func TestNewClient(t *testing.T) {
	cfg := DefaultCallbackConfig()
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)

	client := NewClient(cfg, logger)
	if client == nil {
		t.Fatal("Expected client to be non-nil")
	}
}

func TestClient_SendDisabled(t *testing.T) {
	cfg := DefaultCallbackConfig()
	cfg.Enabled = false

	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	client := NewClient(cfg, logger)

	cmd := &protocol.Command{
		ID:          "cmd-123",
		Action:      types.ActionBlockIP,
		ExecutionID: "exec-456",
	}

	resp := &protocol.Response{
		ID:        "resp-789",
		CommandID: "cmd-123",
		Status:    types.StatusSuccess,
	}

	err := client.SendCommandResult(context.Background(), "agent-1", cmd, resp)
	if err != nil {
		t.Errorf("Expected no error when disabled, got: %v", err)
	}
}

func TestClient_SendCommandResult(t *testing.T) {
	var receivedPayload CallbackPayload
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json")
		}

		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Expected Authorization header")
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &CallbackConfig{
		Enabled:       true,
		URL:           server.URL,
		AuthToken:     "test-token",
		Timeout:       5 * time.Second,
		RetryAttempts: 0,
	}

	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	client := NewClient(cfg, logger)

	cmd := &protocol.Command{
		ID:          "cmd-123",
		Action:      types.ActionBlockIP,
		ExecutionID: "exec-456",
	}

	resp := &protocol.Response{
		ID:              "resp-789",
		CommandID:       "cmd-123",
		Status:          types.StatusSuccess,
		ExecutionTimeMs: 150,
		Result: types.ActionResult{
			Success: true,
			Message: "IP blocked",
		},
	}

	err := client.SendCommandResult(context.Background(), "agent-1", cmd, resp)
	if err != nil {
		t.Fatalf("SendCommandResult failed: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	if receivedPayload.Event != "command_result" {
		t.Errorf("Expected event 'command_result', got '%s'", receivedPayload.Event)
	}

	if receivedPayload.AgentID != "agent-1" {
		t.Errorf("Expected agent_id 'agent-1', got '%s'", receivedPayload.AgentID)
	}

	if receivedPayload.ExecutionID != "exec-456" {
		t.Errorf("Expected execution_id 'exec-456', got '%s'", receivedPayload.ExecutionID)
	}

	if receivedPayload.Status != "success" {
		t.Errorf("Expected status 'success', got '%s'", receivedPayload.Status)
	}
}

func TestClient_SendWithRetry(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &CallbackConfig{
		Enabled:       true,
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    10 * time.Millisecond,
	}

	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	client := NewClient(cfg, logger)

	cmd := &protocol.Command{ID: "cmd-123", Action: types.ActionBlockIP}
	resp := &protocol.Response{ID: "resp-789", Status: types.StatusSuccess}

	err := client.SendCommandResult(context.Background(), "agent-1", cmd, resp)
	if err != nil {
		t.Fatalf("Expected success after retries, got: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("Expected 3 requests (2 failures + 1 success), got %d", requestCount)
	}
}

func TestClient_SendAgentStatus(t *testing.T) {
	var receivedPayload CallbackPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &CallbackConfig{
		Enabled: true,
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	client := NewClient(cfg, logger)

	details := map[string]interface{}{
		"version":  "1.0.0",
		"platform": "linux",
	}

	err := client.SendAgentStatus(context.Background(), "agent-1", "connected", details)
	if err != nil {
		t.Fatalf("SendAgentStatus failed: %v", err)
	}

	if receivedPayload.Event != "agent_status" {
		t.Errorf("Expected event 'agent_status', got '%s'", receivedPayload.Event)
	}

	if receivedPayload.Status != "connected" {
		t.Errorf("Expected status 'connected', got '%s'", receivedPayload.Status)
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &CallbackConfig{
		Enabled:       true,
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 5,
		RetryDelay:    100 * time.Millisecond,
	}

	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	client := NewClient(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cmd := &protocol.Command{ID: "cmd-123", Action: types.ActionBlockIP}
	resp := &protocol.Response{ID: "resp-789", Status: types.StatusSuccess}

	err := client.SendCommandResult(ctx, "agent-1", cmd, resp)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
}
