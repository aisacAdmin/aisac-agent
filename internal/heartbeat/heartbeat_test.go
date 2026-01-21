package heartbeat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Default config should have Enabled = false")
	}

	if cfg.Interval != 120*time.Second {
		t.Errorf("Default interval = %v, want 120s", cfg.Interval)
	}

	if cfg.Timeout != 10*time.Second {
		t.Errorf("Default timeout = %v, want 10s", cfg.Timeout)
	}

	if cfg.URL != "https://api.aisac.cisec.es/functions/v1/agent-heartbeat" {
		t.Errorf("Default URL = %s, want https://api.aisac.cisec.es/functions/v1/agent-heartbeat", cfg.URL)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "disabled heartbeat - no validation",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "missing URL",
			config: Config{
				Enabled: true,
				APIKey:  "test-key",
				AssetID: "test-asset",
			},
			wantErr: true,
		},
		{
			name: "missing API Key",
			config: Config{
				Enabled: true,
				URL:     "https://example.com",
				AssetID: "test-asset",
			},
			wantErr: true,
		},
		{
			name: "missing Asset ID",
			config: Config{
				Enabled: true,
				URL:     "https://example.com",
				APIKey:  "test-key",
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: Config{
				Enabled:  true,
				URL:      "https://example.com",
				APIKey:   "test-key",
				AssetID:  "test-asset",
				Interval: 60 * time.Second,
				Timeout:  10 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHeartbeatSend(t *testing.T) {
	var receivedPayload Payload
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := Response{
			Success:         true,
			NextHeartbeatIn: 60,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		Enabled:  true,
		URL:      server.URL,
		APIKey:   "test-api-key",
		AssetID:  "test-asset-id",
		Interval: 1 * time.Second,
		Timeout:  5 * time.Second,
	}

	logger := zerolog.Nop()
	client := NewClient(cfg, "1.0.0-test", logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Send a single heartbeat
	client.sendHeartbeat(ctx)

	// Verify payload
	if receivedPayload.AssetID != "test-asset-id" {
		t.Errorf("AssetID = %s, want test-asset-id", receivedPayload.AssetID)
	}

	if receivedPayload.AgentVersion != "1.0.0-test" {
		t.Errorf("AgentVersion = %s, want 1.0.0-test", receivedPayload.AgentVersion)
	}

	// Verify Authorization header
	if receivedAuth != "Bearer test-api-key" {
		t.Errorf("Authorization = %s, want Bearer test-api-key", receivedAuth)
	}
}

func TestHeartbeat401StopsClient(t *testing.T) {
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid API key",
		})
	}))
	defer server.Close()

	cfg := Config{
		Enabled:  true,
		URL:      server.URL,
		APIKey:   "invalid-key",
		AssetID:  "test-asset",
		Interval: 100 * time.Millisecond,
		Timeout:  1 * time.Second,
	}

	logger := zerolog.Nop()
	client := NewClient(cfg, "1.0.0", logger)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start should exit after 401
	_ = client.Start(ctx)

	// Should have only made one request before stopping
	if requestCount != 1 {
		t.Errorf("Request count = %d, want 1 (should stop on 401)", requestCount)
	}
}

func TestHeartbeatDynamicInterval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := Response{
			Success:         true,
			NextHeartbeatIn: 30, // Server requests 30 second interval
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		Enabled:  true,
		URL:      server.URL,
		APIKey:   "test-key",
		AssetID:  "test-asset",
		Interval: 120 * time.Second, // Initial interval
		Timeout:  5 * time.Second,
	}

	logger := zerolog.Nop()
	client := NewClient(cfg, "1.0.0", logger)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Send heartbeat
	client.sendHeartbeat(ctx)

	// Verify interval was updated
	if client.interval != 30*time.Second {
		t.Errorf("Interval = %v, want 30s (from server response)", client.interval)
	}
}
