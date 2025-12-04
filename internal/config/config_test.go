package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultAgentConfig(t *testing.T) {
	cfg := DefaultAgentConfig()

	if cfg.Agent.HeartbeatInterval != 30*time.Second {
		t.Errorf("Expected HeartbeatInterval 30s, got %v", cfg.Agent.HeartbeatInterval)
	}

	if cfg.Server.URL != "wss://localhost:8443/ws" {
		t.Errorf("Expected default server URL, got %s", cfg.Server.URL)
	}

	if !cfg.TLS.Enabled {
		t.Error("Expected TLS to be enabled by default")
	}

	if cfg.Callback.Enabled {
		t.Error("Expected callback to be disabled by default")
	}

	if len(cfg.Actions.Enabled) == 0 {
		t.Error("Expected default actions to be configured")
	}
}

func TestIsActionEnabled(t *testing.T) {
	cfg := DefaultAgentConfig()

	if !cfg.IsActionEnabled("block_ip") {
		t.Error("Expected block_ip to be enabled")
	}

	if cfg.IsActionEnabled("nonexistent_action") {
		t.Error("Expected nonexistent_action to be disabled")
	}
}

func TestValidate_ServerURLRequired(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Server.URL = ""
	cfg.TLS.Enabled = false

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for empty server URL")
	}
}

func TestValidate_TLSCertRequired(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = ""

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing cert_file")
	}
}

func TestValidate_TLSKeyRequired(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert"
	cfg.TLS.KeyFile = ""

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing key_file")
	}
}

func TestValidate_TLSCARequired(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/cert"
	cfg.TLS.KeyFile = "/path/to/key"
	cfg.TLS.CAFile = ""

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing ca_file")
	}
}

func TestValidate_TLSDisabled(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.TLS.Enabled = false

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Unexpected validation error when TLS disabled: %v", err)
	}
}

func TestLoadAgentConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	configContent := `
agent:
  id: "test-agent"
  heartbeat_interval: 60s
server:
  url: "ws://localhost:8080/ws"
tls:
  enabled: false
actions:
  enabled:
    - block_ip
    - kill_process
logging:
  level: debug
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadAgentConfig(configPath)
	if err != nil {
		t.Fatalf("LoadAgentConfig failed: %v", err)
	}

	if cfg.Agent.ID != "test-agent" {
		t.Errorf("Expected agent ID 'test-agent', got '%s'", cfg.Agent.ID)
	}

	if cfg.Agent.HeartbeatInterval != 60*time.Second {
		t.Errorf("Expected HeartbeatInterval 60s, got %v", cfg.Agent.HeartbeatInterval)
	}

	if cfg.Server.URL != "ws://localhost:8080/ws" {
		t.Errorf("Expected server URL 'ws://localhost:8080/ws', got '%s'", cfg.Server.URL)
	}

	if cfg.TLS.Enabled {
		t.Error("Expected TLS to be disabled")
	}

	if len(cfg.Actions.Enabled) != 2 {
		t.Errorf("Expected 2 enabled actions, got %d", len(cfg.Actions.Enabled))
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level 'debug', got '%s'", cfg.Logging.Level)
	}
}

func TestLoadAgentConfig_FileNotFound(t *testing.T) {
	_, err := LoadAgentConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent config file")
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	cfg := DefaultAgentConfig()

	// Set environment variables
	os.Setenv("AISAC_AGENT_ID", "env-agent-id")
	os.Setenv("AISAC_SERVER_URL", "ws://env-server:8080/ws")
	os.Setenv("AISAC_LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("AISAC_AGENT_ID")
		os.Unsetenv("AISAC_SERVER_URL")
		os.Unsetenv("AISAC_LOG_LEVEL")
	}()

	cfg.applyEnvOverrides()

	if cfg.Agent.ID != "env-agent-id" {
		t.Errorf("Expected agent ID 'env-agent-id', got '%s'", cfg.Agent.ID)
	}

	if cfg.Server.URL != "ws://env-server:8080/ws" {
		t.Errorf("Expected server URL from env, got '%s'", cfg.Server.URL)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level 'debug', got '%s'", cfg.Logging.Level)
	}
}
