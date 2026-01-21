// Package config handles agent and server configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/cisec/aisac-agent/internal/collector"
	"github.com/cisec/aisac-agent/internal/heartbeat"
	"gopkg.in/yaml.v3"
)

// AgentConfig holds the agent configuration.
type AgentConfig struct {
	Agent     AgentSettings     `yaml:"agent"`
	Server    ServerSettings    `yaml:"server"`
	TLS       TLSSettings       `yaml:"tls"`
	Actions   ActionsSettings   `yaml:"actions"`
	Callback  CallbackSettings  `yaml:"callback"`
	Collector collector.Config  `yaml:"collector"`
	Heartbeat heartbeat.Config  `yaml:"heartbeat"`
	Logging   LoggingSettings   `yaml:"logging"`
}

// AgentSettings contains agent-specific settings.
type AgentSettings struct {
	ID                string        `yaml:"id"`
	Labels            []string      `yaml:"labels"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReconnectDelay    time.Duration `yaml:"reconnect_delay"`
	MaxReconnectDelay time.Duration `yaml:"max_reconnect_delay"`
}

// ServerSettings contains server connection settings.
type ServerSettings struct {
	URL             string        `yaml:"url"`
	ConnectTimeout  time.Duration `yaml:"connect_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
}

// TLSSettings contains mTLS configuration.
type TLSSettings struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	SkipVerify bool   `yaml:"skip_verify"`
}

// ActionsSettings contains action execution settings.
type ActionsSettings struct {
	Enabled       []string               `yaml:"enabled"`
	RateLimits    map[string]RateLimit   `yaml:"rate_limits"`
	DefaultTimeout time.Duration         `yaml:"default_timeout"`
}

// RateLimit defines rate limiting for an action.
type RateLimit struct {
	MaxPerMinute int `yaml:"max_per_minute"`
	MaxPerHour   int `yaml:"max_per_hour"`
}

// LoggingSettings contains logging configuration.
type LoggingSettings struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	File       string `yaml:"file"`
}

// CallbackSettings contains SOAR callback configuration.
type CallbackSettings struct {
	Enabled       bool          `yaml:"enabled"`
	URL           string        `yaml:"url"`
	AuthToken     string        `yaml:"auth_token"`
	Timeout       time.Duration `yaml:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
	SkipTLSVerify bool          `yaml:"skip_tls_verify"`
}

// DefaultAgentConfig returns the default agent configuration.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		Agent: AgentSettings{
			HeartbeatInterval: 30 * time.Second,
			ReconnectDelay:    5 * time.Second,
			MaxReconnectDelay: 5 * time.Minute,
		},
		Server: ServerSettings{
			URL:            "wss://localhost:8443/ws",
			ConnectTimeout: 30 * time.Second,
			WriteTimeout:   10 * time.Second,
			ReadTimeout:    60 * time.Second,
		},
		TLS: TLSSettings{
			Enabled: true,
		},
		Actions: ActionsSettings{
			Enabled: []string{
				"block_ip",
				"unblock_ip",
				"isolate_host",
				"unisolate_host",
				"disable_user",
				"enable_user",
				"collect_forensics",
				"threat_hunt",
				"kill_process",
			},
			DefaultTimeout: 5 * time.Minute,
		},
		Callback: CallbackSettings{
			Enabled:       false,
			Timeout:       30 * time.Second,
			RetryAttempts: 3,
			RetryDelay:    5 * time.Second,
		},
		Collector: *collector.DefaultConfig(),
		Heartbeat: heartbeat.DefaultConfig(),
		Logging: LoggingSettings{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}

// LoadAgentConfig loads agent configuration from a YAML file.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	cfg := DefaultAgentConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Override with environment variables
	cfg.applyEnvOverrides()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the config.
func (c *AgentConfig) applyEnvOverrides() {
	if id := os.Getenv("AISAC_AGENT_ID"); id != "" {
		c.Agent.ID = id
	}
	if url := os.Getenv("AISAC_SERVER_URL"); url != "" {
		c.Server.URL = url
	}
	if cert := os.Getenv("AISAC_CERT_FILE"); cert != "" {
		c.TLS.CertFile = cert
	}
	if key := os.Getenv("AISAC_KEY_FILE"); key != "" {
		c.TLS.KeyFile = key
	}
	if ca := os.Getenv("AISAC_CA_FILE"); ca != "" {
		c.TLS.CAFile = ca
	}
	if level := os.Getenv("AISAC_LOG_LEVEL"); level != "" {
		c.Logging.Level = level
	}

	// Collector environment overrides
	if tenantID := os.Getenv("AISAC_TENANT_ID"); tenantID != "" {
		c.Collector.TenantID = tenantID
	}
	if apiKey := os.Getenv("AISAC_API_KEY"); apiKey != "" {
		c.Collector.Output.APIKey = apiKey
		// Also use for heartbeat if not separately configured
		if c.Heartbeat.APIKey == "" {
			c.Heartbeat.APIKey = apiKey
		}
	}
	if ingestURL := os.Getenv("AISAC_INGEST_URL"); ingestURL != "" {
		c.Collector.Output.URL = ingestURL
	}

	// Heartbeat environment overrides
	if assetID := os.Getenv("AISAC_ASSET_ID"); assetID != "" {
		c.Heartbeat.AssetID = assetID
	}
	if heartbeatURL := os.Getenv("AISAC_HEARTBEAT_URL"); heartbeatURL != "" {
		c.Heartbeat.URL = heartbeatURL
	}
}

// Validate validates the configuration.
func (c *AgentConfig) Validate() error {
	if c.Server.URL == "" {
		return fmt.Errorf("server URL is required")
	}

	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("TLS cert_file is required when TLS is enabled")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("TLS key_file is required when TLS is enabled")
		}
		if c.TLS.CAFile == "" {
			return fmt.Errorf("TLS ca_file is required when TLS is enabled")
		}
	}

	// Validate collector config
	if err := c.Collector.Validate(); err != nil {
		return fmt.Errorf("collector config: %w", err)
	}

	// Validate heartbeat config
	if err := c.Heartbeat.Validate(); err != nil {
		return fmt.Errorf("heartbeat config: %w", err)
	}

	return nil
}

// IsActionEnabled checks if an action is enabled.
func (c *AgentConfig) IsActionEnabled(action string) bool {
	for _, a := range c.Actions.Enabled {
		if a == action {
			return true
		}
	}
	return false
}
