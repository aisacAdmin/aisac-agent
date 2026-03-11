// Package collector implements log collection and forwarding for SIEM integration.
package collector

import (
	"fmt"
	"time"
)

// Config holds the log collector configuration.
type Config struct {
	Enabled  bool           `yaml:"enabled"`
	TenantID string         `yaml:"tenant_id"`
	Sources  []SourceConfig `yaml:"sources"`
	Output   OutputConfig   `yaml:"output"`
	Batch    BatchConfig    `yaml:"batch"`
	File     FileConfig     `yaml:"file"`
}

// SourceConfig defines a log source to collect.
type SourceConfig struct {
	Name   string            `yaml:"name"`
	Type   string            `yaml:"type"` // "json_file", "file", "api"
	Path   string            `yaml:"path"`
	Parser string            `yaml:"parser"` // "suricata_eve", "syslog", "json", "wazuh_alerts"
	Tags   []string          `yaml:"tags"`   // Tags to add to events from this source
	Fields map[string]string `yaml:"fields"` // Additional fields to add to events
	API    *APISourceConfig  `yaml:"api,omitempty"`
}

// APISourceConfig holds configuration for API-based log sources (e.g., Wazuh API).
type APISourceConfig struct {
	URL           string        `yaml:"url"`             // API base URL (set via AISAC_WAZUH_API_URL)
	Username      string        `yaml:"username"`        // API username (set via AISAC_WAZUH_API_USER)
	Password      string        `yaml:"password"`        // API password (set via AISAC_WAZUH_API_PASSWORD)
	PollInterval  time.Duration `yaml:"poll_interval"`   // How often to poll for new alerts (default: 30s)
	PageSize      int           `yaml:"page_size"`       // Items per API page (default: 500, max: 500)
	SkipTLSVerify bool          `yaml:"skip_tls_verify"` // Skip TLS certificate verification
	MinRuleLevel  int           `yaml:"min_rule_level"`  // Minimum Wazuh rule level to fetch (0 = all)
}

// OutputConfig defines where to send collected logs.
type OutputConfig struct {
	Type          string        `yaml:"type"` // "http" or "opensearch"
	URL           string        `yaml:"url"`
	APIKey        string        `yaml:"api_key"`
	AuthToken     string        `yaml:"auth_token"` // JWT token for Supabase gateway auth
	AssetID       string        `yaml:"asset_id"`   // Asset ID for AISAC platform
	Username      string        `yaml:"username"`   // For OpenSearch basic auth
	Password      string        `yaml:"password"`   // For OpenSearch basic auth
	Index         string        `yaml:"index"`      // For OpenSearch index pattern
	Timeout       time.Duration `yaml:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
	SkipTLSVerify bool          `yaml:"skip_tls_verify"`
}

// BatchConfig defines batching behavior for efficiency.
type BatchConfig struct {
	Size     int           `yaml:"size"`     // Number of events per batch
	Interval time.Duration `yaml:"interval"` // Max time between flushes
}

// FileConfig defines file handling behavior.
type FileConfig struct {
	StartPosition string        `yaml:"start_position"` // "beginning" or "end"
	SinceDBPath   string        `yaml:"sincedb_path"`   // Path to store file positions
	PollInterval  time.Duration `yaml:"poll_interval"`  // How often to check for new data
}

// DefaultConfig returns default collector configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Batch: BatchConfig{
			Size:     100,
			Interval: 5 * time.Second,
		},
		File: FileConfig{
			StartPosition: "end",
			SinceDBPath:   "/var/lib/aisac/sincedb",
			PollInterval:  100 * time.Millisecond,
		},
		Output: OutputConfig{
			Type:          "http",
			Timeout:       30 * time.Second,
			RetryAttempts: 3,
			RetryDelay:    5 * time.Second,
		},
	}
}

// Validate validates the collector configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // Skip validation if disabled
	}

	// Note: tenant_id is optional - when using API Key authentication,
	// the tenant is automatically derived from the asset associated with the key

	if len(c.Sources) == 0 {
		return fmt.Errorf("at least one collector.sources entry is required")
	}

	for i, src := range c.Sources {
		if err := src.Validate(i); err != nil {
			return err
		}
	}

	if err := c.Output.Validate(); err != nil {
		return err
	}

	if err := c.Batch.Validate(); err != nil {
		return err
	}

	if err := c.File.Validate(); err != nil {
		return err
	}

	return nil
}

// Validate validates a source configuration.
func (s *SourceConfig) Validate(index int) error {
	if s.Name == "" {
		return fmt.Errorf("collector.sources[%d].name is required", index)
	}

	if s.Parser == "" {
		return fmt.Errorf("collector.sources[%d].parser is required", index)
	}

	validParsers := map[string]bool{"suricata_eve": true, "syslog": true, "json": true, "wazuh_alerts": true}
	if !validParsers[s.Parser] {
		return fmt.Errorf("collector.sources[%d].parser must be one of: suricata_eve, syslog, json, wazuh_alerts", index)
	}

	// wazuh_alerts requires type: api
	if s.Parser == "wazuh_alerts" && s.Type != "api" {
		return fmt.Errorf("collector.sources[%d]: wazuh_alerts parser requires type: api (use Wazuh API instead of file)", index)
	}

	validTypes := map[string]bool{"json_file": true, "file": true, "api": true}
	if s.Type != "" && !validTypes[s.Type] {
		return fmt.Errorf("collector.sources[%d].type must be 'json_file', 'file', or 'api'", index)
	}

	if s.Type == "api" {
		if s.API == nil {
			return fmt.Errorf("collector.sources[%d].api configuration is required for type 'api'", index)
		}
		if err := s.API.Validate(index); err != nil {
			return err
		}
	} else {
		// File-based sources require a path
		if s.Path == "" {
			return fmt.Errorf("collector.sources[%d].path is required", index)
		}
	}

	return nil
}

// Validate validates API source configuration.
func (a *APISourceConfig) Validate(index int) error {
	// URL, Username, Password are expected from env vars, so we only validate
	// them at runtime (in WazuhClient constructor), not here.

	if a.PollInterval < 0 {
		return fmt.Errorf("collector.sources[%d].api.poll_interval must not be negative", index)
	}

	if a.PageSize < 0 || a.PageSize > 500 {
		return fmt.Errorf("collector.sources[%d].api.page_size must be between 0 and 500", index)
	}

	if a.MinRuleLevel < 0 || a.MinRuleLevel > 15 {
		return fmt.Errorf("collector.sources[%d].api.min_rule_level must be between 0 and 15", index)
	}

	return nil
}

// DefaultAPISourceConfig returns default API source configuration.
func DefaultAPISourceConfig() *APISourceConfig {
	return &APISourceConfig{
		PollInterval: 30 * time.Second,
		PageSize:     500,
	}
}

// Validate validates output configuration.
func (o *OutputConfig) Validate() error {
	if o.URL == "" {
		return fmt.Errorf("collector.output.url is required")
	}

	validTypes := map[string]bool{"http": true, "opensearch": true}
	if !validTypes[o.Type] {
		return fmt.Errorf("collector.output.type must be 'http' or 'opensearch'")
	}

	if o.Timeout <= 0 {
		return fmt.Errorf("collector.output.timeout must be positive")
	}

	return nil
}

// Validate validates batch configuration.
func (b *BatchConfig) Validate() error {
	if b.Size <= 0 {
		return fmt.Errorf("collector.batch.size must be positive")
	}

	if b.Interval <= 0 {
		return fmt.Errorf("collector.batch.interval must be positive")
	}

	return nil
}

// Validate validates file configuration.
func (f *FileConfig) Validate() error {
	validPositions := map[string]bool{"beginning": true, "end": true}
	if f.StartPosition != "" && !validPositions[f.StartPosition] {
		return fmt.Errorf("collector.file.start_position must be 'beginning' or 'end'")
	}

	return nil
}
