package collector

import (
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "disabled collector - no validation",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "tenant_id is optional with API Key auth",
			config: Config{
				Enabled:  true,
				TenantID: "", // Optional - derived from API Key on platform side
				Sources: []SourceConfig{
					{Name: "test", Path: "/var/log/test.log", Parser: "json"},
				},
				Output: OutputConfig{
					Type:    "http",
					URL:     "https://example.com/ingest",
					Timeout: 30 * time.Second,
				},
				Batch: BatchConfig{
					Size:     100,
					Interval: 5 * time.Second,
				},
			},
			wantErr: false,
		},
		{
			name: "missing sources",
			config: Config{
				Enabled:  true,
				TenantID: "test-tenant",
				Sources:  []SourceConfig{},
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: Config{
				Enabled:  true,
				TenantID: "test-tenant",
				Sources: []SourceConfig{
					{Name: "test", Path: "/var/log/test.log", Parser: "json"},
				},
				Output: OutputConfig{
					Type:          "http",
					URL:           "https://example.com/ingest",
					Timeout:       30 * time.Second,
					RetryAttempts: 3,
					RetryDelay:    5 * time.Second,
				},
				Batch: BatchConfig{
					Size:     100,
					Interval: 5 * time.Second,
				},
				File: FileConfig{
					StartPosition: "end",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid parser",
			config: Config{
				Enabled:  true,
				TenantID: "test-tenant",
				Sources: []SourceConfig{
					{Name: "test", Path: "/var/log/test.log", Parser: "invalid_parser"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid output type",
			config: Config{
				Enabled:  true,
				TenantID: "test-tenant",
				Sources: []SourceConfig{
					{Name: "test", Path: "/var/log/test.log", Parser: "json"},
				},
				Output: OutputConfig{
					Type:    "invalid",
					URL:     "https://example.com",
					Timeout: 30 * time.Second,
				},
			},
			wantErr: true,
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

func TestSourceConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		source  SourceConfig
		wantErr bool
	}{
		{
			name: "missing name",
			source: SourceConfig{
				Path:   "/var/log/test.log",
				Parser: "json",
			},
			wantErr: true,
		},
		{
			name: "missing path",
			source: SourceConfig{
				Name:   "test",
				Parser: "json",
			},
			wantErr: true,
		},
		{
			name: "missing parser",
			source: SourceConfig{
				Name: "test",
				Path: "/var/log/test.log",
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			source: SourceConfig{
				Name:   "test",
				Path:   "/var/log/test.log",
				Type:   "invalid_type",
				Parser: "json",
			},
			wantErr: true,
		},
		{
			name: "valid source with all fields",
			source: SourceConfig{
				Name:   "test",
				Path:   "/var/log/test.log",
				Type:   "file",
				Parser: "syslog",
				Tags:   []string{"system", "security"},
				Fields: map[string]string{"env": "prod"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.source.Validate(0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAPISourceConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		source  SourceConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid api source",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Type:   "api",
				Parser: "wazuh_alerts",
				API: &APISourceConfig{
					PollInterval: 30 * time.Second,
					PageSize:     500,
				},
			},
			wantErr: false,
		},
		{
			name: "wazuh_alerts with file type is rejected",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Type:   "file",
				Path:   "/var/ossec/logs/alerts/alerts.json",
				Parser: "wazuh_alerts",
			},
			wantErr: true,
			errMsg:  "wazuh_alerts parser requires type: api",
		},
		{
			name: "wazuh_alerts with empty type is rejected",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Path:   "/var/ossec/logs/alerts/alerts.json",
				Parser: "wazuh_alerts",
			},
			wantErr: true,
			errMsg:  "wazuh_alerts parser requires type: api",
		},
		{
			name: "api source missing api config",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Type:   "api",
				Parser: "wazuh_alerts",
			},
			wantErr: true,
			errMsg:  "api configuration is required",
		},
		{
			name: "api source path not required",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Type:   "api",
				Parser: "wazuh_alerts",
				API: &APISourceConfig{
					PageSize: 100,
				},
			},
			wantErr: false,
		},
		{
			name: "api source page_size too large",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Type:   "api",
				Parser: "wazuh_alerts",
				API: &APISourceConfig{
					PageSize: 1000,
				},
			},
			wantErr: true,
			errMsg:  "page_size must be between 0 and 500",
		},
		{
			name: "api source invalid min_rule_level",
			source: SourceConfig{
				Name:   "wazuh_alerts",
				Type:   "api",
				Parser: "wazuh_alerts",
				API: &APISourceConfig{
					MinRuleLevel: 20,
				},
			},
			wantErr: true,
			errMsg:  "min_rule_level must be between 0 and 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.source.Validate(0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestOutputConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		output  OutputConfig
		wantErr bool
	}{
		{
			name: "missing URL",
			output: OutputConfig{
				Type:    "http",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			output: OutputConfig{
				Type:    "kafka",
				URL:     "https://example.com",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			output: OutputConfig{
				Type:    "http",
				URL:     "https://example.com",
				Timeout: 0,
			},
			wantErr: true,
		},
		{
			name: "valid http output",
			output: OutputConfig{
				Type:    "http",
				URL:     "https://example.com",
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.output.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBatchConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		batch   BatchConfig
		wantErr bool
	}{
		{
			name: "zero size",
			batch: BatchConfig{
				Size:     0,
				Interval: 5 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "zero interval",
			batch: BatchConfig{
				Size:     100,
				Interval: 0,
			},
			wantErr: true,
		},
		{
			name: "valid batch config",
			batch: BatchConfig{
				Size:     100,
				Interval: 5 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.batch.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		file    FileConfig
		wantErr bool
	}{
		{
			name: "invalid start_position",
			file: FileConfig{
				StartPosition: "middle",
			},
			wantErr: true,
		},
		{
			name: "valid start_position beginning",
			file: FileConfig{
				StartPosition: "beginning",
			},
			wantErr: false,
		},
		{
			name: "valid start_position end",
			file: FileConfig{
				StartPosition: "end",
			},
			wantErr: false,
		},
		{
			name: "empty start_position is valid",
			file: FileConfig{
				StartPosition: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.file.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if cfg.Enabled {
		t.Error("Default config should have Enabled = false")
	}

	if cfg.Batch.Size != 100 {
		t.Errorf("Default batch size = %d, want 100", cfg.Batch.Size)
	}

	if cfg.Batch.Interval != 5*time.Second {
		t.Errorf("Default batch interval = %v, want 5s", cfg.Batch.Interval)
	}

	if cfg.File.StartPosition != "end" {
		t.Errorf("Default start_position = %s, want 'end'", cfg.File.StartPosition)
	}

	if cfg.Output.Type != "http" {
		t.Errorf("Default output type = %s, want 'http'", cfg.Output.Type)
	}
}
