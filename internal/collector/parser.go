package collector

import (
	"fmt"
	"time"
)

// LogEvent represents a parsed log event ready for forwarding.
type LogEvent struct {
	Timestamp time.Time              `json:"@timestamp"`
	Source    string                 `json:"source"`
	TenantID  string                 `json:"tenant_id"`
	Host      string                 `json:"host"`
	Severity  int                    `json:"severity"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	DestIP    string                 `json:"dest_ip,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Raw       string                 `json:"raw,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
}

// Severity levels for log events
const (
	SeverityInfo     = 0 // Informational (flow, stats, netflow)
	SeverityLow      = 1 // Low severity (dns, http, tls queries)
	SeverityMedium   = 2 // Medium severity (anomalies, suspicious behavior)
	SeverityHigh     = 3 // High severity (security alerts)
	SeverityCritical = 4 // Critical severity (critical security alerts)
)

// Parser parses raw log lines into structured LogEvent objects.
type Parser interface {
	// Name returns the parser name.
	Name() string

	// Parse parses a raw log line and returns a LogEvent.
	Parse(line string) (*LogEvent, error)
}

// NewParser creates a parser by name.
func NewParser(name string) (Parser, error) {
	switch name {
	case "suricata_eve":
		return NewSuricataEVEParser(), nil
	case "syslog":
		return NewSyslogParser(), nil
	case "json":
		return NewJSONParser(), nil
	case "wazuh_alerts":
		return NewWazuhAlertParser(), nil
	default:
		return nil, fmt.Errorf("unknown parser: %s", name)
	}
}

// GetParser is an alias for NewParser for backward compatibility.
func GetParser(name string) (Parser, error) {
	return NewParser(name)
}
