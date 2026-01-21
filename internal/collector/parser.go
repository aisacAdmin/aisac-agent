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
	SourceIP  string                 `json:"source_ip,omitempty"`
	DestIP    string                 `json:"dest_ip,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Raw       string                 `json:"raw,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
}

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
	default:
		return nil, fmt.Errorf("unknown parser: %s", name)
	}
}

// GetParser is an alias for NewParser for backward compatibility.
func GetParser(name string) (Parser, error) {
	return NewParser(name)
}
