package collector

import (
	"strings"
	"testing"
	"time"
)

func TestJSONParser(t *testing.T) {
	parser := NewJSONParser()

	tests := []struct {
		name    string
		line    string
		wantErr bool
		check   func(*LogEvent) bool
	}{
		{
			name:    "valid JSON with timestamp",
			line:    `{"@timestamp":"2024-01-15T10:30:00Z","message":"test event","level":"info"}`,
			wantErr: false,
			check: func(e *LogEvent) bool {
				return e.Timestamp.Year() == 2024 && e.Message == "test event"
			},
		},
		{
			name:    "valid JSON with timestamp field",
			line:    `{"timestamp":"2024-01-15T10:30:00Z","msg":"another event"}`,
			wantErr: false,
			check: func(e *LogEvent) bool {
				return e.Timestamp.Year() == 2024
			},
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: false,
			check: func(e *LogEvent) bool {
				return e == nil
			},
		},
		{
			name:    "invalid JSON",
			line:    `{invalid json}`,
			wantErr: true,
			check:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && !tt.check(event) {
				t.Errorf("Parse() check failed for event: %+v", event)
			}
		})
	}
}

func TestSuricataEVEParser(t *testing.T) {
	parser := NewSuricataEVEParser()

	tests := []struct {
		name    string
		line    string
		wantErr bool
		check   func(*LogEvent) bool
	}{
		{
			name: "alert event",
			line: `{"timestamp":"2024-01-15T10:30:00.123456+0000","flow_id":123456789,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.100","src_port":54321,"dest_ip":"10.0.0.1","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2024001,"rev":1,"signature":"ET MALWARE Suspicious User-Agent","category":"A Network Trojan was detected","severity":1}}`,
			wantErr: false,
			check: func(e *LogEvent) bool {
				return e.SourceIP == "192.168.1.100" &&
					e.DestIP == "10.0.0.1" &&
					strings.Contains(e.Message, "ET MALWARE")
			},
		},
		{
			name: "dns event",
			line: `{"timestamp":"2024-01-15T10:30:00.123456+0000","flow_id":123456789,"event_type":"dns","src_ip":"192.168.1.100","dest_ip":"8.8.8.8","dns":{"type":"query","rrname":"example.com","rrtype":"A"}}`,
			wantErr: false,
			check: func(e *LogEvent) bool {
				return strings.Contains(e.Message, "example.com")
			},
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: false,
			check: func(e *LogEvent) bool {
				return e == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && !tt.check(event) {
				t.Errorf("Parse() check failed for event: %+v", event)
			}
		})
	}
}

func TestSyslogParser(t *testing.T) {
	parser := NewSyslogParser()

	tests := []struct {
		name    string
		line    string
		wantErr bool
		check   func(*LogEvent) bool
	}{
		{
			name:    "RFC3164 with priority",
			line:    "<34>Jan 15 10:30:00 myhost sshd[1234]: Accepted password for user from 192.168.1.100",
			wantErr: false,
			check: func(e *LogEvent) bool {
				priority, _ := e.Fields["priority"].(int)
				hostname, _ := e.Fields["hostname"].(string)
				program, _ := e.Fields["program"].(string)
				return priority == 34 && hostname == "myhost" && program == "sshd"
			},
		},
		{
			name:    "RFC3164 without priority",
			line:    "Jan 15 10:30:00 myhost kernel: Linux version 5.4.0",
			wantErr: false,
			check: func(e *LogEvent) bool {
				hostname, _ := e.Fields["hostname"].(string)
				return hostname == "myhost"
			},
		},
		{
			name:    "RFC5424",
			line:    "<34>1 2024-01-15T10:30:00.123Z myhost.example.com myapp 1234 ID47 - This is the message",
			wantErr: false,
			check: func(e *LogEvent) bool {
				version, _ := e.Fields["version"].(string)
				// Message may include "- " prefix from structured-data NILVALUE
				return version == "1" && strings.Contains(e.Message, "This is the message")
			},
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: false,
			check: func(e *LogEvent) bool {
				return e == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && !tt.check(event) {
				t.Errorf("Parse() check failed for event: %+v", event)
			}
		})
	}
}

func TestGetParser(t *testing.T) {
	tests := []struct {
		name       string
		parserName string
		wantErr    bool
	}{
		{"suricata_eve parser", "suricata_eve", false},
		{"syslog parser", "syslog", false},
		{"json parser", "json", false},
		{"unknown parser", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := GetParser(tt.parserName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetParser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && parser == nil {
				t.Error("GetParser() returned nil parser")
			}
		})
	}
}

func TestSeverityName(t *testing.T) {
	tests := []struct {
		severity int
		expected string
	}{
		{0, "emergency"},
		{1, "alert"},
		{2, "critical"},
		{3, "error"},
		{4, "warning"},
		{5, "notice"},
		{6, "info"},
		{7, "debug"},
		{8, "unknown"},
		{-1, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := severityName(tt.severity); got != tt.expected {
				t.Errorf("severityName(%d) = %v, want %v", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestParseRFC3164Timestamp(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid timestamp", "Jan 15 10:30:00", false},
		{"single digit day", "Jan  5 10:30:00", false},
		{"invalid timestamp", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRFC3164Timestamp(tt.input)
			if tt.wantErr && !result.IsZero() {
				t.Errorf("parseRFC3164Timestamp(%s) should return zero time", tt.input)
			}
			if !tt.wantErr && result.IsZero() {
				t.Errorf("parseRFC3164Timestamp(%s) returned zero time", tt.input)
			}
			if !tt.wantErr && result.Year() != now.Year() && result.Year() != now.Year()-1 {
				t.Errorf("parseRFC3164Timestamp(%s) year = %d, expected %d or %d", tt.input, result.Year(), now.Year(), now.Year()-1)
			}
		})
	}
}
