package collector

import (
	"encoding/json"
	"strings"
	"time"
)

// JSONParser parses generic JSON log lines.
type JSONParser struct{}

// NewJSONParser creates a new JSON parser.
func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

// Name returns the parser name.
func (p *JSONParser) Name() string {
	return "json"
}

// Parse parses a JSON log line.
func (p *JSONParser) Parse(line string) (*LogEvent, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return nil, err
	}

	event := &LogEvent{
		Timestamp: time.Now().UTC(),
		Raw:       line,
		Fields:    fields,
	}

	// Try to extract common timestamp fields
	if ts := extractTimestamp(fields, "@timestamp", "timestamp", "time", "ts", "datetime"); !ts.IsZero() {
		event.Timestamp = ts
	}

	// Try to extract message
	if msg := extractString(fields, "message", "msg", "log"); msg != "" {
		event.Message = msg
	}

	return event, nil
}

// extractTimestamp tries to extract a timestamp from various field names.
func extractTimestamp(fields map[string]interface{}, keys ...string) time.Time {
	for _, key := range keys {
		if val, ok := fields[key]; ok {
			switch v := val.(type) {
			case string:
				// Try common formats
				formats := []string{
					time.RFC3339Nano,
					time.RFC3339,
					"2006-01-02T15:04:05.000000Z0700",
					"2006-01-02T15:04:05.000000",
					"2006-01-02T15:04:05",
					"2006-01-02 15:04:05",
				}
				for _, format := range formats {
					if t, err := time.Parse(format, v); err == nil {
						return t
					}
				}
			case float64:
				// Unix timestamp (seconds or milliseconds)
				if v > 1e12 {
					return time.UnixMilli(int64(v))
				}
				return time.Unix(int64(v), 0)
			}
		}
	}
	return time.Time{}
}

// extractString tries to extract a string from various field names.
func extractString(fields map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := fields[key]; ok {
			if s, ok := val.(string); ok {
				return s
			}
		}
	}
	return ""
}
