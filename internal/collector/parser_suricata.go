package collector

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SuricataEVEParser parses Suricata EVE JSON logs.
type SuricataEVEParser struct{}

// NewSuricataEVEParser creates a new Suricata EVE parser.
func NewSuricataEVEParser() *SuricataEVEParser {
	return &SuricataEVEParser{}
}

// Name returns the parser name.
func (p *SuricataEVEParser) Name() string {
	return "suricata_eve"
}

// Parse parses a Suricata EVE JSON log line.
func (p *SuricataEVEParser) Parse(line string) (*LogEvent, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	var eve map[string]interface{}
	if err := json.Unmarshal([]byte(line), &eve); err != nil {
		return nil, err
	}

	event := &LogEvent{
		Timestamp: time.Now().UTC(),
		Raw:       line,
		Fields:    eve,
	}

	// Extract timestamp (Suricata uses ISO8601 format)
	if ts, ok := eve["timestamp"].(string); ok {
		// Suricata format: 2024-01-15T14:30:00.123456+0000
		formats := []string{
			"2006-01-02T15:04:05.999999-0700",
			"2006-01-02T15:04:05.999999Z0700",
			"2006-01-02T15:04:05.999999Z",
			time.RFC3339Nano,
			time.RFC3339,
		}
		for _, format := range formats {
			if t, err := time.Parse(format, ts); err == nil {
				event.Timestamp = t.UTC()
				break
			}
		}
	}

	// Extract source IP
	if srcIP, ok := eve["src_ip"].(string); ok {
		event.SourceIP = srcIP
	}

	// Extract destination IP
	if dstIP, ok := eve["dest_ip"].(string); ok {
		event.DestIP = dstIP
	}

	// Extract event type as tag and assign severity
	if eventType, ok := eve["event_type"].(string); ok {
		event.Tags = append(event.Tags, eventType)

		// Build a message based on event type
		event.Message = p.buildMessage(eventType, eve)

		// Assign severity based on event type
		event.Severity = p.assignSeverity(eventType, eve)
	} else {
		// Default to info if no event type
		event.Severity = SeverityInfo
	}

	return event, nil
}

// buildMessage creates a human-readable message based on the event type.
func (p *SuricataEVEParser) buildMessage(eventType string, eve map[string]interface{}) string {
	srcIP := getStringField(eve, "src_ip")
	srcPort := getFloatField(eve, "src_port")
	dstIP := getStringField(eve, "dest_ip")
	dstPort := getFloatField(eve, "dest_port")
	proto := getStringField(eve, "proto")

	switch eventType {
	case "alert":
		// Extract alert details
		if alert, ok := eve["alert"].(map[string]interface{}); ok {
			signature := getStringField(alert, "signature")
			severity := getFloatField(alert, "severity")
			category := getStringField(alert, "category")
			return formatMessage("Alert: %s [severity=%d, category=%s] %s:%d -> %s:%d (%s)",
				signature, int(severity), category, srcIP, int(srcPort), dstIP, int(dstPort), proto)
		}

	case "dns":
		if dns, ok := eve["dns"].(map[string]interface{}); ok {
			queryType := getStringField(dns, "type")
			rrname := getStringField(dns, "rrname")
			return formatMessage("DNS %s query for %s from %s", queryType, rrname, srcIP)
		}

	case "http":
		if http, ok := eve["http"].(map[string]interface{}); ok {
			method := getStringField(http, "http_method")
			host := getStringField(http, "hostname")
			url := getStringField(http, "url")
			status := getFloatField(http, "status")
			return formatMessage("HTTP %s %s%s [%d] from %s", method, host, url, int(status), srcIP)
		}

	case "tls":
		if tls, ok := eve["tls"].(map[string]interface{}); ok {
			sni := getStringField(tls, "sni")
			version := getStringField(tls, "version")
			return formatMessage("TLS %s to %s from %s:%d", version, sni, srcIP, int(srcPort))
		}

	case "flow":
		bytesToServer := getFloatField(eve, "flow.bytes_toserver")
		bytesToClient := getFloatField(eve, "flow.bytes_toclient")
		return formatMessage("Flow %s:%d -> %s:%d (%s) bytes: %d/%d",
			srcIP, int(srcPort), dstIP, int(dstPort), proto, int(bytesToServer), int(bytesToClient))

	case "fileinfo":
		if fileinfo, ok := eve["fileinfo"].(map[string]interface{}); ok {
			filename := getStringField(fileinfo, "filename")
			size := getFloatField(fileinfo, "size")
			return formatMessage("File: %s (%d bytes) from %s", filename, int(size), srcIP)
		}
	}

	// Default message
	return formatMessage("%s: %s:%d -> %s:%d (%s)", eventType, srcIP, int(srcPort), dstIP, int(dstPort), proto)
}

func getStringField(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getFloatField(m map[string]interface{}, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	return 0
}

func formatMessage(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// assignSeverity assigns severity level based on event type and alert severity.
func (p *SuricataEVEParser) assignSeverity(eventType string, eve map[string]interface{}) int {
	switch eventType {
	case "alert":
		// WORKAROUND: Send all alerts as Low (1) to bypass platform filtering
		// Platform currently only accepts severity 0-1, filtering out 2+
		// TODO: Fix platform configuration to accept all severities
		// The original Suricata severity is preserved in the "fields" for analysis
		return SeverityLow

	case "flow", "netflow", "stats":
		// Network flows and stats are informational
		return SeverityInfo

	case "anomaly", "drop", "pkthdr":
		// WORKAROUND: Send as Low to bypass platform filtering
		return SeverityLow

	case "dns", "http", "tls", "ssh", "smtp", "ftp", "smb", "rdp", "fileinfo":
		// Protocol events are low severity (informational but useful for SIEM)
		return SeverityLow

	default:
		// Unknown event types default to low
		return SeverityLow
	}
}
