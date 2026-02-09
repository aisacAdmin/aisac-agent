package collector

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WazuhAlertParser parses Wazuh alerts.json log lines.
type WazuhAlertParser struct{}

// NewWazuhAlertParser creates a new Wazuh alert parser.
func NewWazuhAlertParser() *WazuhAlertParser {
	return &WazuhAlertParser{}
}

// Name returns the parser name.
func (p *WazuhAlertParser) Name() string {
	return "wazuh_alerts"
}

// Parse parses a Wazuh alert JSON log line.
func (p *WazuhAlertParser) Parse(line string) (*LogEvent, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	var alert map[string]interface{}
	if err := json.Unmarshal([]byte(line), &alert); err != nil {
		return nil, err
	}

	event := &LogEvent{
		Timestamp: time.Now().UTC(),
		Raw:       line,
		Fields:    alert,
	}

	// Extract timestamp (Wazuh format: 2026-01-28T08:28:55.574+0000)
	if ts, ok := alert["timestamp"].(string); ok {
		formats := []string{
			"2006-01-02T15:04:05.999-0700",
			"2006-01-02T15:04:05.999Z0700",
			"2006-01-02T15:04:05.999Z",
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

	// Extract source IP from data.srcip
	if data, ok := alert["data"].(map[string]interface{}); ok {
		if srcIP, ok := data["srcip"].(string); ok {
			event.SourceIP = srcIP
		}
		if dstIP, ok := data["dstip"].(string); ok {
			event.DestIP = dstIP
		}
	}

	// Add tags from rule groups and extract severity
	event.Tags = append(event.Tags, "wazuh")
	if rule, ok := alert["rule"].(map[string]interface{}); ok {
		if groups, ok := rule["groups"].([]interface{}); ok {
			for _, g := range groups {
				if gs, ok := g.(string); ok {
					event.Tags = append(event.Tags, gs)
				}
			}
		}

		// Add MITRE ATT&CK tags
		if mitre, ok := rule["mitre"].(map[string]interface{}); ok {
			if ids, ok := mitre["id"].([]interface{}); ok {
				for _, id := range ids {
					if idStr, ok := id.(string); ok {
						event.Tags = append(event.Tags, "mitre:"+idStr)
					}
				}
			}
		}

		// Extract severity from rule level
		event.Severity = p.assignSeverity(rule)
	} else {
		// Default to info if no rule
		event.Severity = SeverityInfo
	}

	// Build message
	event.Message = p.buildMessage(alert)

	return event, nil
}

// buildMessage creates a human-readable message from a Wazuh alert.
func (p *WazuhAlertParser) buildMessage(alert map[string]interface{}) string {
	rule, _ := alert["rule"].(map[string]interface{})
	if rule == nil {
		return "Wazuh alert"
	}

	description := getStringField(rule, "description")
	level := getFloatField(rule, "level")
	ruleID := getStringField(rule, "id")

	// Extract agent name
	agentName := ""
	if agent, ok := alert["agent"].(map[string]interface{}); ok {
		agentName = getStringField(agent, "name")
	}

	// Extract MITRE tactic
	mitreTactic := ""
	if mitre, ok := rule["mitre"].(map[string]interface{}); ok {
		if tactics, ok := mitre["tactic"].([]interface{}); ok && len(tactics) > 0 {
			parts := make([]string, 0, len(tactics))
			for _, t := range tactics {
				if ts, ok := t.(string); ok {
					parts = append(parts, ts)
				}
			}
			mitreTactic = strings.Join(parts, ", ")
		}
	}

	if mitreTactic != "" {
		return fmt.Sprintf("[%s] (Rule %s, Level %d) %s [MITRE: %s]",
			agentName, ruleID, int(level), description, mitreTactic)
	}

	return fmt.Sprintf("[%s] (Rule %s, Level %d) %s",
		agentName, ruleID, int(level), description)
}

// assignSeverity assigns severity level based on Wazuh rule level.
// Wazuh levels range from 0-15:
// 0-3: Informational
// 4-6: Low priority
// 7-9: Medium priority
// 10-12: High priority
// 13-15: Critical
func (p *WazuhAlertParser) assignSeverity(rule map[string]interface{}) int {
	level := getFloatField(rule, "level")
	ruleLevel := int(level)

	switch {
	case ruleLevel >= 13:
		return SeverityCritical // Critical (13-15)
	case ruleLevel >= 10:
		return SeverityHigh // High (10-12)
	case ruleLevel >= 7:
		return SeverityMedium // Medium (7-9)
	case ruleLevel >= 4:
		return SeverityLow // Low (4-6)
	default:
		return SeverityInfo // Info (0-3)
	}
}
