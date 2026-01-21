package collector

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SyslogParser parses syslog format logs (RFC3164 and RFC5424).
type SyslogParser struct {
	// RFC3164: <priority>timestamp hostname program[pid]: message
	rfc3164 *regexp.Regexp
	// RFC5424: <priority>version timestamp hostname app-name procid msgid structured-data message
	rfc5424 *regexp.Regexp
	// Simple syslog without priority
	simple *regexp.Regexp
}

// NewSyslogParser creates a new syslog parser.
func NewSyslogParser() *SyslogParser {
	return &SyslogParser{
		// RFC3164 pattern: <34>Oct 11 22:14:15 mymachine su: 'su root' failed
		rfc3164: regexp.MustCompile(`^(?:<(\d{1,3})>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`),
		// RFC5424 pattern: <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - message
		rfc5424: regexp.MustCompile(`^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]\s*)?(.*)$`),
		// Simple pattern: timestamp hostname program: message
		simple: regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`),
	}
}

// Name returns the parser name.
func (p *SyslogParser) Name() string {
	return "syslog"
}

// Parse parses a syslog log line.
func (p *SyslogParser) Parse(line string) (*LogEvent, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	event := &LogEvent{
		Timestamp: time.Now().UTC(),
		Raw:       line,
		Message:   line,
		Fields:    make(map[string]interface{}),
	}

	// Try RFC5424 first (has version number after priority)
	if matches := p.rfc5424.FindStringSubmatch(line); len(matches) > 0 {
		p.parseRFC5424(event, matches)
		return event, nil
	}

	// Try RFC3164
	if matches := p.rfc3164.FindStringSubmatch(line); len(matches) > 0 {
		p.parseRFC3164(event, matches)
		return event, nil
	}

	// Try simple format
	if matches := p.simple.FindStringSubmatch(line); len(matches) > 0 {
		p.parseSimple(event, matches)
		return event, nil
	}

	// Return as-is if no pattern matches
	return event, nil
}

func (p *SyslogParser) parseRFC3164(event *LogEvent, matches []string) {
	// matches: [full, priority, timestamp, hostname, program, pid, message]
	if len(matches) < 7 {
		return
	}

	if matches[1] != "" {
		priority, _ := strconv.Atoi(matches[1])
		event.Fields["priority"] = priority
		event.Fields["facility"] = priority / 8
		event.Fields["severity"] = priority % 8
		event.Tags = append(event.Tags, severityName(priority%8))
	}

	// Parse timestamp (assuming current year)
	if ts := parseRFC3164Timestamp(matches[2]); !ts.IsZero() {
		event.Timestamp = ts
	}
	event.Fields["timestamp_raw"] = matches[2]

	event.Fields["hostname"] = matches[3]
	event.Fields["program"] = matches[4]
	if matches[5] != "" {
		pid, _ := strconv.Atoi(matches[5])
		event.Fields["pid"] = pid
	}
	event.Message = matches[6]
}

func (p *SyslogParser) parseRFC5424(event *LogEvent, matches []string) {
	// matches: [full, priority, version, timestamp, hostname, app_name, procid, msgid, message]
	if len(matches) < 9 {
		return
	}

	if matches[1] != "" {
		priority, _ := strconv.Atoi(matches[1])
		event.Fields["priority"] = priority
		event.Fields["facility"] = priority / 8
		event.Fields["severity"] = priority % 8
		event.Tags = append(event.Tags, severityName(priority%8))
	}

	event.Fields["version"] = matches[2]

	// Parse ISO8601 timestamp
	if ts, err := time.Parse(time.RFC3339Nano, matches[3]); err == nil {
		event.Timestamp = ts.UTC()
	} else if ts, err := time.Parse(time.RFC3339, matches[3]); err == nil {
		event.Timestamp = ts.UTC()
	}
	event.Fields["timestamp_raw"] = matches[3]

	event.Fields["hostname"] = matches[4]
	event.Fields["app_name"] = matches[5]
	if matches[6] != "-" {
		event.Fields["procid"] = matches[6]
	}
	if matches[7] != "-" {
		event.Fields["msgid"] = matches[7]
	}
	event.Message = matches[8]
}

func (p *SyslogParser) parseSimple(event *LogEvent, matches []string) {
	// matches: [full, timestamp, hostname, program, pid, message]
	if len(matches) < 6 {
		return
	}

	if ts := parseRFC3164Timestamp(matches[1]); !ts.IsZero() {
		event.Timestamp = ts
	}
	event.Fields["timestamp_raw"] = matches[1]
	event.Fields["hostname"] = matches[2]
	event.Fields["program"] = matches[3]
	if matches[4] != "" {
		pid, _ := strconv.Atoi(matches[4])
		event.Fields["pid"] = pid
	}
	event.Message = matches[5]
}

// parseRFC3164Timestamp parses timestamps like "Oct 11 22:14:15"
func parseRFC3164Timestamp(ts string) time.Time {
	// Assume current year
	now := time.Now()
	year := now.Year()

	// Try to parse with current year
	t, err := time.Parse("Jan 2 15:04:05 2006", ts+" "+strconv.Itoa(year))
	if err != nil {
		// Try alternative format
		t, err = time.Parse("Jan  2 15:04:05 2006", ts+" "+strconv.Itoa(year))
		if err != nil {
			return time.Time{}
		}
	}

	// If the parsed time is in the future, use last year
	if t.After(now) {
		t = t.AddDate(-1, 0, 0)
	}

	return t.UTC()
}

// severityName returns the name for a syslog severity level.
func severityName(severity int) string {
	names := []string{
		"emergency",
		"alert",
		"critical",
		"error",
		"warning",
		"notice",
		"info",
		"debug",
	}
	if severity >= 0 && severity < len(names) {
		return names[severity]
	}
	return "unknown"
}
