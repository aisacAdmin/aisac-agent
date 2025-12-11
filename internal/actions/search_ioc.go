package actions

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/pkg/types"
)

// SearchIOCAction searches for Indicators of Compromise in system logs.
type SearchIOCAction struct {
	logger zerolog.Logger
}

// NewSearchIOCAction creates a new SearchIOCAction.
func NewSearchIOCAction(logger zerolog.Logger) *SearchIOCAction {
	return &SearchIOCAction{
		logger: logger.With().Str("action", "search_ioc").Logger(),
	}
}

// Name returns the action name.
func (a *SearchIOCAction) Name() types.ActionType {
	return types.ActionSearchIOC
}

// Validate validates the parameters.
func (a *SearchIOCAction) Validate(params map[string]interface{}) error {
	iocValue, ok := params["ioc_value"].(string)
	if !ok || iocValue == "" {
		return fmt.Errorf("ioc_value is required")
	}

	// Validate IOC type if provided
	if iocType, ok := params["ioc_type"].(string); ok {
		validTypes := map[string]bool{
			"ip": true, "domain": true, "hash": true,
			"url": true, "email": true, "any": true,
		}
		if !validTypes[strings.ToLower(iocType)] {
			return fmt.Errorf("invalid ioc_type: %s (valid: ip, domain, hash, url, email, any)", iocType)
		}
	}

	// Validate time range if provided
	if timeRange, ok := params["time_range"].(string); ok {
		validRanges := map[string]bool{
			"1h": true, "6h": true, "12h": true,
			"24h": true, "7d": true, "30d": true,
		}
		if !validRanges[timeRange] {
			return fmt.Errorf("invalid time_range: %s (valid: 1h, 6h, 12h, 24h, 7d, 30d)", timeRange)
		}
	}

	return nil
}

// IOCMatch represents a match found during IOC search.
type IOCMatch struct {
	Source    string `json:"source"`
	Line      string `json:"line"`
	LineNum   int    `json:"line_num,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// Execute searches for the IOC in system logs.
func (a *SearchIOCAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	iocValue := params["ioc_value"].(string)

	iocType := "any"
	if t, ok := params["ioc_type"].(string); ok {
		iocType = strings.ToLower(t)
	}

	timeRange := "24h"
	if tr, ok := params["time_range"].(string); ok {
		timeRange = tr
	}

	a.logger.Info().
		Str("ioc_value", iocValue).
		Str("ioc_type", iocType).
		Str("time_range", timeRange).
		Msg("Searching for IOC in logs")

	// Calculate time threshold
	duration := parseTimeRange(timeRange)
	threshold := time.Now().Add(-duration)

	var matches []IOCMatch
	var searchedSources []string

	// Define log paths to search
	logPaths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/kern.log",
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"/var/log/audit/audit.log",
	}

	// Build search pattern based on IOC type
	pattern := buildSearchPattern(iocValue, iocType)
	regex, err := regexp.Compile(pattern)
	if err != nil {
		// Fall back to literal search if regex fails
		regex = nil
	}

	// Search in log files
	for _, logPath := range logPaths {
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			continue
		}

		searchedSources = append(searchedSources, logPath)
		fileMatches := searchInFile(ctx, logPath, iocValue, regex, threshold, 100)
		matches = append(matches, fileMatches...)
	}

	// Search in journald if available
	journalMatches := searchJournald(ctx, iocValue, timeRange, 100)
	if len(journalMatches) > 0 {
		searchedSources = append(searchedSources, "journald")
		matches = append(matches, journalMatches...)
	}

	// Limit total matches
	if len(matches) > 500 {
		matches = matches[:500]
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("IOC search completed, found %d matches", len(matches)),
		Details: map[string]interface{}{
			"ioc_type":         iocType,
			"ioc_value":        iocValue,
			"time_range":       timeRange,
			"matches_found":    len(matches),
			"matches":          matches,
			"searched_sources": searchedSources,
			"searched_at":      time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// parseTimeRange converts a time range string to duration.
func parseTimeRange(timeRange string) time.Duration {
	switch timeRange {
	case "1h":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "12h":
		return 12 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// buildSearchPattern builds a regex pattern for the IOC type.
func buildSearchPattern(iocValue, iocType string) string {
	// Escape special regex characters in the IOC value
	escaped := regexp.QuoteMeta(iocValue)

	switch iocType {
	case "ip":
		// Match IP with word boundaries
		return `\b` + escaped + `\b`
	case "domain":
		// Match domain (may have subdomains)
		return `\b([a-zA-Z0-9-]+\.)*` + escaped + `\b`
	case "hash":
		// Match hash (hex string)
		return `\b` + escaped + `\b`
	case "email":
		// Match email
		return `\b` + escaped + `\b`
	case "url":
		// Match URL containing the value
		return escaped
	default:
		// Match anywhere
		return escaped
	}
}

// searchInFile searches for IOC in a log file.
func searchInFile(ctx context.Context, filePath, iocValue string, regex *regexp.Regexp, threshold time.Time, maxMatches int) []IOCMatch {
	var matches []IOCMatch

	file, err := os.Open(filePath)
	if err != nil {
		return matches
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return matches
		default:
		}

		lineNum++
		line := scanner.Text()

		// Check if line contains the IOC
		var found bool
		if regex != nil {
			found = regex.MatchString(line)
		} else {
			found = strings.Contains(line, iocValue)
		}

		if found {
			// Truncate long lines
			displayLine := line
			if len(displayLine) > 500 {
				displayLine = displayLine[:500] + "..."
			}

			matches = append(matches, IOCMatch{
				Source:  filepath.Base(filePath),
				Line:    displayLine,
				LineNum: lineNum,
			})

			if len(matches) >= maxMatches {
				break
			}
		}
	}

	return matches
}

// searchJournald searches for IOC in systemd journal.
func searchJournald(ctx context.Context, iocValue, timeRange string, maxMatches int) []IOCMatch {
	var matches []IOCMatch

	// Check if journalctl is available
	_, err := exec.LookPath("journalctl")
	if err != nil {
		return matches
	}

	// Convert time range to journalctl format
	since := ""
	switch timeRange {
	case "1h":
		since = "1 hour ago"
	case "6h":
		since = "6 hours ago"
	case "12h":
		since = "12 hours ago"
	case "24h":
		since = "24 hours ago"
	case "7d":
		since = "7 days ago"
	case "30d":
		since = "30 days ago"
	default:
		since = "24 hours ago"
	}

	// Run journalctl with grep
	cmd := exec.CommandContext(ctx, "journalctl", "--since", since, "--no-pager", "-o", "short")
	output, err := cmd.Output()
	if err != nil {
		return matches
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, iocValue) {
			displayLine := line
			if len(displayLine) > 500 {
				displayLine = displayLine[:500] + "..."
			}

			matches = append(matches, IOCMatch{
				Source: "journald",
				Line:   displayLine,
			})

			if len(matches) >= maxMatches {
				break
			}
		}
	}

	return matches
}
