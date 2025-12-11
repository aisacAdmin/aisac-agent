package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/pkg/types"
)

// CheckIPReputationAction checks IP reputation against threat intelligence services.
type CheckIPReputationAction struct {
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewCheckIPReputationAction creates a new CheckIPReputationAction.
func NewCheckIPReputationAction(logger zerolog.Logger) *CheckIPReputationAction {
	return &CheckIPReputationAction{
		logger: logger.With().Str("action", "check_ip_reputation").Logger(),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the action name.
func (a *CheckIPReputationAction) Name() types.ActionType {
	return types.ActionCheckIPReputation
}

// Validate validates the parameters.
func (a *CheckIPReputationAction) Validate(params map[string]interface{}) error {
	ipStr, ok := params["ip_address"].(string)
	if !ok || ipStr == "" {
		return fmt.Errorf("ip_address is required")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Don't check private IPs
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("cannot check reputation of private/local IP: %s", ipStr)
	}

	return nil
}

// IPReputationResult represents the reputation check result from a single source.
type IPReputationResult struct {
	Source          string  `json:"source"`
	IsMalicious     bool    `json:"is_malicious"`
	AbuseScore      float64 `json:"abuse_score,omitempty"`
	TotalReports    int     `json:"total_reports,omitempty"`
	Country         string  `json:"country,omitempty"`
	ISP             string  `json:"isp,omitempty"`
	Domain          string  `json:"domain,omitempty"`
	Categories      []string `json:"categories,omitempty"`
	LastReportedAt  string  `json:"last_reported_at,omitempty"`
	Error           string  `json:"error,omitempty"`
}

// Execute checks the IP reputation against various threat intelligence sources.
func (a *CheckIPReputationAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	ipStr := params["ip_address"].(string)

	// Get API keys (optional)
	var abuseIPDBKey, otxKey string
	if key, ok := params["abuseipdb_api_key"].(string); ok {
		abuseIPDBKey = key
	}
	if key, ok := params["otx_api_key"].(string); ok {
		otxKey = key
	}

	a.logger.Info().
		Str("ip_address", ipStr).
		Msg("Checking IP reputation")

	var results []IPReputationResult

	// Query AbuseIPDB if API key provided
	if abuseIPDBKey != "" {
		result := a.queryAbuseIPDB(ctx, ipStr, abuseIPDBKey)
		results = append(results, result)
	}

	// Query AlienVault OTX
	if otxKey != "" {
		result := a.queryOTXIP(ctx, ipStr, otxKey)
		results = append(results, result)
	}

	// Query ip-api.com for geolocation (free, no API key)
	geoResult := a.queryIPAPI(ctx, ipStr)
	results = append(results, geoResult)

	// Determine overall reputation
	isMalicious := false
	maxAbuseScore := 0.0
	for _, result := range results {
		if result.IsMalicious {
			isMalicious = true
		}
		if result.AbuseScore > maxAbuseScore {
			maxAbuseScore = result.AbuseScore
		}
	}

	// Determine risk level based on abuse score
	riskLevel := "low"
	if maxAbuseScore > 75 {
		riskLevel = "critical"
	} else if maxAbuseScore > 50 {
		riskLevel = "high"
	} else if maxAbuseScore > 25 {
		riskLevel = "medium"
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("IP reputation check completed for %s", ipStr),
		Details: map[string]interface{}{
			"ip_address":      ipStr,
			"is_malicious":    isMalicious,
			"risk_level":      riskLevel,
			"max_abuse_score": maxAbuseScore,
			"results":         results,
			"checked_at":      time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// queryAbuseIPDB queries AbuseIPDB for IP reputation.
func (a *CheckIPReputationAction) queryAbuseIPDB(ctx context.Context, ip, apiKey string) IPReputationResult {
	result := IPReputationResult{Source: "AbuseIPDB"}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose=true", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
		return result
	}

	var abuseResponse struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			IsPublic             bool   `json:"isPublic"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
			Reports              []struct {
				Categories []int `json:"categories"`
			} `json:"reports"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&abuseResponse); err != nil {
		result.Error = err.Error()
		return result
	}

	data := abuseResponse.Data
	result.AbuseScore = float64(data.AbuseConfidenceScore)
	result.IsMalicious = data.AbuseConfidenceScore > 50
	result.TotalReports = data.TotalReports
	result.Country = data.CountryCode
	result.ISP = data.ISP
	result.Domain = data.Domain
	result.LastReportedAt = data.LastReportedAt

	// Map category IDs to names
	categoryMap := map[int]string{
		3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
		6: "Ping of Death", 7: "Phishing", 9: "Open Proxy",
		10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
		15: "Hacking", 18: "Brute-Force", 19: "Bad Web Bot",
		20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
		23: "IoT Targeted",
	}

	categorySet := make(map[string]bool)
	for _, report := range data.Reports {
		for _, catID := range report.Categories {
			if name, ok := categoryMap[catID]; ok {
				categorySet[name] = true
			}
		}
	}

	for cat := range categorySet {
		result.Categories = append(result.Categories, cat)
	}

	return result
}

// queryOTXIP queries AlienVault OTX for IP reputation.
func (a *CheckIPReputationAction) queryOTXIP(ctx context.Context, ip, apiKey string) IPReputationResult {
	result := IPReputationResult{Source: "AlienVault OTX"}

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("X-OTX-API-KEY", apiKey)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		result.IsMalicious = false
		return result
	}

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("API returned status %d", resp.StatusCode)
		return result
	}

	var otxResponse struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
		CountryCode string `json:"country_code"`
		ASN         string `json:"asn"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&otxResponse); err != nil {
		result.Error = err.Error()
		return result
	}

	result.TotalReports = otxResponse.PulseInfo.Count
	result.IsMalicious = otxResponse.PulseInfo.Count > 0
	result.Country = otxResponse.CountryCode
	result.ISP = otxResponse.ASN

	if result.IsMalicious {
		result.AbuseScore = float64(otxResponse.PulseInfo.Count * 10)
		if result.AbuseScore > 100 {
			result.AbuseScore = 100
		}
	}

	// Extract categories from pulse tags
	categorySet := make(map[string]bool)
	for _, pulse := range otxResponse.PulseInfo.Pulses {
		for _, tag := range pulse.Tags {
			categorySet[tag] = true
		}
	}
	for cat := range categorySet {
		result.Categories = append(result.Categories, cat)
	}

	return result
}

// queryIPAPI queries ip-api.com for geolocation data.
func (a *CheckIPReputationAction) queryIPAPI(ctx context.Context, ip string) IPReputationResult {
	result := IPReputationResult{Source: "ip-api.com (Geolocation)"}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,isp,org,as,proxy,hosting", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	var ipAPIResponse struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ipAPIResponse); err != nil {
		result.Error = err.Error()
		return result
	}

	if ipAPIResponse.Status != "success" {
		result.Error = ipAPIResponse.Message
		return result
	}

	result.Country = ipAPIResponse.CountryCode
	result.ISP = ipAPIResponse.ISP
	if ipAPIResponse.Org != "" {
		result.Domain = ipAPIResponse.Org
	}

	// Flag as suspicious if it's a proxy or hosting provider
	if ipAPIResponse.Proxy {
		result.Categories = append(result.Categories, "Proxy/VPN")
		result.AbuseScore = 25
	}
	if ipAPIResponse.Hosting {
		result.Categories = append(result.Categories, "Hosting Provider")
	}

	return result
}
