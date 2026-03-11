package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	// wazuhTokenTTL is the default Wazuh JWT token lifetime.
	wazuhTokenTTL = 900 * time.Second
	// wazuhTokenRefreshMargin is how early to refresh the token before expiry.
	wazuhTokenRefreshMargin = 60 * time.Second
	// wazuhMaxPageSize is the maximum page size allowed by Wazuh API.
	wazuhMaxPageSize = 500
	// wazuhRequestTimeout is the HTTP timeout for individual API requests.
	wazuhRequestTimeout = 30 * time.Second
)

// WazuhAlertsResponse represents the Wazuh API /alerts response.
type WazuhAlertsResponse struct {
	Data struct {
		AffectedItems      []json.RawMessage `json:"affected_items"`
		TotalAffectedItems int               `json:"total_affected_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// WazuhAuthResponse represents the Wazuh API authentication response.
type WazuhAuthResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// WazuhClient communicates with the Wazuh Manager API v4.
type WazuhClient struct {
	baseURL       string
	username      string
	password      string
	minRuleLevel  int
	httpClient    *http.Client
	logger        zerolog.Logger

	mu         sync.Mutex
	token      string
	tokenExpAt time.Time
}

// NewWazuhClient creates a new Wazuh API client.
func NewWazuhClient(cfg *APISourceConfig, logger zerolog.Logger) (*WazuhClient, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("wazuh API URL is required (set AISAC_WAZUH_API_URL)")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("wazuh API username is required (set AISAC_WAZUH_API_USER)")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("wazuh API password is required (set AISAC_WAZUH_API_PASSWORD)")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
		MaxIdleConns:        5,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	l := logger.With().Str("component", "wazuh_client").Logger()

	return &WazuhClient{
		baseURL:      cfg.URL,
		username:     cfg.Username,
		password:     cfg.Password,
		minRuleLevel: cfg.MinRuleLevel,
		httpClient: &http.Client{
			Timeout:   wazuhRequestTimeout,
			Transport: transport,
		},
		logger: l,
	}, nil
}

// Authenticate obtains a JWT token from the Wazuh API.
func (c *WazuhClient) Authenticate(ctx context.Context) error {
	authURL := c.baseURL + "/security/user/authenticate"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, nil)
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("wazuh auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return fmt.Errorf("reading auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wazuh auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp WazuhAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("parsing auth response: %w", err)
	}

	if authResp.Error != 0 {
		return fmt.Errorf("wazuh auth error %d: %s", authResp.Error, authResp.Message)
	}

	if authResp.Data.Token == "" {
		return fmt.Errorf("wazuh auth returned empty token")
	}

	c.mu.Lock()
	c.token = authResp.Data.Token
	c.tokenExpAt = time.Now().Add(wazuhTokenTTL)
	c.mu.Unlock()

	c.logger.Info().Msg("Wazuh API authentication successful")
	return nil
}

// ensureToken checks if the token is still valid and refreshes if needed.
func (c *WazuhClient) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	needsRefresh := c.token == "" || time.Now().After(c.tokenExpAt.Add(-wazuhTokenRefreshMargin))
	c.mu.Unlock()

	if needsRefresh {
		return c.Authenticate(ctx)
	}
	return nil
}

// FetchAlerts retrieves alerts from the Wazuh API with timestamp filtering and pagination.
func (c *WazuhClient) FetchAlerts(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("ensuring auth token: %w", err)
	}

	if limit <= 0 || limit > wazuhMaxPageSize {
		limit = wazuhMaxPageSize
	}

	// Build query parameters
	alertsURL, err := url.Parse(c.baseURL + "/alerts")
	if err != nil {
		return nil, fmt.Errorf("parsing alerts URL: %w", err)
	}

	q := alertsURL.Query()
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("offset", fmt.Sprintf("%d", offset))
	q.Set("sort", "+timestamp")

	// Build filter query
	var filters []string
	if !since.IsZero() {
		filters = append(filters, fmt.Sprintf("timestamp>%s", since.UTC().Format("2006-01-02T15:04:05Z")))
	}
	if c.minRuleLevel > 0 {
		filters = append(filters, fmt.Sprintf("rule.level>=%d", c.minRuleLevel))
	}
	if len(filters) > 0 {
		qStr := filters[0]
		for i := 1; i < len(filters); i++ {
			qStr += ";" + filters[i]
		}
		q.Set("q", qStr)
	}

	alertsURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alertsURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating alerts request: %w", err)
	}

	c.mu.Lock()
	token := c.token
	c.mu.Unlock()

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	if DebugCollector {
		c.logger.Debug().
			Str("url", alertsURL.String()).
			Int("limit", limit).
			Int("offset", offset).
			Time("since", since).
			Msg("Fetching alerts from Wazuh API")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wazuh alerts request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		return nil, fmt.Errorf("reading alerts response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Token expired, force re-auth on next call
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		return nil, fmt.Errorf("wazuh API returned 401: token expired")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wazuh API returned status %d: %s", resp.StatusCode, truncate(string(body), 500))
	}

	var alertsResp WazuhAlertsResponse
	if err := json.Unmarshal(body, &alertsResp); err != nil {
		return nil, fmt.Errorf("parsing alerts response: %w", err)
	}

	if alertsResp.Error != 0 {
		return nil, fmt.Errorf("wazuh API error %d: %s", alertsResp.Error, alertsResp.Message)
	}

	if DebugCollector {
		c.logger.Debug().
			Int("affected_items", len(alertsResp.Data.AffectedItems)).
			Int("total", alertsResp.Data.TotalAffectedItems).
			Msg("Wazuh alerts fetched")
	}

	return &alertsResp, nil
}

// Close closes the Wazuh client and releases resources.
func (c *WazuhClient) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// marshalAlertToRaw converts a json.RawMessage alert to a raw JSON string
// suitable for the existing WazuhAlertParser.
func marshalAlertToRaw(alert json.RawMessage) string {
	// Compact the JSON to produce a single-line string (same as alerts.json format)
	var buf bytes.Buffer
	if err := json.Compact(&buf, alert); err != nil {
		return string(alert)
	}
	return buf.String()
}
