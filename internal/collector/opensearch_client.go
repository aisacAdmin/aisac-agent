package collector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const (
	// wazuhAlertIndex is the OpenSearch index pattern for Wazuh alerts.
	wazuhAlertIndex = "wazuh-alerts-*"
	// opensearchRequestTimeout is the HTTP timeout for individual requests.
	opensearchRequestTimeout = 30 * time.Second
	// opensearchMaxResponseSize is the maximum response body size (10MB).
	opensearchMaxResponseSize = 10 * 1024 * 1024
)

// OpenSearchClient queries the Wazuh Indexer (OpenSearch) for alerts.
// It implements the APIClient interface used by Poller.
type OpenSearchClient struct {
	baseURL      string
	username     string
	password     string
	minRuleLevel int
	httpClient   *http.Client
	logger       zerolog.Logger
}

// NewOpenSearchClient creates a new OpenSearch client for Wazuh alert collection.
func NewOpenSearchClient(cfg *APISourceConfig, logger zerolog.Logger) (*OpenSearchClient, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("OpenSearch URL is required (set AISAC_WAZUH_INDEXER_URL)")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("OpenSearch username is required (set AISAC_WAZUH_INDEXER_USER)")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("OpenSearch password is required (set AISAC_WAZUH_INDEXER_PASSWORD)")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
		MaxIdleConns:        5,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	l := logger.With().Str("component", "opensearch_client").Logger()

	return &OpenSearchClient{
		baseURL:      strings.TrimRight(cfg.URL, "/"),
		username:     cfg.Username,
		password:     cfg.Password,
		minRuleLevel: cfg.MinRuleLevel,
		httpClient: &http.Client{
			Timeout:   opensearchRequestTimeout,
			Transport: transport,
		},
		logger: l,
	}, nil
}

// Authenticate verifies connectivity to the OpenSearch cluster.
func (c *OpenSearchClient) Authenticate(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/", nil)
	if err != nil {
		return fmt.Errorf("creating health check request: %w", err)
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("OpenSearch health check failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("OpenSearch authentication failed: invalid credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OpenSearch health check returned status %d", resp.StatusCode)
	}

	c.logger.Info().Str("url", c.baseURL).Msg("OpenSearch authentication successful")
	return nil
}

// opensearchSearchRequest is the query body sent to OpenSearch _search endpoint.
type opensearchSearchRequest struct {
	Query json.RawMessage `json:"query"`
	Sort  []interface{}   `json:"sort"`
	Size  int             `json:"size"`
	From  int             `json:"from"`
}

// opensearchResponse is the response from OpenSearch _search endpoint.
type opensearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// FetchWazuhAlerts queries OpenSearch for Wazuh alerts newer than 'since'.
func (c *OpenSearchClient) FetchWazuhAlerts(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
	if limit <= 0 || limit > defaultMaxPageSize {
		limit = defaultMaxPageSize
	}

	query := c.buildWazuhAlertQuery(since)

	searchReq := opensearchSearchRequest{
		Query: query,
		Sort:  []interface{}{map[string]string{"timestamp": "asc"}},
		Size:  limit,
		From:  offset,
	}

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling search request: %w", err)
	}

	searchURL := fmt.Sprintf("%s/%s/_search", c.baseURL, wazuhAlertIndex)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, searchURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating search request: %w", err)
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	if DebugCollector {
		c.logger.Debug().
			Str("url", searchURL).
			Int("limit", limit).
			Int("offset", offset).
			Time("since", since).
			Msg("Fetching Wazuh alerts from OpenSearch")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OpenSearch search request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, opensearchMaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading search response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenSearch returned status %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var osResp opensearchResponse
	if err := json.Unmarshal(respBody, &osResp); err != nil {
		return nil, fmt.Errorf("parsing search response: %w", err)
	}

	// Transform OpenSearch response into WazuhAlertsResponse
	alerts := make([]json.RawMessage, 0, len(osResp.Hits.Hits))
	for _, hit := range osResp.Hits.Hits {
		alerts = append(alerts, hit.Source)
	}

	result := &WazuhAlertsResponse{}
	result.Data.AffectedItems = alerts
	result.Data.TotalAffectedItems = osResp.Hits.Total.Value

	if DebugCollector {
		c.logger.Debug().
			Int("hits", len(alerts)).
			Int("total", osResp.Hits.Total.Value).
			Msg("Wazuh alerts fetched from OpenSearch")
	}

	return result, nil
}

// buildWazuhAlertQuery constructs the OpenSearch Query DSL for Wazuh alert retrieval.
func (c *OpenSearchClient) buildWazuhAlertQuery(since time.Time) json.RawMessage {
	var mustClauses []interface{}

	// Timestamp filter
	if !since.IsZero() {
		mustClauses = append(mustClauses, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]string{
					"gt": since.UTC().Format("2006-01-02T15:04:05Z"),
				},
			},
		})
	}

	// Min rule level filter
	if c.minRuleLevel > 0 {
		mustClauses = append(mustClauses, map[string]interface{}{
			"range": map[string]interface{}{
				"rule.level": map[string]int{
					"gte": c.minRuleLevel,
				},
			},
		})
	}

	var query interface{}
	if len(mustClauses) > 0 {
		query = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		}
	} else {
		query = map[string]interface{}{
			"match_all": map[string]interface{}{},
		}
	}

	raw, _ := json.Marshal(query)
	return raw
}

// Close closes the OpenSearch client and releases resources.
func (c *OpenSearchClient) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}
