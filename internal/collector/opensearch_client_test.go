package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestNewOpenSearchClientValidation(t *testing.T) {
	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)

	tests := []struct {
		name    string
		cfg     *APISourceConfig
		wantErr string
	}{
		{
			name:    "missing URL",
			cfg:     &APISourceConfig{Username: "admin", Password: "secret"},
			wantErr: "AISAC_WAZUH_INDEXER_URL",
		},
		{
			name:    "missing username",
			cfg:     &APISourceConfig{URL: "https://localhost:9200", Password: "secret"},
			wantErr: "AISAC_WAZUH_INDEXER_USER",
		},
		{
			name:    "missing password",
			cfg:     &APISourceConfig{URL: "https://localhost:9200", Username: "admin"},
			wantErr: "AISAC_WAZUH_INDEXER_PASSWORD",
		},
		{
			name: "valid config",
			cfg:  &APISourceConfig{URL: "https://localhost:9200", Username: "admin", Password: "secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOpenSearchClient(tt.cfg, logger)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOpenSearchClientAuthenticate(t *testing.T) {
	t.Run("successful auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"wazuh-indexer","cluster_name":"wazuh-cluster"}`))
		}))
		defer server.Close()

		logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)
		client, err := NewOpenSearchClient(&APISourceConfig{
			URL: server.URL, Username: "admin", Password: "secret",
		}, logger)
		if err != nil {
			t.Fatal(err)
		}

		if err := client.Authenticate(context.Background()); err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)
		client, _ := NewOpenSearchClient(&APISourceConfig{
			URL: server.URL, Username: "admin", Password: "wrong",
		}, logger)

		err := client.Authenticate(context.Background())
		if err == nil {
			t.Fatal("expected error for invalid credentials")
		}
		if !strings.Contains(err.Error(), "invalid credentials") {
			t.Errorf("error = %q, want to contain 'invalid credentials'", err.Error())
		}
	})
}

func TestOpenSearchClientFetchWazuhAlerts(t *testing.T) {
	alertSource := map[string]interface{}{
		"timestamp": "2026-03-11T10:00:00.000+0000",
		"rule":      map[string]interface{}{"id": "5501", "level": 5, "description": "Test alert"},
		"agent":     map[string]interface{}{"id": "001", "name": "test-agent"},
	}
	alertJSON, _ := json.Marshal(alertSource)

	var receivedQuery map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "wazuh-alerts-") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Capture the query for verification
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		receivedQuery = body

		resp := map[string]interface{}{
			"hits": map[string]interface{}{
				"total": map[string]interface{}{"value": 1},
				"hits": []interface{}{
					map[string]interface{}{"_source": json.RawMessage(alertJSON)},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)
	client, _ := NewOpenSearchClient(&APISourceConfig{
		URL: server.URL, Username: "admin", Password: "secret",
	}, logger)

	since := time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)
	resp, err := client.FetchWazuhAlerts(context.Background(), since, 100, 0)
	if err != nil {
		t.Fatalf("FetchWazuhAlerts() error = %v", err)
	}

	if resp.Data.TotalAffectedItems != 1 {
		t.Errorf("TotalAffectedItems = %d, want 1", resp.Data.TotalAffectedItems)
	}
	if len(resp.Data.AffectedItems) != 1 {
		t.Fatalf("AffectedItems count = %d, want 1", len(resp.Data.AffectedItems))
	}

	// Verify the query includes timestamp filter
	if receivedQuery != nil {
		queryMap, ok := receivedQuery["query"].(map[string]interface{})
		if !ok {
			t.Fatal("query field missing or invalid")
		}
		boolMap, ok := queryMap["bool"].(map[string]interface{})
		if !ok {
			t.Fatal("bool query missing")
		}
		mustClauses, ok := boolMap["must"].([]interface{})
		if !ok || len(mustClauses) == 0 {
			t.Fatal("must clauses missing or empty")
		}
	}

	// Verify sort is ascending by timestamp
	sortArr, ok := receivedQuery["sort"].([]interface{})
	if !ok || len(sortArr) == 0 {
		t.Fatal("sort missing")
	}

	// Verify pagination
	size, ok := receivedQuery["size"].(float64)
	if !ok || int(size) != 100 {
		t.Errorf("size = %v, want 100", receivedQuery["size"])
	}
	from, ok := receivedQuery["from"].(float64)
	if !ok || int(from) != 0 {
		t.Errorf("from = %v, want 0", receivedQuery["from"])
	}
}

func TestOpenSearchClientFetchWazuhAlertsWithMinRuleLevel(t *testing.T) {
	var receivedQuery map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedQuery = body

		resp := map[string]interface{}{
			"hits": map[string]interface{}{
				"total": map[string]interface{}{"value": 0},
				"hits":  []interface{}{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)
	client, _ := NewOpenSearchClient(&APISourceConfig{
		URL: server.URL, Username: "admin", Password: "secret",
		MinRuleLevel: 5,
	}, logger)

	since := time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)
	_, err := client.FetchWazuhAlerts(context.Background(), since, 100, 0)
	if err != nil {
		t.Fatalf("FetchWazuhAlerts() error = %v", err)
	}

	// Verify query includes both timestamp and rule.level filters
	queryMap := receivedQuery["query"].(map[string]interface{})
	boolMap := queryMap["bool"].(map[string]interface{})
	mustClauses := boolMap["must"].([]interface{})

	if len(mustClauses) < 2 {
		t.Fatalf("expected at least 2 must clauses (timestamp + rule.level), got %d", len(mustClauses))
	}

	// Find the rule.level clause
	foundRuleLevel := false
	for _, clause := range mustClauses {
		clauseMap := clause.(map[string]interface{})
		if rangeMap, ok := clauseMap["range"].(map[string]interface{}); ok {
			if _, ok := rangeMap["rule.level"]; ok {
				foundRuleLevel = true
			}
		}
	}
	if !foundRuleLevel {
		t.Error("expected rule.level range filter in query")
	}
}

func TestOpenSearchClientFetchWazuhAlertsPagination(t *testing.T) {
	var receivedFrom float64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedFrom = body["from"].(float64)

		resp := map[string]interface{}{
			"hits": map[string]interface{}{
				"total": map[string]interface{}{"value": 0},
				"hits":  []interface{}{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)
	client, _ := NewOpenSearchClient(&APISourceConfig{
		URL: server.URL, Username: "admin", Password: "secret",
	}, logger)

	// Request with offset 500
	_, err := client.FetchWazuhAlerts(context.Background(), time.Time{}, 100, 500)
	if err != nil {
		t.Fatalf("FetchWazuhAlerts() error = %v", err)
	}

	if int(receivedFrom) != 500 {
		t.Errorf("from = %v, want 500", receivedFrom)
	}
}

func TestOpenSearchClientMatchAllQuery(t *testing.T) {
	var receivedQuery map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedQuery = body

		resp := map[string]interface{}{
			"hits": map[string]interface{}{
				"total": map[string]interface{}{"value": 0},
				"hits":  []interface{}{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)
	client, _ := NewOpenSearchClient(&APISourceConfig{
		URL: server.URL, Username: "admin", Password: "secret",
	}, logger)

	// Zero time + no min rule level → match_all
	_, err := client.FetchWazuhAlerts(context.Background(), time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("FetchWazuhAlerts() error = %v", err)
	}

	queryMap := receivedQuery["query"].(map[string]interface{})
	if _, ok := queryMap["match_all"]; !ok {
		t.Errorf("expected match_all query when no filters, got: %v", queryMap)
	}
}
