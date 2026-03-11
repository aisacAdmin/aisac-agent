package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestLogger() zerolog.Logger {
	return zerolog.New(zerolog.NewTestWriter(nil)).Level(zerolog.Disabled)
}

func TestWazuhClientAuthenticate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/security/user/authenticate" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   401,
				"message": "Invalid credentials",
			})
			return
		}

		_ = json.NewEncoder(w).Encode(WazuhAuthResponse{
			Data: struct {
				Token string `json:"token"`
			}{Token: "test-jwt-token"},
		})
	}))
	defer server.Close()

	cfg := &APISourceConfig{
		URL:           server.URL,
		Username:      "testuser",
		Password:      "testpass",
		SkipTLSVerify: true,
	}

	client, err := NewWazuhClient(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("NewWazuhClient() error = %v", err)
	}

	ctx := context.Background()
	if err := client.Authenticate(ctx); err != nil {
		t.Errorf("Authenticate() error = %v", err)
	}

	if client.token != "test-jwt-token" {
		t.Errorf("token = %q, want %q", client.token, "test-jwt-token")
	}
}

func TestWazuhClientAuthenticateInvalidCreds(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   401,
			"message": "Invalid credentials",
		})
	}))
	defer server.Close()

	cfg := &APISourceConfig{
		URL:           server.URL,
		Username:      "wrong",
		Password:      "wrong",
		SkipTLSVerify: true,
	}

	client, err := NewWazuhClient(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("NewWazuhClient() error = %v", err)
	}

	err = client.Authenticate(context.Background())
	if err == nil {
		t.Error("Authenticate() should fail with invalid credentials")
	}
}

func TestWazuhClientFetchAlerts(t *testing.T) {
	alertJSON := `{"timestamp":"2026-03-11T10:00:00.000+0000","rule":{"id":"5501","level":5,"description":"Test alert"},"agent":{"id":"001","name":"wazuh-test","ip":"10.0.0.1"}}`

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/security/user/authenticate":
			_ = json.NewEncoder(w).Encode(WazuhAuthResponse{
				Data: struct {
					Token string `json:"token"`
				}{Token: "test-jwt-token"},
			})
		case "/alerts":
			// Verify auth header
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-jwt-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Verify query params
			q := r.URL.Query()
			if q.Get("sort") != "+timestamp" {
				t.Errorf("sort = %q, want +timestamp", q.Get("sort"))
			}

			resp := WazuhAlertsResponse{}
			resp.Data.AffectedItems = []json.RawMessage{json.RawMessage(alertJSON)}
			resp.Data.TotalAffectedItems = 1
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &APISourceConfig{
		URL:           server.URL,
		Username:      "testuser",
		Password:      "testpass",
		SkipTLSVerify: true,
	}

	client, err := NewWazuhClient(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("NewWazuhClient() error = %v", err)
	}

	ctx := context.Background()
	since := time.Date(2026, 3, 11, 0, 0, 0, 0, time.UTC)
	resp, err := client.FetchAlerts(ctx, since, 500, 0)
	if err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}

	if len(resp.Data.AffectedItems) != 1 {
		t.Errorf("got %d alerts, want 1", len(resp.Data.AffectedItems))
	}

	if resp.Data.TotalAffectedItems != 1 {
		t.Errorf("total = %d, want 1", resp.Data.TotalAffectedItems)
	}
}

func TestWazuhClientFetchAlertsWithMinRuleLevel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/security/user/authenticate":
			_ = json.NewEncoder(w).Encode(WazuhAuthResponse{
				Data: struct {
					Token string `json:"token"`
				}{Token: "test-jwt-token"},
			})
		case "/alerts":
			q := r.URL.Query().Get("q")
			if !strings.Contains(q, "rule.level>=5") {
				t.Errorf("query filter = %q, should contain rule.level>=5", q)
			}

			resp := WazuhAlertsResponse{}
			resp.Data.AffectedItems = []json.RawMessage{}
			resp.Data.TotalAffectedItems = 0
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &APISourceConfig{
		URL:           server.URL,
		Username:      "testuser",
		Password:      "testpass",
		SkipTLSVerify: true,
		MinRuleLevel:  5,
	}

	client, err := NewWazuhClient(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("NewWazuhClient() error = %v", err)
	}

	_, err = client.FetchAlerts(context.Background(), time.Time{}, 500, 0)
	if err != nil {
		t.Errorf("FetchAlerts() error = %v", err)
	}
}

func TestWazuhClientTokenRefresh(t *testing.T) {
	authCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/security/user/authenticate":
			authCount++
			_ = json.NewEncoder(w).Encode(WazuhAuthResponse{
				Data: struct {
					Token string `json:"token"`
				}{Token: "token-v" + string(rune('0'+authCount))},
			})
		case "/alerts":
			resp := WazuhAlertsResponse{}
			resp.Data.AffectedItems = []json.RawMessage{}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	cfg := &APISourceConfig{
		URL:           server.URL,
		Username:      "testuser",
		Password:      "testpass",
		SkipTLSVerify: true,
	}

	client, err := NewWazuhClient(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("NewWazuhClient() error = %v", err)
	}

	ctx := context.Background()

	// First call should authenticate
	_, err = client.FetchAlerts(ctx, time.Time{}, 500, 0)
	if err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}
	if authCount != 1 {
		t.Errorf("auth count = %d, want 1", authCount)
	}

	// Second call should reuse token (not expired)
	_, err = client.FetchAlerts(ctx, time.Time{}, 500, 0)
	if err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}
	if authCount != 1 {
		t.Errorf("auth count = %d, want 1 (should reuse token)", authCount)
	}

	// Simulate token near expiry
	client.mu.Lock()
	client.tokenExpAt = time.Now().Add(30 * time.Second) // Less than 60s margin
	client.mu.Unlock()

	// Third call should trigger re-auth
	_, err = client.FetchAlerts(ctx, time.Time{}, 500, 0)
	if err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}
	if authCount != 2 {
		t.Errorf("auth count = %d, want 2 (should refresh expired token)", authCount)
	}
}

func TestNewWazuhClientValidation(t *testing.T) {
	logger := newTestLogger()

	_, err := NewWazuhClient(&APISourceConfig{Username: "u", Password: "p"}, logger)
	if err == nil || !strings.Contains(err.Error(), "URL is required") {
		t.Errorf("expected URL required error, got: %v", err)
	}

	_, err = NewWazuhClient(&APISourceConfig{URL: "https://x", Password: "p"}, logger)
	if err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Errorf("expected username required error, got: %v", err)
	}

	_, err = NewWazuhClient(&APISourceConfig{URL: "https://x", Username: "u"}, logger)
	if err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Errorf("expected password required error, got: %v", err)
	}
}
