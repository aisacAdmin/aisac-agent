package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// mockAPIClient is a test mock for the APIClient interface.
type mockAPIClient struct {
	authenticateFn func(ctx context.Context) error
	fetchAlertsFn  func(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error)
	authCalls      int
	fetchCalls     int
}

func (m *mockAPIClient) Authenticate(ctx context.Context) error {
	m.authCalls++
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx)
	}
	return nil
}

func (m *mockAPIClient) FetchAlerts(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
	m.fetchCalls++
	if m.fetchAlertsFn != nil {
		return m.fetchAlertsFn(ctx, since, limit, offset)
	}
	return &WazuhAlertsResponse{}, nil
}

func TestPollerProcessesAlerts(t *testing.T) {
	alertJSON := `{"timestamp":"2026-03-11T10:00:00.000+0000","rule":{"id":"5501","level":5,"description":"Login failure","groups":["syslog"]},"agent":{"id":"001","name":"wazuh-test"}}`

	mock := &mockAPIClient{
		fetchAlertsFn: func(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
			resp := &WazuhAlertsResponse{}
			resp.Data.AffectedItems = []json.RawMessage{json.RawMessage(alertJSON)}
			resp.Data.TotalAffectedItems = 1
			return resp, nil
		},
	}

	tmpDir := t.TempDir()
	sincedbPath := filepath.Join(tmpDir, "sincedb")
	sincedb, err := NewSinceDB(sincedbPath)
	if err != nil {
		t.Fatalf("NewSinceDB() error = %v", err)
	}

	eventCh := make(chan *LogEvent, 100)
	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)

	source := SourceConfig{
		Name:   "wazuh_alerts",
		Type:   "api",
		Parser: "wazuh_alerts",
		Tags:   []string{"wazuh", "test"},
		API: &APISourceConfig{
			PollInterval: 100 * time.Millisecond,
			PageSize:     500,
		},
	}

	parser, err := GetParser("wazuh_alerts")
	if err != nil {
		t.Fatalf("GetParser() error = %v", err)
	}

	poller, err := NewPoller(source, parser, sincedb, eventCh, logger, "test-tenant", mock)
	if err != nil {
		t.Fatalf("NewPoller() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() { _ = poller.Run(ctx) }()

	// Wait for at least one event
	select {
	case event := <-eventCh:
		if event.Source != "wazuh_alerts" {
			t.Errorf("event.Source = %q, want %q", event.Source, "wazuh_alerts")
		}
		if event.TenantID != "test-tenant" {
			t.Errorf("event.TenantID = %q, want %q", event.TenantID, "test-tenant")
		}
		// Check tags include source tags
		foundWazuh := false
		foundTest := false
		for _, tag := range event.Tags {
			if tag == "wazuh" {
				foundWazuh = true
			}
			if tag == "test" {
				foundTest = true
			}
		}
		if !foundWazuh || !foundTest {
			t.Errorf("event.Tags = %v, should contain 'wazuh' and 'test'", event.Tags)
		}
		if event.Raw == "" {
			t.Error("event.Raw should not be empty")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}

	// Verify state was saved
	<-ctx.Done()
	ts := sincedb.GetTimestamp("api:wazuh_alerts")
	if ts.IsZero() {
		t.Error("sincedb timestamp should be set after processing alerts")
	}
}

func TestPollerPagination(t *testing.T) {
	alert1 := `{"timestamp":"2026-03-11T10:00:00.000+0000","rule":{"id":"5501","level":5,"description":"Alert 1"},"agent":{"id":"001","name":"test"}}`
	alert2 := `{"timestamp":"2026-03-11T10:00:01.000+0000","rule":{"id":"5502","level":6,"description":"Alert 2"},"agent":{"id":"001","name":"test"}}`

	callCount := 0
	mock := &mockAPIClient{
		fetchAlertsFn: func(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
			callCount++
			resp := &WazuhAlertsResponse{}
			resp.Data.TotalAffectedItems = 2

			if offset == 0 {
				resp.Data.AffectedItems = []json.RawMessage{json.RawMessage(alert1)}
			} else {
				resp.Data.AffectedItems = []json.RawMessage{json.RawMessage(alert2)}
			}
			return resp, nil
		},
	}

	tmpDir := t.TempDir()
	sincedb, _ := NewSinceDB(filepath.Join(tmpDir, "sincedb"))
	eventCh := make(chan *LogEvent, 100)
	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)

	source := SourceConfig{
		Name:   "wazuh_alerts",
		Type:   "api",
		Parser: "wazuh_alerts",
		API: &APISourceConfig{
			PollInterval: 100 * time.Millisecond,
			PageSize:     1, // Force pagination
		},
	}

	parser, _ := GetParser("wazuh_alerts")
	poller, err := NewPoller(source, parser, sincedb, eventCh, logger, "tenant", mock)
	if err != nil {
		t.Fatalf("NewPoller() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() { _ = poller.Run(ctx) }()

	// Collect events
	var events []*LogEvent
	timeout := time.After(400 * time.Millisecond)
	for {
		select {
		case e := <-eventCh:
			events = append(events, e)
			if len(events) >= 2 {
				goto done
			}
		case <-timeout:
			goto done
		}
	}
done:

	if len(events) < 2 {
		t.Errorf("got %d events, want at least 2 (pagination should fetch both pages)", len(events))
	}
}

func TestPollerErrorDoesNotAdvanceCursor(t *testing.T) {
	callCount := 0
	mock := &mockAPIClient{
		fetchAlertsFn: func(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
			callCount++
			return nil, context.DeadlineExceeded
		},
	}

	tmpDir := t.TempDir()
	sincedb, _ := NewSinceDB(filepath.Join(tmpDir, "sincedb"))

	// Set an initial timestamp
	initialTS := time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC)
	sincedb.SetTimestamp("api:wazuh_alerts", initialTS)

	eventCh := make(chan *LogEvent, 100)
	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)

	source := SourceConfig{
		Name:   "wazuh_alerts",
		Type:   "api",
		Parser: "wazuh_alerts",
		API: &APISourceConfig{
			PollInterval: 100 * time.Millisecond,
			PageSize:     500,
		},
	}

	parser, _ := GetParser("wazuh_alerts")
	poller, _ := NewPoller(source, parser, sincedb, eventCh, logger, "tenant", mock)

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	go func() { _ = poller.Run(ctx) }()
	<-ctx.Done()

	// Cursor should not have advanced
	ts := sincedb.GetTimestamp("api:wazuh_alerts")
	if !ts.Equal(initialTS) {
		t.Errorf("timestamp = %v, want %v (cursor should not advance on error)", ts, initialTS)
	}
}

func TestPollerResumesFromSavedTimestamp(t *testing.T) {
	savedTS := time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)
	var receivedSince time.Time

	mock := &mockAPIClient{
		fetchAlertsFn: func(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error) {
			receivedSince = since
			resp := &WazuhAlertsResponse{}
			resp.Data.AffectedItems = []json.RawMessage{}
			resp.Data.TotalAffectedItems = 0
			return resp, nil
		},
	}

	tmpDir := t.TempDir()
	sincedb, _ := NewSinceDB(filepath.Join(tmpDir, "sincedb"))
	sincedb.SetTimestamp("api:wazuh_alerts", savedTS)

	eventCh := make(chan *LogEvent, 100)
	logger := zerolog.New(os.Stderr).Level(zerolog.Disabled)

	source := SourceConfig{
		Name:   "wazuh_alerts",
		Type:   "api",
		Parser: "wazuh_alerts",
		API: &APISourceConfig{
			PollInterval: 1 * time.Second,
			PageSize:     500,
		},
	}

	parser, _ := GetParser("wazuh_alerts")
	poller, _ := NewPoller(source, parser, sincedb, eventCh, logger, "tenant", mock)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go func() { _ = poller.Run(ctx) }()
	<-ctx.Done()

	if !receivedSince.Equal(savedTS) {
		t.Errorf("FetchAlerts received since = %v, want %v (should resume from saved timestamp)", receivedSince, savedTS)
	}
}
