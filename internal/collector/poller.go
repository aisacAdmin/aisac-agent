package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
)

const (
	// DefaultPollInterval is the default interval between API polls.
	DefaultPollInterval = 30 * time.Second
	// MaxPagesPerPoll caps the number of pages fetched in a single poll cycle.
	MaxPagesPerPoll = 10
	// defaultMaxPageSize is the default maximum page size for API sources.
	defaultMaxPageSize = 500
)

// APIClient is the interface for API-based log sources.
// This abstraction allows testing with mocks and future API sources (Suricata, Sophos).
type APIClient interface {
	// Authenticate performs initial authentication with the API.
	Authenticate(ctx context.Context) error
	// FetchWazuhAlerts retrieves Wazuh alerts newer than 'since' with pagination.
	FetchWazuhAlerts(ctx context.Context, since time.Time, limit, offset int) (*WazuhAlertsResponse, error)
}

// Poller polls an API source for log events at a configured interval.
type Poller struct {
	source   SourceConfig
	parser   Parser
	stateDB  *SinceDB
	eventCh  chan<- *LogEvent
	logger   zerolog.Logger
	tenantID string
	hostname string
	client   APIClient

	pollInterval time.Duration
	pageSize     int
	stateKey     string // SinceDB key for this poller
}

// NewPoller creates a new API poller.
func NewPoller(
	source SourceConfig,
	parser Parser,
	stateDB *SinceDB,
	eventCh chan<- *LogEvent,
	logger zerolog.Logger,
	tenantID string,
	client APIClient,
) (*Poller, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	pollInterval := DefaultPollInterval
	pageSize := defaultMaxPageSize

	if source.API != nil {
		if source.API.PollInterval > 0 {
			pollInterval = source.API.PollInterval
		}
		if source.API.PageSize > 0 {
			pageSize = source.API.PageSize
		}
	}

	return &Poller{
		source:       source,
		parser:       parser,
		stateDB:      stateDB,
		eventCh:      eventCh,
		logger:       logger.With().Str("component", "poller").Str("source", source.Name).Logger(),
		tenantID:     tenantID,
		hostname:     hostname,
		client:       client,
		pollInterval: pollInterval,
		pageSize:     pageSize,
		stateKey:     fmt.Sprintf("api:%s", source.Name),
	}, nil
}

// Run starts the poller and polls until context is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info().
		Dur("poll_interval", p.pollInterval).
		Int("page_size", p.pageSize).
		Msg("Starting API poller")

	// Initial authentication
	if err := p.client.Authenticate(ctx); err != nil {
		p.logger.Error().Err(err).Msg("Initial authentication failed, will retry on first poll")
	}

	// Load last timestamp from state
	lastTimestamp := p.stateDB.GetTimestamp(p.stateKey)
	if lastTimestamp.IsZero() {
		lastTimestamp = time.Now().UTC()
		p.logger.Info().Time("since", lastTimestamp).Msg("No previous state, starting from now")
	} else {
		p.logger.Info().Time("since", lastTimestamp).Msg("Resuming from saved timestamp")
	}

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	// Do an initial poll immediately
	if newTs, err := p.poll(ctx, lastTimestamp); err != nil {
		p.logger.Error().Err(err).Msg("Initial poll failed")
	} else {
		lastTimestamp = newTs
	}

	for {
		select {
		case <-ctx.Done():
			p.logger.Info().Msg("Poller stopped")
			return ctx.Err()
		case <-ticker.C:
			newTs, err := p.poll(ctx, lastTimestamp)
			if err != nil {
				p.logger.Error().Err(err).Msg("Poll failed, will retry next interval")
				continue
			}
			lastTimestamp = newTs
		}
	}
}

// poll fetches new alerts since lastTimestamp, processes them, and returns the updated timestamp.
func (p *Poller) poll(ctx context.Context, since time.Time) (time.Time, error) {
	latestTimestamp := since
	totalProcessed := 0

	for page := 0; page < MaxPagesPerPoll; page++ {
		offset := page * p.pageSize

		resp, err := p.client.FetchWazuhAlerts(ctx, since, p.pageSize, offset)
		if err != nil {
			if totalProcessed > 0 {
				// We already processed some pages, save progress
				p.stateDB.SetTimestamp(p.stateKey, latestTimestamp)
			}
			return latestTimestamp, fmt.Errorf("fetching alerts (offset %d): %w", offset, err)
		}

		if len(resp.Data.AffectedItems) == 0 {
			break
		}

		for _, rawAlert := range resp.Data.AffectedItems {
			alertStr := marshalAlertToRaw(rawAlert)

			event, err := p.parser.Parse(alertStr)
			if err != nil {
				p.logger.Warn().Err(err).Msg("Failed to parse alert, skipping")
				continue
			}

			// Enrich event
			event.Source = p.source.Name
			event.TenantID = p.tenantID
			if event.Host == "" {
				event.Host = p.hostname
			}
			event.Tags = append(event.Tags, p.source.Tags...)

			// Track the latest timestamp
			if event.Timestamp.After(latestTimestamp) {
				latestTimestamp = event.Timestamp
			}

			// Send to event channel
			select {
			case p.eventCh <- event:
			case <-ctx.Done():
				return latestTimestamp, ctx.Err()
			}

			totalProcessed++
		}

		// Check if there are more pages
		if offset+len(resp.Data.AffectedItems) >= resp.Data.TotalAffectedItems {
			break
		}
	}

	// Persist the latest timestamp
	if totalProcessed > 0 {
		p.stateDB.SetTimestamp(p.stateKey, latestTimestamp)

		if DebugCollector {
			p.logger.Debug().
				Int("processed", totalProcessed).
				Time("latest_timestamp", latestTimestamp).
				Msg("Poll cycle completed")
		}
	}

	return latestTimestamp, nil
}

// WazuhAlertsResponse is the canonical internal response type for alert fetching.
// API clients (OpenSearch, etc.) transform their native responses into this format.
type WazuhAlertsResponse struct {
	Data struct {
		AffectedItems      []json.RawMessage `json:"affected_items"`
		TotalAffectedItems int               `json:"total_affected_items"`
	} `json:"data"`
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

