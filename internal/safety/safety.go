// Package safety provides safety mechanisms for destructive SOAR actions.
// It handles control plane whitelisting, TTL-based auto-revert, and
// heartbeat failure recovery.
package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// ActiveAction represents an action that is currently active and may need reverting.
type ActiveAction struct {
	ID           string                 `json:"id"`
	Action       string                 `json:"action"`
	Parameters   map[string]interface{} `json:"parameters"`
	StartedAt    time.Time              `json:"started_at"`
	TTL          time.Duration          `json:"ttl"`
	ExpiresAt    time.Time              `json:"expires_at"`
	RevertAction string                 `json:"revert_action"`
}

// State contains the persisted safety state.
type State struct {
	ActiveActions []ActiveAction `json:"active_actions"`
	LastUpdated   time.Time      `json:"last_updated"`
}

// RevertFunc is a function that executes a revert action.
type RevertFunc func(ctx context.Context, action string, params map[string]interface{}) error

// Manager handles safety mechanisms for the agent.
type Manager struct {
	mu            sync.RWMutex
	activeActions map[string]*ActiveAction
	stateFile     string
	logger        zerolog.Logger
	revertFunc    RevertFunc
	stopCh        chan struct{}
	wg            sync.WaitGroup

	// Control plane whitelist
	whitelistIPs     []string
	whitelistDomains []string
	whitelistEnabled bool
}

// Config contains safety manager configuration.
type Config struct {
	StateFile                 string
	DefaultTTL                time.Duration
	ActionTTLs                map[string]time.Duration
	AutoRevertEnabled         bool
	HeartbeatFailureThreshold int
	RecoveryActions           []string
	WhitelistIPs              []string
	WhitelistDomains          []string
	WhitelistEnabled          bool
}

// NewManager creates a new safety manager.
func NewManager(cfg Config, logger zerolog.Logger, revertFunc RevertFunc) (*Manager, error) {
	m := &Manager{
		activeActions:    make(map[string]*ActiveAction),
		stateFile:        cfg.StateFile,
		logger:           logger.With().Str("component", "safety").Logger(),
		revertFunc:       revertFunc,
		stopCh:           make(chan struct{}),
		whitelistIPs:     cfg.WhitelistIPs,
		whitelistDomains: cfg.WhitelistDomains,
		whitelistEnabled: cfg.WhitelistEnabled,
	}

	// Ensure state directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0755); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

	// Load persisted state
	if err := m.loadState(); err != nil {
		m.logger.Warn().Err(err).Msg("Failed to load persisted state, starting fresh")
	}

	return m, nil
}

// Start begins the TTL monitoring goroutine.
func (m *Manager) Start(ctx context.Context) {
	m.wg.Add(1)
	go m.monitorTTLs(ctx)
	m.logger.Info().Msg("Safety manager started")
}

// Stop stops the safety manager.
func (m *Manager) Stop() {
	close(m.stopCh)
	m.wg.Wait()

	// Save state on shutdown
	if err := m.saveState(); err != nil {
		m.logger.Error().Err(err).Msg("Failed to save state on shutdown")
	}

	m.logger.Info().Msg("Safety manager stopped")
}

// RegisterAction registers an active action with TTL.
func (m *Manager) RegisterAction(id, action string, params map[string]interface{}, ttl time.Duration, revertAction string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	aa := &ActiveAction{
		ID:           id,
		Action:       action,
		Parameters:   params,
		StartedAt:    now,
		TTL:          ttl,
		ExpiresAt:    now.Add(ttl),
		RevertAction: revertAction,
	}

	m.activeActions[id] = aa

	m.logger.Info().
		Str("id", id).
		Str("action", action).
		Dur("ttl", ttl).
		Time("expires_at", aa.ExpiresAt).
		Msg("Registered action with TTL")

	// Persist state
	go func() {
		if err := m.saveState(); err != nil {
			m.logger.Error().Err(err).Msg("Failed to persist state")
		}
	}()
}

// UnregisterAction removes an action (e.g., when manually reverted).
func (m *Manager) UnregisterAction(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if aa, ok := m.activeActions[id]; ok {
		delete(m.activeActions, id)
		m.logger.Info().
			Str("id", id).
			Str("action", aa.Action).
			Msg("Unregistered action")

		// Persist state
		go func() {
			if err := m.saveState(); err != nil {
				m.logger.Error().Err(err).Msg("Failed to persist state")
			}
		}()
	}
}

// FindActionByParams finds an active action by its parameters.
func (m *Manager) FindActionByParams(action string, params map[string]interface{}) *ActiveAction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, aa := range m.activeActions {
		if aa.Action == action && paramsMatch(aa.Parameters, params) {
			return aa
		}
	}
	return nil
}

// paramsMatch checks if two parameter maps match on key fields.
func paramsMatch(a, b map[string]interface{}) bool {
	// Check common identifying parameters
	keys := []string{"ip_address", "username", "domain"}
	for _, key := range keys {
		if va, ok := a[key]; ok {
			if vb, ok := b[key]; ok {
				if va != vb {
					return false
				}
			}
		}
	}
	return true
}

// IsWhitelistedIP checks if an IP is in the control plane whitelist.
func (m *Manager) IsWhitelistedIP(ip string) bool {
	if !m.whitelistEnabled {
		return false
	}
	for _, allowed := range m.whitelistIPs {
		if allowed == ip {
			return true
		}
	}
	return false
}

// IsWhitelistedDomain checks if a domain is in the control plane whitelist.
func (m *Manager) IsWhitelistedDomain(domain string) bool {
	if !m.whitelistEnabled {
		return false
	}
	for _, allowed := range m.whitelistDomains {
		if allowed == domain {
			return true
		}
	}
	return false
}

// ValidateAction checks if an action would violate safety rules.
// Returns an error if the action should be blocked.
func (m *Manager) ValidateAction(action string, params map[string]interface{}) error {
	switch action {
	case "block_ip":
		if ip, ok := params["ip_address"].(string); ok {
			if m.IsWhitelistedIP(ip) {
				return fmt.Errorf("cannot block control plane IP: %s", ip)
			}
		}
	case "isolate_host":
		// For isolate_host, we need to ensure control plane IPs remain accessible
		// This is handled by the action implementation itself
		m.logger.Debug().Msg("Isolate host will preserve control plane access")
	}
	return nil
}

// GetActiveActions returns all active actions.
func (m *Manager) GetActiveActions() []ActiveAction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	actions := make([]ActiveAction, 0, len(m.activeActions))
	for _, aa := range m.activeActions {
		actions = append(actions, *aa)
	}
	return actions
}

// TriggerRecovery executes recovery actions (e.g., after heartbeat failure).
func (m *Manager) TriggerRecovery(ctx context.Context, actions []string) {
	m.logger.Warn().Strs("actions", actions).Msg("Triggering recovery actions")

	for _, action := range actions {
		switch action {
		case "unisolate_host":
			// Revert any active isolate_host
			m.mu.RLock()
			for _, aa := range m.activeActions {
				if aa.Action == "isolate_host" {
					m.mu.RUnlock()
					m.revertAction(ctx, aa)
					m.mu.RLock()
				}
			}
			m.mu.RUnlock()
		case "unblock_all_ips":
			// Revert all active block_ip actions
			m.mu.RLock()
			for _, aa := range m.activeActions {
				if aa.Action == "block_ip" {
					m.mu.RUnlock()
					m.revertAction(ctx, aa)
					m.mu.RLock()
				}
			}
			m.mu.RUnlock()
		}
	}
}

// monitorTTLs periodically checks for expired actions and reverts them.
func (m *Manager) monitorTTLs(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkExpiredActions(ctx)
		}
	}
}

// checkExpiredActions finds and reverts expired actions.
func (m *Manager) checkExpiredActions(ctx context.Context) {
	m.mu.RLock()
	var expired []*ActiveAction
	now := time.Now()

	for _, aa := range m.activeActions {
		if now.After(aa.ExpiresAt) {
			expired = append(expired, aa)
		}
	}
	m.mu.RUnlock()

	for _, aa := range expired {
		m.logger.Warn().
			Str("id", aa.ID).
			Str("action", aa.Action).
			Time("expired_at", aa.ExpiresAt).
			Msg("Action TTL expired, auto-reverting")

		m.revertAction(ctx, aa)
	}
}

// revertAction executes the revert action for an active action.
func (m *Manager) revertAction(ctx context.Context, aa *ActiveAction) {
	if aa.RevertAction == "" {
		m.logger.Warn().Str("action", aa.Action).Msg("No revert action defined")
		return
	}

	m.logger.Info().
		Str("id", aa.ID).
		Str("action", aa.Action).
		Str("revert_action", aa.RevertAction).
		Msg("Executing auto-revert")

	if err := m.revertFunc(ctx, aa.RevertAction, aa.Parameters); err != nil {
		m.logger.Error().
			Err(err).
			Str("id", aa.ID).
			Str("revert_action", aa.RevertAction).
			Msg("Failed to auto-revert action")
		return
	}

	// Remove from active actions
	m.UnregisterAction(aa.ID)
}

// loadState loads persisted state from disk.
func (m *Manager) loadState() error {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No state file yet
		}
		return err
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, aa := range state.ActiveActions {
		aaCopy := aa
		m.activeActions[aa.ID] = &aaCopy
	}

	m.logger.Info().
		Int("active_actions", len(state.ActiveActions)).
		Time("last_updated", state.LastUpdated).
		Msg("Loaded persisted state")

	return nil
}

// saveState persists current state to disk.
func (m *Manager) saveState() error {
	m.mu.RLock()
	state := State{
		ActiveActions: make([]ActiveAction, 0, len(m.activeActions)),
		LastUpdated:   time.Now(),
	}
	for _, aa := range m.activeActions {
		state.ActiveActions = append(state.ActiveActions, *aa)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.stateFile, data, 0644)
}
