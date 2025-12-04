// Package actions implements security action execution.
package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/config"
	"github.com/cisec/aisac-agent/pkg/types"
)

// rateLimitEntry tracks rate limit state for an action.
type rateLimitEntry struct {
	minuteCount int
	hourCount   int
	minuteReset time.Time
	hourReset   time.Time
}

// Action defines the interface that all actions must implement.
type Action interface {
	// Name returns the action name.
	Name() types.ActionType

	// Execute runs the action with the given parameters.
	Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error)

	// Validate validates the parameters before execution.
	Validate(params map[string]interface{}) error
}

// Executor manages and executes actions.
type Executor struct {
	cfg         *config.AgentConfig
	logger      zerolog.Logger
	actions     map[types.ActionType]Action
	actionsMu   sync.RWMutex
	rateLimits  map[string]*rateLimitEntry
	rateLimitMu sync.Mutex
}

// NewExecutor creates a new action executor.
func NewExecutor(cfg *config.AgentConfig, logger zerolog.Logger) (*Executor, error) {
	e := &Executor{
		cfg:        cfg,
		logger:     logger.With().Str("component", "executor").Logger(),
		actions:    make(map[types.ActionType]Action),
		rateLimits: make(map[string]*rateLimitEntry),
	}

	// Register built-in actions
	e.registerBuiltinActions()

	return e, nil
}

// Register registers an action with the executor.
func (e *Executor) Register(action Action) {
	e.actionsMu.Lock()
	defer e.actionsMu.Unlock()
	e.actions[action.Name()] = action
	e.logger.Debug().Str("action", string(action.Name())).Msg("Registered action")
}

// Execute executes an action by name.
func (e *Executor) Execute(ctx context.Context, actionType types.ActionType, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	e.actionsMu.RLock()
	action, ok := e.actions[actionType]
	e.actionsMu.RUnlock()

	if !ok {
		return types.ActionResult{}, fmt.Errorf("unknown action: %s", actionType)
	}

	// Check rate limits
	if err := e.checkRateLimit(string(actionType)); err != nil {
		return types.ActionResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	// Validate parameters
	if err := action.Validate(params); err != nil {
		return types.ActionResult{
			Success: false,
			Error:   fmt.Sprintf("parameter validation failed: %v", err),
		}, err
	}

	logger := e.logger.With().
		Str("action", string(actionType)).
		Str("execution_id", actCtx.ExecutionID).
		Logger()

	logger.Info().Interface("params", params).Msg("Executing action")

	result, err := action.Execute(ctx, params, actCtx)
	if err != nil {
		logger.Error().Err(err).Msg("Action execution failed")
	} else {
		logger.Info().Msg("Action execution completed")
	}

	return result, err
}

// checkRateLimit checks and updates rate limits for an action.
func (e *Executor) checkRateLimit(actionName string) error {
	limits, ok := e.cfg.Actions.RateLimits[actionName]
	if !ok {
		// No rate limit configured for this action
		return nil
	}

	e.rateLimitMu.Lock()
	defer e.rateLimitMu.Unlock()

	now := time.Now()

	entry, ok := e.rateLimits[actionName]
	if !ok {
		entry = &rateLimitEntry{
			minuteReset: now.Add(time.Minute),
			hourReset:   now.Add(time.Hour),
		}
		e.rateLimits[actionName] = entry
	}

	// Reset counters if windows have expired
	if now.After(entry.minuteReset) {
		entry.minuteCount = 0
		entry.minuteReset = now.Add(time.Minute)
	}
	if now.After(entry.hourReset) {
		entry.hourCount = 0
		entry.hourReset = now.Add(time.Hour)
	}

	// Check limits
	if limits.MaxPerMinute > 0 && entry.minuteCount >= limits.MaxPerMinute {
		return fmt.Errorf("rate limit exceeded: max %d per minute for action %s", limits.MaxPerMinute, actionName)
	}
	if limits.MaxPerHour > 0 && entry.hourCount >= limits.MaxPerHour {
		return fmt.Errorf("rate limit exceeded: max %d per hour for action %s", limits.MaxPerHour, actionName)
	}

	// Increment counters
	entry.minuteCount++
	entry.hourCount++

	return nil
}

// ListActions returns a list of registered action names.
func (e *Executor) ListActions() []string {
	e.actionsMu.RLock()
	defer e.actionsMu.RUnlock()

	names := make([]string, 0, len(e.actions))
	for name := range e.actions {
		names = append(names, string(name))
	}
	return names
}

// registerBuiltinActions registers the built-in actions.
func (e *Executor) registerBuiltinActions() {
	e.Register(NewBlockIPAction(e.logger))
	e.Register(NewUnblockIPAction(e.logger))
	e.Register(NewIsolateHostAction(e.logger))
	e.Register(NewUnisolateHostAction(e.logger))
	e.Register(NewDisableUserAction(e.logger))
	e.Register(NewEnableUserAction(e.logger))
	e.Register(NewKillProcessAction(e.logger))
}
