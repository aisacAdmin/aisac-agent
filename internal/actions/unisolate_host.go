package actions

import (
	"context"
	"fmt"
	"runtime"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/platform"
	"github.com/cisec/aisac-agent/pkg/types"
)

// UnisolateHostAction removes host network isolation.
type UnisolateHostAction struct {
	logger zerolog.Logger
}

// NewUnisolateHostAction creates a new UnisolateHostAction.
func NewUnisolateHostAction(logger zerolog.Logger) *UnisolateHostAction {
	return &UnisolateHostAction{
		logger: logger.With().Str("action", "unisolate_host").Logger(),
	}
}

// Name returns the action name.
func (a *UnisolateHostAction) Name() types.ActionType {
	return types.ActionUnisolateHost
}

// Validate validates the parameters.
func (a *UnisolateHostAction) Validate(params map[string]interface{}) error {
	// No required parameters for unisolate
	return nil
}

// Execute removes network isolation from the host.
func (a *UnisolateHostAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	a.logger.Info().Msg("Removing host network isolation")

	firewall, err := platform.GetFirewall()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting firewall: %w", err)
	}

	if err := firewall.UnisolateHost(ctx); err != nil {
		return types.ActionResult{}, fmt.Errorf("removing host isolation: %w", err)
	}

	return types.ActionResult{
		Success: true,
		Message: "Host network isolation removed successfully",
		Details: map[string]interface{}{
			"platform": runtime.GOOS,
		},
	}, nil
}
