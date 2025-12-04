package actions

import (
	"context"
	"fmt"
	"runtime"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/platform"
	"github.com/cisec/aisac-agent/pkg/types"
)

// EnableUserAction enables a previously disabled user account.
type EnableUserAction struct {
	logger zerolog.Logger
}

// NewEnableUserAction creates a new EnableUserAction.
func NewEnableUserAction(logger zerolog.Logger) *EnableUserAction {
	return &EnableUserAction{
		logger: logger.With().Str("action", "enable_user").Logger(),
	}
}

// Name returns the action name.
func (a *EnableUserAction) Name() types.ActionType {
	return types.ActionEnableUser
}

// Validate validates the parameters.
func (a *EnableUserAction) Validate(params map[string]interface{}) error {
	username, ok := params["username"].(string)
	if !ok || username == "" {
		return fmt.Errorf("username is required")
	}
	return nil
}

// Execute enables the specified user account.
func (a *EnableUserAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	username := params["username"].(string)

	a.logger.Info().Str("username", username).Msg("Enabling user account")

	userMgr, err := platform.GetUserManager()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting user manager: %w", err)
	}

	if err := userMgr.EnableUser(ctx, username); err != nil {
		return types.ActionResult{}, fmt.Errorf("enabling user: %w", err)
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("Successfully enabled user %s", username),
		Details: map[string]interface{}{
			"username": username,
			"platform": runtime.GOOS,
		},
	}, nil
}
