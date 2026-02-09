package actions

import (
	"context"
	"fmt"
	"runtime"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/platform"
	"github.com/cisec/aisac-agent/pkg/types"
)

// DisableUserAction disables a user account.
type DisableUserAction struct {
	logger zerolog.Logger
}

// NewDisableUserAction creates a new DisableUserAction.
func NewDisableUserAction(logger zerolog.Logger) *DisableUserAction {
	return &DisableUserAction{
		logger: logger.With().Str("action", "disable_user").Logger(),
	}
}

// Name returns the action name.
func (a *DisableUserAction) Name() types.ActionType {
	return types.ActionDisableUser
}

// Validate validates the parameters.
func (a *DisableUserAction) Validate(params map[string]interface{}) error {
	username, ok := params["username"].(string)
	if !ok || username == "" {
		return fmt.Errorf("username is required")
	}

	// Prevent disabling critical system accounts
	protectedUsers := []string{
		// Windows
		"Administrator", "SYSTEM", "LocalSystem", "LocalService", "NetworkService",
		// Linux/Unix - root and system users
		"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
		"news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
		"nobody", "systemd-network", "systemd-resolve", "systemd-timesync",
		"messagebus", "syslog", "_apt", "tss", "uuidd", "tcpdump", "sshd",
		"systemd-coredump", "lxd", "mysql", "postgres", "postfix", "bind",
		// macOS
		"_appserver", "_windowserver", "_securityagent", "_coreaudiod",
	}

	for _, protected := range protectedUsers {
		if username == protected {
			return fmt.Errorf("cannot disable protected system account: %s", username)
		}
	}

	return nil
}

// Execute disables the specified user account.
func (a *DisableUserAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	username := params["username"].(string)

	// Optional: force logout active sessions
	forceLogout := false
	if fl, ok := params["force_logout"].(bool); ok {
		forceLogout = fl
	}

	a.logger.Info().
		Str("username", username).
		Bool("force_logout", forceLogout).
		Msg("Disabling user account")

	userMgr, err := platform.GetUserManager()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting user manager: %w", err)
	}

	if err := userMgr.DisableUser(ctx, username, forceLogout); err != nil {
		return types.ActionResult{}, fmt.Errorf("disabling user: %w", err)
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("Successfully disabled user %s", username),
		Details: map[string]interface{}{
			"username":     username,
			"force_logout": forceLogout,
			"platform":     runtime.GOOS,
		},
	}, nil
}
