package actions

import (
	"context"
	"fmt"
	"runtime"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/platform"
	"github.com/cisec/aisac-agent/pkg/types"
)

// KillProcessAction terminates a process.
type KillProcessAction struct {
	logger zerolog.Logger
}

// NewKillProcessAction creates a new KillProcessAction.
func NewKillProcessAction(logger zerolog.Logger) *KillProcessAction {
	return &KillProcessAction{
		logger: logger.With().Str("action", "kill_process").Logger(),
	}
}

// Name returns the action name.
func (a *KillProcessAction) Name() types.ActionType {
	return types.ActionKillProcess
}

// Validate validates the parameters.
func (a *KillProcessAction) Validate(params map[string]interface{}) error {
	// Either pid or process_name must be provided
	pid, hasPID := params["pid"]
	name, hasName := params["process_name"].(string)

	if !hasPID && !hasName {
		return fmt.Errorf("either pid or process_name is required")
	}

	if hasPID {
		switch v := pid.(type) {
		case float64:
			if v <= 0 {
				return fmt.Errorf("pid must be positive")
			}
		case int:
			if v <= 0 {
				return fmt.Errorf("pid must be positive")
			}
		default:
			return fmt.Errorf("pid must be a number")
		}
	}

	if hasName && name == "" {
		return fmt.Errorf("process_name cannot be empty")
	}

	return nil
}

// Execute terminates the specified process.
func (a *KillProcessAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	procMgr, err := platform.GetProcessManager()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting process manager: %w", err)
	}

	var killed []int
	var processName string

	// Kill by PID if provided
	if pidVal, ok := params["pid"]; ok {
		var pid int
		switch v := pidVal.(type) {
		case float64:
			pid = int(v)
		case int:
			pid = v
		}

		a.logger.Info().Int("pid", pid).Msg("Killing process by PID")

		if err := procMgr.KillProcess(ctx, pid); err != nil {
			return types.ActionResult{}, fmt.Errorf("killing process %d: %w", pid, err)
		}
		killed = append(killed, pid)
	}

	// Kill by name if provided
	if name, ok := params["process_name"].(string); ok && name != "" {
		processName = name
		killAll := false
		if ka, ok := params["kill_all"].(bool); ok {
			killAll = ka
		}

		a.logger.Info().
			Str("name", name).
			Bool("kill_all", killAll).
			Msg("Killing process by name")

		pids, err := procMgr.KillProcessByName(ctx, name, killAll)
		if err != nil {
			return types.ActionResult{}, fmt.Errorf("killing process %s: %w", name, err)
		}
		killed = append(killed, pids...)
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("Successfully killed %d process(es)", len(killed)),
		Details: map[string]interface{}{
			"killed_pids":  killed,
			"process_name": processName,
			"platform":     runtime.GOOS,
		},
	}, nil
}
