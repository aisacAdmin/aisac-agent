package actions

import (
	"context"
	"fmt"
	"runtime"
	"strings"

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
		var pidVal int
		switch v := pid.(type) {
		case float64:
			if v <= 0 {
				return fmt.Errorf("pid must be positive")
			}
			pidVal = int(v)
		case int:
			if v <= 0 {
				return fmt.Errorf("pid must be positive")
			}
			pidVal = v
		default:
			return fmt.Errorf("pid must be a number")
		}

		// SECURITY: Never allow killing PID 1 (init/systemd)
		if pidVal == 1 {
			return fmt.Errorf("cannot kill init process (PID 1)")
		}
	}

	if hasName && name == "" {
		return fmt.Errorf("process_name cannot be empty")
	}

	// SECURITY: Validate process name against critical processes
	if hasName {
		if err := validateProcessName(name); err != nil {
			return err
		}
	}

	return nil
}

// validateProcessName checks if a process name is safe to kill.
func validateProcessName(name string) error {
	// List of critical processes that should never be killed
	protectedProcesses := []string{
		// Init systems
		"init", "systemd", "launchd",
		// SSH daemon
		"sshd", "ssh-agent",
		// System daemons (Linux)
		"systemd-journald", "systemd-logind", "systemd-udevd",
		"systemd-networkd", "systemd-resolved", "systemd-timesyncd",
		"dbus-daemon", "dbus", "rsyslogd", "syslogd",
		// Kernel threads (should never be killed anyway)
		"kthreadd", "ksoftirqd", "kworker", "kswapd",
		// Container runtimes
		"dockerd", "containerd", "containerd-shim",
		// macOS critical processes
		"WindowServer", "loginwindow", "SystemUIServer", "Finder",
		// Windows critical processes
		"csrss.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe",
		"explorer.exe", "System", "wininit.exe",
		// AISAC agent itself
		"aisac-agent", "aisac-server",
	}

	// Normalize process name (remove path and extension)
	processName := strings.ToLower(name)
	processName = strings.TrimSuffix(processName, ".exe")

	// Check if base name matches any protected process
	for _, baseName := range []string{name, processName} {
		for _, protected := range protectedProcesses {
			if baseName == protected || strings.Contains(baseName, protected) {
				return fmt.Errorf("cannot kill protected system process: %s", name)
			}
		}
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

		// Double-check protection before killing
		if err := validateProcessName(name); err != nil {
			return types.ActionResult{}, err
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
