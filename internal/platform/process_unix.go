//go:build linux || darwin

package platform

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// processNameRegex validates process names to prevent command injection.
// Allows alphanumeric, dash, underscore, dot, and forward slash (for paths).
var processNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-./]+$`)

// validateProcessName validates a process name for safety.
func validateProcessName(name string) error {
	if name == "" {
		return fmt.Errorf("process name cannot be empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("process name too long (max 256 characters)")
	}
	if !processNameRegex.MatchString(name) {
		return fmt.Errorf("invalid process name: contains disallowed characters")
	}
	// Prevent path traversal
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid process name: path traversal not allowed")
	}
	return nil
}

// UnixProcessManager implements ProcessManager for Unix systems.
type UnixProcessManager struct{}

// NewUnixProcessManager creates a new Unix process manager.
func NewUnixProcessManager() (*UnixProcessManager, error) {
	return &UnixProcessManager{}, nil
}

// KillProcess kills a process by PID.
func (m *UnixProcessManager) KillProcess(ctx context.Context, pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process: %w", err)
	}

	// First try SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// Process might already be dead
		if err == os.ErrProcessDone {
			return nil
		}
		return fmt.Errorf("sending SIGTERM: %w", err)
	}

	// Wait briefly for graceful shutdown, then force kill
	// In production, you'd want a proper wait with timeout
	if err := process.Signal(syscall.SIGKILL); err != nil {
		if err == os.ErrProcessDone {
			return nil
		}
		// Ignore error if process already terminated
	}

	return nil
}

// KillProcessByName kills processes by name.
func (m *UnixProcessManager) KillProcessByName(ctx context.Context, name string, killAll bool) ([]int, error) {
	// SECURITY: Validate process name to prevent command injection
	if err := validateProcessName(name); err != nil {
		return nil, fmt.Errorf("invalid process name: %w", err)
	}

	// Find processes by name
	pids, err := m.findProcessesByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("finding processes: %w", err)
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("no processes found with name: %s", name)
	}

	var killed []int
	for _, pid := range pids {
		if err := m.KillProcess(ctx, pid); err != nil {
			if !killAll {
				return killed, err
			}
			// Continue killing others if killAll
			continue
		}
		killed = append(killed, pid)

		if !killAll {
			break
		}
	}

	return killed, nil
}

// findProcessesByName finds process PIDs by name.
func (m *UnixProcessManager) findProcessesByName(ctx context.Context, name string) ([]int, error) {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", name)
	output, err := cmd.Output()
	if err != nil {
		// pgrep returns 1 if no processes found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	var pids []int
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		pidStr := strings.TrimSpace(scanner.Text())
		if pid, err := strconv.Atoi(pidStr); err == nil {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

// ListProcesses returns a list of running processes.
func (m *UnixProcessManager) ListProcesses(ctx context.Context) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "ps", "-eo", "pid,user,comm,args", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		processes = append(processes, ProcessInfo{
			PID:     pid,
			User:    fields[1],
			Name:    fields[2],
			Command: strings.Join(fields[3:], " "),
		})
	}

	return processes, nil
}
