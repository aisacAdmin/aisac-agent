//go:build windows

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
)

// processNameRegex validates process names (alphanumeric, underscore, dash, dot)
var processNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// WindowsProcessManager implements ProcessManager for Windows.
type WindowsProcessManager struct{}

// NewWindowsProcessManager creates a new Windows process manager.
func NewWindowsProcessManager() (*WindowsProcessManager, error) {
	return &WindowsProcessManager{}, nil
}

// validatePID validates PID to prevent killing critical processes.
func validatePID(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID: must be positive")
	}
	if pid == 1 || pid == 0 {
		return fmt.Errorf("cannot kill system process (PID %d)", pid)
	}
	// Don't allow killing our own process
	if pid == os.Getpid() {
		return fmt.Errorf("cannot kill agent's own process")
	}
	return nil
}

// validateProcessName validates process name to prevent command injection.
func validateProcessName(name string) error {
	if name == "" {
		return fmt.Errorf("process name cannot be empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("process name too long (max 256 characters)")
	}
	if !processNameRegex.MatchString(name) {
		return fmt.Errorf("process name contains invalid characters (only alphanumeric, underscore, dash, dot allowed)")
	}
	return nil
}

// KillProcess kills a process by PID.
func (m *WindowsProcessManager) KillProcess(ctx context.Context, pid int) error {
	// Validate PID
	if err := validatePID(pid); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid), "/F")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("taskkill failed: %s: %w", string(output), err)
	}
	return nil
}

// KillProcessByName kills processes by name.
func (m *WindowsProcessManager) KillProcessByName(ctx context.Context, name string, killAll bool) ([]int, error) {
	// Validate process name to prevent injection
	if err := validateProcessName(name); err != nil {
		return nil, fmt.Errorf("invalid process name: %w", err)
	}

	// First find the PIDs using safe method
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
			continue
		}
		killed = append(killed, pid)

		if !killAll {
			break
		}
	}

	return killed, nil
}

// findProcessesByName finds process PIDs by name using safe method.
func (m *WindowsProcessManager) findProcessesByName(ctx context.Context, name string) ([]int, error) {
	// Use tasklist with filtering instead of PowerShell to avoid injection
	// tasklist /FI "IMAGENAME eq name.exe" /FO CSV /NH
	filter := fmt.Sprintf("IMAGENAME eq %s*", name)
	cmd := exec.CommandContext(ctx, "tasklist", "/FI", filter, "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil // No processes found or error
	}

	var pids []int
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "No tasks") {
			continue
		}

		// Parse CSV: "process.exe","PID","Session Name","Session#","Mem Usage"
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}

		// Remove quotes and parse PID
		pidStr := strings.Trim(fields[1], "\"")
		if pid, err := strconv.Atoi(pidStr); err == nil {
			// Skip our own process
			if pid != os.Getpid() {
				pids = append(pids, pid)
			}
		}
	}

	return pids, nil
}

// ListProcesses returns a list of running processes.
func (m *WindowsProcessManager) ListProcesses(ctx context.Context) ([]ProcessInfo, error) {
	// Use tasklist instead of PowerShell for safety
	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/V")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := parseCSVLine(line)
		if len(fields) < 4 {
			continue
		}

		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		processes = append(processes, ProcessInfo{
			PID:     pid,
			Name:    fields[0],
			User:    fields[6], // User Name column in /V output
			Command: fields[0],
		})
	}

	return processes, nil
}

// parseCSVLine parses a CSV line handling quoted fields.
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				current.WriteRune(r)
			} else {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())

	return fields
}
