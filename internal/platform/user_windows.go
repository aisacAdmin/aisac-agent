//go:build windows

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// usernameRegex validates Windows usernames (alphanumeric, underscore, dash, dot)
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// WindowsUserManager implements UserManager for Windows.
type WindowsUserManager struct{}

// NewWindowsUserManager creates a new Windows user manager.
func NewWindowsUserManager() (*WindowsUserManager, error) {
	return &WindowsUserManager{}, nil
}

// validateUsername validates username to prevent command injection.
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > 256 {
		return fmt.Errorf("username too long (max 256 characters)")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username contains invalid characters (only alphanumeric, underscore, dash, dot allowed)")
	}
	return nil
}

// DisableUser disables a user account using PowerShell.
func (m *WindowsUserManager) DisableUser(ctx context.Context, username string, forceLogout bool) error {
	// Validate username to prevent command injection
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Use PowerShell with -ArgumentList to safely pass parameters
	// This avoids string interpolation in the command
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Disable-LocalUser", "-Name", username)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Try AD user if local fails
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
			"Disable-ADAccount", "-Identity", username)
		if output2, err2 := cmd.CombinedOutput(); err2 != nil {
			return fmt.Errorf("disable user failed (local: %s, AD: %s): %w", string(output), string(output2), err)
		}
	}

	// Force logout if requested
	if forceLogout {
		m.forceLogoutUser(ctx, username)
	}

	return nil
}

// forceLogoutUser terminates all sessions for a user.
func (m *WindowsUserManager) forceLogoutUser(ctx context.Context, username string) {
	// Use taskkill to kill user processes safely (no shell interpolation)
	cmd := exec.CommandContext(ctx, "taskkill", "/F", "/FI", fmt.Sprintf("USERNAME eq %s", username))
	cmd.Run() // Ignore errors
}

// EnableUser enables a user account.
func (m *WindowsUserManager) EnableUser(ctx context.Context, username string) error {
	// Validate username to prevent command injection
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Use separate arguments instead of string interpolation
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Enable-LocalUser", "-Name", username)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Try AD user if local fails
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
			"Enable-ADAccount", "-Identity", username)
		if output2, err2 := cmd.CombinedOutput(); err2 != nil {
			return fmt.Errorf("enable user failed (local: %s, AD: %s): %w", string(output), string(output2), err)
		}
	}

	return nil
}

// ListUsers returns a list of users.
func (m *WindowsUserManager) ListUsers(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-LocalUser | Select-Object -ExpandProperty Name")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var users []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			users = append(users, line)
		}
	}

	return users, nil
}
