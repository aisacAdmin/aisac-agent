//go:build linux

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// usernameRegex validates usernames to prevent command injection.
// POSIX usernames: start with letter or underscore, followed by alphanumeric, underscore, or dash.
var usernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

// validateUsername validates a username for safety.
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > 32 {
		return fmt.Errorf("username too long (max 32 characters)")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username format: must be a valid POSIX username")
	}
	return nil
}

// LinuxUserManager implements UserManager for Linux.
type LinuxUserManager struct{}

// NewLinuxUserManager creates a new Linux user manager.
func NewLinuxUserManager() (*LinuxUserManager, error) {
	return &LinuxUserManager{}, nil
}

// DisableUser disables a user account.
func (m *LinuxUserManager) DisableUser(ctx context.Context, username string, forceLogout bool) error {
	// SECURITY: Validate username to prevent command injection
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Lock the account
	cmd := exec.CommandContext(ctx, "usermod", "-L", username)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -L failed: %s: %w", string(output), err)
	}

	// Expire the account
	cmd = exec.CommandContext(ctx, "usermod", "-e", "1", username)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -e failed: %s: %w", string(output), err)
	}

	// Force logout if requested
	if forceLogout {
		// Kill all user processes
		cmd = exec.CommandContext(ctx, "pkill", "-u", username)
		cmd.Run() // Ignore error if no processes

		// Kill user sessions
		cmd = exec.CommandContext(ctx, "loginctl", "terminate-user", username)
		cmd.Run() // Ignore error if loginctl not available
	}

	return nil
}

// EnableUser enables a user account.
func (m *LinuxUserManager) EnableUser(ctx context.Context, username string) error {
	// SECURITY: Validate username to prevent command injection
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Unlock the account
	cmd := exec.CommandContext(ctx, "usermod", "-U", username)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -U failed: %s: %w", string(output), err)
	}

	// Remove expiry
	cmd = exec.CommandContext(ctx, "usermod", "-e", "", username)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -e failed: %s: %w", string(output), err)
	}

	return nil
}

// ListUsers returns a list of users.
func (m *LinuxUserManager) ListUsers(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "getent", "passwd")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var users []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) > 0 {
			users = append(users, parts[0])
		}
	}

	return users, nil
}
