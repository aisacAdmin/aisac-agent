//go:build darwin

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// DarwinUserManager implements UserManager for macOS.
type DarwinUserManager struct{}

// NewDarwinUserManager creates a new macOS user manager.
func NewDarwinUserManager() (*DarwinUserManager, error) {
	return &DarwinUserManager{}, nil
}

// DisableUser disables a user account using dscl.
func (m *DarwinUserManager) DisableUser(ctx context.Context, username string, forceLogout bool) error {
	// Disable user authentication by setting AuthenticationAuthority to disabled
	cmd := exec.CommandContext(ctx, "dscl", ".", "-create", "/Users/"+username,
		"AuthenticationAuthority", ";DisabledUser;")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dscl create failed: %s: %w", string(output), err)
	}

	// Force logout if requested
	if forceLogout {
		// Kill all user processes
		cmd = exec.CommandContext(ctx, "pkill", "-u", username)
		cmd.Run() // Ignore error if no processes
	}

	return nil
}

// EnableUser enables a user account.
func (m *DarwinUserManager) EnableUser(ctx context.Context, username string) error {
	// Remove the disabled auth authority and restore default
	cmd := exec.CommandContext(ctx, "dscl", ".", "-delete", "/Users/"+username, "AuthenticationAuthority")
	cmd.Run() // Ignore if not set

	return nil
}

// ListUsers returns a list of users.
func (m *DarwinUserManager) ListUsers(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "dscl", ".", "-list", "/Users")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var users []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "_") {
			users = append(users, line)
		}
	}

	return users, nil
}
