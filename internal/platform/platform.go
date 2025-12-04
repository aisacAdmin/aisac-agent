// Package platform provides platform-specific implementations.
package platform

import "context"

// Firewall interface for firewall operations.
type Firewall interface {
	// BlockIP blocks an IP address.
	BlockIP(ctx context.Context, ip string, direction string) error

	// UnblockIP unblocks an IP address.
	UnblockIP(ctx context.Context, ip string) error

	// IsolateHost isolates the host, optionally allowing specific IPs.
	IsolateHost(ctx context.Context, allowIPs []string) error

	// UnisolateHost removes host isolation.
	UnisolateHost(ctx context.Context) error

	// ListBlockedIPs returns the list of blocked IPs.
	ListBlockedIPs(ctx context.Context) ([]string, error)
}

// UserManager interface for user account operations.
type UserManager interface {
	// DisableUser disables a user account.
	DisableUser(ctx context.Context, username string, forceLogout bool) error

	// EnableUser enables a user account.
	EnableUser(ctx context.Context, username string) error

	// ListUsers returns a list of users.
	ListUsers(ctx context.Context) ([]string, error)
}

// ProcessManager interface for process operations.
type ProcessManager interface {
	// KillProcess kills a process by PID.
	KillProcess(ctx context.Context, pid int) error

	// KillProcessByName kills processes by name.
	KillProcessByName(ctx context.Context, name string, killAll bool) ([]int, error)

	// ListProcesses returns a list of running processes.
	ListProcesses(ctx context.Context) ([]ProcessInfo, error)
}

// ProcessInfo contains process information.
type ProcessInfo struct {
	PID     int
	Name    string
	User    string
	Command string
}
