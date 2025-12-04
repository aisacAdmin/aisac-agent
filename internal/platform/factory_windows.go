//go:build windows

package platform

// GetFirewall returns the Windows firewall implementation.
func GetFirewall() (Firewall, error) {
	return NewWindowsFirewall()
}

// GetUserManager returns the Windows user manager.
func GetUserManager() (UserManager, error) {
	return NewWindowsUserManager()
}

// GetProcessManager returns the Windows process manager.
func GetProcessManager() (ProcessManager, error) {
	return NewWindowsProcessManager()
}
