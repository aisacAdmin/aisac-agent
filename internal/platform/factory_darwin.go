//go:build darwin

package platform

// GetFirewall returns the macOS firewall implementation.
func GetFirewall() (Firewall, error) {
	return NewDarwinFirewall()
}

// GetUserManager returns the macOS user manager.
func GetUserManager() (UserManager, error) {
	return NewDarwinUserManager()
}

// GetProcessManager returns the Unix process manager.
func GetProcessManager() (ProcessManager, error) {
	return NewUnixProcessManager()
}
