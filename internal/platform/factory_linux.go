//go:build linux

package platform

// GetFirewall returns the Linux firewall implementation.
func GetFirewall() (Firewall, error) {
	return NewLinuxFirewall()
}

// GetUserManager returns the Linux user manager.
func GetUserManager() (UserManager, error) {
	return NewLinuxUserManager()
}

// GetProcessManager returns the Unix process manager.
func GetProcessManager() (ProcessManager, error) {
	return NewUnixProcessManager()
}
