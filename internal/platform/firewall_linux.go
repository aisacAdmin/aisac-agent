//go:build linux

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// LinuxFirewall implements Firewall using iptables/nftables.
type LinuxFirewall struct {
	useNftables bool
}

// NewLinuxFirewall creates a new Linux firewall manager.
func NewLinuxFirewall() (*LinuxFirewall, error) {
	// Check if nftables is available
	_, err := exec.LookPath("nft")
	useNftables := err == nil

	return &LinuxFirewall{
		useNftables: useNftables,
	}, nil
}

// BlockIP blocks an IP address using iptables.
func (f *LinuxFirewall) BlockIP(ctx context.Context, ip string, direction string) error {
	if f.useNftables {
		return f.blockIPNftables(ctx, ip, direction)
	}
	return f.blockIPIptables(ctx, ip, direction)
}

func (f *LinuxFirewall) blockIPIptables(ctx context.Context, ip string, direction string) error {
	var cmds []*exec.Cmd

	// Check if rule already exists
	checkCmd := exec.CommandContext(ctx, "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if checkCmd.Run() == nil {
		// Rule already exists
		return nil
	}

	if direction == "inbound" || direction == "both" {
		cmds = append(cmds, exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"))
	}
	if direction == "outbound" || direction == "both" {
		cmds = append(cmds, exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"))
	}

	for _, cmd := range cmds {
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables command failed: %s: %w", string(output), err)
		}
	}

	return nil
}

func (f *LinuxFirewall) blockIPNftables(ctx context.Context, ip string, direction string) error {
	// Ensure the aisac table and chain exist
	setupCmds := []string{
		"nft add table inet aisac",
		"nft add chain inet aisac input { type filter hook input priority 0 \\; }",
		"nft add chain inet aisac output { type filter hook output priority 0 \\; }",
	}

	for _, cmdStr := range setupCmds {
		parts := strings.Fields(cmdStr)
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		cmd.Run() // Ignore errors (tables may already exist)
	}

	// Add block rules
	if direction == "inbound" || direction == "both" {
		cmd := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac", "input", "ip", "saddr", ip, "drop")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft input rule failed: %s: %w", string(output), err)
		}
	}
	if direction == "outbound" || direction == "both" {
		cmd := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac", "output", "ip", "daddr", ip, "drop")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft output rule failed: %s: %w", string(output), err)
		}
	}

	return nil
}

// UnblockIP removes IP block rules.
func (f *LinuxFirewall) UnblockIP(ctx context.Context, ip string) error {
	if f.useNftables {
		return f.unblockIPNftables(ctx, ip)
	}
	return f.unblockIPIptables(ctx, ip)
}

func (f *LinuxFirewall) unblockIPIptables(ctx context.Context, ip string) error {
	// Remove all rules for this IP (ignore errors if rules don't exist)
	exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run()
	return nil
}

func (f *LinuxFirewall) unblockIPNftables(ctx context.Context, ip string) error {
	// List and remove rules matching the IP
	// This is simplified - in production you'd want to track rule handles
	cmd := exec.CommandContext(ctx, "nft", "flush", "chain", "inet", "aisac", "input")
	cmd.Run()
	cmd = exec.CommandContext(ctx, "nft", "flush", "chain", "inet", "aisac", "output")
	cmd.Run()
	return nil
}

// IsolateHost blocks all traffic except allowed IPs.
func (f *LinuxFirewall) IsolateHost(ctx context.Context, allowIPs []string) error {
	if f.useNftables {
		return f.isolateHostNftables(ctx, allowIPs)
	}
	return f.isolateHostIptables(ctx, allowIPs)
}

func (f *LinuxFirewall) isolateHostIptables(ctx context.Context, allowIPs []string) error {
	// Create AISAC chain
	exec.CommandContext(ctx, "iptables", "-N", "AISAC_ISOLATE").Run()

	// Allow loopback
	exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-i", "lo", "-j", "ACCEPT").Run()

	// Allow established connections
	exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()

	// Allow specific IPs
	for _, ip := range allowIPs {
		exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-s", ip, "-j", "ACCEPT").Run()
		exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-d", ip, "-j", "ACCEPT").Run()
	}

	// Drop everything else
	exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-j", "DROP").Run()

	// Insert at the beginning of INPUT and OUTPUT
	exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-j", "AISAC_ISOLATE").Run()
	exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-j", "AISAC_ISOLATE").Run()

	return nil
}

func (f *LinuxFirewall) isolateHostNftables(ctx context.Context, allowIPs []string) error {
	// Create isolation table
	cmd := exec.CommandContext(ctx, "nft", "add", "table", "inet", "aisac_isolate")
	cmd.Run()

	// Create chains with high priority
	cmds := []string{
		"nft add chain inet aisac_isolate input { type filter hook input priority -100 \\; policy drop \\; }",
		"nft add chain inet aisac_isolate output { type filter hook output priority -100 \\; policy drop \\; }",
	}

	for _, cmdStr := range cmds {
		parts := strings.Fields(cmdStr)
		exec.CommandContext(ctx, parts[0], parts[1:]...).Run()
	}

	// Allow loopback
	exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "input", "iif", "lo", "accept").Run()
	exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "output", "oif", "lo", "accept").Run()

	// Allow established
	exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "input", "ct", "state", "established,related", "accept").Run()
	exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "output", "ct", "state", "established,related", "accept").Run()

	// Allow specific IPs
	for _, ip := range allowIPs {
		exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "input", "ip", "saddr", ip, "accept").Run()
		exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "output", "ip", "daddr", ip, "accept").Run()
	}

	return nil
}

// UnisolateHost removes isolation rules.
func (f *LinuxFirewall) UnisolateHost(ctx context.Context) error {
	if f.useNftables {
		exec.CommandContext(ctx, "nft", "delete", "table", "inet", "aisac_isolate").Run()
	} else {
		exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-j", "AISAC_ISOLATE").Run()
		exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-j", "AISAC_ISOLATE").Run()
		exec.CommandContext(ctx, "iptables", "-F", "AISAC_ISOLATE").Run()
		exec.CommandContext(ctx, "iptables", "-X", "AISAC_ISOLATE").Run()
	}
	return nil
}

// ListBlockedIPs returns blocked IPs.
func (f *LinuxFirewall) ListBlockedIPs(ctx context.Context) ([]string, error) {
	// This is a simplified implementation
	var ips []string
	cmd := exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "DROP") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ips = append(ips, fields[3])
			}
		}
	}

	return ips, nil
}
