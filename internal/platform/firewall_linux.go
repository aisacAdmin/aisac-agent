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
	// Ensure the aisac table and chain exist (ignore errors: tables/chains may already exist)
	setupCmds := []string{
		"nft add table inet aisac",
		"nft add chain inet aisac input { type filter hook input priority 0 \\; }",
		"nft add chain inet aisac output { type filter hook output priority 0 \\; }",
	}

	for _, cmdStr := range setupCmds {
		parts := strings.Fields(cmdStr)
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		_ = cmd.Run() //nolint:errcheck // tables/chains may already exist
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
	// Remove all rules for this IP (best-effort: rules may not exist)
	var errs []string
	if err := exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("remove INPUT rule: %v", err))
	}
	if err := exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("remove OUTPUT rule: %v", err))
	}
	if len(errs) == 2 {
		return fmt.Errorf("failed to remove any rules for %s: %s", ip, strings.Join(errs, "; "))
	}
	return nil
}

func (f *LinuxFirewall) unblockIPNftables(ctx context.Context, ip string) error {
	// Flush chains (best-effort: chains may not exist)
	var errs []string
	if err := exec.CommandContext(ctx, "nft", "flush", "chain", "inet", "aisac", "input").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("flush input chain: %v", err))
	}
	if err := exec.CommandContext(ctx, "nft", "flush", "chain", "inet", "aisac", "output").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("flush output chain: %v", err))
	}
	if len(errs) == 2 {
		return fmt.Errorf("failed to flush any chains: %s", strings.Join(errs, "; "))
	}
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
	// Create AISAC chain (may already exist)
	_ = exec.CommandContext(ctx, "iptables", "-N", "AISAC_ISOLATE").Run() //nolint:errcheck // chain may already exist

	// Allow loopback
	if output, err := exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-i", "lo", "-j", "ACCEPT").CombinedOutput(); err != nil {
		return fmt.Errorf("allow loopback failed: %s: %w", string(output), err)
	}

	// Allow established connections
	if output, err := exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT").CombinedOutput(); err != nil {
		return fmt.Errorf("allow established failed: %s: %w", string(output), err)
	}

	// Allow specific IPs
	for _, ip := range allowIPs {
		if output, err := exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-s", ip, "-j", "ACCEPT").CombinedOutput(); err != nil {
			return fmt.Errorf("allow IP %s (inbound) failed: %s: %w", ip, string(output), err)
		}
		if output, err := exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-d", ip, "-j", "ACCEPT").CombinedOutput(); err != nil {
			return fmt.Errorf("allow IP %s (outbound) failed: %s: %w", ip, string(output), err)
		}
	}

	// Drop everything else
	if output, err := exec.CommandContext(ctx, "iptables", "-A", "AISAC_ISOLATE", "-j", "DROP").CombinedOutput(); err != nil {
		return fmt.Errorf("drop rule failed: %s: %w", string(output), err)
	}

	// Insert at the beginning of INPUT and OUTPUT
	if output, err := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-j", "AISAC_ISOLATE").CombinedOutput(); err != nil {
		return fmt.Errorf("insert INPUT chain failed: %s: %w", string(output), err)
	}
	if output, err := exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-j", "AISAC_ISOLATE").CombinedOutput(); err != nil {
		return fmt.Errorf("insert OUTPUT chain failed: %s: %w", string(output), err)
	}

	return nil
}

func (f *LinuxFirewall) isolateHostNftables(ctx context.Context, allowIPs []string) error {
	// Create isolation table (may already exist)
	_ = exec.CommandContext(ctx, "nft", "add", "table", "inet", "aisac_isolate").Run() //nolint:errcheck // table may already exist

	// Create chains with high priority
	cmds := []string{
		"nft add chain inet aisac_isolate input { type filter hook input priority -100 \\; policy drop \\; }",
		"nft add chain inet aisac_isolate output { type filter hook output priority -100 \\; policy drop \\; }",
	}

	for _, cmdStr := range cmds {
		parts := strings.Fields(cmdStr)
		if output, err := exec.CommandContext(ctx, parts[0], parts[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("nft chain setup failed (%s): %s: %w", cmdStr, string(output), err)
		}
	}

	// Allow loopback
	if output, err := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "input", "iif", "lo", "accept").CombinedOutput(); err != nil {
		return fmt.Errorf("nft allow loopback input failed: %s: %w", string(output), err)
	}
	if output, err := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "output", "oif", "lo", "accept").CombinedOutput(); err != nil {
		return fmt.Errorf("nft allow loopback output failed: %s: %w", string(output), err)
	}

	// Allow established
	if output, err := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "input", "ct", "state", "established,related", "accept").CombinedOutput(); err != nil {
		return fmt.Errorf("nft allow established input failed: %s: %w", string(output), err)
	}
	if output, err := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "output", "ct", "state", "established,related", "accept").CombinedOutput(); err != nil {
		return fmt.Errorf("nft allow established output failed: %s: %w", string(output), err)
	}

	// Allow specific IPs
	for _, ip := range allowIPs {
		if output, err := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "input", "ip", "saddr", ip, "accept").CombinedOutput(); err != nil {
			return fmt.Errorf("nft allow IP %s input failed: %s: %w", ip, string(output), err)
		}
		if output, err := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "aisac_isolate", "output", "ip", "daddr", ip, "accept").CombinedOutput(); err != nil {
			return fmt.Errorf("nft allow IP %s output failed: %s: %w", ip, string(output), err)
		}
	}

	return nil
}

// UnisolateHost removes isolation rules.
func (f *LinuxFirewall) UnisolateHost(ctx context.Context) error {
	if f.useNftables {
		if output, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "aisac_isolate").CombinedOutput(); err != nil {
			return fmt.Errorf("nft delete isolation table failed: %s: %w", string(output), err)
		}
		return nil
	}

	// iptables: remove chain references, flush, then delete
	var errs []string
	if err := exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-j", "AISAC_ISOLATE").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("remove INPUT reference: %v", err))
	}
	if err := exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-j", "AISAC_ISOLATE").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("remove OUTPUT reference: %v", err))
	}
	if err := exec.CommandContext(ctx, "iptables", "-F", "AISAC_ISOLATE").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("flush chain: %v", err))
	}
	if err := exec.CommandContext(ctx, "iptables", "-X", "AISAC_ISOLATE").Run(); err != nil {
		errs = append(errs, fmt.Sprintf("delete chain: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("unisolate errors: %s", strings.Join(errs, "; "))
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
