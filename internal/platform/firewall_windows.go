//go:build windows

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// WindowsFirewall implements Firewall using Windows Firewall (netsh).
type WindowsFirewall struct {
	rulePrefix string
}

// NewWindowsFirewall creates a new Windows firewall manager.
func NewWindowsFirewall() (*WindowsFirewall, error) {
	return &WindowsFirewall{
		rulePrefix: "AISAC_",
	}, nil
}

// BlockIP blocks an IP address using Windows Firewall.
func (f *WindowsFirewall) BlockIP(ctx context.Context, ip string, direction string) error {
	if direction == "inbound" || direction == "both" {
		ruleName := fmt.Sprintf("%sBlock_In_%s", f.rulePrefix, strings.ReplaceAll(ip, ".", "_"))
		cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=block",
			"remoteip="+ip,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh inbound rule failed: %s: %w", string(output), err)
		}
	}

	if direction == "outbound" || direction == "both" {
		ruleName := fmt.Sprintf("%sBlock_Out_%s", f.rulePrefix, strings.ReplaceAll(ip, ".", "_"))
		cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=out",
			"action=block",
			"remoteip="+ip,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh outbound rule failed: %s: %w", string(output), err)
		}
	}

	return nil
}

// UnblockIP removes IP block rules.
func (f *WindowsFirewall) UnblockIP(ctx context.Context, ip string) error {
	// Remove inbound rule
	ruleName := fmt.Sprintf("%sBlock_In_%s", f.rulePrefix, strings.ReplaceAll(ip, ".", "_"))
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName).Run()

	// Remove outbound rule
	ruleName = fmt.Sprintf("%sBlock_Out_%s", f.rulePrefix, strings.ReplaceAll(ip, ".", "_"))
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName).Run()

	return nil
}

// IsolateHost blocks all traffic except allowed IPs.
func (f *WindowsFirewall) IsolateHost(ctx context.Context, allowIPs []string) error {
	// Create allow rules for specific IPs
	for i, ip := range allowIPs {
		ruleName := fmt.Sprintf("%sIsolate_Allow_%d", f.rulePrefix, i)

		// Allow inbound
		exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName+"_in",
			"dir=in",
			"action=allow",
			"remoteip="+ip,
		).Run()

		// Allow outbound
		exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName+"_out",
			"dir=out",
			"action=allow",
			"remoteip="+ip,
		).Run()
	}

	// Block all other traffic
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+f.rulePrefix+"Isolate_Block_In",
		"dir=in",
		"action=block",
		"remoteip=any",
	).Run()

	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+f.rulePrefix+"Isolate_Block_Out",
		"dir=out",
		"action=block",
		"remoteip=any",
	).Run()

	return nil
}

// UnisolateHost removes isolation rules.
func (f *WindowsFirewall) UnisolateHost(ctx context.Context) error {
	// Remove all AISAC isolation rules
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name=all",
		"dir=in",
	)
	// We filter by our prefix in a different way - delete specific rules
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+f.rulePrefix+"Isolate_Block_In",
	).Run()
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+f.rulePrefix+"Isolate_Block_Out",
	).Run()

	// Clean up allow rules (simplified - would need to track rule numbers)
	for i := 0; i < 10; i++ {
		ruleName := fmt.Sprintf("%sIsolate_Allow_%d", f.rulePrefix, i)
		exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+ruleName+"_in",
		).Run()
		exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+ruleName+"_out",
		).Run()
	}

	return cmd.Run()
}

// ListBlockedIPs returns blocked IPs.
func (f *WindowsFirewall) ListBlockedIPs(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule",
		"name=all", "dir=in", "status=enabled",
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var ips []string
	lines := strings.Split(string(output), "\n")
	var currentRule string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Rule Name:") && strings.Contains(line, f.rulePrefix+"Block") {
			currentRule = line
		}
		if currentRule != "" && strings.HasPrefix(line, "RemoteIP:") {
			ip := strings.TrimPrefix(line, "RemoteIP:")
			ip = strings.TrimSpace(ip)
			if ip != "Any" {
				ips = append(ips, ip)
			}
			currentRule = ""
		}
	}

	return ips, nil
}
