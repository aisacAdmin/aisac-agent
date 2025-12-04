//go:build darwin

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// DarwinFirewall implements Firewall using pfctl (pf firewall).
type DarwinFirewall struct {
	anchorName string
}

// NewDarwinFirewall creates a new macOS firewall manager.
func NewDarwinFirewall() (*DarwinFirewall, error) {
	return &DarwinFirewall{
		anchorName: "aisac",
	}, nil
}

// BlockIP blocks an IP address using pf.
func (f *DarwinFirewall) BlockIP(ctx context.Context, ip string, direction string) error {
	// Create a pf rule
	var rules []string

	if direction == "inbound" || direction == "both" {
		rules = append(rules, fmt.Sprintf("block in quick from %s to any", ip))
	}
	if direction == "outbound" || direction == "both" {
		rules = append(rules, fmt.Sprintf("block out quick from any to %s", ip))
	}

	// Load rules into the aisac anchor
	ruleStr := strings.Join(rules, "\n")
	cmd := exec.CommandContext(ctx, "pfctl", "-a", f.anchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleStr)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl failed: %s: %w", string(output), err)
	}

	// Enable pf if not already enabled
	exec.CommandContext(ctx, "pfctl", "-e").Run()

	return nil
}

// UnblockIP removes IP block rules.
func (f *DarwinFirewall) UnblockIP(ctx context.Context, ip string) error {
	// Flush the anchor rules
	cmd := exec.CommandContext(ctx, "pfctl", "-a", f.anchorName, "-F", "rules")
	cmd.Run()
	return nil
}

// IsolateHost blocks all traffic except allowed IPs.
func (f *DarwinFirewall) IsolateHost(ctx context.Context, allowIPs []string) error {
	var rules []string

	// Allow loopback
	rules = append(rules, "pass quick on lo0 all")

	// Allow established connections
	rules = append(rules, "pass quick inet proto tcp from any to any flags S/SA keep state")
	rules = append(rules, "pass quick inet proto udp from any to any keep state")

	// Allow specific IPs
	for _, ip := range allowIPs {
		rules = append(rules, fmt.Sprintf("pass quick from %s to any", ip))
		rules = append(rules, fmt.Sprintf("pass quick from any to %s", ip))
	}

	// Block everything else
	rules = append(rules, "block all")

	ruleStr := strings.Join(rules, "\n")
	cmd := exec.CommandContext(ctx, "pfctl", "-a", f.anchorName+"_isolate", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleStr)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl isolate failed: %s: %w", string(output), err)
	}

	exec.CommandContext(ctx, "pfctl", "-e").Run()

	return nil
}

// UnisolateHost removes isolation rules.
func (f *DarwinFirewall) UnisolateHost(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "pfctl", "-a", f.anchorName+"_isolate", "-F", "all")
	cmd.Run()
	return nil
}

// ListBlockedIPs returns blocked IPs.
func (f *DarwinFirewall) ListBlockedIPs(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "pfctl", "-a", f.anchorName, "-sr")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var ips []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "block") {
			// Parse IP from rule - simplified
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.Contains(field, ".") {
					ips = append(ips, field)
					break
				}
			}
		}
	}

	return ips, nil
}
