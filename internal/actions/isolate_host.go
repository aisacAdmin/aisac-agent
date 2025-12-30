package actions

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/platform"
	"github.com/cisec/aisac-agent/pkg/types"
)

// IsolateHostAction isolates the host from the network.
type IsolateHostAction struct {
	logger zerolog.Logger
}

// NewIsolateHostAction creates a new IsolateHostAction.
func NewIsolateHostAction(logger zerolog.Logger) *IsolateHostAction {
	return &IsolateHostAction{
		logger: logger.With().Str("action", "isolate_host").Logger(),
	}
}

// Name returns the action name.
func (a *IsolateHostAction) Name() types.ActionType {
	return types.ActionIsolateHost
}

// Validate validates the parameters.
func (a *IsolateHostAction) Validate(params map[string]interface{}) error {
	// allow_ips is optional but must be a valid list if provided
	if allowIPs, ok := params["allow_ips"]; ok {
		var ips []string
		switch v := allowIPs.(type) {
		case []interface{}:
			for _, ip := range v {
				if ipStr, ok := ip.(string); ok {
					ips = append(ips, ipStr)
				}
			}
		case []string:
			ips = v
		default:
			return fmt.Errorf("allow_ips must be a list of IP addresses, got %T", v)
		}

		// SECURITY: Validate each IP address
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("invalid IP address in allow_ips: %s", ipStr)
			}
			// Validate IP is safe (using same validation as block_ip)
			if err := validateIPForBlocking(ip); err != nil {
				return fmt.Errorf("invalid IP in allow_ips: %w", err)
			}
		}
	}
	return nil
}

// Execute isolates the host from the network.
func (a *IsolateHostAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	// Extract allowed IPs (typically includes the AISAC server IP)
	var allowIPs []string
	if ips, ok := params["allow_ips"].([]interface{}); ok {
		for _, ip := range ips {
			if ipStr, ok := ip.(string); ok {
				allowIPs = append(allowIPs, ipStr)
			}
		}
	}

	a.logger.Info().
		Strs("allow_ips", allowIPs).
		Msg("Isolating host")

	firewall, err := platform.GetFirewall()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting firewall: %w", err)
	}

	if err := firewall.IsolateHost(ctx, allowIPs); err != nil {
		return types.ActionResult{}, fmt.Errorf("isolating host: %w", err)
	}

	return types.ActionResult{
		Success: true,
		Message: "Host successfully isolated from network",
		Details: map[string]interface{}{
			"allow_ips": allowIPs,
			"platform":  runtime.GOOS,
		},
	}, nil
}
