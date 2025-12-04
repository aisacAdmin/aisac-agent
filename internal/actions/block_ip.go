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

// BlockIPAction blocks an IP address in the firewall.
type BlockIPAction struct {
	logger zerolog.Logger
}

// NewBlockIPAction creates a new BlockIPAction.
func NewBlockIPAction(logger zerolog.Logger) *BlockIPAction {
	return &BlockIPAction{
		logger: logger.With().Str("action", "block_ip").Logger(),
	}
}

// Name returns the action name.
func (a *BlockIPAction) Name() types.ActionType {
	return types.ActionBlockIP
}

// Validate validates the parameters.
func (a *BlockIPAction) Validate(params map[string]interface{}) error {
	ipStr, ok := params["ip_address"].(string)
	if !ok || ipStr == "" {
		return fmt.Errorf("ip_address is required")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Security: Block dangerous IPs that should never be blocked
	if err := validateIPForBlocking(ip); err != nil {
		return err
	}

	return nil
}

// validateIPForBlocking checks if an IP is safe to block.
func validateIPForBlocking(ip net.IP) error {
	// Don't block localhost
	if ip.IsLoopback() {
		return fmt.Errorf("cannot block loopback address: %s", ip.String())
	}

	// Don't block unspecified (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return fmt.Errorf("cannot block unspecified address: %s", ip.String())
	}

	// Don't block multicast addresses
	if ip.IsMulticast() {
		return fmt.Errorf("cannot block multicast address: %s", ip.String())
	}

	// Don't block link-local addresses (169.254.x.x or fe80::)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("cannot block link-local address: %s", ip.String())
	}

	// Don't block broadcast address (255.255.255.255)
	if ip.Equal(net.IPv4bcast) {
		return fmt.Errorf("cannot block broadcast address")
	}

	return nil
}

// Execute blocks the specified IP address.
func (a *BlockIPAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	ipStr := params["ip_address"].(string)

	duration := 0
	if d, ok := params["duration"].(float64); ok {
		duration = int(d)
	}

	direction := "both"
	if d, ok := params["direction"].(string); ok {
		direction = d
	}

	a.logger.Info().
		Str("ip", ipStr).
		Int("duration", duration).
		Str("direction", direction).
		Msg("Blocking IP address")

	firewall, err := platform.GetFirewall()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting firewall: %w", err)
	}

	if err := firewall.BlockIP(ctx, ipStr, direction); err != nil {
		return types.ActionResult{}, fmt.Errorf("blocking IP: %w", err)
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("Successfully blocked IP %s", ipStr),
		Details: map[string]interface{}{
			"ip_address": ipStr,
			"direction":  direction,
			"duration":   duration,
			"platform":   runtime.GOOS,
		},
	}, nil
}

// UnblockIPAction unblocks an IP address from the firewall.
type UnblockIPAction struct {
	logger zerolog.Logger
}

// NewUnblockIPAction creates a new UnblockIPAction.
func NewUnblockIPAction(logger zerolog.Logger) *UnblockIPAction {
	return &UnblockIPAction{
		logger: logger.With().Str("action", "unblock_ip").Logger(),
	}
}

// Name returns the action name.
func (a *UnblockIPAction) Name() types.ActionType {
	return types.ActionUnblockIP
}

// Validate validates the parameters.
func (a *UnblockIPAction) Validate(params map[string]interface{}) error {
	ipStr, ok := params["ip_address"].(string)
	if !ok || ipStr == "" {
		return fmt.Errorf("ip_address is required")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return nil
}

// Execute unblocks the specified IP address.
func (a *UnblockIPAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	ipStr := params["ip_address"].(string)

	a.logger.Info().Str("ip", ipStr).Msg("Unblocking IP address")

	firewall, err := platform.GetFirewall()
	if err != nil {
		return types.ActionResult{}, fmt.Errorf("getting firewall: %w", err)
	}

	if err := firewall.UnblockIP(ctx, ipStr); err != nil {
		return types.ActionResult{}, fmt.Errorf("unblocking IP: %w", err)
	}

	return types.ActionResult{
		Success: true,
		Message: fmt.Sprintf("Successfully unblocked IP %s", ipStr),
		Details: map[string]interface{}{
			"ip_address": ipStr,
			"platform":   runtime.GOOS,
		},
	}, nil
}
