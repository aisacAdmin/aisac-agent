package actions

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/pkg/types"
)

// DNSLookupAction performs DNS lookups for investigation.
type DNSLookupAction struct {
	logger zerolog.Logger
}

// NewDNSLookupAction creates a new DNSLookupAction.
func NewDNSLookupAction(logger zerolog.Logger) *DNSLookupAction {
	return &DNSLookupAction{
		logger: logger.With().Str("action", "dns_lookup").Logger(),
	}
}

// Name returns the action name.
func (a *DNSLookupAction) Name() types.ActionType {
	return types.ActionDNSLookup
}

// Validate validates the parameters.
func (a *DNSLookupAction) Validate(params map[string]interface{}) error {
	target, ok := params["target"].(string)
	if !ok || target == "" {
		return fmt.Errorf("target is required (domain or IP)")
	}

	// Validate record types if provided
	if recordTypes, ok := params["record_types"].([]interface{}); ok {
		validTypes := map[string]bool{"A": true, "AAAA": true, "MX": true, "TXT": true, "NS": true, "CNAME": true, "PTR": true}
		for _, rt := range recordTypes {
			rtStr, ok := rt.(string)
			if !ok {
				return fmt.Errorf("record_types must be strings")
			}
			if !validTypes[strings.ToUpper(rtStr)] {
				return fmt.Errorf("invalid record type: %s", rtStr)
			}
		}
	}

	return nil
}

// Execute performs the DNS lookup.
func (a *DNSLookupAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	target := params["target"].(string)

	// Default record types
	recordTypes := []string{"A", "AAAA", "MX", "TXT", "NS"}
	if rt, ok := params["record_types"].([]interface{}); ok {
		recordTypes = make([]string, len(rt))
		for i, r := range rt {
			recordTypes[i] = strings.ToUpper(r.(string))
		}
	}

	a.logger.Info().
		Str("target", target).
		Strs("record_types", recordTypes).
		Msg("Performing DNS lookup")

	results := make(map[string]interface{})
	var errors []string

	// Check if target is an IP (reverse lookup)
	ip := net.ParseIP(target)
	if ip != nil {
		// Reverse DNS lookup
		names, err := net.LookupAddr(target)
		if err != nil {
			errors = append(errors, fmt.Sprintf("PTR lookup failed: %v", err))
		} else {
			results["PTR"] = names
		}
	} else {
		// Forward DNS lookups
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, address)
			},
		}

		for _, recordType := range recordTypes {
			switch recordType {
			case "A":
				ips, err := resolver.LookupIP(ctx, "ip4", target)
				if err != nil {
					errors = append(errors, fmt.Sprintf("A lookup failed: %v", err))
				} else {
					ipStrs := make([]string, len(ips))
					for i, ip := range ips {
						ipStrs[i] = ip.String()
					}
					results["A"] = ipStrs
				}

			case "AAAA":
				ips, err := resolver.LookupIP(ctx, "ip6", target)
				if err != nil {
					errors = append(errors, fmt.Sprintf("AAAA lookup failed: %v", err))
				} else {
					ipStrs := make([]string, len(ips))
					for i, ip := range ips {
						ipStrs[i] = ip.String()
					}
					results["AAAA"] = ipStrs
				}

			case "MX":
				mxs, err := resolver.LookupMX(ctx, target)
				if err != nil {
					errors = append(errors, fmt.Sprintf("MX lookup failed: %v", err))
				} else {
					mxStrs := make([]string, len(mxs))
					for i, mx := range mxs {
						mxStrs[i] = fmt.Sprintf("%d %s", mx.Pref, mx.Host)
					}
					results["MX"] = mxStrs
				}

			case "TXT":
				txts, err := resolver.LookupTXT(ctx, target)
				if err != nil {
					errors = append(errors, fmt.Sprintf("TXT lookup failed: %v", err))
				} else {
					results["TXT"] = txts
				}

			case "NS":
				nss, err := resolver.LookupNS(ctx, target)
				if err != nil {
					errors = append(errors, fmt.Sprintf("NS lookup failed: %v", err))
				} else {
					nsStrs := make([]string, len(nss))
					for i, ns := range nss {
						nsStrs[i] = ns.Host
					}
					results["NS"] = nsStrs
				}

			case "CNAME":
				cname, err := resolver.LookupCNAME(ctx, target)
				if err != nil {
					errors = append(errors, fmt.Sprintf("CNAME lookup failed: %v", err))
				} else {
					results["CNAME"] = cname
				}
			}
		}
	}

	// Determine success based on whether we got any results
	success := len(results) > 0

	return types.ActionResult{
		Success: success,
		Message: fmt.Sprintf("DNS lookup completed for %s", target),
		Details: map[string]interface{}{
			"target":      target,
			"records":     results,
			"errors":      errors,
			"resolved_at": time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}
