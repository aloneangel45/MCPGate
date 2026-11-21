package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

// BlockedError represents a policy or SSRF denial with structured audit metadata.
type BlockedError struct {
	Category string
	RuleID   string
	Severity policy.Severity
	Reason   string
	Target   string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%s (%s): %s", e.RuleID, e.Category, e.Reason)
}

var (
	cloudMetadataAddrs = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"), // AWS / GCP / Azure / DO / Oracle IMDS
		netip.MustParseAddr("169.254.170.2"),   // AWS ECS Task Metadata
		netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud Metadata
		netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6 IMDS
	}

	cloudMetadataHosts = []string{
		"metadata.google.internal",
		"metadata.goog",
		"metadata",
		"instance-data",
		"instance-data.ec2.internal",
	}

	privateIPPrefixes = []struct {
		prefix netip.Prefix
		label  string
	}{
		{netip.MustParsePrefix("0.0.0.0/8"), "unspecified network"},
		{netip.MustParsePrefix("127.0.0.0/8"), "IPv4 loopback"},
		{netip.MustParsePrefix("10.0.0.0/8"), "RFC1918 private"},
		{netip.MustParsePrefix("172.16.0.0/12"), "RFC1918 private"},
		{netip.MustParsePrefix("192.168.0.0/16"), "RFC1918 private"},
		{netip.MustParsePrefix("169.254.0.0/16"), "IPv4 link-local"},
		{netip.MustParsePrefix("100.64.0.0/10"), "CGNAT shared address space"},
		{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments"},
		{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking reserved"},
		{netip.MustParsePrefix("240.0.0.0/4"), "IPv4 reserved"},
		{netip.MustParsePrefix("255.255.255.255/32"), "IPv4 limited broadcast"},
		{netip.MustParsePrefix("::/128"), "IPv6 unspecified"},
		{netip.MustParsePrefix("::1/128"), "IPv6 loopback"},
		{netip.MustParsePrefix("fe80::/10"), "IPv6 link-local"},
		{netip.MustParsePrefix("fc00::/7"), "IPv6 unique local (ULA)"},
		{netip.MustParsePrefix("100::/64"), "IPv6 discard-only"},
		{netip.MustParsePrefix("2001:db8::/32"), "IPv6 documentation"},
		{netip.MustParsePrefix("64:ff9b::/96"), "IPv6 NAT64 well-known"},
		{netip.MustParsePrefix("64:ff9b:1::/48"), "IPv6 NAT64 local-use"},
	}

	nat64WellKnownPrefix  = netip.MustParsePrefix("64:ff9b::/96")
	ipv4TranslatedPrefix  = netip.MustParsePrefix("::ffff:0:0:0/96")
	ipv4CompatiblePrefix  = netip.MustParsePrefix("::/96")
	sixToFourPrefix       = netip.MustParsePrefix("2002::/16")
)

// ValidateTargetHost checks whether a hostname directly targets a cloud metadata endpoint.
func ValidateTargetHost(host string, cfg policy.NetworkPolicy) (blocked bool, ruleID string, reason string) {
	clean := normalizeHost(host)
	if clean == "" {
		return true, "MCP04-SSRF-PRIVATE-IP", "empty target hostname"
	}

	if cfg.BlockCloudMetadata {
		for _, meta := range cloudMetadataHosts {
			if clean == meta || strings.HasSuffix(clean, "."+meta) {
				return true, "MCP04-SSRF-METADATA", fmt.Sprintf("target host %q is a protected cloud metadata endpoint", clean)
			}
		}
	}

	return false, "", ""
}

// ValidateTargetIP enforces cloud metadata and private/internal IP SSRF protections.
func ValidateTargetIP(ip net.IP, cfg policy.NetworkPolicy) (blocked bool, ruleID string, reason string) {
	if ip == nil {
		return true, "MCP04-SSRF-PRIVATE-IP", "target IP is nil"
	}

	// Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254 -> 169.254.169.254)
	// so IPv6-mapped syntax cannot bypass IPv4 SSRF controls.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true, "MCP04-SSRF-PRIVATE-IP", fmt.Sprintf("invalid IP address %q", ip.String())
	}
	return validateTargetAddr(addr.Unmap(), cfg)
}

func validateTargetAddr(addr netip.Addr, cfg policy.NetworkPolicy) (blocked bool, ruleID string, reason string) {
	addr = addr.Unmap().WithZone("")

	// Unwrap IPv6 transition/embedded IPv4 representations (NAT64 64:ff9b::/96,
	// IPv4-translated ::ffff:0:0:0/96, IPv4-compatible ::/96, 6to4 2002::/16) so
	// they cannot bypass cloud metadata or private IPv4 SSRF controls.
	if embedded, ok := extractEmbeddedIPv4(addr); ok {
		if b, r, msg := validateTargetAddr(embedded, cfg); b {
			return true, r, fmt.Sprintf("%s (embedded in %s)", msg, addr.String())
		}
	}

	// 1. Cloud metadata endpoints (checked first so metadata IPs get MCP04-SSRF-METADATA).
	if cfg.BlockCloudMetadata {
		for _, meta := range cloudMetadataAddrs {
			if addr == meta {
				return true, "MCP04-SSRF-METADATA", fmt.Sprintf("target IP %s is a protected cloud metadata endpoint", addr.String())
			}
		}
	}

	// 2. Private, loopback, link-local, CGNAT, ULA, and unspecified ranges.
	if cfg.BlockPrivateIPs {
		for _, entry := range privateIPPrefixes {
			if entry.prefix.Contains(addr) {
				return true, "MCP04-SSRF-PRIVATE-IP", fmt.Sprintf("target IP %s is in blocked %s range (%s)", addr.String(), entry.label, entry.prefix.String())
			}
		}
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
			return true, "MCP04-SSRF-PRIVATE-IP", fmt.Sprintf("target IP %s is a blocked non-public address", addr.String())
		}
	}

	return false, "", ""
}

func extractEmbeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64WellKnownPrefix.Contains(addr), ipv4TranslatedPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case ipv4CompatiblePrefix.Contains(addr) && !addr.IsUnspecified() && !addr.IsLoopback():
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFourPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	default:
		return netip.Addr{}, false
	}
}

// resolveAndPinIP resolves host via DNS before dialing, validates EVERY returned IP against
// SSRF rules, and returns a single pinned IP to dial directly (defeating DNS-rebinding attacks).
func resolveAndPinIP(ctx context.Context, resolver *net.Resolver, host string, cfg policy.NetworkPolicy, allowLoopbackForTest bool) (net.IP, *BlockedError, error) {
	clean := normalizeHost(host)

	if blocked, ruleID, reason := ValidateTargetHost(clean, cfg); blocked {
		return nil, &BlockedError{
			Category: "ssrf",
			RuleID:   ruleID,
			Severity: severityForSSRFRule(ruleID),
			Reason:   reason,
			Target:   clean,
		}, nil
	}

	checkIP := func(ip net.IP) *BlockedError {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if allowLoopbackForTest && ip.IsLoopback() {
			return nil
		}
		if blocked, ruleID, reason := ValidateTargetIP(ip, cfg); blocked {
			return &BlockedError{
				Category: "ssrf",
				RuleID:   ruleID,
				Severity: severityForSSRFRule(ruleID),
				Reason:   reason,
				Target:   clean,
			}
		}
		return nil
	}

	// Direct IP literal target (supports IPv4, IPv6, IPv4-mapped IPv6, and IPv6 zone IDs).
	if literal := parseIPLiteral(clean); literal != nil {
		if blockErr := checkIP(literal); blockErr != nil {
			return nil, blockErr, nil
		}
		if v4 := literal.To4(); v4 != nil {
			return v4, nil, nil
		}
		return literal, nil, nil
	}

	// Hostname resolution before dialing.
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupIPAddr(ctx, clean)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve host %q: %w", clean, err)
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("resolve host %q: no IP addresses returned", clean)
	}

	var preferred net.IP
	for _, a := range addrs {
		if blockErr := checkIP(a.IP); blockErr != nil {
			// Reject if ANY resolved address violates SSRF rules.
			return nil, blockErr, nil
		}
		if preferred == nil {
			preferred = a.IP
		}
		if preferred.To4() == nil && a.IP.To4() != nil {
			preferred = a.IP.To4()
		}
	}

	if v4 := preferred.To4(); v4 != nil {
		preferred = v4
	}
	return preferred, nil, nil
}

func parseIPLiteral(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	// Handle RFC 6874 IPv6 zone identifiers (e.g. fe80::1%eth0 or fe80::1%25eth0).
	candidate := host
	if idx := strings.Index(candidate, "%25"); idx >= 0 {
		candidate = candidate[:idx] + "%" + candidate[idx+3:]
	}
	if addr, err := netip.ParseAddr(candidate); err == nil {
		unmapped := addr.Unmap().WithZone("")
		return net.IP(unmapped.AsSlice())
	}
	return nil
}

func normalizeHost(host string) string {
	clean := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(clean); err == nil {
		clean = h
	}
	clean = strings.Trim(clean, "[]")
	clean = strings.TrimRight(clean, ".")
	return clean
}

func severityForSSRFRule(ruleID string) policy.Severity {
	if ruleID == "MCP04-SSRF-METADATA" {
		return policy.SeverityCritical
	}
	return policy.SeverityHigh
}
