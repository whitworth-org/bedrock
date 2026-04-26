// Package dns implements DNS zone and nameserver checks.
//
// Backed by RFC 1034/1035 (core), 1912 (operational), 2181 (clarifications),
// 2308 (negative caching), 3596 (AAAA), 5936 (AXFR), 7505 (Null MX).
// DNSSEC lives in package dnssec.
package dns

import (
	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/registry"
)

// Each check is registered as its own Check so the registry can list them
// individually (and so a single broken probe doesn't suppress the rest).
// checkutil.Wrap collapses the empty-struct + ID/Category/Run shape; the
// per-check logic lives in the Run* functions in the rest of the package.
func init() {
	registry.Register(checkutil.Wrap("dns.zone.soa", category, runZoneSOA))
	registry.Register(checkutil.Wrap("dns.zone.mx", category, runZoneMX))
	registry.Register(checkutil.Wrap("dns.ns.count", category, runNSCount))
	registry.Register(checkutil.Wrap("dns.ns.diversity", category, runNSDiversity))
	registry.Register(checkutil.Wrap("dns.ns.ipv6", category, runNSIPv6))
	registry.Register(checkutil.Wrap("dns.cname.apex", category, runCNAMEApex))
	registry.Register(checkutil.Wrap("dns.cname.chain", category, runCNAMEChain))
	registry.Register(checkutil.Wrap("dns.dangling", category, runDangling))
	registry.Register(checkutil.Wrap("dns.aaaa.apex", category, runAAAAApex))
	registry.Register(checkutil.Wrap("dns.axfr", category, runAXFR))
}

// category returned by every check in this package.
const category = "DNS"
