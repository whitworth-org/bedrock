// Package dns implements DNS zone and nameserver checks.
//
// Backed by RFC 1034/1035 (core), 1912 (operational), 2181 (clarifications),
// 2308 (negative caching), 3596 (AAAA), 5936 (AXFR), 7505 (Null MX).
// DNSSEC lives in package dnssec.
package dns

import "github.com/whitworth-org/bedrock/internal/registry"

// Each check is registered as its own Check so the registry can list them
// individually (and so a single broken probe doesn't suppress the rest).
func init() {
	registry.Register(zoneCheck{})
	registry.Register(mxCheck{})
	registry.Register(nsCountCheck{})
	registry.Register(nsDiversityCheck{})
	registry.Register(nsIPv6Check{})
	registry.Register(cnameApexCheck{})
	registry.Register(cnameChainCheck{})
	registry.Register(danglingCheck{})
	registry.Register(aaaaApexCheck{})
	registry.Register(axfrCheck{})
}

// category returned by every check in this package.
const category = "DNS"
