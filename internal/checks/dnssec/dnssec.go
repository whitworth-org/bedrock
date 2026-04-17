// Package dnssec implements DNSSEC chain, algorithm, and NSEC3 checks.
//
// Backed by RFC 4033/4034/4035 (core), 4509 (SHA-256 DS), 5011 (auto trust
// anchors), 5155 (NSEC3), 6605 (ECDSA), 6781 (operational), 8624 (algorithm
// requirements), 3658 (delegation signer).
package dnssec

import "github.com/rwhitworth/bedrock/internal/registry"

// init registers the DNSSEC checks. Order is meaningful only because the
// chain check primes a per-run cache (DS, DNSKEY) that the algorithm and
// NSEC checks consume — the registry runs checks within a category
// sequentially, so this ordering is deterministic.
func init() {
	registry.Register(chainCheck{})
	registry.Register(algorithmsCheck{})
	registry.Register(nsecCheck{})
}

const category = "DNSSEC"

// Cache keys shared between the dnssec checks (private to this package).
const (
	cacheKeyDS     = "dnssec.ds"     // []*dns.DS
	cacheKeyDNSKEY = "dnssec.dnskey" // []*dns.DNSKEY
	cacheKeySigned = "dnssec.signed" // bool — true when both DS and DNSKEY present
)
