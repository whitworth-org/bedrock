package dnssec

import (
	"context"
	"fmt"
	"sort"

	mdns "github.com/miekg/dns"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

// algorithmsCheck scores DNSKEY algorithms and DS digest types against
// RFC 8624 §3.1 and §3.3. The chain check has already populated the cache.
type algorithmsCheck struct{}

func (algorithmsCheck) ID() string       { return "dnssec.algorithms" }
func (algorithmsCheck) Category() string { return category }

func (algorithmsCheck) Run(_ context.Context, env *probe.Env) []report.Result {
	signed, _ := env.CacheGet(cacheKeySigned)
	if b, ok := signed.(bool); !ok || !b {
		// Unsigned: nothing to score; chain check already reported Info.
		return nil
	}

	keys := cachedDNSKEYs(env)
	dss := cachedDSs(env)

	out := []report.Result{}

	// DNSKEY algorithm scoring. Reduce to one verdict per distinct algorithm
	// so an operator with multiple keys of the same type sees a single line.
	algs := dedupeUint8(func() []uint8 {
		var a []uint8
		for _, k := range keys {
			a = append(a, k.Algorithm)
		}
		return a
	}())
	for _, alg := range algs {
		score := scoreDNSKEYAlgorithm(alg)
		out = append(out, report.Result{
			ID:       "dnssec.algorithm.dnskey",
			Category: category,
			Title:    fmt.Sprintf("DNSKEY algorithm: %s", algName(alg)),
			Status:   score.Status,
			Evidence: score.Evidence,
			Remediation: func() string {
				if score.Status == report.Fail {
					return "# Re-sign the zone with a modern algorithm:\n" +
						"# ECDSAP256SHA256 (alg 13) or ED25519 (alg 15) per RFC 8624 §3.1."
				}
				return ""
			}(),
			RFCRefs: []string{"RFC 8624 §3.1"},
		})
	}

	// DS digest scoring. RFC 8624 §3.3: SHA-256 MUST, SHA-384 MAY, SHA-1 MUST NOT.
	digests := dedupeUint8(func() []uint8 {
		var d []uint8
		for _, ds := range dss {
			d = append(d, ds.DigestType)
		}
		return d
	}())
	for _, dt := range digests {
		score := scoreDSDigest(dt)
		out = append(out, report.Result{
			ID:       "dnssec.algorithm.ds",
			Category: category,
			Title:    fmt.Sprintf("DS digest type: %s", digestName(dt)),
			Status:   score.Status,
			Evidence: score.Evidence,
			Remediation: func() string {
				if score.Status == report.Fail {
					return "# Replace the DS at your registrar with a SHA-256 (digest type 2)\n" +
						"# variant. Most registrars accept multiple DS records during rollover."
				}
				return ""
			}(),
			RFCRefs: []string{"RFC 8624 §3.3", "RFC 4509"},
		})
	}

	return out
}

// algScore captures the verdict + a short evidence string for a single
// algorithm or digest. Kept as a value type so the lookup tables can be
// declared at package scope.
type algScore struct {
	Status   report.Status
	Evidence string
}

// scoreDNSKEYAlgorithm encodes RFC 8624 §3.1 (DNSKEY algorithms). Verdicts:
//
//	Fail = MUST NOT, Warn = SHOULD NOT / known weak, Pass = MUST/RECOMMENDED.
//
// Algorithms not in the table fall back to Warn (unknown/experimental).
func scoreDNSKEYAlgorithm(alg uint8) algScore {
	switch alg {
	case mdns.RSAMD5:
		return algScore{report.Fail, "RSAMD5 — MUST NOT (RFC 6725, RFC 8624 §3.1)"}
	case mdns.DSA:
		return algScore{report.Fail, "DSA — MUST NOT (RFC 8624 §3.1)"}
	case mdns.RSASHA1:
		return algScore{report.Fail, "RSASHA1 — MUST NOT (SHA-1 broken; RFC 8624 §3.1)"}
	case mdns.DSANSEC3SHA1:
		return algScore{report.Fail, "DSA-NSEC3-SHA1 — MUST NOT (RFC 8624 §3.1)"}
	case mdns.RSASHA1NSEC3SHA1:
		return algScore{report.Fail, "RSASHA1-NSEC3-SHA1 — MUST NOT (SHA-1 broken; RFC 8624 §3.1)"}
	case mdns.RSASHA256:
		return algScore{report.Pass, "RSASHA256 — MUST per RFC 8624 §3.1"}
	case mdns.RSASHA512:
		return algScore{report.Pass, "RSASHA512 — NOT RECOMMENDED for new keys but acceptable (RFC 8624 §3.1)"}
	case mdns.ECCGOST:
		return algScore{report.Fail, "ECC-GOST — MUST NOT (RFC 8624 §3.1)"}
	case mdns.ECDSAP256SHA256:
		return algScore{report.Pass, "ECDSAP256SHA256 — MUST / RECOMMENDED (RFC 8624 §3.1)"}
	case mdns.ECDSAP384SHA384:
		return algScore{report.Pass, "ECDSAP384SHA384 — MAY (RFC 8624 §3.1)"}
	case mdns.ED25519:
		return algScore{report.Pass, "ED25519 — RECOMMENDED (RFC 8624 §3.1, RFC 8080)"}
	case mdns.ED448:
		return algScore{report.Pass, "ED448 — MAY (RFC 8624 §3.1, RFC 8080)"}
	}
	return algScore{report.Warn, fmt.Sprintf("algorithm %d not classified by RFC 8624", alg)}
}

// scoreDSDigest encodes RFC 8624 §3.3 (DS digest types).
func scoreDSDigest(dt uint8) algScore {
	switch dt {
	case mdns.SHA1:
		return algScore{report.Fail, "SHA-1 — MUST NOT (RFC 8624 §3.3)"}
	case mdns.SHA256:
		return algScore{report.Pass, "SHA-256 — MUST (RFC 4509, RFC 8624 §3.3)"}
	case mdns.GOST94:
		return algScore{report.Fail, "GOST R 34.11-94 — MUST NOT (RFC 8624 §3.3)"}
	case mdns.SHA384:
		return algScore{report.Pass, "SHA-384 — MAY (RFC 8624 §3.3)"}
	}
	return algScore{report.Warn, fmt.Sprintf("digest type %d not classified by RFC 8624", dt)}
}

func algName(alg uint8) string {
	if s, ok := mdns.AlgorithmToString[alg]; ok {
		return fmt.Sprintf("%s (%d)", s, alg)
	}
	return fmt.Sprintf("alg %d", alg)
}

func digestName(dt uint8) string {
	if s, ok := mdns.HashToString[dt]; ok {
		return fmt.Sprintf("%s (%d)", s, dt)
	}
	return fmt.Sprintf("digest %d", dt)
}

func cachedDNSKEYs(env *probe.Env) []*mdns.DNSKEY {
	if v, ok := env.CacheGet(cacheKeyDNSKEY); ok {
		if k, ok := v.([]*mdns.DNSKEY); ok {
			return k
		}
	}
	return nil
}

func cachedDSs(env *probe.Env) []*mdns.DS {
	if v, ok := env.CacheGet(cacheKeyDS); ok {
		if d, ok := v.([]*mdns.DS); ok {
			return d
		}
	}
	return nil
}

func dedupeUint8(in []uint8) []uint8 {
	seen := map[uint8]struct{}{}
	var out []uint8
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
