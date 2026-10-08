package dnssec

import (
	"context"
	"fmt"
	"slices"
	"sort"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runAlgorithms scores DNSKEY algorithms and DS digest types against
// RFC 8624 §3.1 and §3.3. ensureChainData fetches the DS+DNSKEY data
// (or returns the cached copy if a sibling check already did).
func runAlgorithms(ctx context.Context, env *probe.Env) []report.Result {
	cd := ensureChainData(ctx, env)
	if !cd.signed {
		// Unsigned: nothing to score; chain check already reported Info.
		return nil
	}
	var algs, digests []uint8
	for _, k := range cd.keySet {
		algs = append(algs, k.Algorithm)
	}
	for _, ds := range cd.dsSet {
		digests = append(digests, ds.DigestType)
	}
	return []report.Result{dnskeyScoring.result(algs), dsScoring.result(digests)}
}

// scoring is one of the RFC 8624 tables runAlgorithms grades against.
type scoring struct {
	id          string
	title       string
	score       func(uint8) algScore
	remediation string // for a FAIL
	rfcRefs     []string
}

var (
	dnskeyScoring = scoring{
		id:    "dnssec.algorithm.dnskey",
		title: "DNSKEY algorithms",
		score: scoreDNSKEYAlgorithm,
		remediation: "# Re-sign the zone with a modern algorithm:\n" +
			"# ECDSAP256SHA256 (alg 13) or ED25519 (alg 15) per RFC 8624 §3.1.",
		rfcRefs: []string{"RFC 8624 §3.1"},
	}
	// RFC 8624 §3.3: SHA-256 MUST, SHA-384 MAY, SHA-1 MUST NOT.
	dsScoring = scoring{
		id:    "dnssec.algorithm.ds",
		title: "DS digest types",
		score: scoreDSDigest,
		remediation: "# Replace the DS at your registrar with a SHA-256 (digest type 2)\n" +
			"# variant. Most registrars accept multiple DS records during rollover.",
		rfcRefs: []string{"RFC 8624 §3.3", "RFC 4509"},
	}
)

// result grades each distinct value and folds the grades into one result
// with the worst status. The evidence lists the verdicts worst first, so its
// bounded list always names the values that set the status.
func (s scoring) result(values []uint8) report.Result {
	var fails, warns, passes []string
	for _, v := range dedupeUint8(values) {
		score := s.score(v)
		switch score.Status {
		case report.Fail:
			fails = append(fails, score.Evidence)
		case report.Warn:
			warns = append(warns, score.Evidence)
		default:
			passes = append(passes, score.Evidence)
		}
	}
	r := report.Result{
		ID:       s.id,
		Category: category,
		Title:    s.title,
		Status:   report.Pass,
		Evidence: checkutil.ListBounded(slices.Concat(fails, warns, passes), "; "),
		RFCRefs:  slices.Clone(s.rfcRefs),
	}
	switch {
	case len(fails) > 0:
		r.Status, r.Remediation = report.Fail, s.remediation
	case len(warns) > 0:
		r.Status = report.Warn
	}
	return r
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
