package dnssec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runNSEC queries a definitely-non-existent name beneath the apex and
// inspects the authority section of the negative answer. NSEC vs NSEC3
// presence (and NSEC3 iteration count + salt length) is reported per
// RFC 5155 + the operational guidance in RFC 9276 (informational): zero
// iterations and an empty salt are now the recommendation.
func runNSEC(ctx context.Context, env *probe.Env) []report.Result {
	ensureChainData(ctx, env)
	signed, _ := env.CacheGet(cacheKeySigned)
	if b, ok := signed.(bool); !ok || !b {
		// Unsigned zones don't publish NSEC/NSEC3 — nothing to evaluate.
		return nil
	}

	cctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	probeName := nonexistentName(env.Target)
	resp, err := env.DNS.ExchangeWithDO(cctx, probeName, mdns.TypeA)
	if err != nil {
		return []report.Result{{
			ID:       "dnssec.nsec.type",
			Category: category,
			Title:    "NSEC/NSEC3 probe failed",
			Status:   report.Warn,
			Evidence: fmt.Sprintf("query %s: %s", probeName, err.Error()),
			RFCRefs:  []string{"RFC 4034 §4", "RFC 5155"},
		}}
	}

	var nsec3 *mdns.NSEC3
	var nsec *mdns.NSEC
	for _, rr := range resp.Ns {
		switch v := rr.(type) {
		case *mdns.NSEC3:
			if nsec3 == nil {
				nsec3 = v
			}
		case *mdns.NSEC:
			if nsec == nil {
				nsec = v
			}
		}
	}

	out := []report.Result{}

	switch {
	case nsec3 != nil:
		out = append(out, report.Result{
			ID:       "dnssec.nsec.type",
			Category: category,
			Title:    "Authenticated denial of existence: NSEC3",
			Status:   report.Pass,
			Evidence: fmt.Sprintf("NSEC3 hash=%s flags=%d salt=%q", hashAlgName(nsec3.Hash), nsec3.Flags, nsec3.Salt),
			RFCRefs:  []string{"RFC 5155"},
		})
		// RFC 9276 §3.1: zero iterations, empty salt is the recommendation.
		// Anything > 0 should be flagged; large counts are abusable for
		// resolver-side hash CPU exhaustion (CVE-2023-50387 style amplification).
		switch {
		case nsec3.Iterations == 0:
			out = append(out, report.Result{
				ID:       "dnssec.nsec3.iterations",
				Category: category,
				Title:    "NSEC3 iterations = 0 (recommended)",
				Status:   report.Pass,
				Evidence: fmt.Sprintf("iterations=%d, salt length=%d", nsec3.Iterations, len(nsec3.Salt)/2),
				RFCRefs:  []string{"RFC 9276 §3.1", "RFC 5155 §5"},
			})
		case nsec3.Iterations <= 100:
			out = append(out, report.Result{
				ID:       "dnssec.nsec3.iterations",
				Category: category,
				Title:    "NSEC3 iterations > 0 (discouraged)",
				Status:   report.Warn,
				Evidence: fmt.Sprintf("iterations=%d (RFC 9276 recommends 0)", nsec3.Iterations),
				RFCRefs:  []string{"RFC 9276 §3.1"},
			})
		default:
			out = append(out, report.Result{
				ID:       "dnssec.nsec3.iterations",
				Category: category,
				Title:    "NSEC3 iterations excessively high",
				Status:   report.Fail,
				Evidence: fmt.Sprintf("iterations=%d; resolvers may treat as insecure (RFC 9276)", nsec3.Iterations),
				Remediation: "# Re-sign the zone with NSEC3 iterations=0 and an empty salt.\n" +
					"# RFC 9276 deprecates extra iterations — they no longer slow down\n" +
					"# offline zone enumeration but do amplify resolver CPU cost.",
				RFCRefs: []string{"RFC 9276 §3.1"},
			})
		}
	case nsec != nil:
		// NSEC is RFC 4034 standard; it does enable trivial zone walking but
		// is otherwise correct. Report as Pass with a note.
		out = append(out, report.Result{
			ID:       "dnssec.nsec.type",
			Category: category,
			Title:    "Authenticated denial of existence: NSEC",
			Status:   report.Pass,
			Evidence: fmt.Sprintf("NSEC next=%s", nsec.NextDomain),
			RFCRefs:  []string{"RFC 4034 §4"},
		})
	default:
		out = append(out, report.Result{
			ID:       "dnssec.nsec.type",
			Category: category,
			Title:    "No NSEC/NSEC3 record in negative response",
			Status:   report.Warn,
			Evidence: fmt.Sprintf("queried %s; authority section had neither NSEC nor NSEC3", probeName),
			RFCRefs:  []string{"RFC 4035 §3.1.3", "RFC 5155 §3"},
		})
	}

	return out
}

// nonexistentName returns a randomized subdomain that is overwhelmingly
// unlikely to exist. We use 8 bytes of randomness — 16 hex chars — which
// is plenty to avoid colliding with real names while staying short enough
// to fit in any zone with sane label limits.
func nonexistentName(apex string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to a fixed string so we still emit
		// a check rather than crashing.
		return "bedrock-nx." + apex
	}
	return "nonexistent-" + hex.EncodeToString(b[:]) + "." + apex
}

func hashAlgName(h uint8) string {
	if s, ok := mdns.HashToString[h]; ok {
		return s
	}
	return fmt.Sprintf("hash-%d", h)
}
