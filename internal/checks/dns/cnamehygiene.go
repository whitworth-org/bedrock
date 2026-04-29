package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// Conservative ceiling. RFC 2181 doesn't fix a number, but RFC 1034 §3.6.2
// and RFC 1912 §2.4 warn that long CNAME chains tickle resolver bugs and
// burn lookup budget. 8 mirrors what major recursors enforce in practice.
const maxCNAMEChain = 8

// runCNAMEApex: RFC 1912 §2.4 / RFC 2181 §10.3 — a CNAME at the apex breaks
// SOA, NS, MX, and DNSSEC RRSIG/DNSKEY semantics.
func runCNAMEApex(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	target, err := env.DNS.LookupCNAME(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID:       "dns.cname.apex",
			Category: category,
			Title:    "CNAME at apex",
			Status:   report.Warn,
			Evidence: "lookup error: " + err.Error(),
			RFCRefs:  []string{"RFC 1912 §2.4", "RFC 2181 §10.3"},
		}}
	}
	if target == "" {
		return []report.Result{{
			ID:       "dns.cname.apex",
			Category: category,
			Title:    "No CNAME at apex (correct)",
			Status:   report.Pass,
			RFCRefs:  []string{"RFC 1912 §2.4", "RFC 2181 §10.3"},
		}}
	}
	return []report.Result{{
		ID:       "dns.cname.apex",
		Category: category,
		Title:    "CNAME present at zone apex (forbidden)",
		Status:   report.Fail,
		Evidence: env.Target + " IN CNAME " + target,
		Remediation: fmt.Sprintf(`# Replace the apex CNAME with concrete RRsets (or use ALIAS/ANAME at the provider).
# Delete:
%s. IN CNAME %s.
# Publish A/AAAA (and re-add MX/NS/SOA as needed):
%s. IN A    <ipv4-of-%s>
%s. IN AAAA <ipv6-of-%s>`, env.Target, target, env.Target, target, env.Target, target),
		RFCRefs: []string{"RFC 1912 §2.4", "RFC 2181 §10.3"},
	}}
}

// runCNAMEChain walks the CNAME chain starting at www.<target>, the most
// common host that operators chain through CDNs. We warn at >maxCNAMEChain
// hops or at a loop. Skipped (NotApplicable) if there is no CNAME at all.
func runCNAMEChain(ctx context.Context, env *probe.Env) []report.Result {
	host := "www." + env.Target

	visited := map[string]bool{}
	chain := []string{host}
	cur := host
	for i := 0; i < maxCNAMEChain+2; i++ {
		// Mid-flight ctx gate so a cancelled scan stops chasing the
		// chain instead of issuing one more doomed lookup per hop.
		if err := ctx.Err(); err != nil {
			return []report.Result{{
				ID:       "dns.cname.chain",
				Category: category,
				Title:    "CNAME chain length (www host)",
				Status:   report.Warn,
				Evidence: "context cancelled at " + cur + ": " + err.Error(),
				RFCRefs:  []string{"RFC 1912 §2.4"},
			}}
		}
		c, cancel := env.WithTimeout(ctx)
		next, err := env.DNS.LookupCNAME(c, cur)
		cancel()
		if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
			return []report.Result{{
				ID:       "dns.cname.chain",
				Category: category,
				Title:    "CNAME chain length (www host)",
				Status:   report.Warn,
				Evidence: "lookup error at " + cur + ": " + err.Error(),
				RFCRefs:  []string{"RFC 1912 §2.4"},
			}}
		}
		if next == "" {
			break
		}
		next = strings.TrimSuffix(strings.ToLower(next), ".")
		if visited[next] {
			return []report.Result{{
				ID:          "dns.cname.chain",
				Category:    category,
				Title:       "CNAME loop detected",
				Status:      report.Fail,
				Evidence:    strings.Join(append(chain, next), " -> "),
				Remediation: "Break the CNAME loop by removing or repointing one of the records in the chain shown above.",
				RFCRefs:     []string{"RFC 1912 §2.4"},
			}}
		}
		visited[next] = true
		chain = append(chain, next)
		cur = next
	}
	if len(chain) == 1 {
		return []report.Result{{
			ID:       "dns.cname.chain",
			Category: category,
			Title:    "No CNAME chain at " + host,
			Status:   report.Info,
			Evidence: host + " is not a CNAME",
			RFCRefs:  []string{"RFC 1912 §2.4"},
		}}
	}
	hops := len(chain) - 1
	if hops > maxCNAMEChain {
		return []report.Result{{
			ID:          "dns.cname.chain",
			Category:    category,
			Title:       fmt.Sprintf("CNAME chain too long (%d hops > %d)", hops, maxCNAMEChain),
			Status:      report.Fail,
			Evidence:    strings.Join(chain, " -> "),
			Remediation: "Collapse the chain by pointing the leftmost name directly at the final target's address records.",
			RFCRefs:     []string{"RFC 1912 §2.4"},
		}}
	}
	return []report.Result{{
		ID:       "dns.cname.chain",
		Category: category,
		Title:    fmt.Sprintf("CNAME chain depth %d for %s", hops, host),
		Status:   report.Pass,
		Evidence: strings.Join(chain, " -> "),
		RFCRefs:  []string{"RFC 1912 §2.4"},
	}}
}
