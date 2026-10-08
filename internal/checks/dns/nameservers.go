package dns

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

const (
	// cacheKeyNSList is the probe.Shared key of the apex NS lookup
	// (*nsLookup) that the NS, AXFR and SOA checks share.
	cacheKeyNSList = "dns.ns.list"
	// maxNSExamined and nsLookupConcurrency bound the address lookups of a
	// hostile NS RRset: at most 16 nameservers, 4 at a time.
	maxNSExamined       = 16
	nsLookupConcurrency = 4
)

// runNSCount: RFC 1034/1912 expect ≥2 NS for redundancy.
func runNSCount(ctx context.Context, env *probe.Env) []report.Result {
	ns, err := nameserverList(ctx, env)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{checkutil.Inconclusive(report.Result{
			ID:       "dns.ns.count",
			Category: category,
			Title:    "Apex NS RRset",
			RFCRefs:  []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
		}, err)}
	}
	if err != nil {
		return []report.Result{{
			ID:          "dns.ns.count",
			Category:    category,
			Title:       "Apex NS RRset",
			Status:      report.Fail,
			Evidence:    "NS lookup failed: " + probe.ErrNXDOMAIN.Error(),
			Remediation: "Publish at least two NS records at the apex pointing to authoritative nameservers reachable over IPv4 (and ideally IPv6).",
			RFCRefs:     []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
		}}
	}
	if len(ns) < 2 {
		return []report.Result{{
			ID:          "dns.ns.count",
			Category:    category,
			Title:       "Apex NS RRset has fewer than two nameservers",
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("NS count=%d (%s)", len(ns), strings.Join(ns, ",")),
			Remediation: nsCountRemediation(env.Target),
			RFCRefs:     []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
		}}
	}
	return []report.Result{{
		ID:       "dns.ns.count",
		Category: category,
		Title:    fmt.Sprintf("Apex has %d NS records", len(ns)),
		Status:   report.Pass,
		Evidence: strings.Join(ns, ", "),
		RFCRefs:  []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
	}}
}

func nsCountRemediation(apex string) string {
	return fmt.Sprintf(`%[1]s. IN NS ns1.%[1]s.
%[1]s. IN NS ns2.%[1]s.`, report.InlineValue(apex))
}

// runNSDiversity is a lightweight topology heuristic. Two NS in the same
// IPv4 /24 are a single failure domain. The full ASN check would need an
// external feed (RIPE / Team Cymru), which we deliberately don't take a dep
// on; /24 is a coarse but useful proxy.
func runNSDiversity(ctx context.Context, env *probe.Env) []report.Result {
	base := report.Result{
		ID:       "dns.ns.diversity",
		Category: category,
		Title:    "Nameserver topology diversity",
		RFCRefs:  []string{"RFC 2182 §3.1"},
	}
	ns, err := nameserverList(ctx, env)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{checkutil.Inconclusive(base, err)}
	}
	if len(ns) == 0 {
		base.Status = report.NotApplicable
		base.Evidence = "no NS records resolved"
		return []report.Result{base}
	}
	addrs := lookupNSAddrs(ctx, env, ns, env.DNS.LookupA)
	return []report.Result{gradeDiversity(base, addrs, nsSkippedNote(len(ns)))}
}

// gradeDiversity grades the IPv4 /24 spread of the examined nameservers. A
// nameserver whose lookup failed is listed as such, not as one without an
// address, and when every lookup failed the result is inconclusive.
func gradeDiversity(base report.Result, addrs []nsAddrs, note string) report.Result {
	s := v4SpreadOf(addrs)
	switch {
	case s.failed == len(addrs):
		return checkutil.Inconclusive(base, errors.New(strings.Join(s.missing, "; ")+note))
	case s.resolved == 0:
		base.Title = "No NS resolved to an IPv4 address"
		base.Status = report.Fail
		base.Evidence = strings.Join(s.missing, "; ") + note
		base.Remediation = "Provide A records (glue or in-bailiwick) for every " +
			"authoritative nameserver."
		base.RFCRefs = []string{"RFC 1912 §2.3"}
	case len(s.prefixes) < 2 && s.resolved >= 2:
		base.Title = "All nameservers share a single /24 (single failure domain)"
		base.Status = report.Warn
		base.Evidence = fmt.Sprintf("prefixes=%v", s.prefixes) + note
	default:
		base.Title = fmt.Sprintf("Nameservers span %d distinct /24 prefix(es)", len(s.prefixes))
		base.Status = report.Pass
		base.Evidence = fmt.Sprintf("prefixes=%v", s.prefixes) + note
	}
	return base
}

// v4Spread is what the A lookups of the examined nameservers found.
type v4Spread struct {
	prefixes []string // distinct IPv4 /24s, sorted
	resolved int      // nameservers with an IPv4 address
	failed   int      // lookups that failed
	missing  []string // "<name> (no A)" or "<name> (A lookup failed: <why>)"
}

func v4SpreadOf(addrs []nsAddrs) v4Spread {
	var s v4Spread
	prefixes := map[string]bool{}
	for _, a := range addrs {
		switch {
		case len(a.ips) > 0:
			s.resolved++
			for _, ip := range a.ips {
				if v4 := ip.To4(); v4 != nil {
					prefixes[fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])] = true
				}
			}
		case a.failed():
			s.failed++
			s.missing = append(s.missing, fmt.Sprintf("%s (A lookup failed: %v)", a.name, a.err))
		default:
			s.missing = append(s.missing, a.name+" (no A)")
		}
	}
	s.prefixes = slices.Sorted(maps.Keys(prefixes))
	return s
}

// runNSIPv6: RFC 3596 §1 / current IETF practice — at least one authoritative
// NS should have an AAAA. Not a Fail — IPv6 deployment is still operationally
// optional.
func runNSIPv6(ctx context.Context, env *probe.Env) []report.Result {
	base := report.Result{
		ID:       "dns.ns.ipv6",
		Category: category,
		Title:    "Nameserver IPv6 reachability",
		RFCRefs:  []string{"RFC 3596"},
	}
	ns, err := nameserverList(ctx, env)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{checkutil.Inconclusive(base, err)}
	}
	if len(ns) == 0 {
		base.Status = report.NotApplicable
		base.Evidence = "no NS records resolved"
		return []report.Result{base}
	}
	addrs := lookupNSAddrs(ctx, env, ns, env.DNS.LookupAAAA)
	return []report.Result{gradeIPv6(base, addrs, nsSkippedNote(len(ns)))}
}

// gradeIPv6 grades how many of the examined nameservers have an IPv6
// address. A nameserver whose lookup failed is listed as such, not as
// IPv4-only, and when every lookup failed the result is inconclusive.
func gradeIPv6(base report.Result, addrs []nsAddrs, note string) report.Result {
	var withV6, without []string
	failed := 0
	for _, a := range addrs {
		switch {
		case len(a.ips) > 0:
			withV6 = append(withV6, a.name)
		case a.failed():
			failed++
			without = append(without, fmt.Sprintf("%s (AAAA lookup failed: %v)", a.name, a.err))
		default:
			without = append(without, a.name)
		}
	}
	switch {
	case failed == len(addrs):
		return checkutil.Inconclusive(base, errors.New(strings.Join(without, "; ")+note))
	case len(withV6) == 0:
		base.Title = "No nameserver has an IPv6 (AAAA) address"
		base.Status = report.Warn
		base.Evidence = "all NS resolve to IPv4 only: " + strings.Join(without, ",") + note
	default:
		base.Title = fmt.Sprintf("%d/%d nameserver(s) advertise IPv6", len(withV6), len(addrs))
		base.Status = report.Pass
		base.Evidence = "AAAA: " + strings.Join(withV6, ",") + note
	}
	return base
}

// nsLookup is the outcome of the apex NS lookup.
type nsLookup struct {
	names []string // as uniqueNameservers returns them
	err   error
}

// nameserverList returns the apex nameservers as uniqueNameservers returns
// them, or the error of their lookup. The lookup runs once per Env, under
// its own per-operation timeout, however many checks ask concurrently.
func nameserverList(ctx context.Context, env *probe.Env) ([]string, error) {
	l := probe.Shared(env, cacheKeyNSList, func() *nsLookup {
		c, cancel := env.WithTimeout(ctx)
		defer cancel()
		ns, err := env.DNS.LookupNS(c, env.Target)
		if err != nil {
			return &nsLookup{err: fmt.Errorf("NS lookup for %s: %w", env.Target, err)}
		}
		return &nsLookup{names: uniqueNameservers(ns)}
	})
	if l == nil {
		return nil, fmt.Errorf("NS lookup for %s: no result, because the check that ran it "+
			"panicked; see its registry.panic result", env.Target)
	}
	return l.names, l.err
}

// uniqueNameservers returns names lower-cased, without a trailing dot,
// sorted and without duplicates, so NS1.example. and ns1.example are one
// nameserver, examined once and probed once under one ID.
func uniqueNameservers(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.ToLower(strings.TrimSuffix(n, "."))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// nsAddrs is the outcome of one nameserver's address lookup.
type nsAddrs struct {
	name string
	ips  []net.IP
	err  error
}

// failed reports whether the lookup could not tell whether the nameserver
// has addresses. NXDOMAIN is an answer: it has none.
func (a nsAddrs) failed() bool {
	return a.err != nil && !errors.Is(a.err, probe.ErrNXDOMAIN)
}

// lookupNSAddrs resolves the first maxNSExamined names with lookup,
// nsLookupConcurrency at a time and each under its own per-operation
// timeout, and returns the outcomes in names order.
func lookupNSAddrs(
	ctx context.Context, env *probe.Env, names []string,
	lookup func(context.Context, string) ([]net.IP, error),
) []nsAddrs {
	names = names[:min(len(names), maxNSExamined)]
	out := make([]nsAddrs, len(names))
	checkutil.ForEach(len(names), nsLookupConcurrency, func(i int) {
		c, cancel := env.WithTimeout(ctx)
		defer cancel()
		ips, err := lookup(c, names[i])
		out[i] = nsAddrs{name: names[i], ips: ips, err: err}
	})
	return out
}

// nsSkippedNote is the evidence suffix that counts the nameservers beyond
// maxNSExamined, which lookupNSAddrs does not examine, or "" when there are
// none.
func nsSkippedNote(total int) string {
	if total <= maxNSExamined {
		return ""
	}
	return fmt.Sprintf("; %d nameserver(s) beyond the first %d not examined",
		total-maxNSExamined, maxNSExamined)
}
