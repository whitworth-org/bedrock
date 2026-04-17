package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// nsCountCheck: RFC 1034/1912 expect ≥2 NS for redundancy.
type nsCountCheck struct{}

func (nsCountCheck) ID() string       { return "dns.ns.count" }
func (nsCountCheck) Category() string { return category }

func (nsCountCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	ns, err := env.DNS.LookupNS(ctx, env.Target)
	if err != nil {
		return []report.Result{{
			ID:          "dns.ns.count",
			Category:    category,
			Title:       "Apex NS RRset",
			Status:      report.Fail,
			Evidence:    "NS lookup failed: " + err.Error(),
			Remediation: "Publish at least two NS records at the apex pointing to authoritative nameservers reachable over IPv4 (and ideally IPv6).",
			RFCRefs:     []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
		}}
	}
	if len(ns) < 2 {
		return []report.Result{{
			ID:       "dns.ns.count",
			Category: category,
			Title:    "Apex NS RRset has fewer than two nameservers",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("NS count=%d (%s)", len(ns), strings.Join(ns, ",")),
			Remediation: fmt.Sprintf(`%s. IN NS ns1.%s.
%s. IN NS ns2.%s.`, env.Target, env.Target, env.Target, env.Target),
			RFCRefs: []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
		}}
	}
	sort.Strings(ns)
	// Cache for downstream checks (diversity/IPv6) without re-querying.
	env.CachePut("dns.ns.list", ns)
	return []report.Result{{
		ID:       "dns.ns.count",
		Category: category,
		Title:    fmt.Sprintf("Apex has %d NS records", len(ns)),
		Status:   report.Pass,
		Evidence: strings.Join(ns, ", "),
		RFCRefs:  []string{"RFC 1034 §4.1", "RFC 1912 §2.8"},
	}}
}

// nsDiversityCheck: a lightweight topology heuristic. Two NS in the same
// IPv4 /24 are a single failure domain. The full ASN check would need an
// external feed (RIPE / Team Cymru), which we deliberately don't take a dep
// on; /24 is a coarse but useful proxy.
type nsDiversityCheck struct{}

func (nsDiversityCheck) ID() string       { return "dns.ns.diversity" }
func (nsDiversityCheck) Category() string { return category }

func (nsDiversityCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	ns := nameserverList(ctx, env)
	if len(ns) == 0 {
		return []report.Result{{
			ID:       "dns.ns.diversity",
			Category: category,
			Title:    "Nameserver topology diversity",
			Status:   report.NotApplicable,
			Evidence: "no NS records resolved",
			RFCRefs:  []string{"RFC 2182 §3.1"},
		}}
	}

	type host struct {
		name string
		v4s  []net.IP
	}
	var hs []host
	var lameLines []string
	for _, n := range ns {
		c, cancel := env.WithTimeout(ctx)
		ips, err := env.DNS.LookupA(c, n)
		cancel()
		if err != nil || len(ips) == 0 {
			lameLines = append(lameLines, n+" (no A)")
			continue
		}
		hs = append(hs, host{name: n, v4s: ips})
	}
	if len(hs) == 0 {
		return []report.Result{{
			ID:          "dns.ns.diversity",
			Category:    category,
			Title:       "No NS resolved to an IPv4 address",
			Status:      report.Fail,
			Evidence:    strings.Join(lameLines, "; "),
			Remediation: "Provide A records (glue or in-bailiwick) for every authoritative nameserver.",
			RFCRefs:     []string{"RFC 1912 §2.3"},
		}}
	}

	// Group by /24.
	prefixes := map[string][]string{}
	for _, h := range hs {
		for _, ip := range h.v4s {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			key := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
			prefixes[key] = append(prefixes[key], h.name)
		}
	}
	var prefixKeys []string
	for k := range prefixes {
		prefixKeys = append(prefixKeys, k)
	}
	sort.Strings(prefixKeys)

	if len(prefixKeys) < 2 && len(hs) >= 2 {
		return []report.Result{{
			ID:       "dns.ns.diversity",
			Category: category,
			Title:    "All nameservers share a single /24 (single failure domain)",
			Status:   report.Warn,
			Evidence: fmt.Sprintf("prefixes=%v", prefixKeys),
			RFCRefs:  []string{"RFC 2182 §3.1"},
		}}
	}
	return []report.Result{{
		ID:       "dns.ns.diversity",
		Category: category,
		Title:    fmt.Sprintf("Nameservers span %d distinct /24 prefix(es)", len(prefixKeys)),
		Status:   report.Pass,
		Evidence: fmt.Sprintf("prefixes=%v", prefixKeys),
		RFCRefs:  []string{"RFC 2182 §3.1"},
	}}
}

// nsIPv6Check: RFC 3596 §1 / current IETF practice — at least one
// authoritative NS should have an AAAA. Not a Fail — IPv6 deployment is
// still operationally optional.
type nsIPv6Check struct{}

func (nsIPv6Check) ID() string       { return "dns.ns.ipv6" }
func (nsIPv6Check) Category() string { return category }

func (nsIPv6Check) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	ns := nameserverList(ctx, env)
	if len(ns) == 0 {
		return []report.Result{{
			ID:       "dns.ns.ipv6",
			Category: category,
			Title:    "Nameserver IPv6 reachability",
			Status:   report.NotApplicable,
			Evidence: "no NS records resolved",
			RFCRefs:  []string{"RFC 3596"},
		}}
	}

	var withV6, withoutV6 []string
	for _, n := range ns {
		c, cancel := env.WithTimeout(ctx)
		v6, err := env.DNS.LookupAAAA(c, n)
		cancel()
		if err == nil && len(v6) > 0 {
			withV6 = append(withV6, n)
		} else {
			withoutV6 = append(withoutV6, n)
		}
	}
	if len(withV6) == 0 {
		return []report.Result{{
			ID:       "dns.ns.ipv6",
			Category: category,
			Title:    "No nameserver has an IPv6 (AAAA) address",
			Status:   report.Warn,
			Evidence: "all NS resolve to IPv4 only: " + strings.Join(withoutV6, ","),
			RFCRefs:  []string{"RFC 3596"},
		}}
	}
	return []report.Result{{
		ID:       "dns.ns.ipv6",
		Category: category,
		Title:    fmt.Sprintf("%d/%d nameserver(s) advertise IPv6", len(withV6), len(ns)),
		Status:   report.Pass,
		Evidence: "AAAA: " + strings.Join(withV6, ","),
		RFCRefs:  []string{"RFC 3596"},
	}}
}

// nameserverList returns the apex NS list, reading from the cache
// (populated by nsCountCheck) when available so we don't re-query.
func nameserverList(ctx context.Context, env *probe.Env) []string {
	if v, ok := env.CacheGet("dns.ns.list"); ok {
		if ns, ok := v.([]string); ok {
			return ns
		}
	}
	c, cancel := env.WithTimeout(ctx)
	defer cancel()
	ns, err := env.DNS.LookupNS(c, env.Target)
	if err != nil {
		return nil
	}
	sort.Strings(ns)
	env.CachePut("dns.ns.list", ns)
	return ns
}
