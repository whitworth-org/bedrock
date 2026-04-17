package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

// SOA negative-cache TTL bounds. RFC 2308 §5 recommends "1 hour to 1 day"
// (3600..86400 s). Values outside this range are flagged Warn (still
// functional, just operationally suboptimal).
const (
	soaMinNegTTL  = 3600    // 1 hour
	soaMaxNegTTL  = 86400   // 1 day
	soaMaxRefresh = 86400   // 1 day — RFC 1912 §2.2 suggests 20m..2h, allow up to a day
	soaMinRefresh = 1200    // 20 minutes
	soaMaxExpire  = 2419200 // 28 days; RFC 1912 §2.2 says 2-4 weeks
	soaMinExpire  = 1209600 // 14 days
)

// zoneCheck verifies SOA presence and that its timer values match the
// recommendations in RFC 1912 §2.2 / RFC 2308 §5. The SOA MNAME / NS-set
// consistency check is folded in here because we already have the SOA.
type zoneCheck struct{}

func (zoneCheck) ID() string       { return "dns.zone.soa" }
func (zoneCheck) Category() string { return category }

func (zoneCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	soa, err := env.DNS.LookupSOA(ctx, env.Target)
	if err != nil {
		return []report.Result{{
			ID:          "dns.zone.soa",
			Category:    category,
			Title:       "SOA record",
			Status:      report.Fail,
			Evidence:    "lookup error: " + err.Error(),
			Remediation: soaRemediationExample(env.Target),
			RFCRefs:     []string{"RFC 1035 §3.3.13", "RFC 1912 §2.2", "RFC 2308 §5"},
		}}
	}
	if soa == nil {
		return []report.Result{{
			ID:          "dns.zone.soa",
			Category:    category,
			Title:       "SOA record",
			Status:      report.Fail,
			Evidence:    "no SOA returned for apex",
			Remediation: soaRemediationExample(env.Target),
			RFCRefs:     []string{"RFC 1035 §3.3.13", "RFC 1912 §2.2"},
		}}
	}

	results := []report.Result{soaTimers(env.Target, soa)}

	// MNAME / NS-set consistency: the SOA MNAME ("primary master") should
	// itself appear in the apex NS RRset OR be intentionally hidden. We only
	// Warn when it's missing — hidden primaries are a legitimate setup.
	nsList, _ := env.DNS.LookupNS(ctx, env.Target)
	results = append(results, soaMNAMEvsNS(env.Target, soa, nsList))
	return results
}

func soaTimers(target string, soa *probe.SOA) report.Result {
	var problems []string

	// RFC 2308 §5: negative-cache TTL = MIN(SOA.MINIMUM, SOA TTL). We can
	// only see MINIMUM here; that's the dominant lever operators tune.
	if soa.Minimum < soaMinNegTTL {
		problems = append(problems, fmt.Sprintf("MINIMUM=%ds < %ds (RFC 2308 §5 recommends ≥1h)", soa.Minimum, soaMinNegTTL))
	} else if soa.Minimum > soaMaxNegTTL {
		problems = append(problems, fmt.Sprintf("MINIMUM=%ds > %ds (RFC 2308 §5 recommends ≤1d)", soa.Minimum, soaMaxNegTTL))
	}
	if soa.Refresh < soaMinRefresh || soa.Refresh > soaMaxRefresh {
		problems = append(problems, fmt.Sprintf("REFRESH=%ds outside %d..%ds (RFC 1912 §2.2)", soa.Refresh, soaMinRefresh, soaMaxRefresh))
	}
	if soa.Expire < soaMinExpire || soa.Expire > soaMaxExpire {
		problems = append(problems, fmt.Sprintf("EXPIRE=%ds outside %d..%ds (RFC 1912 §2.2 suggests 2-4w)", soa.Expire, soaMinExpire, soaMaxExpire))
	}
	// RFC 1912 §2.2: hostmaster mailbox should be sensible.
	if soa.Mbox == "" || !strings.Contains(soa.Mbox, ".") {
		problems = append(problems, "RNAME (hostmaster mailbox) missing or malformed")
	}

	ev := fmt.Sprintf("MNAME=%s RNAME=%s serial=%d refresh=%d retry=%d expire=%d minimum=%d",
		soa.NS, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)

	if len(problems) == 0 {
		return report.Result{
			ID:       "dns.zone.soa",
			Category: category,
			Title:    "SOA timers within RFC 1912 / RFC 2308 recommendations",
			Status:   report.Pass,
			Evidence: ev,
			RFCRefs:  []string{"RFC 1912 §2.2", "RFC 2308 §5"},
		}
	}
	return report.Result{
		ID:          "dns.zone.soa",
		Category:    category,
		Title:       "SOA timer values",
		Status:      report.Warn,
		Evidence:    ev + "; issues: " + strings.Join(problems, "; "),
		Remediation: soaRemediationExample(target),
		RFCRefs:     []string{"RFC 1912 §2.2", "RFC 2308 §5"},
	}
}

func soaMNAMEvsNS(target string, soa *probe.SOA, nsList []string) report.Result {
	if soa.NS == "" {
		return report.Result{
			ID:          "dns.zone.mname",
			Category:    category,
			Title:       "SOA MNAME present",
			Status:      report.Fail,
			Evidence:    "SOA MNAME field is empty",
			Remediation: soaRemediationExample(target),
			RFCRefs:     []string{"RFC 1035 §3.3.13"},
		}
	}
	want := strings.ToLower(strings.TrimSuffix(soa.NS, "."))
	for _, ns := range nsList {
		if strings.EqualFold(strings.TrimSuffix(ns, "."), want) {
			return report.Result{
				ID:       "dns.zone.mname",
				Category: category,
				Title:    "SOA MNAME appears in apex NS RRset",
				Status:   report.Pass,
				Evidence: "MNAME=" + want,
				RFCRefs:  []string{"RFC 1912 §2.2", "RFC 1996"},
			}
		}
	}
	// Hidden-primary setups are common; downgrade to Info, not Warn.
	return report.Result{
		ID:       "dns.zone.mname",
		Category: category,
		Title:    "SOA MNAME not in apex NS RRset (possibly hidden primary)",
		Status:   report.Info,
		Evidence: fmt.Sprintf("MNAME=%s; apex NS=%s", want, strings.Join(nsList, ",")),
		RFCRefs:  []string{"RFC 1996"},
	}
}

func soaRemediationExample(target string) string {
	return fmt.Sprintf(`%s. IN SOA ns1.%s. hostmaster.%s. (
    2026041601   ; serial
    7200         ; refresh (2h)
    3600         ; retry   (1h)
    1209600      ; expire  (2w)
    3600         ; minimum (1h, RFC 2308 negative cache)
)`, target, target, target)
}

// mxCheck verifies the apex either has an MX (RFC 1912 §2.5) or publishes
// the RFC 7505 "Null MX" assertion ("0 ."). Both are valid; missing MX with
// no Null MX is a Warn (operational ambiguity).
type mxCheck struct{}

func (mxCheck) ID() string       { return "dns.zone.mx" }
func (mxCheck) Category() string { return category }

func (mxCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	mx, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil {
		return []report.Result{{
			ID:       "dns.zone.mx",
			Category: category,
			Title:    "Apex MX records",
			Status:   report.Warn,
			Evidence: "lookup error: " + err.Error(),
			RFCRefs:  []string{"RFC 1912 §2.5", "RFC 7505"},
		}}
	}
	if len(mx) == 0 {
		return []report.Result{{
			ID:       "dns.zone.mx",
			Category: category,
			Title:    "Apex MX records",
			Status:   report.Warn,
			Evidence: "no MX records (consider RFC 7505 Null MX if domain does not receive mail)",
			RFCRefs:  []string{"RFC 1912 §2.5", "RFC 7505"},
		}}
	}
	// RFC 7505: Null MX is "0 ." (preference 0, target "."). The host comes
	// back from miekg as "" after we trim the trailing dot.
	if len(mx) == 1 && mx[0].Preference == 0 && (mx[0].Host == "" || mx[0].Host == ".") {
		return []report.Result{{
			ID:       "dns.zone.mx",
			Category: category,
			Title:    "Null MX (RFC 7505) — domain does not accept mail",
			Status:   report.Pass,
			Evidence: "MX 0 .",
			RFCRefs:  []string{"RFC 7505"},
		}}
	}
	var hosts []string
	for _, m := range mx {
		hosts = append(hosts, fmt.Sprintf("%d %s", m.Preference, m.Host))
	}
	return []report.Result{{
		ID:       "dns.zone.mx",
		Category: category,
		Title:    fmt.Sprintf("Apex has %d MX record(s)", len(mx)),
		Status:   report.Pass,
		Evidence: strings.Join(hosts, "; "),
		RFCRefs:  []string{"RFC 1912 §2.5"},
	}}
}
