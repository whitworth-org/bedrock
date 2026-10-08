package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
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

// runZoneSOA verifies SOA presence and that its timer values match the
// recommendations in RFC 1912 §2.2 / RFC 2308 §5. The SOA MNAME / NS-set
// consistency check is folded in here because we already have the SOA.
func runZoneSOA(ctx context.Context, env *probe.Env) []report.Result {
	soa, err := lookupZoneSOA(ctx, env)
	var alias *probe.AliasError
	if errors.As(err, &alias) {
		return zoneAliasResults(alias)
	}
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{checkutil.Inconclusive(report.Result{
			ID:       "dns.zone.soa",
			Category: category,
			Title:    "SOA record",
			RFCRefs:  []string{"RFC 1035 §3.3.13", "RFC 1912 §2.2", "RFC 2308 §5"},
		}, fmt.Errorf("SOA lookup for %s: %w", env.Target, err))}
	}
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

	// Mid-flight ctx gate between SOA and NS lookups.
	if err := ctx.Err(); err != nil {
		return results
	}

	// MNAME / NS-set consistency: the SOA MNAME ("primary master") should
	// itself appear in the apex NS RRset OR be intentionally hidden. We only
	// Warn when it's missing — hidden primaries are a legitimate setup. The
	// NS checks report a failed NS lookup, so its error is not repeated here.
	nsList, _ := nameserverList(ctx, env)
	results = append(results, soaMNAMEvsNS(env.Target, soa, nsList))
	return results
}

// lookupZoneSOA looks up the target's SOA. A resolver that flattens CNAME
// chains leaves the alias out of the SOA reply, so when no SOA answers for
// the target it also asks for a CNAME, each lookup with its own timeout.
func lookupZoneSOA(ctx context.Context, env *probe.Env) (*probe.SOA, error) {
	c, cancel := env.WithTimeout(ctx)
	soa, err := env.DNS.LookupSOA(c, env.Target)
	cancel()
	if soa != nil || err != nil {
		return soa, err
	}
	c, cancel = env.WithTimeout(ctx)
	defer cancel()
	target, err := env.DNS.LookupCNAME(c, env.Target)
	switch {
	case err != nil:
		return nil, fmt.Errorf("CNAME lookup: %w", err)
	case target != "":
		return nil, &probe.AliasError{Name: env.Target, Target: target}
	}
	return nil, nil
}

// zoneAliasResults reports a target that is an alias, and so not a zone
// apex: it has no SOA of its own to grade, which is correct, not a fault.
func zoneAliasResults(alias *probe.AliasError) []report.Result {
	evidence := alias.Error() + ", not a zone apex"
	return []report.Result{{
		ID:       "dns.zone.soa",
		Category: category,
		Title:    "SOA record",
		Status:   report.NotApplicable,
		Evidence: evidence,
		RFCRefs:  []string{"RFC 1034 §3.6.2", "RFC 1035 §3.3.13"},
	}, {
		ID:       "dns.zone.mname",
		Category: category,
		Title:    "SOA MNAME appears in apex NS RRset",
		Status:   report.NotApplicable,
		Evidence: evidence,
		RFCRefs:  []string{"RFC 1034 §3.6.2", "RFC 1996"},
	}}
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

// soaRemediationExample keeps the SOA record on one line, because a
// continuation line would start with whitespace. The serial is a
// placeholder: a fixed date could be lower than the zone's live serial.
func soaRemediationExample(target string) string {
	return fmt.Sprintf("; serial <YYYYMMDDnn>, refresh 2h, retry 1h, expire 2w, "+
		"minimum 1h (RFC 2308 negative cache)\n"+
		"%[1]s. IN SOA ns1.%[1]s. hostmaster.%[1]s. <YYYYMMDDnn> 7200 3600 1209600 3600",
		report.InlineValue(target))
}

// runZoneMX verifies the apex either has an MX (RFC 1912 §2.5) or publishes
// the RFC 7505 "Null MX" assertion ("0 ."). Both are valid; missing MX with
// no Null MX is a Warn (operational ambiguity).
func runZoneMX(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	mx, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil {
		return []report.Result{zoneMXLookupFailed(env.Target, err)}
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

// zoneMXLookupFailed grades a failed apex MX lookup: NXDOMAIN says the name
// does not exist, so it stays a WARN; any other failure is inconclusive.
func zoneMXLookupFailed(target string, err error) report.Result {
	res := report.Result{
		ID:       "dns.zone.mx",
		Category: category,
		Title:    "Apex MX records",
		RFCRefs:  []string{"RFC 1912 §2.5", "RFC 7505"},
	}
	if !errors.Is(err, probe.ErrNXDOMAIN) {
		return checkutil.Inconclusive(res, fmt.Errorf("MX lookup for %s: %w", target, err))
	}
	res.Status = report.Warn
	res.Evidence = "lookup error: " + err.Error()
	return res
}
