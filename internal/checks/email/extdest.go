package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// maxExtDestProbes bounds the consent lookups so a hostile record listing
// dozens of destinations cannot turn the check into a query amplifier.
const maxExtDestProbes = 4

// runDMARCExtDest verifies RFC 9990 external-destination authorization:
// when rua=/ruf= point outside the target's Organizational Domain, the
// destination must consent by publishing a v=DMARC1 record at
// <policy-domain>._report._dmarc.<destination>, or compliant report
// generators will refuse to send there.
func runDMARCExtDest(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.dmarc.extdest"
	const title = "External DMARC report destinations authorized (RFC 9990)"
	refs := []string{"RFC 9990", "RFC 9991"}

	walk := ensureDMARCWalk(ctx, env)
	if walk == nil || walk.Policy == nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no DMARC record; no report destinations to authorize",
			RFCRefs:  refs,
		}}
	}
	dests := reportDestHosts(walk.Policy)
	if len(dests) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no rua= or ruf= destinations published",
			RFCRefs:  refs,
		}}
	}

	org := walk.OrgDomain
	if org == "" {
		org = env.Target
	}
	var external []string
	for _, d := range dests {
		if !isInternalDest(d, org) {
			external = append(external, d)
		}
	}
	if len(external) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "all report destinations are inside the organizational domain " + org,
			RFCRefs:  refs,
		}}
	}
	return []report.Result{extDestVerdict(ctx, env, walk.PolicyDomain, external, refs)}
}

// extDestVerdict probes consent records for the external destinations and
// folds the outcomes into one result.
func extDestVerdict(ctx context.Context, env *probe.Env, policyDomain string,
	external, refs []string) report.Result {
	const id = "email.dmarc.extdest"
	const title = "External DMARC report destinations authorized (RFC 9990)"

	note := ""
	if len(external) > maxExtDestProbes {
		note = fmt.Sprintf("; %d further destination(s) not probed", len(external)-maxExtDestProbes)
		external = external[:maxExtDestProbes]
	}

	var authorized, missing, inconclusive []string
	for _, dest := range external {
		switch ok, err := checkExtDestConsent(ctx, env, policyDomain, dest); {
		case err != nil:
			inconclusive = append(inconclusive, dest+" ("+err.Error()+")")
		case ok:
			authorized = append(authorized, dest)
		default:
			missing = append(missing, dest)
		}
	}

	res := report.Result{ID: id, Category: category, Title: title, RFCRefs: refs}
	switch {
	case len(missing) > 0:
		res.Status = report.Warn
		res.Evidence = fmt.Sprintf(
			"destination(s) have not authorized %s (no v=DMARC1 record at %s._report._dmarc.<dest>): %s"+
				" — compliant receivers will not send reports there%s",
			policyDomain, policyDomain, strings.Join(missing, ", "), note)
		res.Remediation = fmt.Sprintf(
			`%s._report._dmarc.%s. IN TXT "v=DMARC1" (published by the destination operator)`,
			policyDomain, missing[0])
	case len(inconclusive) > 0:
		res.Status = report.Info
		res.Evidence = "authorization lookups inconclusive: " + strings.Join(inconclusive, ", ") + note
	default:
		res.Status = report.Pass
		res.Evidence = fmt.Sprintf("external destination(s) authorized via %s._report._dmarc.<dest>: %s%s",
			policyDomain, strings.Join(authorized, ", "), note)
	}
	return res
}

// checkExtDestConsent looks for the RFC 9990 consent record at
// <policyDomain>._report._dmarc.<dest>.
func checkExtDestConsent(ctx context.Context, env *probe.Env, policyDomain, dest string) (bool, error) {
	lctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	txt, err := env.DNS.LookupTXT(lctx, policyDomain+"._report._dmarc."+dest)
	if errors.Is(err, probe.ErrNXDOMAIN) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(dmarcTXTRecords(txt)) > 0, nil
}

// reportDestHosts extracts the destination hosts from the record's rua= and
// ruf= URIs, deduplicated in record order.
func reportDestHosts(p *DMARC) []string {
	var hosts []string
	seen := map[string]struct{}{}
	for _, uri := range append(append([]string{}, p.Rua...), p.Ruf...) {
		h := destHost(uri)
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	return hosts
}

// destHost pulls the host out of a mailto: or https:// report URI
// (parseReportURIs has already rejected other schemes). The RFC 9990 "!size"
// suffix is stripped before parsing.
func destHost(uri string) string {
	if bang := strings.IndexByte(uri, '!'); bang >= 0 {
		uri = uri[:bang]
	}
	lower := strings.ToLower(strings.TrimSpace(uri))
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		addr := lower[len("mailto:"):]
		if at := strings.LastIndexByte(addr, '@'); at >= 0 && at+1 < len(addr) {
			return addr[at+1:]
		}
	case strings.HasPrefix(lower, "https://"):
		rest := lower[len("https://"):]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		host := rest[:end]
		if c := strings.IndexByte(host, ':'); c >= 0 {
			host = host[:c]
		}
		return host
	}
	return ""
}

// isInternalDest treats a destination as internal when it is the target's
// Organizational Domain or sits beneath it. Deciding the destination's OWN
// org domain would cost a full tree walk (up to 8 queries) per destination;
// the suffix test is the cheap approximation and only ever errs by treating
// a same-org destination as internal, which needs no consent anyway.
func isInternalDest(host, org string) bool {
	return host == org || strings.HasSuffix(host, "."+org)
}
