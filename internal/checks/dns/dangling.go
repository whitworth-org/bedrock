package dns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// danglingCheck looks for dangling-DNS conditions on a small set of common
// host labels. We deliberately stay narrow:
//
//   - CNAME → NXDOMAIN target  (any host) — clear takeover risk; Fail.
//   - CNAME → known-takeover provider (S3/Heroku/GitHub Pages) whose web
//     page shows the canonical "no app / no bucket" marker — Fail.
//   - CNAME → known provider with a marker, but active probing disabled or
//     the page could not be fetched — Warn.
//   - CNAME → known provider without a reliable marker (CloudFront) — Info.
//
// A host whose lookups failed is not checked; the summary says so instead
// of passing.
//
// Hosts probed: the target itself plus a short list of operationally common
// labels. Wider zone-walking would need an AXFR (which RFC 5936 §6 requires
// be REFUSED) or NSEC[3] enumeration.
var danglingHosts = []string{
	"", // apex
	"www",
	"api",
	"blog",
	"shop",
	"docs",
	"status",
	"static",
	"assets",
	"cdn",
	"mail",
	"app",
}

// takeoverPattern is a provider we recognize by the CNAME target's suffix.
// Marker is a short body substring of the page the provider serves for an
// unclaimed name.
type takeoverPattern struct {
	suffix string // matches the CNAME target (lowercased, trailing dot trimmed)
	name   string
	marker string // substring in body when unclaimed; "" means "we cannot disambiguate via HTTP"
}

// takeoverPatterns is intentionally short; adding entries needs evidence
// that the marker is stable and unambiguous.
var takeoverPatterns = []takeoverPattern{
	{".s3.amazonaws.com", "AWS S3", "NoSuchBucket"},
	{".s3-website.amazonaws.com", "AWS S3 website", "NoSuchBucket"},
	{".herokudns.com", "Heroku", "no-such-app.html"},
	{".herokuapp.com", "Heroku", "no-such-app.html"},
	{".github.io", "GitHub Pages", "There isn't a GitHub Pages site here"},
	{".cloudfront.net", "CloudFront", ""}, // no marker: Info, but an NXDOMAIN target Fails
	{".azurewebsites.net", "Azure App Service", "404 Web Site not found"},
}

// markerURL is the address of host's root page over scheme. Only tests
// change it, to send the marker probe to local servers.
var markerURL = func(scheme, host string) string {
	return scheme + "://" + host + "/"
}

// danglingConcurrency caps the hosts the dangling-DNS check probes at once.
// Each host can take four per-operation timeouts: its CNAME and A lookups
// and the marker fetch over HTTPS, then HTTP.
const danglingConcurrency = 4

// danglingOutcome is what danglingForHost found for one host.
type danglingOutcome struct {
	host    string
	finding *report.Result
	err     error
}

func runDangling(ctx context.Context, env *probe.Env) []report.Result {
	outcomes := make([]danglingOutcome, len(danglingHosts))
	checkutil.ForEach(len(danglingHosts), danglingConcurrency, func(i int) {
		o := &outcomes[i]
		o.host = env.Target
		if label := danglingHosts[i]; label != "" {
			o.host = label + "." + env.Target
		}
		o.finding, o.err = danglingForHost(ctx, env, o.host)
	})
	var results []report.Result
	var unchecked []string // "<host>: <why>" for each host that could not be checked
	for _, o := range outcomes {
		if o.err != nil {
			unchecked = append(unchecked, o.host+": "+o.err.Error())
		}
		if o.finding != nil {
			results = append(results, *o.finding)
		}
	}
	if s := danglingSummary(unchecked, len(results)); s != nil {
		results = append(results, *s)
	}
	return results
}

// danglingSummary sums up the run: PASS when every host was checked and none
// had a finding, and inconclusive naming the hosts that could not be checked,
// because a lookup failed or the scan was cancelled (alongside any other
// host's finding). It returns nil when every host was checked and some had
// findings.
func danglingSummary(unchecked []string, findings int) *report.Result {
	r := report.Result{
		ID:       "dns.dangling.summary",
		Category: category,
		RFCRefs:  []string{"RFC 1912 §2.4"},
	}
	switch {
	case len(unchecked) == 0 && findings > 0:
		return nil
	case len(unchecked) == 0:
		r.Title = "No dangling-DNS candidates found among probed hosts"
		r.Status = report.Pass
		r.Evidence = fmt.Sprintf("hosts probed: %s", strings.Join(danglingHosts, ","))
	default:
		r.Title = fmt.Sprintf("%d of %d hosts could not be checked for dangling DNS",
			len(unchecked), len(danglingHosts))
		r = checkutil.Inconclusive(r, errors.New(strings.Join(unchecked, "; ")))
	}
	return &r
}

// danglingForHost checks one host. It returns the host's finding, or nil
// when there is none, and an error when a lookup failed, so the host could
// not be checked. NXDOMAIN is an answer: for host it leaves nothing to
// check, and for the CNAME target it is the cleanest dangling signal there
// is.
func danglingForHost(ctx context.Context, env *probe.Env, host string) (*report.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, cancel := env.WithTimeout(ctx)
	target, err := env.DNS.LookupCNAME(c, host)
	cancel()
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return nil, fmt.Errorf("CNAME lookup: %w", err)
	}
	if target == "" {
		return nil, nil
	}
	target = strings.TrimSuffix(strings.ToLower(target), ".")

	c2, cancel2 := env.WithTimeout(ctx)
	_, err = env.DNS.LookupA(c2, target)
	cancel2()
	switch {
	case errors.Is(err, probe.ErrNXDOMAIN):
		r := danglingResult(host, report.Fail,
			fmt.Sprintf("Dangling CNAME: %s → %s (NXDOMAIN)", host, target),
			fmt.Sprintf("%s IN CNAME %s; target returns NXDOMAIN (orphaned)", host, target))
		r.Remediation = orphanCNAMERemediation(host, target)
		return r, nil
	case err != nil:
		return nil, fmt.Errorf("CNAME target %s: A lookup: %w", target, err)
	}
	return providerCheck(ctx, env, host, target)
}

// providerCheck grades a CNAME whose target resolves into a takeover-prone
// provider's namespace. A provider without a reliable marker is Info with
// or without active probing, since no probe could tell claimed from
// unclaimed.
func providerCheck(
	ctx context.Context, env *probe.Env, host, target string,
) (*report.Result, error) {
	i := slices.IndexFunc(takeoverPatterns, func(p takeoverPattern) bool {
		return strings.HasSuffix(target, p.suffix)
	})
	if i < 0 {
		return nil, nil
	}
	p := takeoverPatterns[i]
	switch {
	case p.marker == "":
		return danglingResult(host, report.Info,
			fmt.Sprintf("%s CNAME present (manual verification recommended)", p.name),
			fmt.Sprintf("%s IN CNAME %s", host, target)), nil
	case !env.Active:
		return danglingResult(host, report.Warn,
			fmt.Sprintf("Possible %s takeover candidate (active probe skipped)", p.name),
			fmt.Sprintf("%s IN CNAME %s; --no-active prevents marker check", host, target)), nil
	}
	return markerProbe(ctx, env, host, target, p)
}

// markerProbe looks for p's unclaimed-resource marker on host's root page,
// fetched over HTTPS. A provider cannot present a certificate for a custom
// domain nobody has claimed, and Get drops the body of a response whose
// certificate did not verify, so then, and when the HTTPS fetch fails (S3
// website endpoints serve no HTTPS), the marker is looked for over plain
// HTTP instead. It returns no finding when the page lacks the marker: the
// resource is most likely claimed.
func markerProbe(
	ctx context.Context, env *probe.Env, host, target string, p takeoverPattern,
) (*report.Result, error) {
	resp, httpsErr := fetchRootPage(ctx, env, "https", host)
	via := "HTTPS"
	if httpsErr != nil || !resp.Verified {
		var httpErr error
		if resp, httpErr = fetchRootPage(ctx, env, "http", host); httpErr != nil {
			r := danglingResult(host, report.Warn, p.name+" CNAME present; marker probe failed",
				host+" IN CNAME "+target)
			return markerFetchFailed(ctx, r, httpsErr, httpErr)
		}
		via = "HTTP"
	}
	if !strings.Contains(string(resp.Body), p.marker) {
		return nil, nil
	}
	r := danglingResult(host, report.Fail,
		fmt.Sprintf("Dangling %s CNAME: %s appears unclaimed", p.name, host),
		fmt.Sprintf("%s IN CNAME %s; %s body matched %q (%s unclaimed)",
			host, target, via, p.marker, p.name))
	r.Remediation = takeoverRemediation(p.name, host, target)
	return r, nil
}

// markerFetchFailed grades r, a marker probe whose plain-HTTP fetch failed
// with httpErr after its HTTPS fetch failed with httpsErr, or, when httpsErr
// is nil, answered behind a certificate that did not verify. A probe the
// scan's cancellation cut short leaves the host unchecked, one that could
// not complete is inconclusive, and any other failure, such as a refused
// connection, is a warning naming both.
func markerFetchFailed(
	ctx context.Context, r *report.Result, httpsErr, httpErr error,
) (*report.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	httpsWhy := "HTTPS certificate did not verify"
	if httpsErr != nil {
		httpsWhy = httpsErr.Error()
	}
	why := fmt.Errorf("%s; %s; %w", r.Evidence, httpsWhy, httpErr)
	if probe.IsProbeFailure(httpsErr) || probe.IsProbeFailure(httpErr) {
		*r = checkutil.Inconclusive(*r, why)
		return r, nil
	}
	r.Evidence = why.Error()
	return r, nil
}

// fetchRootPage GETs host's root page over scheme within one per-operation
// timeout.
func fetchRootPage(
	ctx context.Context, env *probe.Env, scheme, host string,
) (*probe.Response, error) {
	c, cancel := env.WithTimeout(ctx)
	defer cancel()
	return env.HTTP.Get(c, markerURL(scheme, host))
}

// danglingResult is host's result with the fields every one shares.
func danglingResult(host string, status report.Status, title, evidence string) *report.Result {
	return &report.Result{
		ID:       "dns.dangling." + host,
		Category: category,
		Title:    title,
		Status:   status,
		Evidence: evidence,
		RFCRefs:  []string{"RFC 1912 §2.4"},
	}
}

// orphanCNAMERemediation and takeoverRemediation are zone-file snippets:
// every line starts at column 0 and comments use ';' (RFC 1035 §5.1).
func orphanCNAMERemediation(host, target string) string {
	return fmt.Sprintf(`; Remove the orphan record:
%s. IN CNAME %s.   ; DELETE THIS`, report.InlineValue(host), report.InlineValue(target))
}

func takeoverRemediation(provider, host, target string) string {
	provider = report.InlineValue(provider)
	return fmt.Sprintf(`; Either reclaim the %s resource or delete the CNAME:
%s. IN CNAME %s.   ; DELETE THIS if the %s endpoint is no longer in use`,
		provider, report.InlineValue(host), report.InlineValue(target), provider)
}
