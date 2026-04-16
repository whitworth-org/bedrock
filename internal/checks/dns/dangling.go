package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

// danglingCheck looks for dangling-DNS conditions on a small set of common
// host labels. We deliberately stay narrow:
//
//   - CNAME → NXDOMAIN target  (any host) — clear takeover risk; Fail.
//   - CNAME → known-takeover provider (S3/Heroku/GitHub Pages) where the
//     active HTTPS probe sees the canonical "no app / no bucket" body — Fail.
//   - CNAME → known provider but active probing disabled or response is
//     ambiguous — Warn.
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

// Provider patterns we recognize. Marker is a short body substring an active
// HTTPS GET would return when the named target is unclaimed. The list is
// intentionally short; adding entries needs evidence that the marker is
// stable and unambiguous.
var takeoverPatterns = []struct {
	suffix string // matches the CNAME target (lowercased, trailing dot trimmed)
	name   string
	marker string // substring in body when unclaimed; "" means "we cannot disambiguate via HTTP"
}{
	{".s3.amazonaws.com", "AWS S3", "NoSuchBucket"},
	{".s3-website.amazonaws.com", "AWS S3 website", "NoSuchBucket"},
	{".herokudns.com", "Heroku", "no-such-app.html"},
	{".herokuapp.com", "Heroku", "no-such-app.html"},
	{".github.io", "GitHub Pages", "There isn't a GitHub Pages site here"},
	{".cloudfront.net", "CloudFront", ""}, // no stable cheap marker; treat as informational on NXDOMAIN only
	{".azurewebsites.net", "Azure App Service", "404 Web Site not found"},
}

type danglingCheck struct{}

func (danglingCheck) ID() string       { return "dns.dangling" }
func (danglingCheck) Category() string { return category }

func (danglingCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	var results []report.Result

	for _, label := range danglingHosts {
		host := env.Target
		if label != "" {
			host = label + "." + env.Target
		}
		if r := danglingForHost(ctx, env, host); r != nil {
			results = append(results, *r)
		}
	}
	if len(results) == 0 {
		results = append(results, report.Result{
			ID:       "dns.dangling.summary",
			Category: category,
			Title:    "No dangling-DNS candidates found among probed hosts",
			Status:   report.Pass,
			Evidence: fmt.Sprintf("hosts probed: %s", strings.Join(danglingHosts, ",")),
			RFCRefs:  []string{"RFC 1912 §2.4"},
		})
	}
	return results
}

func danglingForHost(ctx context.Context, env *probe.Env, host string) *report.Result {
	c, cancel := env.WithTimeout(ctx)
	target, err := env.DNS.LookupCNAME(c, host)
	cancel()
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		// Resolver glitch — don't surface noise.
		return nil
	}
	if target == "" {
		return nil
	}
	target = strings.TrimSuffix(strings.ToLower(target), ".")

	// Resolve the CNAME target. NXDOMAIN at the target is the cleanest
	// dangling signal there is.
	c2, cancel2 := env.WithTimeout(ctx)
	_, aerr := env.DNS.LookupA(c2, target)
	cancel2()
	if errors.Is(aerr, probe.ErrNXDOMAIN) {
		return &report.Result{
			ID:       "dns.dangling." + host,
			Category: category,
			Title:    fmt.Sprintf("Dangling CNAME: %s → %s (NXDOMAIN)", host, target),
			Status:   report.Fail,
			Evidence: fmt.Sprintf("%s IN CNAME %s; target returns NXDOMAIN (orphaned)", host, target),
			Remediation: fmt.Sprintf(`# Remove the orphan record:
%s. IN CNAME %s.   # DELETE THIS`, host, target),
			RFCRefs: []string{"RFC 1912 §2.4"},
		}
	}

	// Match against known takeover-prone providers.
	for _, p := range takeoverPatterns {
		if !strings.HasSuffix(target, p.suffix) {
			continue
		}
		if !env.Active {
			return &report.Result{
				ID:       "dns.dangling." + host,
				Category: category,
				Title:    fmt.Sprintf("Possible %s takeover candidate (active probe skipped)", p.name),
				Status:   report.Warn,
				Evidence: fmt.Sprintf("%s IN CNAME %s; --no-active prevents marker check", host, target),
				RFCRefs:  []string{"RFC 1912 §2.4"},
			}
		}
		if p.marker == "" {
			// No reliable HTTP marker — note it as Info so the operator can verify.
			return &report.Result{
				ID:       "dns.dangling." + host,
				Category: category,
				Title:    fmt.Sprintf("%s CNAME present (manual verification recommended)", p.name),
				Status:   report.Info,
				Evidence: fmt.Sprintf("%s IN CNAME %s", host, target),
				RFCRefs:  []string{"RFC 1912 §2.4"},
			}
		}
		// Active marker check — HEAD won't include the body; do a GET.
		// http.Get follows redirects and caps body at 1 MiB.
		c3, cancel3 := env.WithTimeout(ctx)
		resp, herr := env.HTTP.Get(c3, "https://"+host)
		cancel3()
		if herr != nil || resp == nil {
			return &report.Result{
				ID:       "dns.dangling." + host,
				Category: category,
				Title:    fmt.Sprintf("%s CNAME present; HTTPS probe failed", p.name),
				Status:   report.Warn,
				Evidence: fmt.Sprintf("%s IN CNAME %s; GET https://%s failed", host, target, host),
				RFCRefs:  []string{"RFC 1912 §2.4"},
			}
		}
		if strings.Contains(string(resp.Body), p.marker) {
			return &report.Result{
				ID:       "dns.dangling." + host,
				Category: category,
				Title:    fmt.Sprintf("Dangling %s CNAME: %s appears unclaimed", p.name, host),
				Status:   report.Fail,
				Evidence: fmt.Sprintf("%s IN CNAME %s; HTTPS body matched %q (%s unclaimed)", host, target, p.marker, p.name),
				Remediation: fmt.Sprintf(`# Either reclaim the %s resource or delete the CNAME:
%s. IN CNAME %s.   # DELETE THIS if the %s endpoint is no longer in use`, p.name, host, target, p.name),
				RFCRefs: []string{"RFC 1912 §2.4"},
			}
		}
		// Provider returned content — likely live. Don't spam Pass per host.
		return nil
	}
	return nil
}
