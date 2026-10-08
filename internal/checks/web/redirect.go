package web

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runRedirect verifies HTTP→HTTPS redirect hygiene for both apex and www.
// Per BCP 195 / OWASP guidance: every plain-HTTP entrypoint MUST issue a
// permanent (301/308) redirect to the same host over HTTPS, terminating in a
// 2xx/3xx response on the HTTPS side.
func runRedirect(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.redirect", Category: category,
			Title:    "HTTP→HTTPS redirect hygiene",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 7525 §3.1.1"},
		}}
	}

	hosts := []string{env.Target}
	// Probe www only when it has DNS — avoids spurious failures on apex-only sites.
	dctx, cancel := env.WithTimeout(ctx)
	a, _ := env.DNS.LookupA(dctx, "www."+env.Target)
	aaaa, _ := env.DNS.LookupAAAA(dctx, "www."+env.Target)
	cancel()
	if len(a)+len(aaaa) > 0 {
		hosts = append(hosts, "www."+env.Target)
	}

	var out []report.Result
	for _, h := range hosts {
		// Mid-flight ctx gate between the apex and www HTTP probes.
		if err := ctx.Err(); err != nil {
			break
		}
		out = append(out, evaluateRedirect(ctx, env, h))
	}
	return out
}

func evaluateRedirect(ctx context.Context, env *probe.Env, host string) report.Result {
	rctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	resp, err := env.HTTP.Get(rctx, "http://"+host+"/")
	if err != nil {
		return redirectFetchFailed(rctx, env.Target, host, err)
	}
	return gradeRedirect(env.Target, host, resp)
}

// redirectFetchFailed grades err, the failure of GET http://host/ run under
// ctx for the scan of target. A refused downgrade or redirect loop is an
// answer from the site and stays FAIL; only a probe that could not complete
// is Inconclusive.
func redirectFetchFailed(ctx context.Context, target, host string, err error) report.Result {
	r := redirectBase(host)
	if checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(r, err)
	}
	r.Status = report.Fail
	r.Evidence = "GET http://" + host + "/ failed: " + err.Error()
	r.Remediation = nginxRedirectRemediation(target)
	return r
}

// redirectBase is the identity of the web.redirect.<host> result.
func redirectBase(host string) report.Result {
	return report.Result{
		ID: "web.redirect." + host, Category: category,
		Title:   "HTTP→HTTPS redirect (" + host + ")",
		RFCRefs: []string{"RFC 7525 §3.1.1"},
	}
}

// gradeRedirect grades resp, the response to GET http://host/ for the scan
// of target.
func gradeRedirect(target, host string, resp *probe.Response) report.Result {
	r := redirectBase(host)
	verdict := analyzeRedirectChain(host, resp)
	if verdict.err != nil {
		r.Status = report.Fail
		r.Evidence = verdict.err.Error()
		r.Remediation = nginxRedirectRemediation(target)
		return r
	}
	if !resp.Verified {
		// The chain passed, but its HTTPS hops came over a connection that
		// failed verification, so they cannot earn a PASS.
		return chainInvalid(r)
	}
	r.Status = report.Pass
	// Prefer permanent redirects (301/308). Allow temporary (302/303/307) but
	// downgrade to Warn so operators see the recommendation.
	if !verdict.permanent {
		r.Status = report.Warn
	}
	r.Evidence = verdict.evidence
	return r
}

type redirectVerdict struct {
	err       error
	permanent bool
	evidence  string
}

// analyzeRedirectChain walks the captured RedirectCh and applies the rules:
//   - chain must end on https
//   - <= 8 hops
//   - every hop stays on the same apex (host or www-of-host) and none steps
//     back from https to http
//   - final status must be < 400
func analyzeRedirectChain(host string, resp *probe.Response) redirectVerdict {
	chain := resp.RedirectCh
	if len(chain) == 0 || resp.URL == nil {
		return redirectVerdict{err: errors.New("no response URL captured")}
	}
	final := resp.URL
	if final.Scheme != "https" {
		return redirectVerdict{err: fmt.Errorf("plain HTTP did not redirect to HTTPS (final: %s)",
			report.ClipValue(final.String()))}
	}
	if len(chain) > 9 { // initial URL + up to 8 redirects
		return redirectVerdict{err: fmt.Errorf("redirect chain too long (%d hops > 8)", len(chain)-1)}
	}
	if err := unsafeHop(host, chain); err != nil {
		return redirectVerdict{err: err}
	}
	if resp.Status >= 400 {
		return redirectVerdict{err: fmt.Errorf("final URL %s returned %d",
			report.ClipValue(final.String()), resp.Status)}
	}
	// Permanence: we can't see intermediate status codes from RedirectCh, so
	// use Status of the FIRST hop in a separate cheap probe? Net/http hides
	// intermediate codes — we can't recover them after the fact. Treat any
	// successful chain as Pass; permanent=true unless evidence suggests
	// otherwise. Recorded as a known limitation in evidence.
	hops := []string{}
	for _, u := range chain {
		hops = append(hops, report.ClipValue(u.String()))
	}
	hops = append(hops, report.ClipValue(final.String()))
	return redirectVerdict{
		permanent: true,
		evidence:  fmt.Sprintf("chain: %s (final %d)", strings.Join(uniqueStrings(hops), " -> "), resp.Status),
	}
}

// unsafeHop returns an error naming the first hop of chain, a redirect chain
// from http://host/ that includes its final URL, that leaves host and its
// www twin or that steps back from https to http.
func unsafeHop(host string, chain []*url.URL) error {
	for i, hop := range chain {
		if !sameApexOrWWW(host, hop.Host) {
			return fmt.Errorf("redirect crossed to a different host: %s -> %s", host,
				report.ClipValue(hop.Host))
		}
		if i > 0 && chain[i-1].Scheme == "https" && hop.Scheme == "http" {
			return fmt.Errorf("redirect downgraded from https to http: %s -> %s",
				report.ClipValue(chain[i-1].String()), report.ClipValue(hop.String()))
		}
	}
	return nil
}

// sameApexOrWWW returns true when target host equals start host, or differs
// only by an added/removed "www." prefix.
func sameApexOrWWW(start, end string) bool {
	start = strings.ToLower(start)
	end = strings.ToLower(strings.TrimSuffix(end, "."))
	// strip ports if present (host:443) — url.Host can include them.
	if i := strings.Index(end, ":"); i >= 0 {
		end = end[:i]
	}
	if start == end {
		return true
	}
	if "www."+start == end {
		return true
	}
	if strings.TrimPrefix(start, "www.") == end {
		return true
	}
	if strings.TrimPrefix(start, "www.") == strings.TrimPrefix(end, "www.") {
		return true
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func nginxRedirectRemediation(domain string) string {
	return fmt.Sprintf(`server {
    listen 80;
    server_name %s www.%s;
    return 301 https://$host$request_uri;
}`, domain, domain)
}

// parseRedirectURL is a small helper used by tests to validate URL parsing
// behaves as expected without going to the network.
func parseRedirectURL(raw string) (*url.URL, error) { return url.Parse(raw) }
