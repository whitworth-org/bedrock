package web

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

const (
	hstsMinAgeFloor = 15552000 // 180 days, RFC 6797 minimum we accept
	hstsOneYear     = 31536000
)

// runHSTS enforces RFC 6797 Strict-Transport-Security on the apex's HTTPS
// root. The embedded profile baseline recommends max-age >= 63072000 (2y);
// we require >= 15552000 (180d) to Pass and warn under 31536000 (1y).
func runHSTS(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.hsts", Category: category,
			Title:    "Strict-Transport-Security",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 6797"},
		}}
	}
	resp, err := getHTTPSRoot(ctx, env)
	if err != nil {
		return []report.Result{rootFetchFailed(ctx, report.Result{
			ID: "web.hsts", Category: category,
			Title:       "Strict-Transport-Security",
			Status:      report.Fail,
			Evidence:    "could not fetch https://" + env.Target + "/",
			Remediation: hstsRemediation(),
			RFCRefs:     []string{"RFC 6797"},
		}, err)}
	}
	if !resp.Verified {
		// Browsers ignore an STS header received over a connection with
		// certificate errors (RFC 6797 §8.1), so it cannot pass here either.
		return []report.Result{chainInvalid(report.Result{
			ID: "web.hsts", Category: category,
			Title:   "Strict-Transport-Security",
			RFCRefs: []string{"RFC 6797 §8.1"},
		})}
	}
	return []report.Result{gradeHSTS(env.Target, resp.Headers.Get("Strict-Transport-Security"))}
}

// gradeHSTS grades hdr, the Strict-Transport-Security header served on
// https://<target>/ over a verified connection.
func gradeHSTS(target, hdr string) report.Result {
	if hdr == "" {
		return report.Result{
			ID: "web.hsts", Category: category,
			Title:       "Strict-Transport-Security present",
			Status:      report.Fail,
			Evidence:    "no Strict-Transport-Security header on https://" + target + "/",
			Remediation: hstsRemediation(),
			RFCRefs:     []string{"RFC 6797 §6.1"},
		}
	}
	parsed := parseHSTS(hdr)
	r := report.Result{
		ID: "web.hsts", Category: category,
		Title:   "Strict-Transport-Security present and well-formed",
		RFCRefs: []string{"RFC 6797 §6.1", "RFC 6797 §6.1.1"},
	}
	if !parsed.hasMaxAge {
		r.Status = report.Fail
		r.Evidence = "HSTS header missing max-age directive: " + report.ClipValue(hdr)
		r.Remediation = hstsRemediation()
		return r
	}
	if parsed.maxAge < hstsMinAgeFloor {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf("max-age=%d (< %d / 180d): %s", parsed.maxAge, hstsMinAgeFloor,
			report.ClipValue(hdr))
		r.Remediation = hstsRemediation()
		return r
	}
	if parsed.maxAge < hstsOneYear {
		r.Status = report.Warn
		r.Evidence = fmt.Sprintf("max-age=%d (< 1y); consider increasing to 31536000+", parsed.maxAge)
		return r
	}
	notes := []string{fmt.Sprintf("max-age=%d", parsed.maxAge)}
	if parsed.includeSubDomains {
		notes = append(notes, "includeSubDomains")
	} else {
		notes = append(notes, "no includeSubDomains")
	}
	if parsed.preload {
		notes = append(notes, "preload")
	}
	r.Status = report.Pass
	r.Evidence = strings.Join(notes, "; ")
	return r
}

type hstsParsed struct {
	hasMaxAge         bool
	maxAge            int64
	includeSubDomains bool
	preload           bool
}

// parseHSTS is permissive about whitespace and case (RFC 6797 §6.1: directive
// names are case-insensitive). Unknown directives are ignored per the spec.
func parseHSTS(h string) hstsParsed {
	out := hstsParsed{}
	for _, raw := range strings.Split(h, ";") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		name := tok
		value := ""
		if i := strings.IndexByte(tok, '='); i >= 0 {
			name = strings.TrimSpace(tok[:i])
			value = strings.TrimSpace(tok[i+1:])
			value = strings.Trim(value, `"`)
		}
		switch strings.ToLower(name) {
		case "max-age":
			n, err := strconv.ParseInt(value, 10, 64)
			if err == nil && n >= 0 {
				out.hasMaxAge = true
				out.maxAge = n
			}
		case "includesubdomains":
			out.includeSubDomains = true
		case "preload":
			out.preload = true
		}
	}
	return out
}

func hstsRemediation() string {
	return "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
}

// rootFetch is the outcome of fetching https://<apex>/.
type rootFetch struct {
	resp *probe.Response
	err  error
}

// getHTTPSRoot returns the response to, or error from, the one GET of
// https://<apex>/ that the hsts, headers, cookies, mixedcontent and http3
// checks share, fetching it on first use, so every check grades the same
// response and a failed fetch is not repeated. A response from
// probe.HTTP.Get's diagnostic retry has Verified false, and what it served
// must not be graded (see chainInvalid).
func getHTTPSRoot(ctx context.Context, env *probe.Env) (*probe.Response, error) {
	f := probe.Shared(env, probe.CacheKeyHTTPSRoot, func() *rootFetch {
		gctx, cancel := env.WithTimeout(ctx)
		defer cancel()
		resp, err := env.HTTP.Get(gctx, "https://"+env.Target+"/")
		return &rootFetch{resp: resp, err: err}
	})
	if f == nil {
		return nil, fmt.Errorf("fetch of https://%s/ %w", env.Target,
			checkutil.ErrSharedProbePanicked)
	}
	return f.resp, f.err
}

// rootFetchFailed grades a failed fetch of the HTTPS root for a check that
// cannot run without it: Inconclusive when the probe could not complete,
// otherwise fail, the check's own failure result, with the error appended
// to its evidence.
func rootFetchFailed(ctx context.Context, fail report.Result, err error) report.Result {
	if checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(fail, err)
	}
	fail.Evidence += ": " + err.Error()
	return fail
}

// chainInvalid returns base as N/A for a check of what a TLS connection
// whose chain did not verify served: the HTTPS root response from
// probe.HTTP.Get's diagnostic retry, or the staple, OCSP and CRL data and
// SCTs that only a verified chain binds to an issuer. Such data is
// unauthenticated, so it is not graded; web.cert.* reports the chain itself.
func chainInvalid(base report.Result) report.Result {
	base.Status = report.NotApplicable
	base.Evidence = "TLS chain invalid; see web.cert.*"
	base.Remediation = ""
	return base
}
