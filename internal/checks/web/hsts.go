package web

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

// hstsCheck enforces RFC 6797 Strict-Transport-Security on the apex's HTTPS
// root. The embedded profile baseline recommends max-age >= 63072000 (2y);
// we require >= 15552000 (180d) to Pass and warn under 31536000 (1y).
type hstsCheck struct{}

func (hstsCheck) ID() string       { return "web.hsts" }
func (hstsCheck) Category() string { return category }

const (
	hstsMinAgeFloor = 15552000 // 180 days, RFC 6797 minimum we accept
	hstsOneYear     = 31536000
)

func (hstsCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.hsts", Category: category,
			Title:    "Strict-Transport-Security",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 6797"},
		}}
	}
	resp := getHTTPSRoot(ctx, env)
	if resp == nil {
		return []report.Result{{
			ID: "web.hsts", Category: category,
			Title:       "Strict-Transport-Security",
			Status:      report.Fail,
			Evidence:    "could not fetch https://" + env.Target + "/",
			Remediation: hstsRemediation(),
			RFCRefs:     []string{"RFC 6797"},
		}}
	}
	hdr := resp.Headers.Get("Strict-Transport-Security")
	if hdr == "" {
		return []report.Result{{
			ID: "web.hsts", Category: category,
			Title:       "Strict-Transport-Security present",
			Status:      report.Fail,
			Evidence:    "no Strict-Transport-Security header on https://" + env.Target + "/",
			Remediation: hstsRemediation(),
			RFCRefs:     []string{"RFC 6797 §6.1"},
		}}
	}
	parsed := parseHSTS(hdr)
	r := report.Result{
		ID: "web.hsts", Category: category,
		Title:    "Strict-Transport-Security present and well-formed",
		Evidence: hdr,
		RFCRefs:  []string{"RFC 6797 §6.1", "RFC 6797 §6.1.1"},
	}
	if !parsed.hasMaxAge {
		r.Status = report.Fail
		r.Evidence = "HSTS header missing max-age directive: " + hdr
		r.Remediation = hstsRemediation()
		return []report.Result{r}
	}
	if parsed.maxAge < hstsMinAgeFloor {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf("max-age=%d (< %d / 180d): %s", parsed.maxAge, hstsMinAgeFloor, hdr)
		r.Remediation = hstsRemediation()
		return []report.Result{r}
	}
	if parsed.maxAge < hstsOneYear {
		r.Status = report.Warn
		r.Evidence = fmt.Sprintf("max-age=%d (< 1y); consider increasing to 31536000+", parsed.maxAge)
		return []report.Result{r}
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
	return []report.Result{r}
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

// getHTTPSRoot fetches https://<apex>/ once and is shared by hsts/headers/
// cookies/mixedcontent — keeps us from issuing N parallel root GETs.
func getHTTPSRoot(ctx context.Context, env *probe.Env) *probe.Response {
	if cached, ok := env.CacheGet("web.https.root"); ok {
		if r, ok := cached.(*probe.Response); ok {
			return r
		}
	}
	gctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	resp, err := env.HTTP.Get(gctx, "https://"+env.Target+"/")
	if err != nil || resp == nil {
		return nil
	}
	env.CachePut("web.https.root", resp)
	return resp
}
