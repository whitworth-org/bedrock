package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

// headersCheck inspects the security headers on the apex's HTTPS root.
// CSP is too project-specific to require — Warn if absent. nosniff and
// frame-options (or CSP frame-ancestors) are required.
type headersCheck struct{}

func (headersCheck) ID() string       { return "web.headers" }
func (headersCheck) Category() string { return category }

func (headersCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.headers", Category: category,
			Title:    "Security headers",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"WHATWG Fetch", "RFC 7034"},
		}}
	}
	resp := getHTTPSRoot(ctx, env)
	if resp == nil {
		return []report.Result{{
			ID: "web.headers", Category: category,
			Title:       "Security headers",
			Status:      report.Fail,
			Evidence:    "could not fetch https://" + env.Target + "/",
			Remediation: "ensure HTTPS root returns 2xx so security headers can be inspected",
			RFCRefs:     []string{"WHATWG Fetch"},
		}}
	}
	h := resp.Headers
	return []report.Result{
		cspResult(h),
		nosniffResult(h),
		frameOptionsResult(h),
		referrerPolicyResult(h),
		permissionsPolicyResult(h),
	}
}

func cspResult(h http.Header) report.Result {
	r := report.Result{
		ID: "web.header.csp", Category: category,
		Title:   "Content-Security-Policy header present",
		RFCRefs: []string{"W3C CSP3"},
	}
	v := h.Get("Content-Security-Policy")
	if v == "" {
		r.Status = report.Warn
		r.Evidence = "no Content-Security-Policy header (project-specific; recommend deploying one)"
		return r
	}
	r.Status = report.Pass
	r.Evidence = v
	return r
}

func nosniffResult(h http.Header) report.Result {
	r := report.Result{
		ID: "web.header.x-content-type-options", Category: category,
		Title:   "X-Content-Type-Options: nosniff",
		RFCRefs: []string{"WHATWG Fetch §6.6"},
	}
	v := h.Get("X-Content-Type-Options")
	if !strings.EqualFold(strings.TrimSpace(v), "nosniff") {
		r.Status = report.Fail
		r.Evidence = "X-Content-Type-Options not set to 'nosniff' (got: " + v + ")"
		r.Remediation = "X-Content-Type-Options: nosniff"
		return r
	}
	r.Status = report.Pass
	r.Evidence = "nosniff"
	return r
}

// frameOptionsResult accepts EITHER X-Frame-Options DENY/SAMEORIGIN OR a CSP
// frame-ancestors directive. CSP frame-ancestors supersedes X-Frame-Options
// per the CSP3 spec (W3C: "frame-ancestors obsoletes the X-Frame-Options
// header"), so we don't require both.
func frameOptionsResult(h http.Header) report.Result {
	r := report.Result{
		ID: "web.header.x-frame-options", Category: category,
		Title:   "Clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
		RFCRefs: []string{"RFC 7034", "W3C CSP3 §6.1"},
	}
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	if xfo == "DENY" || xfo == "SAMEORIGIN" {
		r.Status = report.Pass
		r.Evidence = "X-Frame-Options: " + xfo
		return r
	}
	csp := h.Get("Content-Security-Policy")
	if csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		r.Status = report.Pass
		r.Evidence = "CSP frame-ancestors directive present"
		return r
	}
	r.Status = report.Fail
	r.Evidence = "no X-Frame-Options DENY/SAMEORIGIN and no CSP frame-ancestors"
	r.Remediation = "X-Frame-Options: SAMEORIGIN"
	return r
}

func referrerPolicyResult(h http.Header) report.Result {
	r := report.Result{
		ID: "web.header.referrer-policy", Category: category,
		Title:   "Referrer-Policy header present",
		RFCRefs: []string{"W3C Referrer Policy"},
	}
	v := h.Get("Referrer-Policy")
	if v == "" {
		r.Status = report.Warn
		r.Evidence = "no Referrer-Policy header"
		return r
	}
	r.Status = report.Pass
	r.Evidence = v
	return r
}

func permissionsPolicyResult(h http.Header) report.Result {
	r := report.Result{
		ID: "web.header.permissions-policy", Category: category,
		Title:   "Permissions-Policy header present",
		RFCRefs: []string{"W3C Permissions Policy"},
	}
	v := h.Get("Permissions-Policy")
	if v == "" {
		r.Status = report.Info
		r.Evidence = "no Permissions-Policy header (informational)"
		return r
	}
	r.Status = report.Pass
	r.Evidence = v
	return r
}
