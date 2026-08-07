package web

// securitytxt.go implements web.securitytxt: RFC 9116 vulnerability-disclosure
// contact file (security.txt) presence and conformance.
//
// Retrieval is https://<apex>/.well-known/security.txt over verified HTTPS;
// redirects are permitted (§3), unlike the MTA-STS policy fetch. Absence is a
// Warn — publishing security.txt is optional — while a published file that
// breaches a MUST (§2.5, §3) is a Fail and a SHOULD breach is a Warn. Parser
// caps follow the §5.4 hardening guidance: ≤32 KB, ≤1000 lines, ≤2048 bytes
// per field value.

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

const (
	securityTxtID    = "web.securitytxt"
	securityTxtTitle = "security.txt disclosure policy (RFC 9116)"

	maxSecTxtBytes    = 32 << 10
	maxSecTxtLines    = 1000
	maxSecTxtFieldLen = 2048
	// secTxtExpiryHorizon is the §2.5.5 SHOULD: Expires under a year out.
	secTxtExpiryHorizon = 365 * 24 * time.Hour

	pgpSignedHeader    = "-----BEGIN PGP SIGNED MESSAGE-----"
	pgpSignatureHeader = "-----BEGIN PGP SIGNATURE-----"
)

// secTxtWebURIFields are the optional fields whose values, when web URIs,
// MUST use https, each per its own field definition. Encryption legitimately
// uses non-web schemes (dns:, openpgp4fpr:), so only an explicit http://
// value is flagged.
var secTxtWebURIFields = []struct{ name, section string }{
	{"acknowledgments", "§2.5.1"},
	{"canonical", "§2.5.2"},
	{"encryption", "§2.5.4"},
	{"hiring", "§2.5.6"},
	{"policy", "§2.5.7"},
}

// securityTxt is a parsed file: field name (lowercased) → values in order,
// plus whether the file carried an OpenPGP cleartext signature (§2.3).
type securityTxt struct {
	fields map[string][]string
	signed bool
}

func (s *securityTxt) values(name string) []string { return s.fields[name] }

func runSecurityTxt(ctx context.Context, env *probe.Env) []report.Result {
	origin := "https://" + env.Target + "/.well-known/security.txt"
	resp, err := fetchSecTxt(ctx, env, origin)
	if err != nil {
		return secTxtAbsent(ctx, env, origin, "GET failed: "+err.Error())
	}
	if resp.Body == nil {
		// probe.HTTP.Get fell back to its verification-disabled diagnostic
		// retry and dropped the body: the file is not retrievable over
		// verified HTTPS, which §3 requires.
		return []report.Result{secTxtResult(report.Fail,
			origin+" is served with an unverifiable TLS chain; RFC 9116 §3 requires verified HTTPS",
			securityTxtRemediation(env.Target, time.Now()), "RFC 9116 §3")}
	}
	if resp.Status != http.StatusOK {
		return secTxtAbsent(ctx, env, origin, fmt.Sprintf("HTTP %d", resp.Status))
	}
	return classifySecTxt(ctx, env, origin, resp)
}

// classifySecTxt turns a 200 response into the check verdict.
func classifySecTxt(ctx context.Context, env *probe.Env, origin string, resp *probe.Response) []report.Result {
	if resp.Truncated {
		return []report.Result{secTxtResult(report.Fail,
			origin+" exceeds the 1 MiB fetch cap; §5.4 advises rejecting files over 32 KB",
			securityTxtRemediation(env.Target, time.Now()), "RFC 9116 §5.4")}
	}
	ctIssue := secTxtContentTypeIssue(resp.Headers.Get("Content-Type"))
	st, perr := parseSecurityTxt(string(resp.Body))
	if ctIssue != "" && (perr != nil || !looksLikeSecTxt(st)) {
		// Catch-all handlers commonly return HTML 200 for any path; treat
		// that as absent rather than failing a file that was never published.
		return secTxtAbsent(ctx, env, origin, ctIssue)
	}
	if perr != nil {
		return []report.Result{secTxtResult(report.Fail,
			"malformed security.txt at "+origin+": "+perr.Error(),
			securityTxtRemediation(env.Target, time.Now()), "RFC 9116 §4")}
	}
	finalURL := origin
	if resp.URL != nil {
		finalURL = resp.URL.String()
	}
	violations, warnings, summary := evaluateSecTxt(st, finalURL, time.Now())
	if ctIssue != "" {
		violations = append([]string{ctIssue}, violations...)
	}
	if finalURL != origin {
		summary = append(summary, "retrieved via redirect: "+finalURL)
	}
	return []report.Result{secTxtVerdict(env.Target, violations, warnings, summary)}
}

func secTxtVerdict(target string, violations, warnings, summary []string) report.Result {
	if len(violations) > 0 {
		ev := strings.Join(violations, "; ")
		if len(warnings) > 0 {
			ev += "; also: " + strings.Join(warnings, "; ")
		}
		return secTxtResult(report.Fail, ev,
			securityTxtRemediation(target, time.Now()), "RFC 9116 §2.5", "RFC 9116 §3")
	}
	if len(warnings) > 0 {
		return secTxtResult(report.Warn,
			strings.Join(append(warnings, summary...), "; "), "", "RFC 9116 §2.5")
	}
	return secTxtResult(report.Pass, strings.Join(summary, "; "), "", "RFC 9116")
}

// secTxtAbsent reports the Warn for a domain publishing no usable file at the
// well-known path. It probes the legacy top-level path once so a misplaced
// file is called out (§3: /.well-known/ is required; top-level is legacy).
func secTxtAbsent(ctx context.Context, env *probe.Env, origin, reason string) []report.Result {
	legacy := "https://" + env.Target + "/security.txt"
	if resp, err := fetchSecTxt(ctx, env, legacy); err == nil &&
		resp.Status == http.StatusOK && resp.Body != nil {
		if st, perr := parseSecurityTxt(string(resp.Body)); perr == nil && looksLikeSecTxt(st) {
			return []report.Result{secTxtResult(report.Warn,
				"security.txt found only at legacy "+legacy+" ("+origin+": "+reason+
					"); RFC 9116 §3 requires /.well-known/security.txt",
				securityTxtRemediation(env.Target, time.Now()), "RFC 9116 §3")}
		}
	}
	return []report.Result{secTxtResult(report.Warn,
		"no security.txt at "+origin+" ("+reason+")",
		securityTxtRemediation(env.Target, time.Now()), "RFC 9116")}
}

// fetchSecTxt GETs target under its own per-operation timeout (mirrors
// getHTTPSRoot). Redirects are followed and recorded by probe.HTTP.Get.
func fetchSecTxt(ctx context.Context, env *probe.Env, target string) (*probe.Response, error) {
	fctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	return env.HTTP.Get(fctx, target)
}

func secTxtResult(status report.Status, evidence, remediation string, refs ...string) report.Result {
	return report.Result{
		ID: securityTxtID, Category: category, Title: securityTxtTitle,
		Status: status, Evidence: evidence, Remediation: remediation,
		RFCRefs: refs,
	}
}

// looksLikeSecTxt reports whether a parsed body plausibly is a security.txt:
// it defines at least one of the two required fields. Distinguishes a
// catch-all page served at the well-known path from a real, broken file.
func looksLikeSecTxt(st *securityTxt) bool {
	return st != nil && (len(st.values("contact")) > 0 || len(st.values("expires")) > 0)
}

// secTxtContentTypeIssue returns "" when header satisfies the §3 MUST
// (text/plain with a utf-8 charset, charset defaulting when absent).
func secTxtContentTypeIssue(header string) string {
	mt, params, err := mime.ParseMediaType(header)
	if err != nil || mt != "text/plain" {
		return fmt.Sprintf("Content-Type %q; §3 requires text/plain", header)
	}
	if cs, ok := params["charset"]; ok && !strings.EqualFold(cs, "utf-8") {
		return fmt.Sprintf("Content-Type charset %q; §3 requires utf-8", cs)
	}
	return ""
}

// parseSecurityTxt parses body per the §4 grammar. Field names are
// case-insensitive and collected in order; comment (#) and blank lines are
// skipped. An OpenPGP cleartext wrapper is stripped first (§2.3 — the
// signature is noted, never verified).
func parseSecurityTxt(body string) (*securityTxt, error) {
	if len(body) > maxSecTxtBytes {
		return nil, fmt.Errorf("%d bytes exceeds the %d-byte cap (§5.4)", len(body), maxSecTxtBytes)
	}
	body = strings.TrimPrefix(body, "\uFEFF")
	body, signed := stripClearsign(body)
	body = strings.ReplaceAll(body, "\r\n", "\n")
	lines := strings.Split(body, "\n")
	if len(lines) > maxSecTxtLines {
		return nil, fmt.Errorf("%d lines exceeds the %d-line cap (§5.4)", len(lines), maxSecTxtLines)
	}
	st := &securityTxt{fields: map[string][]string{}, signed: signed}
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("line %d is not a \"Field: value\" pair: %.40q", i+1, line)
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if len(value) > maxSecTxtFieldLen {
			return nil, fmt.Errorf("line %d value is %d bytes; cap is %d (§5.4)", i+1, len(value), maxSecTxtFieldLen)
		}
		if value == "" {
			return nil, fmt.Errorf("line %d has an empty value for %q", i+1, name)
		}
		st.fields[name] = append(st.fields[name], value)
	}
	return st, nil
}

// stripClearsign unwraps an RFC 4880 §7 cleartext signature: armor headers up
// to the first blank line are dropped, the trailing signature block is cut,
// and dash-escaped lines are unescaped. Input is returned unchanged when no
// wrapper is present (or the armor lacks the blank line — the field parser
// then rejects the armor lines, which is the right failure).
func stripClearsign(body string) (string, bool) {
	if !strings.HasPrefix(body, pgpSignedHeader) {
		return body, false
	}
	normalized := strings.ReplaceAll(body, "\r\n", "\n")
	_, rest, found := strings.Cut(normalized, "\n\n")
	if !found {
		return body, false
	}
	if i := strings.Index(rest, pgpSignatureHeader); i >= 0 {
		rest = rest[:i]
	}
	lines := strings.Split(rest, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimPrefix(l, "- ")
	}
	return strings.Join(lines, "\n"), true
}

// evaluateSecTxt applies the §2.5 field rules. violations are MUST breaches
// (→ Fail), warnings are SHOULD breaches (→ Warn), summary feeds the Pass
// evidence. now is injected so tests are deterministic.
func evaluateSecTxt(st *securityTxt, finalURL string, now time.Time) (violations, warnings, summary []string) {
	violations = append(violations, secTxtContactIssues(st)...)
	expViol, expWarn, expSummary := secTxtExpiresIssues(st, now)
	violations = append(violations, expViol...)
	warnings = append(warnings, expWarn...)
	violations = append(violations, secTxtWebURIIssues(st)...)
	if n := len(st.values("preferred-languages")); n > 1 {
		violations = append(violations,
			fmt.Sprintf("Preferred-Languages appears %d times; §2.5.8 allows one", n))
	}
	if w := secTxtCanonicalIssue(st, finalURL); w != "" {
		warnings = append(warnings, w)
	}
	if c := st.values("contact"); len(c) > 0 {
		summary = append(summary, "contact: "+c[0])
	}
	summary = append(summary, expSummary...)
	if st.signed {
		summary = append(summary, "OpenPGP clearsigned (signature not verified)")
	}
	return violations, warnings, summary
}

func secTxtContactIssues(st *securityTxt) []string {
	contacts := st.values("contact")
	if len(contacts) == 0 {
		return []string{"missing required Contact field (§2.5.3)"}
	}
	var out []string
	for _, c := range contacts {
		u, err := url.Parse(c)
		switch {
		case err != nil || !u.IsAbs():
			out = append(out, fmt.Sprintf(
				"Contact %q is not an absolute URI — use mailto:, tel: or https:// (§2.5.3)", c))
		case u.Scheme == "http":
			out = append(out, fmt.Sprintf("Contact %q uses http; web URIs must be https (§2.5.3)", c))
		}
	}
	return out
}

func secTxtExpiresIssues(st *securityTxt, now time.Time) (violations, warnings, summary []string) {
	exp := st.values("expires")
	switch len(exp) {
	case 0:
		return []string{"missing required Expires field (§2.5.5)"}, nil, nil
	case 1:
	default:
		return []string{fmt.Sprintf("Expires appears %d times; §2.5.5 allows exactly one", len(exp))}, nil, nil
	}
	// RFC 3339 §5.6 permits lowercase 't'/'z' (github.com publishes one);
	// Go's RFC3339 layout accepts only uppercase. The value is otherwise
	// digits and punctuation, so uppercasing the whole string is lossless.
	t, err := time.Parse(time.RFC3339, strings.ToUpper(exp[0]))
	if err != nil {
		return []string{fmt.Sprintf("Expires %q is not an RFC 3339 timestamp (§2.5.5)", exp[0])}, nil, nil
	}
	switch {
	case t.Before(now):
		return []string{"security.txt expired " + exp[0] + " (§5.3: stale files must not be used)"}, nil, nil
	case t.After(now.Add(secTxtExpiryHorizon)):
		warnings = append(warnings,
			"Expires "+exp[0]+" is more than a year out; §2.5.5 recommends under a year")
	}
	return nil, warnings, []string{"expires: " + exp[0]}
}

func secTxtWebURIIssues(st *securityTxt) []string {
	var out []string
	for _, f := range secTxtWebURIFields {
		for _, v := range st.values(f.name) {
			if strings.HasPrefix(strings.ToLower(v), "http://") {
				out = append(out, fmt.Sprintf("%s %q must begin with https:// (%s)", f.name, v, f.section))
			}
		}
	}
	return out
}

func secTxtCanonicalIssue(st *securityTxt, finalURL string) string {
	canon := st.values("canonical")
	if len(canon) == 0 {
		return ""
	}
	for _, c := range canon {
		if c == finalURL {
			return ""
		}
	}
	return "retrieval URI " + finalURL +
		" is not listed in Canonical; §2.5.2: the file should not be trusted for it"
}

// securityTxtRemediation is a minimal conformant file: the two required
// fields, expiring one year out (§2.5.5 recommends staying under a year).
func securityTxtRemediation(domain string, now time.Time) string {
	return fmt.Sprintf(
		"https://%s/.well-known/security.txt (Content-Type: text/plain; charset=utf-8):\n"+
			"Contact: mailto:security@%s\n"+
			"Expires: %s",
		domain, domain, now.AddDate(1, 0, 0).UTC().Format(time.RFC3339))
}
