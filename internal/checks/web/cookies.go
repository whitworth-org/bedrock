package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

// cookiesCheck enforces Secure / HttpOnly / SameSite on all Set-Cookie
// headers from the apex's HTTPS root. RFC 6265 §4.1.2 defines the
// attributes; modern guidance (BCP 195, OWASP) requires Secure on all
// cookies served over HTTPS, HttpOnly on session cookies, and an explicit
// SameSite to mitigate CSRF.
type cookiesCheck struct{}

func (cookiesCheck) ID() string       { return "web.cookies" }
func (cookiesCheck) Category() string { return category }

func (cookiesCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.cookies", Category: category,
			Title:    "Cookie attributes",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 6265"},
		}}
	}
	resp := getHTTPSRoot(ctx, env)
	if resp == nil {
		return []report.Result{{
			ID: "web.cookies", Category: category,
			Title:    "Cookie attributes",
			Status:   report.Info,
			Evidence: "could not fetch https://" + env.Target + "/",
			RFCRefs:  []string{"RFC 6265"},
		}}
	}
	raws := resp.Headers.Values("Set-Cookie")
	if len(raws) == 0 {
		return []report.Result{{
			ID: "web.cookies", Category: category,
			Title:    "Cookie attributes",
			Status:   report.Info,
			Evidence: "no Set-Cookie headers on https://" + env.Target + "/",
			RFCRefs:  []string{"RFC 6265"},
		}}
	}
	var out []report.Result
	for _, raw := range raws {
		c := parseSetCookie(raw)
		out = append(out, evaluateCookie(c, raw))
	}
	return out
}

// cookieAttrs is the subset of Set-Cookie attributes we care about. We do our
// own parsing rather than using net/http.Response.Cookies because we need to
// see absent attributes too (the stdlib helpfully drops them).
type cookieAttrs struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string // "", "Lax", "Strict", "None"
}

func parseSetCookie(raw string) cookieAttrs {
	c := cookieAttrs{}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return c
	}
	if eq := strings.IndexByte(parts[0], '='); eq >= 0 {
		c.Name = strings.TrimSpace(parts[0][:eq])
	} else {
		c.Name = strings.TrimSpace(parts[0])
	}
	for _, p := range parts[1:] {
		tok := strings.TrimSpace(p)
		name := tok
		value := ""
		if i := strings.IndexByte(tok, '='); i >= 0 {
			name = strings.TrimSpace(tok[:i])
			value = strings.TrimSpace(tok[i+1:])
		}
		switch strings.ToLower(name) {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HTTPOnly = true
		case "samesite":
			c.SameSite = value
		}
	}
	return c
}

// evaluateCookie returns one Result per cookie. JS-readable cookies (heuristic:
// names starting with "__Host-js-") are exempt from HttpOnly.
func evaluateCookie(c cookieAttrs, raw string) report.Result {
	id := "web.cookie." + cookieSlug(c.Name)
	r := report.Result{
		ID: id, Category: category,
		Title:    "Set-Cookie attributes (" + c.Name + ")",
		Evidence: raw,
		RFCRefs:  []string{"RFC 6265 §4.1.2", "RFC 6265bis §4.1.2.5–4.1.2.7"},
	}
	var problems []string
	if !c.Secure {
		problems = append(problems, "missing Secure")
	}
	jsCookie := strings.HasPrefix(c.Name, "__Host-js-")
	if !jsCookie && !c.HTTPOnly {
		problems = append(problems, "missing HttpOnly (cookie not exempt via __Host-js- prefix)")
	}
	switch strings.ToLower(c.SameSite) {
	case "lax", "strict", "none":
		// ok
	default:
		problems = append(problems, "missing or invalid SameSite (need Lax|Strict|None)")
	}
	if len(problems) == 0 {
		r.Status = report.Pass
		return r
	}
	r.Status = report.Fail
	r.Evidence = fmt.Sprintf("%s — %s", strings.Join(problems, ", "), raw)
	r.Remediation = fmt.Sprintf("Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax; Path=/", c.Name)
	return r
}

// cookieSlug normalizes a cookie name into something safe for the result ID
// stream — strips characters that would be ambiguous in IDs.
func cookieSlug(name string) string {
	if name == "" {
		return "anon"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// readSetCookieFromHeader exists to keep tests dependency-free — they construct
// an http.Header literal and pass it through the same parsing path as Run.
func readSetCookieFromHeader(h http.Header) []cookieAttrs {
	var out []cookieAttrs
	for _, raw := range h.Values("Set-Cookie") {
		out = append(out, parseSetCookie(raw))
	}
	return out
}
