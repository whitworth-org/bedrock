package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// cookieRemediation is generic because the evidence names the cookies.
const cookieRemediation = "Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax; Path=/"

// cookieDateLayouts are the Expires formats net/http's cookie parser accepts:
// RFC 1123 and the dashed Netscape form.
var cookieDateLayouts = []string{time.RFC1123, "Mon, 02-Jan-2006 15:04:05 MST"}

// runCookies enforces Secure / HttpOnly / SameSite on all Set-Cookie
// headers from the apex's HTTPS root. RFC 6265 §4.1.2 defines the
// attributes; modern guidance (BCP 195, OWASP) requires Secure on all
// cookies served over HTTPS, HttpOnly on session cookies, and an explicit
// SameSite to mitigate CSRF.
func runCookies(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.cookies", Category: category,
			Title:    "Cookie attributes",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 6265"},
		}}
	}
	resp, err := getHTTPSRoot(ctx, env)
	if err != nil {
		return []report.Result{{
			ID: "web.cookies", Category: category,
			Title:    "Cookie attributes",
			Status:   report.Info,
			Evidence: "could not fetch https://" + env.Target + "/: " + err.Error(),
			RFCRefs:  []string{"RFC 6265"},
		}}
	}
	if !resp.Verified {
		return []report.Result{chainInvalid(report.Result{
			ID: "web.cookies", Category: category,
			Title:   "Cookie attributes",
			RFCRefs: []string{"RFC 6265"},
		})}
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
	return []report.Result{gradeCookies(env.Target, raws, responseTime(resp.Headers))}
}

// responseTime is when the server sent the response, from its Date header,
// or the local time when the header is missing or does not parse. A server
// deletes a cookie by setting Expires to its own clock's time, so judging
// deletions against that clock keeps the local one out of the result.
func responseTime(h http.Header) time.Time {
	if t, err := http.ParseTime(h.Get("Date")); err == nil {
		return t
	}
	return time.Now()
}

// gradeCookies folds the cookies set by raws into one result with the worst
// status. The evidence quotes at most checkutil.MaxListed names and never a
// value, and headers that delete a cookie are skipped.
func gradeCookies(target string, raws []string, now time.Time) report.Result {
	r := report.Result{
		ID: "web.cookies", Category: category,
		Title:   "Cookie attributes",
		RFCRefs: []string{"RFC 6265 §4.1.2", "RFC 6265bis §4.1.2.5–4.1.2.7"},
	}
	var set, lacking []string
	for _, raw := range raws {
		c := parseSetCookie(raw)
		if c.deletes(now) {
			continue
		}
		name := strconv.Quote(report.ClipValue(c.Name))
		set = append(set, name)
		if missing := missingCookieAttrs(c); len(missing) > 0 {
			lacking = append(lacking, name+" ("+strings.Join(missing, ", ")+")")
		}
	}
	note := ""
	if deleted := len(raws) - len(set); deleted > 0 {
		note = fmt.Sprintf("; %d deletion header(s) ignored", deleted)
	}
	switch {
	case len(set) == 0:
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("no cookies set on https://%s/: the %d Set-Cookie header(s) "+
			"only delete cookies", target, len(raws))
	case len(lacking) > 0:
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf("%d of %d cookies lack required attributes: %s%s",
			len(lacking), len(set), checkutil.ListBounded(lacking, ", "), note)
		r.Remediation = cookieRemediation
	default:
		r.Status = report.Pass
		r.Evidence = fmt.Sprintf("%d of %d cookies have the required attributes: %s%s",
			len(set), len(set), checkutil.ListBounded(set, ", "), note)
	}
	return r
}

// cookieAttrs is the subset of Set-Cookie attributes we care about. We do our
// own parsing rather than using net/http.Response.Cookies because we need to
// see absent attributes too (the stdlib helpfully drops them).
type cookieAttrs struct {
	Name      string
	Secure    bool
	HTTPOnly  bool
	SameSite  string    // "", "Lax", "Strict", "None"
	HasMaxAge bool      // a Max-Age value parsed
	MaxAge    int       // seconds from the last Max-Age that parsed
	Expires   time.Time // last Expires that parsed; zero when none did
}

func parseSetCookie(raw string) cookieAttrs {
	nameValue, attrs, _ := strings.Cut(raw, ";")
	name, _, _ := strings.Cut(nameValue, "=")
	c := cookieAttrs{Name: strings.TrimSpace(name)}
	for _, attr := range strings.Split(attrs, ";") {
		key, value, _ := strings.Cut(attr, "=")
		c.set(strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value))
	}
	return c
}

// set records one attribute. A Max-Age or Expires value that does not parse
// is ignored, so an earlier one that did still applies (RFC 6265 §5.2.1,
// §5.2.2).
func (c *cookieAttrs) set(key, value string) {
	switch key {
	case "secure":
		c.Secure = true
	case "httponly":
		c.HTTPOnly = true
	case "samesite":
		c.SameSite = value
	case "max-age":
		if seconds, err := strconv.Atoi(value); err == nil {
			c.HasMaxAge, c.MaxAge = true, seconds
		}
	case "expires":
		if t, ok := parseCookieDate(value); ok {
			c.Expires = t
		}
	}
}

func parseCookieDate(value string) (time.Time, bool) {
	for _, layout := range cookieDateLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// deletes reports whether the header expires the cookie at once instead of
// setting it: a Max-Age of zero or less, or an Expires no later than now.
// Max-Age wins over Expires (RFC 6265 §5.3).
func (c cookieAttrs) deletes(now time.Time) bool {
	if c.HasMaxAge {
		return c.MaxAge <= 0
	}
	return !c.Expires.IsZero() && !c.Expires.After(now)
}

// missingCookieAttrs names the attributes c lacks. A cookie whose name starts
// with "__Host-js-" is meant to be read by scripts, so it needs no HttpOnly.
func missingCookieAttrs(c cookieAttrs) []string {
	var missing []string
	if !c.Secure {
		missing = append(missing, "Secure")
	}
	if !c.HTTPOnly && !strings.HasPrefix(c.Name, "__Host-js-") {
		missing = append(missing, "HttpOnly")
	}
	switch strings.ToLower(c.SameSite) {
	case "lax", "strict", "none":
	default:
		missing = append(missing, "SameSite")
	}
	return missing
}
