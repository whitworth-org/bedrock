package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// hugeValue stands in for a header value or URL path as long as the
// response-header cap allows.
var hugeValue = strings.Repeat("a", 250<<10)

// assertClipped fails unless r quotes hugeValue only in part: a clipped
// value ends in an ellipsis, and the evidence stays short.
func assertClipped(t *testing.T, r report.Result) {
	t.Helper()
	if len(r.Evidence) > 1024 || !strings.Contains(r.Evidence, "a…") {
		t.Errorf("%s evidence is %d bytes (%.100q), want the long value clipped",
			r.ID, len(r.Evidence), r.Evidence)
	}
}

// TestEvidenceClipsHeaderValues: evidence quotes only the start of a
// response header's value, which the server chooses.
func TestEvidenceClipsHeaderValues(t *testing.T) {
	h := http.Header{}
	for _, name := range []string{
		"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy",
		"Permissions-Policy",
	} {
		h.Set(name, hugeValue)
	}
	for _, r := range []report.Result{
		cspResult(h), nosniffResult(h), referrerPolicyResult(h), permissionsPolicyResult(h),
		gradeHSTS("example.test", "includeSubDomains; "+hugeValue),
		gradeHSTS("example.test", "max-age=60; "+hugeValue),
	} {
		assertClipped(t, r)
	}
}

// TestEvidenceClipsAltSvc: the HTTP/3 check quotes only the start of the
// Alt-Svc header.
func TestEvidenceClipsAltSvc(t *testing.T) {
	// Refuse the QUIC dial to 127.0.0.1 before it is sent.
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	env := probe.NewEnv("127.0.0.1", time.Second, true, "")
	env.CachePut(probe.CacheKeyHTTPSRoot, &rootFetch{resp: &probe.Response{
		Status:   http.StatusOK,
		Headers:  http.Header{"Alt-Svc": {`h3=":443"; ma=86400; x=` + hugeValue}},
		Verified: true,
	}})
	assertClipped(t, runHTTP3(context.Background(), env)[0])
}

// TestEvidenceClipsRedirectURLs: redirect evidence quotes only the start of
// each URL, which the server's Location headers choose.
func TestEvidenceClipsRedirectURLs(t *testing.T) {
	long := mustURL("https://example.com/" + hugeValue)
	plain := mustURL("http://example.com/" + hugeValue)
	for _, resp := range []*probe.Response{
		{Status: 200, URL: long, RedirectCh: []*url.URL{mustURL("http://example.com/"), long}},
		{Status: 200, URL: plain, RedirectCh: []*url.URL{plain}},
		{Status: 404, URL: long, RedirectCh: []*url.URL{mustURL("http://example.com/"), long}},
		{Status: 200, URL: long, RedirectCh: []*url.URL{mustURL("http://example.com/"),
			mustURL("https://www.example.com/" + hugeValue), plain, long}},
		{Status: 200, URL: long, RedirectCh: []*url.URL{mustURL("http://example.com/"),
			mustURL("https://" + hugeValue + ".test/"), long}},
	} {
		resp.Verified = true
		assertClipped(t, gradeRedirect("example.com", "example.com", resp))
	}
}

// TestEvidenceClipsSecurityTxtURL: security.txt evidence quotes only the
// start of the URL a redirect delivered the file from, and of its
// Content-Type.
func TestEvidenceClipsSecurityTxtURL(t *testing.T) {
	env := probe.NewEnv("example.com", time.Second, false, "")
	origin := "https://example.com/.well-known/security.txt"
	body := "Contact: mailto:security@example.com\n" +
		"Expires: " + time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339) + "\n" +
		"Canonical: " + origin + "\n"
	for _, contentType := range []string{
		"text/plain; charset=utf-8", "text/" + hugeValue, "text/plain; charset=" + hugeValue,
	} {
		resp := &probe.Response{
			Status:   http.StatusOK,
			Headers:  http.Header{"Content-Type": {contentType}},
			Body:     []byte(body),
			Verified: true,
			URL:      mustURL("https://example.com/" + hugeValue),
		}
		assertClipped(t, classifySecTxt(context.Background(), env, origin, resp)[0])
	}
}
