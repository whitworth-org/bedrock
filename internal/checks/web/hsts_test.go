package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestParseHSTS(t *testing.T) {
	cases := []struct {
		raw  string
		want hstsParsed
	}{
		{
			raw:  "max-age=31536000; includeSubDomains; preload",
			want: hstsParsed{hasMaxAge: true, maxAge: 31536000, includeSubDomains: true, preload: true},
		},
		{
			raw:  "max-age=15552000",
			want: hstsParsed{hasMaxAge: true, maxAge: 15552000},
		},
		{
			// case-insensitive directive names (RFC 6797 §6.1)
			raw:  "MAX-AGE=600 ; INCLUDESUBDOMAINS",
			want: hstsParsed{hasMaxAge: true, maxAge: 600, includeSubDomains: true},
		},
		{
			raw:  "preload",
			want: hstsParsed{preload: true},
		},
		{
			// max-age value can be quoted
			raw:  `max-age="63072000"; includeSubDomains`,
			want: hstsParsed{hasMaxAge: true, maxAge: 63072000, includeSubDomains: true},
		},
		{
			// negative max-age is invalid
			raw:  "max-age=-1",
			want: hstsParsed{},
		},
	}
	for _, tc := range cases {
		got := parseHSTS(tc.raw)
		if got != tc.want {
			t.Errorf("parseHSTS(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

// rootChecks are the checks that grade the HTTPS root response.
var rootChecks = []struct {
	id  string
	run func(context.Context, *probe.Env) []report.Result
}{
	{"web.hsts", runHSTS},
	{"web.headers", runHeaders},
	{"web.cookies", runCookies},
	{"web.mixedcontent", runMixedContent},
	{"web.http3", runHTTP3},
}

// serveRoot answers with content every root check grades: PASS for HSTS,
// CSP, cookies and Alt-Svc, WARN for the mixed-content image.
func serveRoot(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")
	h.Set("Alt-Svc", `h3=":443"; ma=86400`)
	_, _ = io.WriteString(w, `<img src="http://cdn.example/a.png">`)
}

// TestGradeHSTS: a missing header, a missing max-age and a max-age under
// 180 days FAIL with the header fix; under a year WARNs.
func TestGradeHSTS(t *testing.T) {
	cases := []struct {
		hdr      string
		status   report.Status
		evidence string
	}{
		{"", report.Fail, "no Strict-Transport-Security header on https://example.test/"},
		{"includeSubDomains", report.Fail,
			"HSTS header missing max-age directive: includeSubDomains"},
		{"max-age=15551999", report.Fail,
			"max-age=15551999 (< 15552000 / 180d): max-age=15551999"},
		{"max-age=15552000", report.Warn,
			"max-age=15552000 (< 1y); consider increasing to 31536000+"},
		{"max-age=31536000", report.Pass, "max-age=31536000; no includeSubDomains"},
		{"max-age=31536000; includeSubDomains; preload", report.Pass,
			"max-age=31536000; includeSubDomains; preload"},
	}
	for _, tc := range cases {
		r := gradeHSTS("example.test", tc.hdr)
		wantFix := ""
		if tc.status == report.Fail {
			wantFix = hstsRemediation()
		}
		if r.ID != "web.hsts" || r.Status != tc.status || r.Evidence != tc.evidence ||
			r.Remediation != wantFix {
			t.Errorf("gradeHSTS(%q) = %s %q (remediation %q), want %s %q",
				tc.hdr, r.Status, r.Evidence, r.Remediation, tc.status, tc.evidence)
		}
	}
}

// TestRootChecks_UnverifiedRootIsNotApplicable: a root that came from
// probe.HTTP.Get's diagnostic retry, past a self-signed certificate, is
// unauthenticated, so none of the checks grades it.
func TestRootChecks_UnverifiedRootIsNotApplicable(t *testing.T) {
	srv := startTLSServer(t, http.HandlerFunc(serveRoot), nil, false)
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	env := probe.NewEnv(srv.Listener.Addr().String(), time.Second, true, "")
	for _, c := range rootChecks {
		out := c.run(context.Background(), env)
		if len(out) != 1 || out[0].ID != c.id || out[0].Status != report.NotApplicable ||
			out[0].Evidence != "TLS chain invalid; see web.cert.*" || out[0].Remediation != "" {
			t.Errorf("%s = %+v, want one N/A pointing at web.cert.*", c.id, out)
		}
	}
}

// TestRootChecks_VerifiedRootIsGraded: the same content over a verified
// chain is graded.
func TestRootChecks_VerifiedRootIsGraded(t *testing.T) {
	// Refuse the HTTP/3 check's QUIC dial to 127.0.0.1 before it is sent.
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	rec := httptest.NewRecorder()
	serveRoot(rec, nil)
	env := probe.NewEnv("127.0.0.1", time.Second, true, "")
	env.CachePut(probe.CacheKeyHTTPSRoot, &rootFetch{resp: &probe.Response{
		Status: http.StatusOK, Headers: rec.Result().Header, Body: rec.Body.Bytes(), Verified: true,
	}})
	want := map[string]report.Status{
		"web.hsts": report.Pass, "web.headers": report.Pass, "web.cookies": report.Pass,
		"web.mixedcontent": report.Warn, "web.http3": report.Pass,
	}
	for _, c := range rootChecks {
		if r := c.run(context.Background(), env)[0]; r.Status != want[c.id] {
			t.Errorf("%s: first result %s = %s %q, want %s", c.id, r.ID, r.Status, r.Evidence,
				want[c.id])
		}
	}
}

// TestRootChecks_FetchFailures: hsts and headers, which need the root, are
// inconclusive when the fetch could not complete and FAIL on other errors;
// the informational checks stay INFO. Every result quotes the error.
func TestRootChecks_FetchFailures(t *testing.T) {
	tarpit := func(t *testing.T) string { addr, _ := tarpitListener(t); return addr.String() }
	refused := func(t *testing.T) string { return "127.0.0.1:" + closedPort(t) }
	const short = 200 * time.Millisecond
	cases := []struct {
		name, override string
		target         func(*testing.T) string
		timeout        time.Duration
		detail         string
		strict         report.Status // web.hsts and web.headers
	}{
		{"blocked by the SSRF denylist", "", tarpit, short, "ssrf dial: refusing 127.0.0.1",
			wantInconclusive},
		{"timed out", "1", tarpit, short, `Get "https://127.0.0.1:`, wantInconclusive},
		{"connection refused", "1", refused, refusedDialTimeout, "refused", report.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", tc.override)
			target := tc.target(t)
			env := probe.NewEnv(target, tc.timeout, true, "")
			for _, c := range rootChecks {
				r := c.run(context.Background(), env)[0]
				assertRootFetchFailure(t, r, target, tc.detail, tc.strict)
			}
		})
	}
}

// assertRootFetchFailure checks r, the first result of a root check whose
// fetch of https://target/ failed with an error naming detail. strict is
// the status web.hsts and web.headers must report.
func assertRootFetchFailure(
	t *testing.T, r report.Result, target, detail string, strict report.Status,
) {
	t.Helper()
	if r.ID != "web.hsts" && r.ID != "web.headers" {
		assertFetchFailure(t, r, report.Info, target, detail)
		return
	}
	if strict == wantInconclusive {
		assertInconclusive(t, r, detail)
		return
	}
	assertFetchFailure(t, r, strict, target, detail)
	if r.Remediation == "" {
		t.Errorf("%s = %s %q, want a remediation", r.ID, r.Status, r.Evidence)
	}
}

// assertFetchFailure checks that r has status and quotes both the failed
// fetch of https://target/ and detail, the error.
func assertFetchFailure(
	t *testing.T, r report.Result, status report.Status, target, detail string,
) {
	t.Helper()
	fetchFailed := "could not fetch https://" + target + "/: "
	if r.Status != status || !strings.Contains(r.Evidence, fetchFailed) ||
		!strings.Contains(r.Evidence, detail) {
		t.Errorf("%s = %s %q, want %s quoting %q", r.ID, r.Status, r.Evidence, status, detail)
	}
}

// TestGetHTTPSRoot_OneFetchPerScan: the root checks, released together,
// share one fetch of https://<apex>/, whether it returns a response or an
// error.
func TestGetHTTPSRoot_OneFetchPerScan(t *testing.T) {
	t.Run("response", func(t *testing.T) {
		t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
		var gets atomic.Int32
		srv := startTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			gets.Add(1)
			time.Sleep(100 * time.Millisecond) // every check asks before this fetch ends
			serveRoot(w, req)
		}), nil, false)
		env := probe.NewEnv(srv.Listener.Addr().String(), time.Second, true, "")

		runRootChecksTogether(env)
		if n := gets.Load(); n != 1 {
			t.Errorf("%d root checks sent %d GETs, want 1", len(rootChecks), n)
		}
	})
	t.Run("error", func(t *testing.T) {
		t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
		addr, accepted := tarpitListener(t)
		env := probe.NewEnv(addr.String(), 200*time.Millisecond, true, "")

		for _, r := range runRootChecksTogether(env) {
			assertRootFetchFailure(t, r, addr.String(), `Get "https://127.0.0.1:`, wantInconclusive)
		}
		if n := accepted.Load(); n != 1 {
			t.Errorf("%d root checks made %d connections, want 1", len(rootChecks), n)
		}
	})
}

// TestGetHTTPSRoot_ProducerPanicked: when the check that fetched the root
// panicked, hsts and headers are inconclusive and the informational checks
// report the fetch as failed, each pointing at the registry.panic result.
func TestGetHTTPSRoot_ProducerPanicked(t *testing.T) {
	// Refuse the HTTP/3 check's QUIC dial to 127.0.0.1 before it is sent.
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	env := probe.NewEnv("127.0.0.1", time.Second, true, "")
	env.CachePut(probe.CacheKeyHTTPSRoot, "not a fetch") // what Shared yields as nil
	for _, c := range rootChecks {
		r := c.run(context.Background(), env)[0]
		assertRootFetchFailure(t, r, "127.0.0.1", "fetch of https://127.0.0.1/ did not "+
			"complete in another check; see its registry.panic result", wantInconclusive)
	}
}

// runRootChecksTogether releases every root check at once and returns each
// one's first result.
func runRootChecksTogether(env *probe.Env) []report.Result {
	out := make([]report.Result, len(rootChecks))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range rootChecks {
		wg.Go(func() {
			<-start
			out[i] = c.run(context.Background(), env)[0]
		})
	}
	close(start)
	wg.Wait()
	return out
}
