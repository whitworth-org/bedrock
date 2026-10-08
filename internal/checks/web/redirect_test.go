package web

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestSameApexOrWWW(t *testing.T) {
	cases := []struct {
		start, end string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"www.example.com", "example.com", true},
		{"www.example.com", "www.example.com", true},
		{"example.com", "evil.com", false},
		{"example.com", "Example.com:443", true},
		{"sub.example.com", "example.com", false},
		{"example.com", "www.example.com.", true}, // trailing dot tolerated
	}
	for _, tc := range cases {
		got := sameApexOrWWW(tc.start, tc.end)
		if got != tc.want {
			t.Errorf("sameApexOrWWW(%q,%q) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestAnalyzeRedirectChain_HappyPath(t *testing.T) {
	final, _ := url.Parse("https://example.com/")
	resp := &probe.Response{
		Status:     200,
		URL:        final,
		RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err != nil {
		t.Fatalf("expected no error, got %v", v.err)
	}
	if !v.permanent {
		t.Errorf("expected permanent=true")
	}
}

func TestAnalyzeRedirectChain_FinalNotHTTPS(t *testing.T) {
	final, _ := url.Parse("http://example.com/")
	resp := &probe.Response{
		Status:     200,
		URL:        final,
		RedirectCh: []*url.URL{final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for non-HTTPS final URL")
	}
}

func TestAnalyzeRedirectChain_DifferentHost(t *testing.T) {
	final, _ := url.Parse("https://other.com/")
	resp := &probe.Response{
		Status:     200,
		URL:        final,
		RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for cross-host redirect")
	}
}

func TestAnalyzeRedirectChain_TooManyHops(t *testing.T) {
	final, _ := url.Parse("https://example.com/x")
	chain := []*url.URL{mustURL("http://example.com/")}
	for i := 0; i < 10; i++ {
		chain = append(chain, mustURL("https://example.com/"))
	}
	chain = append(chain, final)
	resp := &probe.Response{Status: 200, URL: final, RedirectCh: chain}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for chain >8 hops")
	}
}

func TestAnalyzeRedirectChain_FinalErrorStatus(t *testing.T) {
	final, _ := url.Parse("https://example.com/")
	resp := &probe.Response{
		Status:     500,
		URL:        final,
		RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for final 5xx")
	}
}

// TestAnalyzeRedirectChain_EveryHop: each hop must stay on the target's
// apex or its www twin, and none may step back from https to http.
func TestAnalyzeRedirectChain_EveryHop(t *testing.T) {
	cases := []struct {
		name    string
		chain   []string // RedirectCh, ending with the final URL
		wantErr string   // "" for a chain that passes
	}{
		{"https then http", []string{"http://example.com/", "https://example.com/",
			"http://example.com/x"},
			"plain HTTP did not redirect to HTTPS (final: http://example.com/x)"},
		{"downgrade mid-chain", []string{"http://example.com/", "https://example.com/",
			"http://example.com/x", "https://example.com/y"},
			"redirect downgraded from https to http: https://example.com/ -> http://example.com/x"},
		{"cross-host hop", []string{"http://example.com/", "https://tracker.evil.test/r",
			"https://www.example.com/"},
			"redirect crossed to a different host: example.com -> tracker.evil.test"},
		{"apex to www", []string{"http://example.com/", "https://www.example.com/"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := make([]*url.URL, len(tc.chain))
			for i, raw := range tc.chain {
				chain[i] = mustURL(raw)
			}
			resp := &probe.Response{Status: 200, URL: chain[len(chain)-1], RedirectCh: chain}
			got := ""
			if err := analyzeRedirectChain("example.com", resp).err; err != nil {
				got = err.Error()
			}
			if got != tc.wantErr {
				t.Errorf("error = %q, want %q", got, tc.wantErr)
			}
		})
	}
}

// TestGradeRedirect_UnverifiedChainIsNotApplicable: a chain that passes
// every rule is graded only when its HTTPS hops were verified.
func TestGradeRedirect_UnverifiedChainIsNotApplicable(t *testing.T) {
	final := mustURL("https://www.example.com/")
	resp := &probe.Response{
		Status: 200, URL: final, RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	r := gradeRedirect("example.com", "example.com", resp)
	if r.ID != "web.redirect.example.com" || r.Status != report.NotApplicable ||
		r.Evidence != "TLS chain invalid; see web.cert.*" || r.Remediation != "" {
		t.Errorf("unverified chain = %+v, want N/A pointing at web.cert.*", r)
	}
	resp.Verified = true
	if r := gradeRedirect("example.com", "example.com", resp); r.Status != report.Pass {
		t.Errorf("verified chain = %s %q, want PASS", r.Status, r.Evidence)
	}
}

// TestGradeRedirect_BrokenChainFails: a chain that never reaches HTTPS
// FAILs with the redirect fix, whether or not its connection verified.
func TestGradeRedirect_BrokenChainFails(t *testing.T) {
	final := mustURL("http://example.com/")
	for _, verified := range []bool{false, true} {
		resp := &probe.Response{
			Status: 200, URL: final, RedirectCh: []*url.URL{final}, Verified: verified,
		}
		r := gradeRedirect("example.com", "example.com", resp)
		want := "plain HTTP did not redirect to HTTPS (final: http://example.com/)"
		if r.Status != report.Fail || r.Evidence != want ||
			r.Remediation != nginxRedirectRemediation("example.com") {
			t.Errorf("verified=%v: got %s %q (remediation %q), want FAIL %q with the fix",
				verified, r.Status, r.Evidence, r.Remediation, want)
		}
	}
}

// TestRedirectFetchFailed: a GET that could not complete is inconclusive,
// while a refused downgrade or a redirect loop is the site's answer.
func TestRedirectFetchFailed(t *testing.T) {
	getErr := func(err error) error {
		return &url.Error{Op: "Get", URL: "http://example.com/", Err: err}
	}
	assertInconclusive(t, redirectFetchFailed(context.Background(), "example.com",
		"example.com", getErr(context.DeadlineExceeded)), "context deadline exceeded")
	for _, msg := range []string{
		"redirect downgraded from https to http (http://example.com/x)",
		"too many redirects (>8)",
	} {
		r := redirectFetchFailed(context.Background(), "example.com", "example.com",
			getErr(errors.New(msg)))
		if r.Status != report.Fail || !strings.Contains(r.Evidence, msg) || r.Remediation == "" {
			t.Errorf("%q: got %s %q, want FAIL with a remediation", msg, r.Status, r.Evidence)
		}
	}
}

// TestEvaluateRedirect_TimeoutIsInconclusive: a server that accepts the
// connection and never answers leaves the redirect undetermined.
func TestEvaluateRedirect_TimeoutIsInconclusive(t *testing.T) {
	addr, _ := tarpitListener(t)
	env := newLoopbackEnv(t)
	env.Target = "127.0.0.1"
	env.Timeout, env.HTTP = 200*time.Millisecond, probe.NewHTTP(200*time.Millisecond)
	assertInconclusive(t, evaluateRedirect(context.Background(), env, addr.String()),
		`Get "http://`+addr.String()+`/"`)
}

func mustURL(s string) *url.URL {
	u, err := parseRedirectURL(s)
	if err != nil {
		panic(err)
	}
	return u
}
