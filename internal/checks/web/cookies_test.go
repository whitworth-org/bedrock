package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestParseSetCookie(t *testing.T) {
	cases := []struct {
		raw  string
		want cookieAttrs
	}{
		{
			raw:  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
			want: cookieAttrs{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Lax"},
		},
		{
			raw:  "tracker=xyz; Path=/",
			want: cookieAttrs{Name: "tracker"},
		},
		{
			// case-insensitive attribute names
			raw:  "id=1; secure; httponly; samesite=Strict",
			want: cookieAttrs{Name: "id", Secure: true, HTTPOnly: true, SameSite: "Strict"},
		},
		{
			raw:  "lone",
			want: cookieAttrs{Name: "lone"},
		},
	}
	for _, tc := range cases {
		got := parseSetCookie(tc.raw)
		if got != tc.want {
			t.Errorf("parseSetCookie(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

func TestCookieAttrsDeletes(t *testing.T) {
	now := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		raw  string
		want bool
	}{
		{"sid=1", false},
		{"old=; Max-Age=0", true},
		{"old=; Max-Age=-1", true},
		{"sid=1; Max-Age=3600", false},
		{"old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT", true},
		{"old=; expires=Thu, 01-Jan-1970 00:00:01 GMT", true},
		{"sid=1; Expires=Fri, 01 Jan 2100 00:00:00 GMT", false},
		// Expiring at the response time is a deletion.
		{"old=; Expires=Thu, 08 Oct 2026 12:00:00 GMT", true},
		{"sid=1; Expires=Thu, 08 Oct 2026 12:00:01 GMT", false},
		{"sid=1; Expires=yesterday", false},
		// The last Max-Age wins over Expires, whatever the order (RFC 6265 §5.3).
		{"sid=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT", false},
		{"sid=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=3600", false},
		{"sid=1; Max-Age=0; Max-Age=3600", false},
		// A value that does not parse is ignored: Expires decides, or an
		// earlier value that parsed still applies.
		{"old=; Max-Age=soon; Expires=Thu, 01 Jan 1970 00:00:00 GMT", true},
		{"old=; Max-Age=0; Max-Age=soon", true},
		{"old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Expires=never", true},
	}
	for _, tc := range cases {
		if got := parseSetCookie(tc.raw).deletes(now); got != tc.want {
			t.Errorf("parseSetCookie(%q).deletes() = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestMissingCookieAttrs(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"session=abc; Secure; HttpOnly; SameSite=Lax", nil},
		{"session=abc; HttpOnly; SameSite=Lax", []string{"Secure"}},
		{"session=abc; Secure; SameSite=None", []string{"HttpOnly"}},
		{"__Host-js-csrf=abc; Secure; SameSite=Strict", nil},
		{"session=abc; Secure; HttpOnly", []string{"SameSite"}},
		{"session=abc; Secure; HttpOnly; SameSite=Sometimes", []string{"SameSite"}},
		{"tracker=xyz", []string{"Secure", "HttpOnly", "SameSite"}},
	}
	for _, tc := range cases {
		if got := missingCookieAttrs(parseSetCookie(tc.raw)); !slices.Equal(got, tc.want) {
			t.Errorf("missingCookieAttrs(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// envWithRootCookies returns an active Env whose cached HTTPS root response,
// fetched over a verified connection, carries raws as Set-Cookie headers, so
// runCookies sends no request.
func envWithRootCookies(raws ...string) *probe.Env {
	env := probe.NewEnv("example.com", time.Second, true, "")
	env.CachePut(probe.CacheKeyHTTPSRoot, &rootFetch{resp: &probe.Response{
		Status:   http.StatusOK,
		Headers:  http.Header{"Set-Cookie": raws},
		Verified: true,
	}})
	return env
}

// runOneCookieResult runs the cookie check and fails unless it returns
// exactly one web.cookies result.
func runOneCookieResult(t *testing.T, raws ...string) report.Result {
	t.Helper()
	results := runCookies(context.Background(), envWithRootCookies(raws...))
	if err := report.CheckUniqueIDs(results); err != nil {
		t.Error(err)
	}
	if len(results) != 1 || results[0].ID != "web.cookies" {
		ids := make([]string, len(results))
		for i, r := range results {
			ids[i] = r.ID
		}
		t.Fatalf("got %d results %q, want one web.cookies result", len(results), ids)
	}
	return results[0]
}

func TestRunCookies_OneResultWithWorstStatus(t *testing.T) {
	cases := []struct {
		name        string
		raws        []string
		status      report.Status
		evidence    []string
		remediation string
	}{
		{
			name: "three cookies",
			raws: []string{
				"sid=SECRET-SID; Secure; HttpOnly; SameSite=Lax",
				"theme=SECRET-THEME; Path=/",
				"__Host-js-csrf=SECRET-CSRF; Secure; SameSite=Strict",
			},
			status:      report.Fail,
			evidence:    []string{`1 of 3 cookies`, `"theme" (Secure, HttpOnly, SameSite)`},
			remediation: cookieRemediation,
		},
		{
			name: "names that shared an ID slug",
			raws: []string{
				"a.b=SECRET-1; Secure; HttpOnly; SameSite=Lax",
				"a_b=SECRET-2; Secure; HttpOnly; SameSite=Lax",
			},
			status:   report.Pass,
			evidence: []string{`2 of 2 cookies`, `"a.b", "a_b"`},
		},
		{
			name: "deletion of a cookie the response also sets",
			raws: []string{
				"sid=SECRET-SID; Secure; HttpOnly; SameSite=Lax",
				"sid=; Path=/app; Max-Age=0",
			},
			status:   report.Pass,
			evidence: []string{`1 of 1 cookies`, "1 deletion header(s) ignored"},
		},
		{
			name: "only deletions",
			raws: []string{
				"old=; Max-Age=0; Path=/",
				"legacy=; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
			},
			status:   report.Info,
			evidence: []string{"no cookies set on https://example.com/"},
		},
		{
			name:        "hostile name",
			raws:        []string{"\x1b[2J" + strings.Repeat("n", 100) + "=SECRET-1"},
			status:      report.Fail,
			evidence:    []string{`"�[2J` + strings.Repeat("n", 60) + `…" (Secure,`},
			remediation: cookieRemediation,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runOneCookieResult(t, tc.raws...)
			if r.Status != tc.status {
				t.Errorf("status = %v, want %v; evidence=%q", r.Status, tc.status, r.Evidence)
			}
			for _, want := range tc.evidence {
				if !strings.Contains(r.Evidence, want) {
					t.Errorf("evidence %q lacks %q", r.Evidence, want)
				}
			}
			if strings.Contains(r.Evidence, "SECRET") || strings.ContainsRune(r.Evidence, '\x1b') {
				t.Errorf("evidence %q quotes a cookie value or a control character", r.Evidence)
			}
			if r.Remediation != tc.remediation {
				t.Errorf("remediation = %q, want %q", r.Remediation, tc.remediation)
			}
		})
	}
}

// TestRunCookies_DeletionJudgedByResponseDate: a cookie expiring at the
// response's Date is a deletion, whatever the local clock says; without a
// usable Date the local clock decides.
func TestRunCookies_DeletionJudgedByResponseDate(t *testing.T) {
	const cookie = "CAS_PROGRAM=echo; expires=Fri, 01-Jan-2100 00:00:00 GMT"
	cases := []struct {
		date   string
		status report.Status
	}{
		{"Fri, 01 Jan 2100 00:00:00 GMT", report.Info},
		{"Thu, 31 Dec 2099 23:59:59 GMT", report.Fail},
		{"", report.Fail},
		{"not a date", report.Fail},
	}
	for _, tc := range cases {
		env := envWithRootCookies(cookie)
		f, _ := env.CacheGet(probe.CacheKeyHTTPSRoot)
		f.(*rootFetch).resp.Headers.Set("Date", tc.date)
		results := runCookies(context.Background(), env)
		if len(results) != 1 || results[0].Status != tc.status {
			t.Errorf("Date %q: got %+v, want one %s result", tc.date, results, tc.status)
		}
	}
}

func TestRunCookies_ManyHeadersGiveOneBoundedResult(t *testing.T) {
	raws := make([]string, 500)
	for i := range raws {
		raws[i] = fmt.Sprintf("c%03d%s=%s; Path=/", i, strings.Repeat("n", 200),
			strings.Repeat("v", 200))
	}
	r := runOneCookieResult(t, raws...)
	if r.Status != report.Fail {
		t.Errorf("status = %v, want %v", r.Status, report.Fail)
	}
	if !strings.HasPrefix(r.Evidence, "500 of 500 cookies") ||
		!strings.HasSuffix(r.Evidence, ", and 490 more") {
		t.Errorf("evidence should count 500 cookies and list 10: %.300q", r.Evidence)
	}
	if len(r.Evidence) > 2048 {
		t.Errorf("evidence is %d bytes, want at most 2048", len(r.Evidence))
	}
}
