package report

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func renderHumanString(t *testing.T, r Report, v View) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderHuman(&buf, r, v); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	return buf.String()
}

// humanFixture has every kind of entry: N/A results sharing a reason, a
// PASS, an INFO, a WARN with a multi-line fix, a FAIL emitted twice under
// one ID, and a second FAIL.
func humanFixture() Report {
	dmarcFix := `_dmarc.example.org. IN TXT "v=DMARC1; p=quarantine; adkim=s"`
	dmarcRefs := []string{"Gmail BIMI requirements"}
	return Report{
		Target: "example.org",
		Results: []Result{
			{ID: "dns.axfr", Category: "DNS", Title: "AXFR refusal probe",
				Status: NotApplicable, Evidence: "skipped: --no-active"},
			{ID: "dns.ns.count", Category: "DNS", Title: "Apex has 2 NS records",
				Status: Pass, Evidence: "a.example, b.example"},
			{ID: "dns.zone.soa", Category: "DNS", Title: "SOA timer values", Status: Warn,
				Evidence:    "MINIMUM=1800s",
				Remediation: "example.org. IN SOA ns1 host (\n    3600 ; minimum\n)\n",
				RFCRefs:     []string{"RFC 1912 §2.2", "RFC 2308 §5"}},
			{ID: "bimi.gmail.dmarc", Category: "Email", Title: "BIMI Gmail gate", Status: Fail,
				Evidence: `DMARC p="none"`, Remediation: dmarcFix, RFCRefs: dmarcRefs},
			{ID: "bimi.gmail.dmarc", Category: "Email", Title: "BIMI Gmail gate", Status: Fail,
				Evidence: `DMARC adkim="r"`, Remediation: dmarcFix, RFCRefs: dmarcRefs},
			{ID: "email.mtasts.policy", Category: "Email", Title: "MTA-STS policy",
				Status: NotApplicable, Evidence: "skipped: --no-active"},
			{ID: "email.rbl", Category: "Email", Title: "DNSBL listings", Status: Info,
				Evidence: "disabled"},
			{ID: "web.hsts", Category: "WWW", Title: "HSTS present", Status: Fail,
				Evidence:    "no header",
				Remediation: "Strict-Transport-Security: max-age=31536000",
				RFCRefs:     []string{"RFC 6797 §6.1"}},
		},
	}
}

func TestRenderHumanLayout(t *testing.T) {
	want := `bedrock report for example.org (8 results)

Not run or not applicable (2)
N/A   2 results: skipped: --no-active
      dns.axfr, email.mtasts.policy

Passed (1)
PASS  dns.ns.count  Apex has 2 NS records

Information (1)
INFO  email.rbl  DNSBL listings: disabled

Warnings (1)
WARN  dns.zone.soa  SOA timer values
      evidence: MINIMUM=1800s
      refs: RFC 1912 §2.2, RFC 2308 §5
      fix (3 lines):
example.org. IN SOA ns1 host (
    3600 ; minimum
)

Failures (3)
FAIL  bimi.gmail.dmarc  BIMI Gmail gate (2 results)
      evidence: DMARC p="none"
      evidence: DMARC adkim="r"
      refs: Gmail BIMI requirements
      fix (1 line):
_dmarc.example.org. IN TXT "v=DMARC1; p=quarantine; adkim=s"

FAIL  web.hsts  HSTS present
      evidence: no header
      refs: RFC 6797 §6.1
      fix (1 line):
Strict-Transport-Security: max-age=31536000

Summary for example.org
DNS    0 FAIL  1 WARN  1 PASS  0 INFO  1 N/A
Email  2 FAIL  0 WARN  0 PASS  1 INFO  1 N/A
WWW    1 FAIL  0 WARN  0 PASS  0 INFO  0 N/A
Total  3 FAIL  1 WARN  1 PASS  1 INFO  2 N/A

Result: FAIL. 3 FAIL (Email 2, WWW 1), 1 WARN. Exit code 1.
`
	got := renderHumanString(t, humanFixture(), View{Exit: 1})
	if got != want {
		t.Errorf("layout mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestRenderHumanEmptyReport(t *testing.T) {
	want := `bedrock report for example.org (0 results)

Summary for example.org
Total  0 FAIL  0 WARN  0 PASS  0 INFO  0 N/A

Result: PASS. No results. Exit code 0.
`
	for _, results := range [][]Result{nil, {}} {
		got := renderHumanString(t, Report{Target: "example.org", Results: results}, View{})
		if got != want {
			t.Errorf("empty report (results %#v):\n--- got ---\n%s--- want ---\n%s",
				results, got, want)
		}
	}
}

func TestRenderHumanHeader(t *testing.T) {
	three := []Result{{ID: "a", Status: Pass}, {ID: "b", Status: Pass}, {ID: "c", Status: Pass}}
	tests := []struct {
		name    string
		results []Result
		v       View
		want    string
	}{
		{"unfiltered", three, View{Scanned: 3}, "(3 results)"},
		{"scanned unset", three, View{}, "(3 results)"},
		{"one result", three[:1], View{Scanned: 1}, "(1 result)"},
		{"filtered", three[:1], View{Scanned: 84}, "(1 of 84 results)"},
		{"filtered to nothing", nil, View{Scanned: 84}, "(0 of 84 results)"},
		{"elapsed rounded to tenths", three, View{Elapsed: 3149 * time.Millisecond},
			"(3 results, 3.1s)"},
		{"passive only", three, View{Passive: true}, "(3 results, passive only)"},
		{"resolver", three, View{Resolvers: []string{"cloudflare-doh"}},
			"(3 results, resolver cloudflare-doh)"},
		{"resolvers", three, View{Resolvers: []string{"cloudflare", "google"}},
			"(3 results, resolvers cloudflare,google)"},
		{"interrupted", three, View{Interrupted: true}, "(3 results, interrupted)"},
		{"everything", three[:2], View{Scanned: 9, Elapsed: 10 * time.Second, Passive: true,
			Resolvers: []string{"1.1.1.1:53"}, Interrupted: true},
			"(2 of 9 results, 10s, passive only, resolver 1.1.1.1:53, interrupted)"},
		{"resolver is display-safe", three, View{Resolvers: []string{"x\x1b[2J\u202e\ty\n"}},
			"(3 results, resolver x\ufffd[2J\\u202E y\ufffd)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := renderHumanString(t, Report{Target: "example.org", Results: tt.results}, tt.v)
			first, _, _ := strings.Cut(out, "\n")
			if want := "bedrock report for example.org " + tt.want; first != want {
				t.Errorf("header = %q, want %q", first, want)
			}
		})
	}
}

func TestRenderHumanMergesOnlyAdjacentIdenticalResults(t *testing.T) {
	fail := func(id, ev string) Result {
		return Result{ID: id, Category: "Email", Title: "BIMI Gmail gate", Status: Fail,
			Evidence: ev, Remediation: "fix", RFCRefs: []string{"Gmail"}}
	}
	variant := func(mod func(*Result)) Result {
		r := fail("bimi.gmail.dmarc", "second")
		mod(&r)
		return r
	}
	tests := []struct {
		name       string
		results    []Result
		wantBlocks int
	}{
		{"adjacent identical merge", []Result{fail("bimi.gmail.dmarc", "p"),
			fail("bimi.gmail.dmarc", "adkim"), fail("bimi.gmail.dmarc", "aspf")}, 1},
		{"non-adjacent do not merge", []Result{fail("bimi.gmail.dmarc", "p"),
			fail("bimi.txt", "x"), fail("bimi.gmail.dmarc", "aspf")}, 3},
		{"different title", []Result{fail("bimi.gmail.dmarc", "p"),
			variant(func(r *Result) { r.Title = "other" })}, 2},
		{"different fix", []Result{fail("bimi.gmail.dmarc", "p"),
			variant(func(r *Result) { r.Remediation = "other" })}, 2},
		{"different refs", []Result{fail("bimi.gmail.dmarc", "p"),
			variant(func(r *Result) { r.RFCRefs = []string{"Gmail", "RFC 9989"} })}, 2},
		{"different category", []Result{fail("bimi.gmail.dmarc", "p"),
			variant(func(r *Result) { r.Category = "DNS" })}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := renderHumanString(t, Report{Target: "example.org", Results: tt.results},
				View{Exit: 1})
			if got := strings.Count(out, "\nFAIL  "); got != tt.wantBlocks {
				t.Errorf("FAIL blocks = %d, want %d\n%s", got, tt.wantBlocks, out)
			}
			if got := strings.Count(out, "\n      evidence: "); got != len(tt.results) {
				t.Errorf("evidence lines = %d, want one per result (%d)\n%s",
					got, len(tt.results), out)
			}
		})
	}
}

func TestRenderHumanMergedOneLinersNameTheirCount(t *testing.T) {
	pass := Result{ID: "dnssec.chain", Category: "DNSSEC", Title: "RRSIG verifies", Status: Pass}
	infoA := Result{ID: "web.ja3s", Category: "WWW", Title: "TLS fingerprint", Status: Info,
		Evidence: "JA3S=a"}
	infoB := infoA
	infoB.Evidence = "JA3S=b"
	gate := ResultRef{ID: "bimi.gmail.dmarc", Title: "gate"}
	r := Report{
		Target:      "example.org",
		Results:     []Result{pass, pass, infoA, infoB},
		Regressions: []ResultRef{gate, gate},
	}
	out := renderHumanString(t, r, View{Baseline: "base.json", Exit: 1})
	for _, want := range []string{
		"\nPassed (2)\nPASS  dnssec.chain  RRSIG verifies (2 results)\n",
		"\nInformation (2)\nINFO  web.ja3s  TLS fingerprint: JA3S=a; JA3S=b (2 results)\n",
		"\nNew failures since base.json (2)\nFAIL  bimi.gmail.dmarc  gate (2 results)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestRenderHumanNotApplicableGroupedByReason(t *testing.T) {
	na := func(id, category, reason string) Result {
		return Result{ID: id, Category: category, Status: NotApplicable, Evidence: reason}
	}
	const noActive, noMX = "active probing disabled (--no-active)", "no usable MX records"
	var results []Result
	for i := 1; i <= 20; i++ {
		results = append(results, na(fmt.Sprintf("web.c%02d", i), "WWW", noActive))
	}
	for i := 1; i <= 6; i++ {
		results = append(results, na(fmt.Sprintf("email.m%02d", i), "Email", noMX))
	}
	results[6].ID = "web.c07.lng"   // fills the first ID line to exactly 72 columns
	results[25].ID = "email.m06.xy" // one column too wide for the first line
	results = append(results, na("dnssec.chain", "DNSSEC", ""), na("dnssec.chain", "DNSSEC", ""),
		Result{ID: "dns.axfr", Category: "DNS", Status: Status(42), Evidence: "future status"})
	out := renderHumanString(t, Report{Target: "example.org", Results: results}, View{})

	// The counts are of results, so they add up to the heading's even where
	// an ID repeats; the repeated ID is listed once with its count.
	want := `
Not run or not applicable (29)
N/A   20 results: active probing disabled (--no-active)
      web.c01, web.c02, web.c03, web.c04, web.c05, web.c06, web.c07.lng,
      web.c08, web.c09, web.c10, web.c11, web.c12, web.c13, web.c14,
      web.c15, web.c16, web.c17, web.c18, web.c19, web.c20
N/A   6 results: no usable MX records
      email.m01, email.m02, email.m03, email.m04, email.m05,
      email.m06.xy
N/A   2 results: no reason given
      dnssec.chain (2 results)
N/A   1 result: future status
      dns.axfr

Summary for example.org
`
	if !strings.Contains(out, want) {
		t.Errorf("N/A section mismatch\n--- got ---\n%s--- want it to contain ---\n%s", out, want)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, detailIndent) && len(l) > idListWidth {
			t.Errorf("ID line is %d columns, want at most %d: %q", len(l), idListWidth, l)
		}
	}
}

func TestRenderHumanCountsWhatItLists(t *testing.T) {
	r := humanFixture()
	stale := StatusCounts{Fail: 99, Total: 99}
	r.Summary = &Summary{
		Categories: []CategoryCounts{{Category: "Stale", Counts: stale}},
		Totals:     stale,
	}
	out := renderHumanString(t, r, View{Exit: 1})
	for _, want := range []string{"\nTotal  3 FAIL  1 WARN  1 PASS  1 INFO  2 N/A\n",
		"Result: FAIL. 3 FAIL (Email 2, WWW 1), 1 WARN. Exit code 1.\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "Stale") || strings.Contains(out, "99") {
		t.Errorf("the view used the caller's stale summary\n%s", out)
	}
}

func TestRenderHumanFixLineCount(t *testing.T) {
	tests := []struct {
		name, rem, want string
	}{
		{"one line", "a", "fix (1 line):\na\n"},
		{"two lines", "a\nb", "fix (2 lines):\na\nb\n"},
		{"trailing newline is not a line", "a\nb\n", "fix (2 lines):\na\nb\n"},
		{"several trailing newlines", "a\n\n\n", "fix (1 line):\na\n"},
		{"blank line inside counts", "a\n\nb", "fix (3 lines):\na\n\nb\n"},
		{"leading blank line counts", "\na", "fix (2 lines):\n\na\n"},
		{"CRLF ends one line", "a\r\nb\r\n", "fix (2 lines):\na\nb\n"},
		{"lone CR breaks a line", "a\rb", "fix (2 lines):\na\nb\n"},
		{"whitespace-only last line kept", "a\n  ", "fix (2 lines):\na\n  \n"},
		{"indentation kept", "x (\n    1 ; serial\n)", "fix (3 lines):\nx (\n    1 ; serial\n)\n"},
		{"empty fix prints nothing", "", ""},
		{"newline-only fix prints nothing", "\n\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Report{Target: "example.org", Results: []Result{{ID: "x", Category: "DNS",
				Title: "t", Status: Fail, Evidence: "e", Remediation: tt.rem}}}
			out := renderHumanString(t, r, View{Exit: 1})
			got := ""
			if _, fix, ok := strings.Cut(out, "\n"+detailIndent+"fix ("); ok {
				fix, _, _ = strings.Cut(fix, "\n\nSummary for")
				got = "fix (" + fix + "\n"
			}
			if got != tt.want {
				t.Errorf("fix section = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderHumanInterruptedListsUnfinished(t *testing.T) {
	r := Report{Target: "example.org", Results: []Result{
		{ID: "email.spf.record", Category: "Email", Title: "SPF", Status: Fail, Remediation: "x"},
	}}
	unfinished := []string{"dns.axfr", "email.smtp.starttls", "web.cert.chain", "web.cookies",
		"web.crl.status", "web.headers", "web.hsts", "web.http2", "web.http3", "web.redirect"}
	v := View{Interrupted: true, Unfinished: slices.Clone(unfinished), Exit: 1}
	out := renderHumanString(t, r, v)
	for _, want := range []string{
		"bedrock report for example.org (1 result, interrupted)\n",
		"\nChecks not finished when interrupted (10)\n" +
			"      dns.axfr, email.smtp.starttls, web.cert.chain, web.cookies,\n" +
			"      web.crl.status, web.headers, web.hsts, web.http2, web.http3,\n" +
			"      web.redirect\n" +
			"      Results from these checks may reflect the interrupt, not the target.\n" +
			"\nSummary for example.org\n",
		"\nResult: INCOMPLETE. Scan interrupted; 10 checks did not finish. " +
			"1 FAIL (Email 1), 0 WARN. Exit code 1.\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if !reflect.DeepEqual(v.Unfinished, unfinished) {
		t.Errorf("RenderHuman changed the caller's Unfinished slice to %q", v.Unfinished)
	}
}

func TestRenderHumanRegressions(t *testing.T) {
	r := humanFixture()
	t.Run("baseline without regressions", func(t *testing.T) {
		out := renderHumanString(t, r, View{Baseline: "base.json", Exit: 1})
		if !strings.Contains(out, "\n\nNo new failures since base.json\n\nSummary for") {
			t.Errorf("missing the no-regressions line\n%s", out)
		}
	})
	t.Run("no baseline", func(t *testing.T) {
		if out := renderHumanString(t, r, View{Exit: 1}); strings.Contains(out, "since") {
			t.Errorf("regressions section printed without a baseline\n%s", out)
		}
	})
	t.Run("regressions listed before the summary", func(t *testing.T) {
		r.Regressions = []ResultRef{{ID: "web.hsts", Title: "HSTS present"}}
		out := renderHumanString(t, r, View{Baseline: "base.json", Exit: 1})
		want := "\n\nNew failures since base.json (1)\nFAIL  web.hsts  HSTS present\n\nSummary for"
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	})
}

func TestVerdict(t *testing.T) {
	fixture := humanFixture()
	regressed := humanFixture()
	regressed.Regressions = []ResultRef{{ID: "web.hsts", Title: "HSTS present"}}
	passing := Report{Target: "example.org", Results: []Result{
		{ID: "a", Category: "DNS", Status: Pass}, {ID: "b", Category: "DNS", Status: Warn},
	}}
	tests := []struct {
		name string
		r    Report
		v    View
		want string
	}{
		{"fail", fixture, View{Exit: 1}, "FAIL. 3 FAIL (Email 2, WWW 1), 1 WARN. Exit code 1."},
		{"pass with warnings", passing, View{}, "PASS. 0 FAIL, 1 WARN. Exit code 0."},
		{"empty", Report{}, View{}, "PASS. No results. Exit code 0."},
		{"filtered to nothing", Report{}, View{Scanned: 56}, "PASS. 0 of 56 results shown; " +
			"check --only, --exclude, --severity and --ids. Exit code 0."},
		{"regression-only with regressions", regressed,
			View{RegressionOnly: true, Baseline: "base.json", Exit: 1},
			"FAIL. 1 new FAIL since base.json; 3 FAIL in total. Exit code 1."},
		{"regression-only without regressions", fixture,
			View{RegressionOnly: true, Baseline: "base.json"},
			"PASS. 0 new FAIL since base.json; 3 FAIL in total. Exit code 0."},
		{"regression-only without a baseline", fixture, View{RegressionOnly: true},
			"PASS. No --baseline to compare with, so --regression-only ignores 3 FAIL. " +
				"Exit code 0."},
		{"interrupted with unfinished checks", fixture,
			View{Interrupted: true, Unfinished: []string{"web.hsts"}, Exit: 1},
			"INCOMPLETE. Scan interrupted; 1 check did not finish. " +
				"3 FAIL (Email 2, WWW 1), 1 WARN. Exit code 1."},
		{"interrupted after every check finished", passing, View{Interrupted: true},
			"INCOMPLETE. Scan interrupted; results are partial. 0 FAIL, 1 WARN. Exit code 0."},
		{"word and code follow v.Exit", passing, View{Exit: 2},
			"FAIL. 0 FAIL, 1 WARN. Exit code 2."},
		{"hostile baseline path stays on one safe line", regressed,
			View{RegressionOnly: true, Baseline: "b\n\x1b[2J\u2066.json", Exit: 1},
			"FAIL. 1 new FAIL since b\ufffd\ufffd[2J\\u2066.json; 3 FAIL in total. Exit code 1."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verdict(tt.r, tt.v); got != tt.want {
				t.Errorf("Verdict = %q\nwant      %q", got, tt.want)
			}
		})
	}
}

// TestRenderHumanEndsWithVerdict pins that the report's last line is the
// verdict main also prints on stderr, naming the process exit code.
func TestRenderHumanEndsWithVerdict(t *testing.T) {
	views := []View{
		{Exit: 1},
		{Exit: 0},
		{Exit: 2, Scanned: 99},
		{Interrupted: true, Unfinished: []string{"a"}, Exit: 1},
		{RegressionOnly: true, Baseline: "base.json"},
	}
	for _, v := range views {
		verdict := Verdict(humanFixture(), v)
		if want := fmt.Sprintf(" Exit code %d.", v.Exit); !strings.HasSuffix(verdict, want) {
			t.Errorf("view %+v: verdict %q does not end with %q", v, verdict, want)
		}
		out := renderHumanString(t, humanFixture(), v)
		if want := "\n\nResult: " + verdict + "\n"; !strings.HasSuffix(out, want) {
			t.Errorf("view %+v: report does not end with %q\n%s", v, want, out)
		}
	}
}

func TestFailingIDs(t *testing.T) {
	r := humanFixture()
	r.Results = append(r.Results, Result{ID: "x\u202e\x1b[0m", Category: "WWW", Status: Fail})
	r.Regressions = []ResultRef{{ID: "web.hsts"}, {ID: "web.hsts"}, {ID: "bimi.gmail.dmarc"}}
	tests := []struct {
		name string
		r    Report
		v    View
		want []string
	}{
		{"distinct FAIL IDs in report order, display-safe", r, View{Exit: 1},
			[]string{"bimi.gmail.dmarc", "web.hsts", "x\\u202E\ufffd[0m"}},
		{"regression-only lists regressions", r, View{RegressionOnly: true, Exit: 1},
			[]string{"web.hsts", "bimi.gmail.dmarc"}},
		{"nothing failing", Report{Results: []Result{{ID: "a", Status: Warn}}}, View{}, nil},
		{"regression-only without regressions", humanFixture(), View{RegressionOnly: true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FailingIDs(tt.r, tt.v); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FailingIDs = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWrapIDs(t *testing.T) {
	tests := []struct {
		name  string
		ids   []string
		width int
		want  []string
	}{
		{"nil", nil, 72, nil},
		{"empty", []string{}, 72, nil},
		{"single", []string{"dns.axfr"}, 72, []string{"dns.axfr"}},
		{"fits exactly", []string{"ab", "cd"}, 6, []string{"ab, cd"}},
		{"one column short", []string{"ab", "cd"}, 5, []string{"ab,", "cd"}},
		{"broken lines keep their comma", []string{"a", "b", "c", "d", "e"}, 8,
			[]string{"a, b, c,", "d, e"}},
		{"comma counts toward the width", []string{"a", "b", "c", "d", "e"}, 7,
			[]string{"a, b,", "c, d, e"}},
		{"long first ID gets its own line", []string{"abcdefghij", "k", "l"}, 5,
			[]string{"abcdefghij,", "k, l"}},
		{"long middle ID gets its own line", []string{"a", "abcdefghij", "b"}, 5,
			[]string{"a,", "abcdefghij,", "b"}},
		{"long last ID gets its own line", []string{"a", "b", "abcdefghij"}, 5,
			[]string{"a, b,", "abcdefghij"}},
		{"zero width puts each ID on a line", []string{"a", "b"}, 0, []string{"a,", "b"}},
		{"empty IDs survive", []string{"", "a", ""}, 72, []string{", a, "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapIDs(tt.ids, tt.width)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WrapIDs(%q, %d) = %q, want %q", tt.ids, tt.width, got, tt.want)
			}
			if joined := strings.Join(got, " "); joined != strings.Join(tt.ids, ", ") {
				t.Errorf("lines rejoin to %q, want %q", joined, strings.Join(tt.ids, ", "))
			}
		})
	}
}

// humanSGR matches exactly the SGR sequences the colour rules allow:
// reset, bold, FAIL 1;31, WARN 33, PASS 32 and INFO 36.
var humanSGR = regexp.MustCompile(`\x1b\[(?:0|1|1;31|33|32|36)m`)

// anySGR matches every SGR sequence, allowed or not.
var anySGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// paintedRuns returns the text a terminal shows with an attribute set:
// from any SGR other than reset up to the next reset, nested codes removed.
func paintedRuns(s string) []string {
	var runs []string
	open := -1
	for _, loc := range anySGR.FindAllStringIndex(s, -1) {
		reset := s[loc[0]:loc[1]] == sgrReset
		switch {
		case reset && open >= 0:
			runs = append(runs, anySGR.ReplaceAllString(s[open:loc[0]], ""))
			open = -1
		case !reset && open < 0:
			open = loc[1]
		}
	}
	if open >= 0 {
		runs = append(runs, anySGR.ReplaceAllString(s[open:], ""))
	}
	return runs
}

func TestRenderHumanColorOnlyOnOwnTokens(t *testing.T) {
	r := humanFixture()
	r.Results = append(r.Results, Result{ID: "web.server", Category: "WWW",
		Title: "Server header", Status: Info, Evidence: "\x1b[32mPASS\x1b[0m"})
	r.Regressions = []ResultRef{{ID: "web.hsts", Title: "HSTS present"}}
	v := View{Baseline: "base.json", Interrupted: true, Unfinished: []string{"dns.axfr"}, Exit: 1}
	plain := renderHumanString(t, r, v)
	v.Color = true
	colored := renderHumanString(t, r, v)

	if strings.Contains(plain, "\x1b") {
		t.Fatalf("plain view contains ESC:\n%q", plain)
	}
	if stripped := humanSGR.ReplaceAllString(colored, ""); stripped != plain {
		t.Fatalf("stripping bedrock's SGR codes does not give the plain view\n"+
			"--- stripped ---\n%s--- plain ---\n%s", stripped, plain)
	}
	for _, want := range []string{"\x1b[1;31mFAIL\x1b[0m  ", "\x1b[33mWARN\x1b[0m  ",
		"\x1b[32mPASS\x1b[0m  ", "\x1b[36mINFO\x1b[0m  ", "\x1b[1;31m3 FAIL\x1b[0m",
		"\x1b[33m1 WARN\x1b[0m", "Result: \x1b[33mINCOMPLETE\x1b[0m.",
		"\x1b[1mSummary for example.org\x1b[0m"} {
		if !strings.Contains(colored, want) {
			t.Errorf("coloured view lacks %q", want)
		}
	}
	want := []string{
		"Not run or not applicable (2)",
		"Passed (1)", "PASS",
		"Information (2)", "INFO", "INFO",
		"Warnings (1)", "WARN",
		"Failures (3)", "FAIL", "FAIL",
		"New failures since base.json (1)", "FAIL",
		"Checks not finished when interrupted (1)",
		"Summary for example.org", "1 WARN", "2 FAIL", "1 FAIL", "3 FAIL", "1 WARN",
		"INCOMPLETE",
	}
	if got := paintedRuns(colored); !slices.Equal(got, want) {
		t.Errorf("painted text = %q\nwant only bedrock's own tokens %q", got, want)
	}
}

func hostileFixture() Report {
	r := humanFixture()
	r.Results = append(r.Results, Result{
		ID: "email.spf.record", Category: "Email", Title: "SPF\u202eflaw", Status: Fail,
		Evidence:    "v=spf1\t\u2066-all\u2069 \u200b\ufeff\u2028\u2029\U000e0041",
		Remediation: "example.org. IN TXT \"v=spf1\t-all\"\n\u00adsecond line",
		RFCRefs:     []string{"RFC 7208\u200d"},
	})
	return r
}

func TestRenderHumanDisplaySafe(t *testing.T) {
	r := hostileFixture()
	v := View{Interrupted: true, Unfinished: []string{"web.\u202ehsts"}, Exit: 1}
	out := renderHumanString(t, r, v)
	for _, want := range []string{
		"FAIL  email.spf.record  SPF\\u202Eflaw\n",
		"evidence: v=spf1 \\u2066-all\\u2069 \\u200B\\uFEFF\\u2028\\u2029\\U000E0041\n",
		"refs: RFC 7208\\u200D\n",
		"fix (2 lines):\nexample.org. IN TXT \"v=spf1 -all\"\n\\u00ADsecond line\n",
		"\nChecks not finished when interrupted (1)\n      web.\\u202Ehsts\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if !reflect.DeepEqual(r, hostileFixture()) {
		t.Errorf("RenderHuman modified the caller's report, which still feeds the JSON output")
	}
	if v.Unfinished[0] != "web.\u202ehsts" {
		t.Errorf("RenderHuman modified the caller's Unfinished slice to %q", v.Unfinished)
	}
}

// TestRenderHumanPaintsPassOnlyOverEvaluatedResults checks that a PASS over
// nothing evaluated stays unpainted, so it cannot read as an all-clear at a
// glance: no results shown, or --regression-only with no baseline to
// compare with. A PASS over real results is green.
func TestRenderHumanPaintsPassOnlyOverEvaluatedResults(t *testing.T) {
	passing := Report{Target: "example.org", Results: []Result{
		{ID: "a", Category: "DNS", Status: Pass}}}
	empty := Report{Target: "example.org"}
	const green, plain = "Result: \x1b[32mPASS\x1b[0m. ", "Result: PASS. "
	tests := []struct {
		name string
		r    Report
		v    View
		want string
	}{
		{"results shown", passing, View{}, green},
		{"no results", empty, View{}, plain},
		{"filtered to nothing", empty, View{Scanned: 56}, plain},
		{"regression-only without a baseline", humanFixture(), View{RegressionOnly: true}, plain},
		{"regression-only with a baseline", humanFixture(),
			View{RegressionOnly: true, Baseline: "base.json"}, green},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v.Color = true
			out := renderHumanString(t, tt.r, tt.v)
			verdict := out[strings.LastIndex(out, "\nResult: ")+1:]
			if !strings.HasPrefix(verdict, tt.want) {
				t.Errorf("verdict = %q, want it to start %q", verdict, tt.want)
			}
		})
	}
}

func TestDisplaySafe(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain text", "dns.axfr", "dns.axfr"},
		{"control characters, line breaks included", "a\x1b[2J\r\n\x07b",
			"a\ufffd[2J\ufffd\ufffd\ufffdb"},
		{"invalid UTF-8", "a\xffb", "a\ufffdb"},
		{"TAB", "a\tb", "a b"},
		{"bidi controls and zero-width characters", "a\u202eb\u2066c\u200bd\ufeff",
			`a\u202Eb\u2066c\u200Bd\uFEFF`},
		{"line and paragraph separators", "a\u2028b\u2029c", `a\u2028b\u2029c`},
		{"fillers and other default-ignorable characters",
			"\u034f\u115f\u1160\u3164\uffa0\u17b4\u17b5",
			`\u034F\u115F\u1160\u3164\uFFA0\u17B4\u17B5`},
		{"variation selectors", "a\u180bb\ufe0fc\U000e0100", `a\u180Bb\uFE0Fc\U000E0100`},
		{"unassigned and private-use code points", "\u2065\ufff0\U000e0080\ue000",
			`\u2065\uFFF0\U000E0080\uE000`},
		{"letters, marks and symbols of every script stay", "é e\u0301 \u05d0\u0627 中文 \U0001f600",
			"é e\u0301 \u05d0\u0627 中文 \U0001f600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DisplaySafe(tt.in); got != tt.want {
				t.Errorf("DisplaySafe(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRenderHumanOmitsEmptyEvidence(t *testing.T) {
	hsts := Result{ID: "web.hsts", Category: "WWW", Title: "HSTS present", Status: Fail,
		Remediation: "Strict-Transport-Security: max-age=31536000"}
	withEvidence := hsts
	withEvidence.Evidence = "no header"
	r := Report{Target: "example.org", Results: []Result{
		{ID: "dns.caa", Category: "DNS", Title: "CAA records", Status: Info}, hsts, withEvidence,
	}}
	out := renderHumanString(t, r, View{Exit: 1})
	for _, want := range []string{
		"\nINFO  dns.caa  CAA records\n",
		"\nFailures (2)\nFAIL  web.hsts  HSTS present (2 results)\n      evidence: no header\n" +
			"      fix (1 line):\nStrict-Transport-Security: max-age=31536000\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestRenderHumanSummaryAlignsLabelsAndCounts(t *testing.T) {
	results := []Result{{ID: "sub.www", Category: "Subdomain", Status: Fail, Remediation: "x"}}
	for i := range 10 {
		results = append(results, Result{ID: fmt.Sprintf("web.c%02d", i), Category: "WWW",
			Status: Pass})
	}
	out := renderHumanString(t, Report{Target: "example.org", Results: results}, View{Exit: 1})
	want := "\nSummary for example.org\n" +
		"Subdomain   1 FAIL   0 WARN   0 PASS   0 INFO   0 N/A\n" +
		"WWW         0 FAIL   0 WARN  10 PASS   0 INFO   0 N/A\n" +
		"Total       1 FAIL   0 WARN  10 PASS   0 INFO   0 N/A\n"
	if !strings.Contains(out, want) {
		t.Errorf("summary rows mismatch\n--- got ---\n%s--- want it to contain ---\n%s", out, want)
	}
}

func TestRenderHumanNeverWrapsOrTruncatesUntrustedText(t *testing.T) {
	long := strings.Repeat("v=spf1 include:_spf.example.net ", 40)
	r := Report{Target: "example.org", Results: []Result{
		{ID: "email.spf.record", Category: "Email", Title: long, Status: Warn, Evidence: long,
			Remediation: long},
		{ID: "email.arc.guidance", Category: "Email", Title: "ARC", Status: Info, Evidence: long},
	}}
	out := renderHumanString(t, r, View{})
	for _, want := range []string{
		"WARN  email.spf.record  " + long + "\n",
		"\n      evidence: " + long + "\n",
		"fix (1 line):\n" + long + "\n",
		"INFO  email.arc.guidance  ARC: " + long + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("long text was wrapped or truncated; output lacks %.60q...", want)
		}
	}
}

type humanFailWriter struct{ err error }

func (w humanFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRenderHumanReportsWriteError(t *testing.T) {
	sentinel := errors.New("broken pipe")
	err := RenderHuman(humanFailWriter{err: sentinel}, humanFixture(), View{Exit: 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("RenderHuman error = %v, want it to wrap %v", err, sentinel)
	}
	if want := "write terminal report for example.org: broken pipe"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}
