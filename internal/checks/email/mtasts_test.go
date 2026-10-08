package email

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestParseSTSPolicy(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
		mode    string
		maxAge  int
		mxLen   int
	}{
		{
			name:   "RFC 8461 example",
			body:   "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n",
			mode:   "enforce",
			maxAge: 604800,
			mxLen:  2,
		},
		{
			name:   "CRLF line endings",
			body:   "version: STSv1\r\nmode: testing\r\nmx: mx.example.org\r\nmax_age: 86400\r\n",
			mode:   "testing",
			maxAge: 86400,
			mxLen:  1,
		},
		{name: "missing version", body: "mode: enforce\nmx: x\nmax_age: 1", wantErr: true},
		{name: "bad mode", body: "version: STSv1\nmode: yes\nmax_age: 1", wantErr: true},
		{name: "bad max_age", body: "version: STSv1\nmode: enforce\nmax_age: forever", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSTSPolicy(tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSTSPolicy: %v", err)
			}
			if got.Mode != tc.mode {
				t.Errorf("Mode = %q, want %q", got.Mode, tc.mode)
			}
			if got.MaxAge != tc.maxAge {
				t.Errorf("MaxAge = %d, want %d", got.MaxAge, tc.maxAge)
			}
			if len(got.MX) != tc.mxLen {
				t.Errorf("len(MX) = %d, want %d", len(got.MX), tc.mxLen)
			}
		})
	}
}

func TestExtractSTSID(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`v=STSv1; id=20160831085700Z;`, "20160831085700Z"},
		{`v=STSv1`, ""},
		{`v=STSv1; foo=bar`, ""},
		{`v=STSv1; ID=ABC`, "ABC"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := extractSTSID(tc.raw); got != tc.want {
				t.Errorf("extractSTSID(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseSTSPolicy_ErrorQuoteIsBounded(t *testing.T) {
	huge := strings.Repeat("x", 1<<20)
	cases := []struct {
		name     string
		body     string
		maxBytes int
	}{
		{"malformed line", huge, 200},
		// Each control byte becomes a 3-byte U+FFFD, so 64 of them need more room.
		{"malformed line of control bytes", strings.Repeat("\x01", 1<<20), 256},
		{"max_age", "version: STSv1\nmode: enforce\nmax_age: " + huge, 200},
		{"version", "version: " + huge + "\nmode: enforce", 200},
		{"mode", "version: STSv1\nmode: " + huge, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSTSPolicy(tc.body)
			if err == nil {
				t.Fatal("ParseSTSPolicy accepted a malformed 1 MiB policy")
			}
			if n := len(err.Error()); n > tc.maxBytes {
				t.Errorf("error is %d bytes, want at most %d: %.80q", n, tc.maxBytes, err.Error())
			}
		})
	}
}

func TestMTASTSTXTRemediation_PlaceholderID(t *testing.T) {
	got := mtastsTXTRemediation("example.com")
	_, txt, _ := strings.Cut(got, `"`)
	id := extractSTSID(strings.TrimSuffix(txt, `"`))
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") {
		t.Errorf("remediation %q: id=%q must be a placeholder, because senders refetch the "+
			"policy only when the id changes", got, id)
	}
}

// TestRunMTASTSTXT_LookupFailures: a failed _mta-sts TXT lookup leaves the
// record unknown, so the check is inconclusive rather than FAIL.
func TestRunMTASTSTXT_LookupFailures(t *testing.T) {
	assertTXTLookupFailuresInconclusive(t, runMTASTSTXT, "example.com", "_mta-sts.example.com",
		cannedZone{})
}

// TestRunMTASTSTXT_NXDOMAINIsNoRecord: NXDOMAIN at _mta-sts means the domain
// publishes no MTA-STS record, which FAILs.
func TestRunMTASTSTXT_NXDOMAINIsNoRecord(t *testing.T) {
	res := runMTASTSTXT(context.Background(), newCannedEnv(t, "example.com", cannedZone{}))
	if len(res) != 1 || res[0].Status != report.Fail || res[0].Remediation == "" ||
		res[0].Evidence != "no v=STSv1 TXT record at _mta-sts.example.com" {
		t.Fatalf("got %+v, want one FAIL naming the missing record, with a remediation", res)
	}
}

// TestGradeSTSPolicy: a policy fetch that could not complete is
// inconclusive. Senders ignore a policy served with an invalid certificate,
// through a redirect, with any status but 200 or in a form that does not
// parse (RFC 8461 §3.3), and a host name that does not exist serves none, so
// those FAIL. A policy that was fetched grades by its mode.
func TestGradeSTSPolicy(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	_, certErr := probe.NewHTTP(2*time.Second).GetStrict(context.Background(), srv.URL)
	if certErr == nil {
		t.Fatal("GetStrict accepted the test server's self-signed certificate")
	}
	getErr := func(err error) error {
		return &url.Error{Op: "Get", URL: mtastsPolicyURL("example.com"), Err: err}
	}
	blocked := &probe.BlockedAddrError{Addr: netip.MustParseAddr("10.0.0.1"), Reason: "private"}
	noHost := &net.DNSError{Err: "no such host", Name: "mta-sts.example.com", IsNotFound: true}
	live := context.Background()
	ended, cancel := context.WithCancel(live)
	cancel()
	policy := func(mode string) *probe.Response {
		body := "version: STSv1\nmode: " + mode + "\nmx: mx.example.com\nmax_age: 604800\n"
		return &probe.Response{Status: 200, Body: []byte(body)}
	}
	// inconclusive is no real status: it wants a checkutil.Inconclusive result,
	// whose status a "testing" policy's WARN shares.
	const inconclusive report.Status = -1
	cases := []struct {
		name   string
		ctx    context.Context
		resp   *probe.Response
		err    error
		want   report.Status
		detail string // in the evidence
	}{
		{"timeout", live, nil, getErr(context.DeadlineExceeded), inconclusive, "deadline exceeded"},
		{"SSRF refusal", live, nil, getErr(blocked), inconclusive, "ssrf dial: refusing 10.0.0.1"},
		{"scan ended", ended, nil, getErr(context.Canceled), inconclusive, "context canceled"},
		{"certificate error", live, nil, certErr, report.Fail, "certificate"},
		{"no such host", live, nil, getErr(noHost), report.Fail, "no such host"},
		{"redirect", live, &probe.Response{Status: 302}, nil, report.Fail, "returned HTTP 302"},
		{"parse error", live, &probe.Response{Status: 200, Body: []byte("<html>")}, nil,
			report.Fail, "policy parse error"},
		{"enforce", live, policy("enforce"), nil, report.Pass, "mode=enforce"},
		{"testing", live, policy("testing"), nil, report.Warn, "mode=testing"},
		{"none", live, policy("none"), nil, report.Fail, "mode=none"},
	}
	base := report.Result{
		ID: "email.mtasts.policy", Category: category, RFCRefs: []string{"RFC 8461 §3.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gradeSTSPolicy(tc.ctx, base, "example.com", tc.resp, tc.err)
			if tc.want == inconclusive {
				assertInconclusive(t, r, tc.detail)
				return
			}
			if r.Status != tc.want || !strings.Contains(r.Evidence, tc.detail) ||
				(r.Remediation != "") != (tc.want == report.Fail) {
				t.Errorf("got %s %q (remediation %q), want %s naming %q, with a remediation "+
					"only on FAIL", r.Status, r.Evidence, r.Remediation, tc.want, tc.detail)
			}
		})
	}
}

// TestInboundTransportChecks_NullMX: a domain that publishes null MX
// accepts no mail (RFC 7505), so neither MTA-STS nor TLS-RPT applies, and
// the policy is not fetched.
func TestInboundTransportChecks_NullMX(t *testing.T) {
	zone := cannedZone{mx: map[string][]string{"example.invalid": {"0 ."}}}
	env := probe.NewEnv("example.invalid", 2*time.Second, true, startCannedDNS(t, zone))
	checks := []struct {
		id  string
		run func(context.Context, *probe.Env) []report.Result
	}{
		{"email.mtasts.txt", runMTASTSTXT},
		{"email.mtasts.policy", runMTASTSPolicy},
		{"email.tlsrpt.record", runTLSRPT},
	}
	for _, c := range checks {
		res := c.run(context.Background(), env)
		if len(res) != 1 || res[0].ID != c.id || res[0].Status != report.NotApplicable ||
			res[0].Evidence != "domain publishes null MX (RFC 7505)" || res[0].Remediation != "" {
			t.Errorf("%s: got %+v, want one N/A naming the null MX", c.id, res)
		}
	}
}

// TestRunMTASTSPolicy_CancelledScanIsInconclusive: the policy is fetched
// from the mta-sts host; a fetch the scan's end cut short is inconclusive.
func TestRunMTASTSPolicy_CancelledScanIsInconclusive(t *testing.T) {
	zone := cannedZone{mx: map[string][]string{"example.com": {"10 mx.example.com."}}}
	env := probe.NewEnv("example.com", 2*time.Second, true, startCannedDNS(t, zone))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := runMTASTSPolicy(ctx, env)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	assertInconclusive(t, res[0],
		`Get "https://mta-sts.example.com/.well-known/mta-sts.txt"`, "context canceled")
}

// TestInboundTransportChecks_MXLookupFailure: a failed MX lookup does not
// show a null MX, so the MTA-STS and TLS-RPT records are still graded.
func TestInboundTransportChecks_MXLookupFailure(t *testing.T) {
	env := newCannedEnv(t, "example.com", cannedZone{
		rcode: map[string]int{"example.com": mdns.RcodeServerFailure},
		txt: map[string][]string{
			"_mta-sts.example.com":   {"v=STSv1; id=20240101T000000Z"},
			"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
		},
	})
	for _, run := range []func(context.Context, *probe.Env) []report.Result{
		runMTASTSTXT, runTLSRPT,
	} {
		if res := run(context.Background(), env); len(res) != 1 || res[0].Status != report.Pass {
			t.Errorf("got %+v, want one PASS", res)
		}
	}
}
