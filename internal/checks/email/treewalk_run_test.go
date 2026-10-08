// treewalk_run_test.go exercises the DMARCbis checks end-to-end against a
// canned in-process DNS server (the same technique as the top-level golden
// integration test): TXT answers come from a per-test zone map, and A-query
// behavior is switchable so the RFC 8020 probe's NXDOMAIN / NODATA /
// wildcard paths can each be driven deterministically.

package email

import (
	"context"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestRunDMARCInheritedFromOrgDomain(t *testing.T) {
	env := newCannedEnv(t, "mail.example.com", cannedZone{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	})

	res := runDMARC(context.Background(), env)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	r := res[0]
	if r.Status != report.Pass {
		t.Errorf("Status = %s, want Pass (evidence=%q)", r.Status, r.Evidence)
	}
	if !contains(r.Evidence, "covered by _dmarc.example.com") {
		t.Errorf("evidence should name the covering domain; got %q", r.Evidence)
	}

	disc := runDMARCDiscovery(context.Background(), env)
	if len(disc) != 1 {
		t.Fatalf("discovery: want 1 result, got %d", len(disc))
	}
	d := disc[0]
	if d.Status != report.Pass {
		t.Errorf("discovery Status = %s, want Pass (evidence=%q)", d.Status, d.Evidence)
	}
	if !contains(d.Evidence, "organizational domain example.com") ||
		!contains(d.Evidence, "queries 3/8") {
		t.Errorf("discovery evidence = %q", d.Evidence)
	}
}

func TestRunDMARCDiscoveryAnomalies(t *testing.T) {
	env := newCannedEnv(t, "mail.example.com", cannedZone{
		txt: map[string][]string{
			"_dmarc.mail.example.com": {"v=DMARC1; p=bogus"}, // malformed
			"_dmarc.example.com":      {"v=DMARC1; p=quarantine"},
		},
	})

	// The author domain's record is malformed: the record check must Fail...
	res := runDMARC(context.Background(), env)
	if len(res) != 1 || res[0].Status != report.Fail {
		t.Fatalf("want single Fail, got %+v", res)
	}
	if !contains(res[0].Evidence, "parse error") {
		t.Errorf("evidence = %q, want parse error", res[0].Evidence)
	}

	// ...and discovery must surface the ignored malformed step as an anomaly.
	disc := runDMARCDiscovery(context.Background(), env)
	if len(disc) != 1 || disc[0].Status != report.Warn {
		t.Fatalf("discovery: want single Warn, got %+v", disc)
	}
	if !contains(disc[0].Evidence, "anomalies:") ||
		!contains(disc[0].Evidence, "_dmarc.mail.example.com is malformed") {
		t.Errorf("discovery evidence = %q", disc[0].Evidence)
	}
}

func TestRunDMARCNP_RFC8020(t *testing.T) {
	const rfc8020ID = "email.dmarc.np.rfc8020"
	zone := map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; np=reject"},
	}
	cases := []struct {
		name       string
		aMode      string
		wantStatus report.Status
		wantSub    string
		wantRemed  bool
	}{
		{name: "NXDOMAIN passes", aMode: aNXDomain, wantStatus: report.Pass, wantSub: "NXDOMAIN"},
		{name: "wildcard warns", aMode: aWildcard, wantStatus: report.Warn, wantSub: "wildcard", wantRemed: true},
		{name: "NODATA warns", aMode: aNoData, wantStatus: report.Warn, wantSub: "NOERROR", wantRemed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newCannedEnv(t, "example.com", cannedZone{txt: zone, aMode: tc.aMode})
			res := runDMARCNonExistentPolicy(context.Background(), env)
			if len(res) != 2 {
				t.Fatalf("want np + rfc8020 results, got %d: %+v", len(res), res)
			}
			if res[0].ID != "email.dmarc.np" || res[0].Status != report.Pass {
				t.Errorf("np result = %+v, want Pass", res[0])
			}
			r := res[1]
			if r.ID != rfc8020ID {
				t.Fatalf("second result ID = %q, want %q", r.ID, rfc8020ID)
			}
			if r.Status != tc.wantStatus {
				t.Errorf("Status = %s, want %s (evidence=%q)", r.Status, tc.wantStatus, r.Evidence)
			}
			if !contains(r.Evidence, tc.wantSub) {
				t.Errorf("evidence = %q, want substring %q", r.Evidence, tc.wantSub)
			}
			if tc.wantRemed && r.Remediation == "" {
				t.Error("expected remediation, got empty")
			}
		})
	}
}

func TestRunDMARCExtDest(t *testing.T) {
	cases := []struct {
		name       string
		record     string
		extra      map[string][]string
		wantStatus report.Status
		wantSub    string
		wantRemed  bool
	}{
		{
			name:   "external destination authorized",
			record: "v=DMARC1; p=reject; rua=mailto:agg@monitor.example",
			extra: map[string][]string{
				"example.com._report._dmarc.monitor.example": {"v=DMARC1"},
			},
			wantStatus: report.Pass,
			wantSub:    "monitor.example",
		},
		{
			name:       "external destination missing consent",
			record:     "v=DMARC1; p=reject; rua=mailto:agg@monitor.example",
			wantStatus: report.Warn,
			wantSub:    "have not authorized example.com",
			wantRemed:  true,
		},
		{
			name:       "internal destinations only",
			record:     "v=DMARC1; p=reject; rua=mailto:box@example.com",
			wantStatus: report.Info,
			wantSub:    "inside the organizational domain",
		},
		{
			name:       "no destinations published",
			record:     "v=DMARC1; p=reject",
			wantStatus: report.NotApplicable,
			wantSub:    "no rua= or ruf= destinations",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := map[string][]string{"_dmarc.example.com": {tc.record}}
			for k, v := range tc.extra {
				zone[k] = v
			}
			env := newCannedEnv(t, "example.com", cannedZone{txt: zone})
			res := runDMARCExtDest(context.Background(), env)
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(res), res)
			}
			r := res[0]
			if r.Status != tc.wantStatus {
				t.Errorf("Status = %s, want %s (evidence=%q)", r.Status, tc.wantStatus, r.Evidence)
			}
			if !contains(r.Evidence, tc.wantSub) {
				t.Errorf("evidence = %q, want substring %q", r.Evidence, tc.wantSub)
			}
			if tc.wantRemed && r.Remediation == "" {
				t.Error("expected remediation, got empty")
			}
		})
	}
}

// TestDMARCChecksIncompleteWalk: when the tree walk could not settle which
// DMARC record applies, because the scan was interrupted, the check that ran
// the walk panicked or an ancestor's lookup failed, the checks that need
// that record are inconclusive rather than failing or N/A for a missing
// record.
func TestDMARCChecksIncompleteWalk(t *testing.T) {
	interrupted := func(t *testing.T) (context.Context, *probe.Env) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, newCannedEnv(t, "example.com", cannedZone{})
	}
	panicked := func(t *testing.T) (context.Context, *probe.Env) {
		env := &probe.Env{Target: "example.com", Timeout: time.Second} // nil DNS panics
		func() {
			defer func() { _ = recover() }()
			EnsureDMARCWalk(context.Background(), env)
			t.Error("EnsureDMARCWalk returned, want the walk's panic")
		}()
		return context.Background(), env
	}
	ancestorFails := func(t *testing.T) (context.Context, *probe.Env) {
		return context.Background(), newCannedEnv(t, "mail.example.com", cannedZone{
			rcode: map[string]int{"_dmarc.example.com": mdns.RcodeServerFailure},
		})
	}
	cases := []struct {
		name  string
		setup func(*testing.T) (context.Context, *probe.Env)
		want  string
	}{
		{"scan interrupted", interrupted,
			"DMARC tree walk stopped after 0 of 2 queries: context canceled"},
		{"walk panicked", panicked, errWalkPanicked.Error()},
		{"ancestor lookup failed", ancestorFails,
			"TXT lookup for _dmarc.example.com: resolver answered SERVFAIL"},
	}
	arcDMARC := func(ctx context.Context, env *probe.Env) []report.Result {
		return []report.Result{arcDMARCResult(ctx, env)}
	}
	checks := []func(context.Context, *probe.Env) []report.Result{
		runDMARC, runDMARCDiscovery, runDMARCExtDest, runDMARCRejectDKIM,
		runDMARCNonExistentPolicy, arcDMARC,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, env := tc.setup(t)
			for _, run := range checks {
				res := run(ctx, env)
				if len(res) != 1 {
					t.Fatalf("want 1 result, got %d: %+v", len(res), res)
				}
				assertInconclusive(t, res[0], "could not determine: "+tc.want)
			}
		})
	}
}
