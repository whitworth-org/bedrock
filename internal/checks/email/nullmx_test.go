package email

import (
	"context"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestIsNullMX(t *testing.T) {
	cases := []struct {
		name string
		in   []probe.MX
		want bool
	}{
		{name: "RFC 7505 form", in: []probe.MX{{Preference: 0, Host: "."}}, want: true},
		{name: "RFC 7505 with empty host (trim-suffix output)", in: []probe.MX{{Preference: 0, Host: ""}}, want: true},
		{name: "real MX", in: []probe.MX{{Preference: 10, Host: "mail.example.com"}}, want: false},
		{name: "two records (cannot be null MX)", in: []probe.MX{{Preference: 0, Host: "."}, {Preference: 10, Host: "x"}}, want: false},
		{name: "empty", in: nil, want: false},
		{name: "wrong preference", in: []probe.MX{{Preference: 10, Host: "."}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNullMX(tc.in); got != tc.want {
				t.Errorf("isNullMX(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestMXChecks_ShareOneLookup: the checks that read the target's MX RRset
// share one lookup, so running them together sends one MX query and every
// check grades the same answer, here a null MX.
func TestMXChecks_ShareOneLookup(t *testing.T) {
	const nullMX = "domain publishes null MX (RFC 7505)"
	stats := &zoneStats{}
	zone := cannedZone{
		mx:    map[string][]string{"example.invalid": {"0 ."}},
		delay: 50 * time.Millisecond,
		stats: stats,
	}
	env := probe.NewEnv("example.invalid", 2*time.Second, true, startCannedDNS(t, zone))
	checks := []struct {
		run      func(context.Context, *probe.Env) []report.Result
		status   report.Status
		evidence string
	}{
		{runNullMX, report.Info, "domain advertises null MX (0 .) — accepts no mail"},
		{runMTASTSTXT, report.NotApplicable, nullMX},
		{runMTASTSPolicy, report.NotApplicable, nullMX},
		{runTLSRPT, report.NotApplicable, nullMX},
		{runDANE, report.NotApplicable, "no usable MX records — DANE not applicable"},
		{runSTARTTLS, report.NotApplicable, "no usable MX records"},
	}
	results := make([][]report.Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Go(func() { results[i] = c.run(context.Background(), env) })
	}
	wg.Go(func() {
		if res := runGoogleWorkspaceMX(context.Background(), env); res != nil {
			t.Errorf("email.google_workspace_mx: got %+v, want no result for a null MX", res)
		}
	})
	wg.Wait()

	if n := stats.count("example.invalid", mdns.TypeMX); n != 1 {
		t.Errorf("MX queries for example.invalid = %d, want 1 shared by every check", n)
	}
	for i, c := range checks {
		res := results[i]
		if len(res) != 1 || res[0].Status != c.status || res[0].Evidence != c.evidence {
			t.Errorf("got %+v, want one %s %q", res, c.status, c.evidence)
		}
	}
}

// TestMXChecks_PanickedLookup: when the shared MX lookup panics in the check
// that ran it, the checks that need the MX RRset are inconclusive and say
// so, rather than reading the missing answer as no MX.
func TestMXChecks_PanickedLookup(t *testing.T) {
	env := &probe.Env{Target: "example.com", Timeout: time.Second} // nil DNS: the lookup panics
	func() {
		defer func() { _ = recover() }()
		_, _ = targetMX(context.Background(), env)
		t.Error("the first targetMX call returned, want the lookup's panic")
	}()
	want := "could not determine: MX lookup for example.com: no result, because the check " +
		"that ran it panicked; see its registry.panic result"
	for _, run := range []func(context.Context, *probe.Env) []report.Result{
		runNullMX, runDANE, runSTARTTLS,
	} {
		res := run(context.Background(), env)
		if len(res) != 1 || res[0].Status != wantInconclusive || res[0].Evidence != want {
			t.Errorf("got %+v, want one inconclusive result %q", res, want)
		}
	}
}
