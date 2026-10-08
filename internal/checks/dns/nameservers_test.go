package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// nsCheckRuns are the checks that read the apex NS RRset.
var nsCheckRuns = []func(context.Context, *probe.Env) []report.Result{
	runNSCount, runNSDiversity, runNSIPv6, runAXFR, runZoneSOA,
}

// TestNameserverList_OneLookupForConcurrentChecks: the checks that need
// the apex NS RRset run concurrently under the registry, and they share
// one NS query and one view of the RRset: sorted, lower-cased and without
// duplicates.
func TestNameserverList_OneLookupForConcurrentChecks(t *testing.T) {
	fake, env := axfrEnv(t, "ns2.example.test.", "NS1.example.test.", "ns1.example.test.")
	fake.add(t, testSOA)
	fake.setDelay("example.test.", 100*time.Millisecond) // keeps every check waiting at once
	startAXFRServer(t, answer(miekg.RcodeRefused))

	results := map[string]report.Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, run := range nsCheckRuns {
		wg.Go(func() {
			for _, r := range run(context.Background(), env) {
				mu.Lock()
				results[r.ID] = r
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if n := fake.queryCount("example.test.", miekg.TypeNS); n != 1 {
		t.Errorf("sent %d apex NS queries, want 1", n)
	}
	if r := results["dns.ns.count"]; r.Status != report.Pass ||
		r.Title != "Apex has 2 NS records" || r.Evidence != "ns1.example.test, ns2.example.test" {
		t.Errorf("dns.ns.count = %s %q %q, want PASS naming the two nameservers in order",
			r.Status, r.Title, r.Evidence)
	}
	if r := results["dns.zone.mname"]; r.Status != report.Pass {
		t.Errorf("dns.zone.mname = %s %q, want PASS: the MNAME is in the shared NS list",
			r.Status, r.Evidence)
	}
}

// TestNSAddressChecks_BoundFanout: a 40-name NS RRset is examined 16 names
// deep and at most 4 lookups wide, each lookup under its own timeout, so
// ceil(16/4) rounds of answers that together take longer than one timeout
// still count; the evidence counts the names not examined. Concurrency is
// read from the resolver, not the clock, so a slow machine cannot fail it.
func TestNSAddressChecks_BoundFanout(t *testing.T) {
	const timeout, delay = time.Second, 300 * time.Millisecond
	fake := newFakeDNS(t)
	names := slowNameservers(t, fake, 40, delay)
	env := fake.env(t, "example.test", timeout)

	cases := []struct {
		run   func(context.Context, *probe.Env) []report.Result
		qtype uint16
		title string
	}{
		{runNSDiversity, miekg.TypeA, "Nameservers span 16 distinct /24 prefix(es)"},
		{runNSIPv6, miekg.TypeAAAA, "16/16 nameserver(s) advertise IPv6"},
	}
	results := make([]report.Result, len(cases))
	var wg sync.WaitGroup
	for i, tc := range cases {
		wg.Go(func() { results[i] = tc.run(context.Background(), env)[0] })
	}
	wg.Wait()

	for i, tc := range cases {
		r := results[i]
		if n := fake.peakInFlight(tc.qtype); n < 2 || n > 4 {
			t.Errorf("%s sent up to %d lookups at once, want 2 to 4", r.ID, n)
		}
		const skipped = "; 24 nameserver(s) beyond the first 16 not examined"
		if r.Status != report.Pass || r.Title != tc.title ||
			!strings.HasSuffix(r.Evidence, skipped) {
			t.Errorf("%s = %s %q %q, want PASS %q with evidence ending %q",
				r.ID, r.Status, r.Title, r.Evidence, tc.title, skipped)
		}
	}
	assertNotLookedUp(t, fake, names[16:])
}

// slowNameservers delegates example.test to n nameservers, ns01 up, each
// with its own IPv4 /24 and IPv6 address and answering after delay, and
// returns their names.
func slowNameservers(t *testing.T, fake *fakeDNS, n int, delay time.Duration) []string {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		ns := fmt.Sprintf("ns%02d.example.test.", i+1)
		fake.add(t, "example.test. 300 IN NS "+ns,
			fmt.Sprintf("%s 300 IN A 10.0.%d.1", ns, i+1),
			fmt.Sprintf("%s 300 IN AAAA 2001:db8:%x::1", ns, i+1))
		fake.setDelay(ns, delay)
		names[i] = ns
	}
	return names
}

// assertNotLookedUp checks that fake received no address query for names.
func assertNotLookedUp(t *testing.T, fake *fakeDNS, names []string) {
	t.Helper()
	for _, ns := range names {
		if n := fake.queryCount(ns, miekg.TypeA) + fake.queryCount(ns, miekg.TypeAAAA); n != 0 {
			t.Errorf("looked up skipped nameserver %s %d times", ns, n)
		}
	}
}

// TestNSAddressChecks_LookupFailures: a nameserver whose address lookup
// failed is not reported as having no address. When every lookup failed
// the checks are inconclusive; when some answered, the failures are named
// beside the definite answers.
func TestNSAddressChecks_LookupFailures(t *testing.T) {
	const servfail = "lookup failed: resolver answered SERVFAIL"
	cases := []struct {
		name     string
		failing  []string // nameservers whose lookups SERVFAIL; the rest do not exist
		status   report.Status
		evidence string
		run      func(context.Context, *probe.Env) []report.Result
	}{
		{"every A lookup failed", []string{"ns1", "ns2"}, wantInconclusive,
			"could not determine: ns1.example.test (A " + servfail +
				"); ns2.example.test (A " + servfail + ")", runNSDiversity},
		{"every AAAA lookup failed", []string{"ns1", "ns2"}, wantInconclusive,
			"could not determine: ns1.example.test (AAAA " + servfail +
				"); ns2.example.test (AAAA " + servfail + ")", runNSIPv6},
		{"one A lookup failed", []string{"ns1"}, report.Fail,
			"ns1.example.test (A " + servfail + "); ns2.example.test (no A)", runNSDiversity},
		{"one AAAA lookup failed", []string{"ns1"}, report.Warn,
			"all NS resolve to IPv4 only: ns1.example.test (AAAA " + servfail +
				"),ns2.example.test", runNSIPv6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.add(t, "example.test. 300 IN NS ns1.example.test.",
				"example.test. 300 IN NS ns2.example.test.")
			for _, ns := range tc.failing {
				fake.setRcode(ns+".example.test.", miekg.RcodeServerFailure)
			}
			env := fake.env(t, "example.test", axfrTestTimeout)
			r := tc.run(context.Background(), env)[0]
			if r.Status != tc.status || r.Evidence != tc.evidence {
				t.Errorf("%s = %s %q, want %s %q",
					r.ID, r.Status, r.Evidence, tc.status, tc.evidence)
			}
			if (r.Remediation != "") != (tc.status == report.Fail) {
				t.Errorf("remediation %q, want one only on FAIL", r.Remediation)
			}
		})
	}
}

// TestNSChecks_ApexLookupFailures: an NS or SOA lookup the resolver could
// not answer, or that the scan's cancellation interrupted, makes the checks
// that need it inconclusive; NXDOMAIN keeps its N/A and FAIL. Evidence is
// matched by prefix, as a cancelled lookup's names the resolver's address.
func TestNSChecks_ApexLookupFailures(t *testing.T) {
	type want struct {
		status   report.Status
		evidence string
	}
	const (
		nsFailed  = "could not determine: NS lookup for example.test: resolver answered SERVFAIL"
		soaFailed = "could not determine: SOA lookup for example.test: resolver answered SERVFAIL"
	)
	cases := []struct {
		name   string
		rcode  int
		cancel bool
		want   map[string]want
	}{
		{"SERVFAIL", miekg.RcodeServerFailure, false, map[string]want{
			"dns.ns.count":     {wantInconclusive, nsFailed},
			"dns.ns.diversity": {wantInconclusive, nsFailed},
			"dns.ns.ipv6":      {wantInconclusive, nsFailed},
			"dns.axfr":         {wantInconclusive, nsFailed},
			"dns.zone.soa":     {wantInconclusive, soaFailed},
		}},
		{"NXDOMAIN", miekg.RcodeNameError, false, map[string]want{
			"dns.ns.count":     {report.Fail, "NS lookup failed: NXDOMAIN"},
			"dns.ns.diversity": {report.NotApplicable, "no NS records resolved"},
			"dns.ns.ipv6":      {report.NotApplicable, "no NS records resolved"},
			"dns.axfr":         {report.NotApplicable, "no NS records to probe"},
			"dns.zone.soa":     {report.Fail, "lookup error: NXDOMAIN"},
		}},
		{"cancelled", miekg.RcodeSuccess, true, map[string]want{
			"dns.axfr": {wantInconclusive, "could not determine: NS lookup for example.test: "},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.setRcode("example.test.", tc.rcode)
			env := fake.env(t, "example.test", axfrTestTimeout)
			ctx, cancel := context.WithCancel(context.Background())
			if tc.cancel {
				cancel()
			}
			defer cancel()
			for _, run := range nsCheckRuns {
				r := run(ctx, env)[0]
				w, ok := tc.want[r.ID]
				if !ok {
					continue
				}
				if r.Status != w.status || !strings.HasPrefix(r.Evidence, w.evidence) {
					t.Errorf("%s = %s %q, want %s %q",
						r.ID, r.Status, r.Evidence, w.status, w.evidence)
				}
				if (r.Remediation != "") != (w.status == report.Fail) {
					t.Errorf("%s remediation %q, want one only on FAIL", r.ID, r.Remediation)
				}
			}
		})
	}
}

// TestLookupNSAddrs_PanicReachesCaller: a panic in one nameserver's address
// lookup reaches the check's goroutine, where the registry turns it into a
// result, rather than ending the scan.
func TestLookupNSAddrs_PanicReachesCaller(t *testing.T) {
	env := &probe.Env{Target: "example.test", Timeout: time.Second}
	names := []string{"ns1.example.test", "ns2.example.test"}
	got := func() (r any) {
		defer func() { r = recover() }()
		lookupNSAddrs(context.Background(), env, names,
			func(_ context.Context, name string) ([]net.IP, error) {
				if name == "ns2.example.test" {
					panic("boom in " + name)
				}
				return nil, nil
			})
		return nil
	}()
	if got != "boom in ns2.example.test" {
		t.Fatalf("recovered %v, want the lookup's panic", got)
	}
}

// TestNSCount_SingleNameserverFails: one NS record gives no redundancy.
func TestNSCount_SingleNameserverFails(t *testing.T) {
	fake := newFakeDNS(t)
	fake.add(t, "example.test. 300 IN NS ns1.example.test.")
	env := fake.env(t, "example.test", time.Second)

	r := runNSCount(context.Background(), env)[0]

	if r.Status != report.Fail || r.Title != "Apex NS RRset has fewer than two nameservers" ||
		r.Evidence != "NS count=1 (ns1.example.test)" ||
		r.Remediation != nsCountRemediation("example.test") {
		t.Errorf("dns.ns.count = %s %q %q, want FAIL naming the one nameserver",
			r.Status, r.Title, r.Evidence)
	}
}

// TestNameserverList_PanickedLookup: when the shared NS lookup panics in
// the check that ran it, the other checks get an error naming that, not an
// empty NS list.
func TestNameserverList_PanickedLookup(t *testing.T) {
	env := &probe.Env{Target: "example.test", Timeout: time.Second} // nil DNS: the lookup panics
	func() {
		defer func() { _ = recover() }()
		_, _ = nameserverList(context.Background(), env)
		t.Error("the first nameserverList call returned, want the lookup's panic")
	}()
	r := runNSCount(context.Background(), env)[0]
	want := "could not determine: NS lookup for example.test: no result, because the check " +
		"that ran it panicked; see its registry.panic result"
	if r.Status != wantInconclusive || r.Evidence != want {
		t.Errorf("dns.ns.count = %s %q, want inconclusive %q", r.Status, r.Evidence, want)
	}
}
