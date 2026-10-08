package email

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// These tests run the shared DKIM selector sweep and the email.dkim check
// against the canned resolver in fakedns_test.go.

// ed25519Record is a key record holding the RFC 8463 example key.
const ed25519Record = "v=DKIM1; k=ed25519; p=" + ed25519TestKey

// TestDKIMSweepBoundedConcurrency: the sweep keeps several lookups in
// flight, never more than dkimSweepConcurrency, asks for each selector once
// and reports the selectors in list order.
func TestDKIMSweepBoundedConcurrency(t *testing.T) {
	stats := &zoneStats{}
	env := newCannedEnv(t, "example.com", cannedZone{
		txt:   map[string][]string{"google._domainkey.example.com": {ed25519Record}},
		delay: 25 * time.Millisecond,
		stats: stats,
	})
	sweep := dkimSweep(context.Background(), env)

	if peak := stats.maxInFlight(); peak < 2 || peak > dkimSweepConcurrency {
		t.Errorf("peak lookups in flight = %d, want 2..%d", peak, dkimSweepConcurrency)
	}
	assertProbedInOrder(t, sweep, stats)
	if found := sweep.Found(); len(found) != 1 || found[0].Selector != "google" {
		t.Errorf("keys found at %+v, want google only", found)
	}
}

// assertProbedInOrder fails unless sweep holds one probe per selector, in
// selector order, each from a single TXT query.
func assertProbedInOrder(t *testing.T, sweep *DKIMSweep, stats *zoneStats) {
	t.Helper()
	if len(sweep.Probes) != len(sweep.Selectors) {
		t.Fatalf("%d probes for %d selectors", len(sweep.Probes), len(sweep.Selectors))
	}
	for i, p := range sweep.Probes {
		if p.Selector != sweep.Selectors[i] {
			t.Errorf("Probes[%d] is for %s, want %s", i, p.Selector, sweep.Selectors[i])
		}
		if n := stats.count(p.Name, mdns.TypeTXT); n != 1 {
			t.Errorf("%s queried %d times, want once", p.Name, n)
		}
	}
}

// TestRunDKIMLookupFailures: a failed lookup says nothing about whether the
// selector publishes a key, so it never makes the check FAIL.
func TestRunDKIMLookupFailures(t *testing.T) {
	servfail := map[string]int{"google._domainkey.example.com": mdns.RcodeServerFailure}

	t.Run("every lookup fails", func(t *testing.T) {
		env := newCannedEnv(t, "example.com", cannedZone{
			rcode: map[string]int{"*": mdns.RcodeServerFailure},
		})
		res := runDKIM(context.Background(), env)
		if len(res) != 1 || res[0].ID != "email.dkim.selector.none" {
			t.Fatalf("results = %v, want only email.dkim.selector.none", resultIDs(res))
		}
		assertInconclusive(t, res[0], fmt.Sprintf("all %d selectors", len(commonSelectors)),
			"resolver answered SERVFAIL")
	})

	t.Run("one lookup fails and no selector has a key", func(t *testing.T) {
		env := newCannedEnv(t, "example.com", cannedZone{rcode: servfail})
		res := runDKIM(context.Background(), env)
		if len(res) != 1 || res[0].ID != "email.dkim.selector.none" {
			t.Fatalf("results = %v, want only email.dkim.selector.none", resultIDs(res))
		}
		assertInconclusive(t, res[0],
			fmt.Sprintf("1 of %d selectors (google;", len(commonSelectors)),
			"resolver answered SERVFAIL", "the others publish no key")
	})

	t.Run("one lookup fails beside a key", func(t *testing.T) {
		env := newCannedEnv(t, "example.com", cannedZone{
			txt:   map[string][]string{"selector1._domainkey.example.com": {ed25519Record}},
			rcode: servfail,
		})
		res := runDKIM(context.Background(), env)
		want := []string{"email.dkim.selector.selector1", "email.dkim.selector.google"}
		if !slices.Equal(resultIDs(res), want) {
			t.Fatalf("results = %v, want %v", resultIDs(res), want)
		}
		if res[0].Status != report.Pass {
			t.Errorf("selector1 = %s %q, want PASS", res[0].Status, res[0].Evidence)
		}
		assertInconclusive(t, res[1], "google._domainkey.example.com", "resolver answered SERVFAIL")
	})
}

// TestRunDKIMCancelledScan: once the scan is cancelled no selector lookup
// goes out, and the sweep is inconclusive rather than a missing key.
func TestRunDKIMCancelledScan(t *testing.T) {
	stats := &zoneStats{}
	env := newCannedEnv(t, "example.com", cannedZone{stats: stats})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := runDKIM(ctx, env)
	if len(res) != 1 || res[0].ID != "email.dkim.selector.none" {
		t.Fatalf("results = %v, want only email.dkim.selector.none", resultIDs(res))
	}
	assertInconclusive(t, res[0], "TXT lookups failed for all", "context canceled")
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if len(stats.queries) != 0 {
		t.Errorf("sent %v after the cancel, want no queries", stats.queries)
	}
}

// TestRunDKIMWildcard: a TXT wildcard under _domainkey answers every
// selector that has no record of its own, so the check reports it once, as
// email.dkim.wildcard, and never names the random selector it probes with.
func TestRunDKIMWildcard(t *testing.T) {
	const wildcard = "*._domainkey.example.com"
	cases := []struct {
		name  string
		txt   map[string][]string
		want  map[string]report.Status
		found []string // the selectors whose key DKIMSweep.Found returns
	}{
		{
			name: "key wildcard",
			txt:  map[string][]string{wildcard: {ed25519Record}},
			want: map[string]report.Status{"email.dkim.wildcard": report.Pass},
		},
		{
			name: "revoke-all wildcard",
			txt:  map[string][]string{wildcard: {"v=DKIM1; p="}},
			want: map[string]report.Status{"email.dkim.wildcard": report.Info},
		},
		{
			name: "revoke-all wildcard beside a key",
			txt: map[string][]string{
				wildcard:                        {"v=DKIM1; p="},
				"google._domainkey.example.com": {ed25519Record},
			},
			want: map[string]report.Status{
				"email.dkim.wildcard":        report.Info,
				"email.dkim.selector.google": report.Pass,
			},
			found: []string{"google"},
		},
		{
			name: "malformed wildcard",
			txt:  map[string][]string{wildcard: {"v=DKIM1; k=rsa"}},
			want: map[string]report.Status{"email.dkim.wildcard": report.Fail},
		},
		{
			name: "SPF wildcard holds no DKIM key",
			txt:  map[string][]string{"*.example.com": {"v=spf1 -all"}},
			want: map[string]report.Status{"email.dkim.selector.none": report.Fail},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stats := &zoneStats{}
			env := newCannedEnv(t, "example.com", cannedZone{txt: tc.txt, stats: stats})
			res := runDKIM(context.Background(), env)

			got := make(map[string]report.Status, len(res))
			for _, r := range res {
				got[r.ID] = r.Status
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("results = %v, want %v", got, tc.want)
			}
			if err := report.CheckUniqueIDs(res); err != nil {
				t.Error(err)
			}
			sweep := dkimSweep(context.Background(), env)
			var found []string
			for _, p := range sweep.Found() {
				found = append(found, p.Selector)
			}
			_, wantWildcard := tc.want["email.dkim.wildcard"]
			if (sweep.Wildcard != nil) != wantWildcard || !slices.Equal(found, tc.found) {
				t.Errorf("sweep: wildcard %+v, keys at %q; want wildcard %v, keys at %q",
					sweep.Wildcard, found, wantWildcard, tc.found)
			}
			assertWildcardEvidence(t, res, wildcardProbeLabel(t, stats))
		})
	}
}

// assertWildcardEvidence fails when a result names the random selector, or
// when the email.dkim.wildcard result does not name the wildcard owner.
func assertWildcardEvidence(t *testing.T, res []report.Result, label string) {
	t.Helper()
	for _, r := range res {
		if strings.Contains(r.ID+r.Title+r.Evidence+r.Remediation, label) {
			t.Errorf("%s names the random selector %q: %q", r.ID, label, r.Evidence)
		}
		const owner = "*._domainkey.example.com"
		if r.ID == "email.dkim.wildcard" && !strings.Contains(r.Evidence, owner) {
			t.Errorf("wildcard evidence %q does not name %s", r.Evidence, owner)
		}
	}
}

// wildcardProbeLabel returns the one _domainkey label the zone was asked
// about that is not on the selector list: the random selector the sweep
// probes a wildcard with.
func wildcardProbeLabel(t *testing.T, stats *zoneStats) string {
	t.Helper()
	known := selectorList(nil)
	stats.mu.Lock()
	defer stats.mu.Unlock()
	var labels []string
	for key := range stats.queries {
		name, _, _ := strings.Cut(key, " ")
		label, ok := strings.CutSuffix(name, "._domainkey.example.com")
		if ok && !slices.Contains(known, label) {
			labels = append(labels, label)
		}
	}
	if len(labels) != 1 {
		t.Fatalf("labels queried beside the selector list = %q, want one random label", labels)
	}
	return labels[0]
}

// randomSelectorZone answers like zone, except for queries about the random
// selectors the sweep probes for a wildcard (any _domainkey label off the
// selector list): it holds each one for hold and answers the first fail of
// them with SERVFAIL. It counts those queries, and the selector queries that
// arrive while one is held.
type randomSelectorZone struct {
	zone cannedZone
	hold time.Duration
	fail int

	mu         sync.Mutex
	random     int
	holding    int
	overlapped int
}

func (z *randomSelectorZone) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	name := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))
	label, _ := strings.CutSuffix(name, "._domainkey.example.com")
	z.mu.Lock()
	if slices.Contains(selectorList(nil), label) {
		z.overlapped += min(z.holding, 1)
		z.mu.Unlock()
		z.zone.ServeDNS(w, req)
		return
	}
	z.random++
	z.holding++
	failing := z.random <= z.fail
	z.mu.Unlock()

	time.Sleep(z.hold)
	z.mu.Lock()
	z.holding--
	z.mu.Unlock()
	if failing {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		_ = w.WriteMsg(resp)
		return
	}
	z.zone.ServeDNS(w, req)
}

// counts returns the random-selector queries received and the selector
// queries that arrived while one was held.
func (z *randomSelectorZone) counts() (random, overlapped int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.random, z.overlapped
}

// TestRunDKIMWildcardLookupFails: a failed lookup for the random selector is
// retried once with another, and when both fail the record that most
// selectors share is reported once, as an inconclusive email.dkim.wildcard,
// instead of once per selector.
func TestRunDKIMWildcardLookupFails(t *testing.T) {
	revokeAll := map[string][]string{
		"*._domainkey.example.com":      {"v=DKIM1; p="},
		"google._domainkey.example.com": {ed25519Record},
	}
	onlyGoogleAnswers := map[string]int{}
	onlyGoogleWant := map[string]report.Status{"email.dkim.selector.google": report.Pass}
	for _, sel := range selectorList(nil) {
		if sel != "google" {
			onlyGoogleAnswers[sel+"._domainkey.example.com"] = mdns.RcodeServerFailure
			onlyGoogleWant["email.dkim.selector."+sel] = wantInconclusive
		}
	}
	cases := []struct {
		name  string
		fail  int
		txt   map[string][]string
		rcode map[string]int
		want  map[string]report.Status
	}{
		{
			name: "the retry finds the wildcard",
			fail: 1,
			txt:  revokeAll,
			want: map[string]report.Status{
				"email.dkim.selector.google": report.Pass,
				"email.dkim.wildcard":        report.Info,
			},
		},
		{
			name: "both lookups fail",
			fail: 2,
			txt:  revokeAll,
			want: map[string]report.Status{
				"email.dkim.selector.google": report.Pass,
				"email.dkim.wildcard":        wantInconclusive,
			},
		},
		{
			name: "both lookups fail and no record is shared",
			fail: 2,
			txt:  map[string][]string{"google._domainkey.example.com": {ed25519Record}},
			want: map[string]report.Status{"email.dkim.selector.google": report.Pass},
		},
		{
			name: "both lookups fail and few selectors share a record",
			fail: 2,
			txt: map[string][]string{
				"selector1._domainkey.example.com": {ed25519Record},
				"selector2._domainkey.example.com": {ed25519Record},
			},
			want: map[string]report.Status{
				"email.dkim.selector.selector1": report.Pass,
				"email.dkim.selector.selector2": report.Pass,
			},
		},
		{
			name:  "both lookups fail and one selector is answered",
			fail:  2,
			txt:   revokeAll,
			rcode: onlyGoogleAnswers,
			want:  onlyGoogleWant,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := &randomSelectorZone{zone: cannedZone{txt: tc.txt, rcode: tc.rcode}, fail: tc.fail}
			env := probe.NewEnv("example.com", 2*time.Second, false, serveDNS(t, z))
			res := runDKIM(context.Background(), env)

			got := make(map[string]report.Status, len(res))
			for _, r := range res {
				got[r.ID] = r.Status
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("results = %v, want %v", got, tc.want)
			}
			if random, _ := z.counts(); random != 2 {
				t.Errorf("%d random selectors probed, want 2", random)
			}
			if tc.want["email.dkim.wildcard"] == wantInconclusive {
				assertInconclusive(t, res[len(res)-1],
					"whether *._domainkey.example.com is a wildcard: TXT lookups for random "+
						"selectors failed (resolver answered SERVFAIL); "+
						fmt.Sprintf("%d selectors share its key record", len(selectorList(nil))-1))
			}
		})
	}
}

// TestDKIMSweepProbesRandomSelectorBesideList: the random selector's lookup
// overlaps the selector lookups rather than delaying them.
func TestDKIMSweepProbesRandomSelectorBesideList(t *testing.T) {
	z := &randomSelectorZone{
		zone: cannedZone{delay: 20 * time.Millisecond},
		hold: 300 * time.Millisecond,
	}
	env := probe.NewEnv("example.com", 2*time.Second, false, serveDNS(t, z))
	dkimSweep(context.Background(), env)
	if _, overlapped := z.counts(); overlapped == 0 {
		t.Error("no selector was probed while the random selector's lookup was in flight")
	}
}

// TestDKIMSweepPanicReachesCaller: a panic in a sweep lookup reaches the
// check's goroutine, where the registry turns it into a result, rather
// than ending the scan.
func TestDKIMSweepPanicReachesCaller(t *testing.T) {
	env := &probe.Env{Target: "example.com", Timeout: time.Second} // nil DNS panics
	got := func() (r any) {
		defer func() { r = recover() }()
		runDKIMSweep(context.Background(), env)
		return nil
	}()
	if got == nil {
		t.Fatal("runDKIMSweep returned; want the lookup's panic")
	}
}
