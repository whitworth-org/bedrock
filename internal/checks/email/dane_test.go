package email

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// daneEE is the RDATA of a well-formed DANE-EE SPKI SHA-256 TLSA record.
var daneEE = "3 1 1 " + strings.Repeat("ab", 32)

var wantInconclusive = checkutil.Inconclusive(report.Result{}, errors.New("probe")).Status

// assertInconclusive fails unless r is a checkutil.Inconclusive result whose
// evidence names every detail.
func assertInconclusive(t *testing.T, r report.Result, details ...string) {
	t.Helper()
	ok := r.Status == wantInconclusive && strings.HasPrefix(r.Evidence, "could not determine: ") &&
		r.Remediation == ""
	for _, d := range details {
		ok = ok && strings.Contains(r.Evidence, d)
	}
	if !ok {
		t.Errorf("%s = %s %q (remediation %q), want inconclusive naming %q",
			r.ID, r.Status, r.Evidence, r.Remediation, details)
	}
}

func resultIDs(rs []report.Result) []string {
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID
	}
	return ids
}

// TestRunDANE_TLSALookupFailures: a TLSA query answered with SERVFAIL or
// REFUSED, or not answered at all, says nothing about whether the MX
// publishes TLSA (RFC 7672 §2.1.2), so the result is inconclusive rather
// than "not deployed".
func TestRunDANE_TLSALookupFailures(t *testing.T) {
	cases := []struct {
		name   string
		rcode  int
		detail string
	}{
		{"SERVFAIL", mdns.RcodeServerFailure, "resolver answered SERVFAIL"},
		{"REFUSED", mdns.RcodeRefused, "resolver answered REFUSED"},
		{"no answer", noReply, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := cannedZone{
				mx:    map[string][]string{"example.com": {"10 mx.example.com."}},
				rcode: map[string]int{"_25._tcp.mx.example.com": tc.rcode},
			}
			env := probe.NewEnv("example.com", 300*time.Millisecond, false, startCannedDNS(t, zone))
			res := runDANE(context.Background(), env)
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(res), res)
			}
			assertInconclusive(t, res[0], "TLSA lookup for _25._tcp.mx.example.com", tc.detail)
		})
	}
}

// TestRunDANE_NXDOMAINIsNotDeployed: NXDOMAIN at the TLSA name is an answer:
// the MX does not publish TLSA.
func TestRunDANE_NXDOMAINIsNotDeployed(t *testing.T) {
	env := newCannedEnv(t, "example.com", cannedZone{
		mx: map[string][]string{"example.com": {"10 mx.example.com."}},
	})
	res := runDANE(context.Background(), env)
	if len(res) != 1 || res[0].Status != report.NotApplicable ||
		!strings.Contains(res[0].Evidence, "DANE not deployed") {
		t.Fatalf("got %+v, want one N/A 'DANE not deployed' result", res)
	}
}

// TestRunDANE_TLSAErrorAnswerIsNotApplicable: a resolver that answers the
// TLSA query with an error other than SERVFAIL or REFUSED has answered, and
// DANE cannot be evaluated for the MX.
func TestRunDANE_TLSAErrorAnswerIsNotApplicable(t *testing.T) {
	env := newCannedEnv(t, "example.com", cannedZone{
		mx:    map[string][]string{"example.com": {"10 mx.example.com."}},
		rcode: map[string]int{"_25._tcp.mx.example.com": mdns.RcodeNotImplemented},
	})
	res := runDANE(context.Background(), env)
	want := "TLSA lookup error: resolver answered NOTIMP"
	if len(res) != 1 || res[0].Status != report.NotApplicable || res[0].Evidence != want {
		t.Fatalf("got %+v, want one N/A %q", res, want)
	}
}

// TestProbeDANE_CancelledScanIsInconclusive: once the scan is cancelled no
// TLSA query goes out and the host's result is inconclusive.
func TestProbeDANE_CancelledScanIsInconclusive(t *testing.T) {
	stats := &zoneStats{}
	env := newCannedEnv(t, "example.com", cannedZone{stats: stats})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertInconclusive(t, probeDANE(ctx, env, "mx.example.com", nil),
		"TLSA lookup for _25._tcp.mx.example.com", "context canceled")
	if n := stats.count("_25._tcp.mx.example.com", mdns.TypeTLSA); n != 0 {
		t.Errorf("sent %d TLSA queries after the cancel, want 0", n)
	}
}

// TestRunDANE_DuplicateMXHosts: exchanges that differ only in preference,
// letter case or the trailing dot are one host, looked up once and reported
// once under a lowercase ID.
func TestRunDANE_DuplicateMXHosts(t *testing.T) {
	stats := &zoneStats{}
	env := newCannedEnv(t, "example.com", cannedZone{
		mx: map[string][]string{"example.com": {
			"10 mx.example.com.", "20 mx.example.com.", "30 MX.Example.COM.",
			"40 backup.example.com.",
		}},
		tlsa:  map[string][]string{"_25._tcp.mx.example.com": {daneEE}},
		stats: stats,
	})
	res := runDANE(context.Background(), env)
	if err := report.CheckUniqueIDs(res); err != nil {
		t.Error(err)
	}
	want := []string{"email.dane.mx.example.com", "email.dane.backup.example.com"}
	if got := resultIDs(res); !slices.Equal(got, want) {
		t.Errorf("result IDs = %q, want %q", got, want)
	}
	if n := stats.count("_25._tcp.mx.example.com", mdns.TypeTLSA); n != 1 {
		t.Errorf("sent %d TLSA queries for mx.example.com, want 1", n)
	}
}

// TestMXHosts_IPLiteralSpellings: an IP literal published as an exchange is
// one host however it is spelled, so one address cannot fill every probe
// slot.
func TestMXHosts_IPLiteralSpellings(t *testing.T) {
	var mxs []probe.MX
	for i, spelling := range []string{
		"192.0.2.1", "::ffff:192.0.2.1", "::FFFF:c000:201", "0::ffff:192.0.2.1.",
		"0:0:0:0:0:ffff:c000:0201", "2001:DB8::1", "2001:db8:0:0::1.", "mx.example.com",
	} {
		mxs = append(mxs, probe.MX{Preference: uint16(i), Host: spelling})
	}
	probed, skipped := mxHosts(mxs)
	want := []string{"192.0.2.1", "2001:db8::1", "mx.example.com"}
	if !slices.Equal(probed, want) || skipped != nil {
		t.Errorf("mxHosts = %q, %q; want %q and none skipped", probed, skipped, want)
	}
}

// TestRunDANE_NullMX: a null MX ("0 .") names no server, alone or beside
// real MX hosts, so it is never looked up.
func TestRunDANE_NullMX(t *testing.T) {
	cases := []struct {
		name string
		mx   []string
		want []string // result IDs
	}{
		{"alone", []string{"0 ."}, []string{"email.dane"}},
		{"beside a host", []string{"0 .", "10 mx.example.com."},
			[]string{"email.dane.mx.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newCannedEnv(t, "example.com", cannedZone{
				mx: map[string][]string{"example.com": tc.mx},
			})
			if got := resultIDs(runDANE(context.Background(), env)); !slices.Equal(got, tc.want) {
				t.Errorf("result IDs = %q, want %q", got, tc.want)
			}
		})
	}
}

// fifteenMX returns MX RDATA for mx01 to mx15.example.com, where a higher
// number means a lower preference value, so mx15 is the most preferred.
func fifteenMX() []string {
	var mxs []string
	for i := 1; i <= 15; i++ {
		mxs = append(mxs, fmt.Sprintf("%d mx%02d.example.com.", 100-i, i))
	}
	return mxs
}

// TestRunDANE_CapsMXHosts: of 15 MX hosts the 10 most preferred are looked
// up and the other 5 are named in one INFO result.
func TestRunDANE_CapsMXHosts(t *testing.T) {
	stats := &zoneStats{}
	env := newCannedEnv(t, "example.com", cannedZone{
		mx:    map[string][]string{"example.com": fifteenMX()},
		stats: stats,
	})
	res := runDANE(context.Background(), env)
	if len(res) != 11 {
		t.Fatalf("want 10 host results and 1 skipped-host result, got %d: %q",
			len(res), resultIDs(res))
	}
	for i := 1; i <= 15; i++ {
		want := 0
		if i > 5 { // mx06 to mx15 are the 10 most preferred
			want = 1
		}
		name := fmt.Sprintf("_25._tcp.mx%02d.example.com", i)
		if n := stats.count(name, mdns.TypeTLSA); n != want {
			t.Errorf("sent %d TLSA queries for %s, want %d", n, name, want)
		}
	}
	skipped, _ := findResult(res, "email.dane")
	wantEvidence := "probed the 10 most preferred MX hosts; not probed: mx05.example.com, " +
		"mx04.example.com, mx03.example.com, mx02.example.com, mx01.example.com"
	if skipped.Status != report.Info || skipped.Evidence != wantEvidence {
		t.Errorf("email.dane = %s %q, want INFO %q", skipped.Status, skipped.Evidence,
			wantEvidence)
	}
}

// TestRunDANE_LooksUpMXHostsConcurrently: the TLSA lookups for different MX
// hosts overlap, at most 4 at a time.
func TestRunDANE_LooksUpMXHostsConcurrently(t *testing.T) {
	stats := &zoneStats{}
	env := newCannedEnv(t, "example.com", cannedZone{
		mx:    map[string][]string{"example.com": fifteenMX()},
		delay: 50 * time.Millisecond,
		stats: stats,
	})
	runDANE(context.Background(), env)
	if peak := stats.maxInFlight(); peak < 2 || peak > 4 {
		t.Errorf("%d TLSA queries were in flight at once, want 2 to 4", peak)
	}
}

// TestProbeMXHostsPanicReachesCaller: a panic while probing one MX host
// reaches the check's goroutine, where the registry turns it into a result,
// rather than ending the scan.
func TestProbeMXHostsPanicReachesCaller(t *testing.T) {
	hosts := []string{"mx1.example.com", "mx2.example.com", "mx3.example.com"}
	got := func() (r any) {
		defer func() { r = recover() }()
		probeMXHosts(context.Background(), hosts,
			func(_ context.Context, host string) report.Result {
				if host == "mx2.example.com" {
					panic("boom in " + host)
				}
				return report.Result{ID: host}
			})
		return nil
	}()
	if got != "boom in mx2.example.com" {
		t.Fatalf("recovered %v, want the probe's panic", got)
	}
}

// TestRunDANE_EachLookupHasItsOwnTimeout: every TLSA lookup gets the full
// --timeout, so a slow resolver does not leave later MX hosts unchecked.
// Here the lookups together take longer than one timeout.
func TestRunDANE_EachLookupHasItsOwnTimeout(t *testing.T) {
	var mxs []string
	for i := range 10 {
		mxs = append(mxs, fmt.Sprintf("10 mx%d.example.com.", i))
	}
	zone := cannedZone{mx: map[string][]string{"example.com": mxs}, delay: 300 * time.Millisecond}
	env := probe.NewEnv("example.com", time.Second, false, startCannedDNS(t, zone))
	res := runDANE(context.Background(), env)
	if len(res) != 10 {
		t.Fatalf("want 10 results, got %d: %q", len(res), resultIDs(res))
	}
	for _, r := range res {
		if r.Status != report.NotApplicable || !strings.Contains(r.Evidence, "DANE not deployed") {
			t.Errorf("%s = %s %q, want N/A 'DANE not deployed'", r.ID, r.Status, r.Evidence)
		}
	}
}
