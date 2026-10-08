package dns

import (
	"context"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

const (
	s3Marker  = "<Error><Code>NoSuchBucket</Code></Error>"
	s3Listing = "<ListBucketResult/>" // a claimed bucket's page
	s3CNAME   = "www.example.test. 300 IN CNAME bucket.s3.amazonaws.com."
	s3Address = "bucket.s3.amazonaws.com. 300 IN A 192.0.2.1"
)

// TestDangling_MarkerProbe: the takeover marker is looked for on the
// host's page over HTTPS and, when the certificate does not verify (a
// provider cannot present one for a custom domain nobody has claimed) or
// the HTTPS fetch fails, on the page over plain HTTP, since Get drops an
// unverified body.
func TestDangling_MarkerProbe(t *testing.T) {
	const cname = "www.example.test IN CNAME bucket.s3.amazonaws.com; "
	unclaimed := func(via string) finding {
		return finding{report.Fail, "Dangling AWS S3 CNAME: www.example.test appears unclaimed",
			cname + via + ` body matched "NoSuchBucket" (AWS S3 unclaimed)`, true}
	}
	cases := []struct {
		name        string
		verified    bool    // the HTTPS page's certificate verifies
		https, http string  // page bodies; "" means nothing listens
		want        finding // of www.example.test; none when zero
	}{
		{"marker over verified HTTPS", true, s3Marker, "", unclaimed("HTTPS")},
		{"claimed bucket over verified HTTPS", true, s3Listing, "", finding{}},
		{"marker over HTTP behind an unverified certificate", false, s3Marker, s3Marker,
			unclaimed("HTTP")},
		{"claimed bucket behind an unverified certificate", false, s3Marker, s3Listing, finding{}},
		{"marker over HTTP when HTTPS is refused", false, "", s3Marker, unclaimed("HTTP")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.add(t, s3CNAME, s3Address)
			env := fake.env(t, "example.test", refusedDialTimeout)
			setMarkerURL(t, markerPages(t, tc.verified, tc.https, tc.http))
			results := danglingByID(t, context.Background(), env)
			if got := findingOf(results["dns.dangling.www.example.test"]); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
			if s, ok := results["dns.dangling.summary"]; ok && s.Status != report.Pass {
				t.Errorf("summary = %+v, want PASS or none", s)
			}
		})
	}
}

// TestDangling_MarkerFetchFailures: when neither fetch returns the page, a
// probe that could not complete (a server that never answers) is
// inconclusive and any other failure (a refused connection) is a warning,
// and the evidence names both failures. A host that never answers HTTPS
// still has its page checked over HTTP.
func TestDangling_MarkerFetchFailures(t *testing.T) {
	const (
		cname     = "www.example.test IN CNAME bucket.s3.amazonaws.com; "
		failed    = "AWS S3 CNAME present; marker probe failed"
		httpsFail = cname + `Get "https://127.0.0.1:`
		httpFail  = `; Get "http://127.0.0.1:`
	)
	refused := func(scheme string) func(*testing.T) string {
		return func(t *testing.T) string {
			return scheme + "://127.0.0.1:" + closedLoopbackPort(t) + "/"
		}
	}
	serving := func(scheme, body string) func(*testing.T) string {
		return func(t *testing.T) string { return pageServer(t, scheme, body) }
	}
	silent := func(scheme string) func(*testing.T) string {
		return func(t *testing.T) string { return tarpitURL(t, scheme) }
	}
	cases := []struct {
		name             string
		https, http      func(*testing.T) string
		timeout          time.Duration
		status           report.Status
		title            string
		prefix, contains string // of the evidence
	}{
		{"both refused", refused("https"), refused("http"), refusedDialTimeout,
			report.Warn, failed, httpsFail, httpFail},
		{"HTTP refused behind an unverified certificate", serving("https", s3Marker),
			refused("http"), refusedDialTimeout, report.Warn, failed,
			cname + "HTTPS certificate did not verify" + httpFail, ""},
		{"neither answers", silent("https"), silent("http"), 300 * time.Millisecond,
			wantInconclusive, failed, "could not determine: " + httpsFail, httpFail},
		{"HTTPS never answers, HTTP refused", silent("https"), refused("http"),
			300 * time.Millisecond, wantInconclusive, failed,
			"could not determine: " + httpsFail, httpFail},
		{"marker over HTTP when HTTPS never answers", silent("https"),
			serving("http", s3Marker), 300 * time.Millisecond, report.Fail,
			"Dangling AWS S3 CNAME: www.example.test appears unclaimed",
			cname + `HTTP body matched "NoSuchBucket"`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.add(t, s3CNAME, s3Address)
			env := fake.env(t, "example.test", tc.timeout)
			setMarkerURL(t, map[string]string{"https": tc.https(t), "http": tc.http(t)})

			r := danglingByID(t, context.Background(), env)["dns.dangling.www.example.test"]

			if r.Status != tc.status || r.Title != tc.title ||
				!strings.HasPrefix(r.Evidence, tc.prefix) ||
				!strings.Contains(r.Evidence, tc.contains) {
				t.Errorf("got %s %q %q, want %s %q with evidence %q...%q",
					r.Status, r.Title, r.Evidence, tc.status, tc.title, tc.prefix, tc.contains)
			}
		})
	}
}

// tarpitURL returns a URL for scheme whose loopback server accepts
// connections and never answers.
func tarpitURL(t *testing.T, scheme string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return scheme + "://" + ln.Addr().String() + "/"
}

// TestDangling_LookupFailures: a host whose CNAME or CNAME-target lookup
// failed was not checked, so the summary is inconclusive and names it, even
// beside another host's finding.
func TestDangling_LookupFailures(t *testing.T) {
	const servfail = "resolver answered SERVFAIL"
	summaryOnly := []string{"dns.dangling.summary"}
	cases := []struct {
		name     string
		setup    func(*testing.T, *fakeDNS)
		title    string
		evidence string
		ids      []string // of every result, sorted
	}{
		{"SERVFAIL on three hosts", func(_ *testing.T, f *fakeDNS) {
			f.setRcode("www.example.test.", miekg.RcodeServerFailure)
			f.setRcode("api.example.test.", miekg.RcodeServerFailure)
			f.setRcode("blog.example.test.", miekg.RcodeServerFailure)
		}, "3 of 12 hosts could not be checked for dangling DNS",
			"could not determine: www.example.test: CNAME lookup: " + servfail +
				"; api.example.test: CNAME lookup: " + servfail +
				"; blog.example.test: CNAME lookup: " + servfail, summaryOnly},
		{"SERVFAIL on the CNAME target", func(t *testing.T, f *fakeDNS) {
			f.add(t, "www.example.test. 300 IN CNAME edge.example.net.")
			f.setRcode("edge.example.net.", miekg.RcodeServerFailure)
		}, "1 of 12 hosts could not be checked for dangling DNS",
			"could not determine: www.example.test: CNAME target edge.example.net: A lookup: " +
				servfail, summaryOnly},
		{"beside a dangling CNAME", func(t *testing.T, f *fakeDNS) {
			f.add(t, "www.example.test. 300 IN CNAME gone.example.net.")
			f.setRcode("api.example.test.", miekg.RcodeServerFailure)
		}, "1 of 12 hosts could not be checked for dangling DNS",
			"could not determine: api.example.test: CNAME lookup: " + servfail,
			[]string{"dns.dangling.summary", "dns.dangling.www.example.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			tc.setup(t, fake)
			results := danglingByID(t, context.Background(),
				fake.env(t, "example.test", axfrTestTimeout))
			want := finding{wantInconclusive, tc.title, tc.evidence, false}
			if got := findingOf(results["dns.dangling.summary"]); got != want {
				t.Errorf("summary = %+v, want %+v", got, want)
			}
			if ids := slices.Sorted(maps.Keys(results)); !slices.Equal(ids, tc.ids) {
				t.Errorf("got results %v, want %v", ids, tc.ids)
			}
		})
	}
}

// TestDangling_CancelledScanIsInconclusive: hosts the scan's cancellation
// left unchecked make the summary inconclusive, not PASS, and send no
// queries.
func TestDangling_CancelledScanIsInconclusive(t *testing.T) {
	fake := newFakeDNS(t)
	env := fake.env(t, "example.test", axfrTestTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := danglingByID(t, ctx, env)
	s := results["dns.dangling.summary"]
	const want = "could not determine: example.test: context canceled; " +
		"www.example.test: context canceled; "
	if len(results) != 1 || s.Status != wantInconclusive || !strings.HasPrefix(s.Evidence, want) {
		t.Errorf("got %+v, want only the inconclusive summary naming the cancellation", results)
	}
	if n := fake.queryCount("www.example.test.", miekg.TypeCNAME); n != 0 {
		t.Errorf("sent %d CNAME queries after the cancellation", n)
	}
}

// TestDangling_BoundFanout: the hosts are probed up to 4 at a time, so a
// slow zone costs a few rounds of lookups rather than one per host, and the
// summary still covers every host.
func TestDangling_BoundFanout(t *testing.T) {
	fake := newFakeDNS(t)
	for _, label := range danglingHosts {
		fake.setDelay(strings.TrimPrefix(label+".example.test.", "."), 200*time.Millisecond)
	}
	env := fake.env(t, "example.test", time.Second)

	results := runDangling(context.Background(), env)

	if n := fake.peakInFlight(miekg.TypeCNAME); n < 2 || n > 4 {
		t.Errorf("sent up to %d CNAME lookups at once, want 2 to 4", n)
	}
	if len(results) != 1 || results[0].ID != "dns.dangling.summary" ||
		results[0].Status != report.Pass {
		t.Errorf("got %+v, want only the PASS summary", results)
	}
}

// TestDangling_CancelledMarkerProbeIsNotAFinding: a marker fetch that failed
// because the scan was cancelled leaves the host unchecked; it is not a
// failed probe to warn about.
func TestDangling_CancelledMarkerProbeIsNotAFinding(t *testing.T) {
	fake := newFakeDNS(t)
	fake.add(t, s3CNAME, s3Address)
	// www answers late, so the hosts probed beside it are all checked
	// before its marker fetch cancels the scan.
	fake.setDelay("www.example.test.", 100*time.Millisecond)
	env := fake.env(t, "example.test", axfrTestTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	page := pageServer(t, "http", s3Marker)
	old := markerURL
	markerURL = func(string, string) string {
		cancel() // as the fetch starts
		return page
	}
	t.Cleanup(func() { markerURL = old })

	results := danglingByID(t, ctx, env)
	s := results["dns.dangling.summary"]
	const want = "could not determine: www.example.test: context canceled"
	if len(results) != 1 || s.Status != wantInconclusive || !strings.HasPrefix(s.Evidence, want) {
		t.Errorf("got %+v, want only the inconclusive summary", results)
	}
}

// TestDangling_ProviderWithoutMarkerIsInfo: a provider without a reliable
// takeover marker (CloudFront) is INFO with or without active probing, as
// no probe could tell claimed from unclaimed; a provider with a marker still
// warns when --no-active skips its probe.
func TestDangling_ProviderWithoutMarkerIsInfo(t *testing.T) {
	cloudFront := []string{"www.example.test. 300 IN CNAME d123.cloudfront.net.",
		"d123.cloudfront.net. 300 IN A 192.0.2.10"}
	cloudFrontInfo := finding{report.Info,
		"CloudFront CNAME present (manual verification recommended)",
		"www.example.test IN CNAME d123.cloudfront.net", false}
	cases := []struct {
		name    string
		records []string
		active  bool
		want    finding
	}{
		{"CloudFront", cloudFront, true, cloudFrontInfo},
		{"CloudFront under --no-active", cloudFront, false, cloudFrontInfo},
		{"S3 under --no-active", []string{s3CNAME, s3Address}, false, finding{report.Warn,
			"Possible AWS S3 takeover candidate (active probe skipped)",
			"www.example.test IN CNAME bucket.s3.amazonaws.com; --no-active prevents marker check",
			false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.add(t, tc.records...)
			env := fake.env(t, "example.test", axfrTestTimeout)
			env.Active = tc.active
			setMarkerURL(t, nil)
			r := danglingByID(t, context.Background(), env)["dns.dangling.www.example.test"]
			if got := findingOf(r); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// finding is what the tests compare of a result.
type finding struct {
	Status     report.Status
	Title      string
	Evidence   string
	Remediated bool // has a remediation
}

func findingOf(r report.Result) finding {
	return finding{r.Status, r.Title, r.Evidence, r.Remediation != ""}
}

// markerPages starts the pages the marker probe fetches, given their
// bodies, and returns their URLs by scheme for setMarkerURL. A verified
// HTTPS page is served over plain HTTP, which Get marks verified, standing
// in for a page behind a trusted certificate; then no HTTP page is served,
// so a fetch over HTTP fails the test.
func markerPages(t *testing.T, verified bool, httpsBody, httpBody string) map[string]string {
	t.Helper()
	if verified {
		return map[string]string{"https": pageServer(t, "http", httpsBody)}
	}
	return map[string]string{
		"https": pageServer(t, "https", httpsBody),
		"http":  pageServer(t, "http", httpBody),
	}
}

// danglingByID runs the check and returns its results by ID.
func danglingByID(t *testing.T, ctx context.Context, env *probe.Env) map[string]report.Result {
	t.Helper()
	results := runDangling(ctx, env)
	if err := report.CheckUniqueIDs(results); err != nil {
		t.Fatal(err)
	}
	byID := map[string]report.Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	return byID
}

// setMarkerURL sends the marker probe's fetches to urls, keyed by scheme,
// for the rest of the test. A nil map fails the test on any fetch.
func setMarkerURL(t *testing.T, urls map[string]string) {
	t.Helper()
	old := markerURL
	markerURL = func(scheme, host string) string {
		u, ok := urls[scheme]
		if !ok {
			t.Errorf("marker probe fetched %s://%s", scheme, host)
		}
		return u
	}
	t.Cleanup(func() { markerURL = old })
}

// pageServer starts a server for scheme that answers every request with
// body and returns its root URL, or a URL nothing listens on when body is
// empty. The HTTPS server's certificate is not trusted, so Get's verified
// fetch fails and its diagnostic retry returns the response without a body.
func pageServer(t *testing.T, scheme, body string) string {
	t.Helper()
	if body == "" {
		return scheme + "://127.0.0.1:" + closedLoopbackPort(t) + "/"
	}
	page := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewUnstartedServer(page)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	if scheme == "https" {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv.URL + "/"
}

// TestTakeoverPatterns_Coverage is a tripwire: if someone deletes a pattern
// or accidentally removes the marker, the test fails. The patterns are
// load-bearing — operators rely on the literal markers to confirm a takeover.
func TestTakeoverPatterns_Coverage(t *testing.T) {
	wantSuffixes := []string{
		".s3.amazonaws.com",
		".s3-website.amazonaws.com",
		".herokudns.com",
		".herokuapp.com",
		".github.io",
		".azurewebsites.net",
	}
	got := map[string]bool{}
	for _, p := range takeoverPatterns {
		got[p.suffix] = true
	}
	for _, s := range wantSuffixes {
		if !got[s] {
			t.Errorf("missing takeover pattern for suffix %q", s)
		}
	}
}

// TestTakeoverPatterns_HaveMarkersOrAreInfoOnly: every pattern is either
// active (has a marker we Fail on) or explicitly marker-empty (we treat as
// Info). The test prevents a future edit from silently downgrading a known
// fail-only pattern to "no marker, never fail."
func TestTakeoverPatterns_HaveMarkersOrAreInfoOnly(t *testing.T) {
	mustHaveMarker := map[string]bool{
		".s3.amazonaws.com":         true,
		".s3-website.amazonaws.com": true,
		".herokudns.com":            true,
		".herokuapp.com":            true,
		".github.io":                true,
		".azurewebsites.net":        true,
	}
	for _, p := range takeoverPatterns {
		if mustHaveMarker[p.suffix] && p.marker == "" {
			t.Errorf("pattern %s should have a marker — empty marker means we cannot fail on it", p.suffix)
		}
	}
}

func TestDanglingHosts_IncludesApexAndCommonLabels(t *testing.T) {
	want := []string{"", "www", "api"}
	got := strings.Join(danglingHosts, ",")
	for _, w := range want {
		// "" matches the comma-joined start; check positionally
		found := false
		for _, h := range danglingHosts {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("danglingHosts missing %q (have %s)", w, got)
		}
	}
}
