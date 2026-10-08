//go:debug x509usefallbackroots=1

package bimi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// testZone is a DNS zone served on loopback: TXT answers from txt, SERVFAIL
// for every name in servfail and NXDOMAIN for any other name.
type testZone struct {
	txt      map[string][]string // lower-case name, no trailing dot -> TXT strings
	servfail map[string]bool
}

func (z testZone) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	values, ok := z.txt[name]
	switch {
	case z.servfail[name]:
		resp.Rcode = mdns.RcodeServerFailure
	case !ok:
		resp.Rcode = mdns.RcodeNameError
	case q.Qtype == mdns.TypeTXT:
		hdr := mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60}
		for _, v := range values {
			resp.Answer = append(resp.Answer, &mdns.TXT{Hdr: hdr, Txt: []string{v}})
		}
	}
	_ = w.WriteMsg(resp)
}

// countingZone is a testZone that counts the queries it answers per name.
type countingZone struct {
	testZone
	mu      sync.Mutex
	queries map[string]int // lower-case name, no trailing dot -> queries
}

func (z *countingZone) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	z.mu.Lock()
	z.queries[strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))]++
	z.mu.Unlock()
	z.testZone.ServeDNS(w, req)
}

// count returns how many queries for name z answered.
func (z *countingZone) count(name string) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.queries[name]
}

// newZoneEnv serves zone on a loopback port and returns an active Env for
// target that resolves through it. It also allows loopback dials for the
// test, so the HTTPS fixtures on localhost are reachable.
func newZoneEnv(t *testing.T, target string, zone mdns.Handler, timeout time.Duration) *probe.Env {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on a loopback UDP port for the test zone: %v", err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: zone}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		_ = srv.Shutdown()
		t.Fatal("test DNS server did not start within 2s")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return probe.NewEnv(target, timeout, true, pc.LocalAddr().String())
}

// bimiZone returns a zone for example.test publishing a BIMI record with
// the given l= and a= URLs and DMARC p=reject.
func bimiZone(logoURL, vmcURL string) testZone {
	return testZone{txt: map[string][]string{
		"default._bimi.example.test": {"v=BIMI1; l=" + logoURL + "; a=" + vmcURL},
		"_dmarc.example.test":        {"v=DMARC1; p=reject"},
	}}
}

// testCA is a certificate authority for the TLS and VMC fixtures.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var (
	trustOnce   sync.Once
	trustedRoot *testCA
	errTrust    error
	serials     atomic.Int64
)

// trustedCA returns the root that x509.SystemCertPool and every TLS client
// in this test binary trust. The x509usefallbackroots setting on the first
// line of this file makes x509.SetFallbackRoots replace the system roots,
// so this root stands in for a public CA.
func trustedCA(t *testing.T) *testCA {
	t.Helper()
	trustOnce.Do(func() {
		trustedRoot, errTrust = newTestCA("bedrock test root")
		if errTrust == nil {
			pool := x509.NewCertPool()
			pool.AddCert(trustedRoot.cert)
			x509.SetFallbackRoots(pool)
		}
	})
	if errTrust != nil {
		t.Fatalf("create the trusted test root: %v", errTrust)
	}
	return trustedRoot
}

// untrustedCA returns a root that nothing in this test binary trusts.
func untrustedCA(t *testing.T) *testCA {
	t.Helper()
	trustedCA(t) // install the fallback pool first, so it cannot include this root
	ca, err := newTestCA("bedrock untrusted root")
	if err != nil {
		t.Fatalf("create the untrusted test root: %v", err)
	}
	return ca
}

func newTestCA(cn string) (*testCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serials.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-72 * time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &testCA{cert: cert, key: key}, nil
}

// issue signs tmpl for a fresh key and returns the certificate DER and key.
func (ca *testCA) issue(t *testing.T, tmpl *x509.Certificate) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key for %q: %v", tmpl.Subject.CommonName, err)
	}
	tmpl.SerialNumber = big.NewInt(serials.Add(1))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issue %q from %q: %v", tmpl.Subject.CommonName, ca.cert.Subject.CommonName, err)
	}
	return der, key
}

// serveTLS serves handler as https://localhost:<port> with a certificate ca
// issued and returns that base URL. Hostnames, not IP literals, because the
// BIMI checks refuse IP-literal URLs.
func serveTLS(t *testing.T, ca *testCA, handler http.Handler) string {
	t.Helper()
	der, key := ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "localhost"},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	srv := httptest.NewUnstartedServer(handler)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // handshakes the client refuses
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server address %q: %v", srv.Listener.Addr(), err)
	}
	return "https://localhost:" + port
}

// siteFile is a body served at one path, with its Content-Type.
type siteFile struct {
	contentType string
	body        []byte
}

// site is an HTTPS server the test binary trusts, serving fixed files and
// counting requests per path.
type site struct {
	base string
	mu   sync.Mutex
	hits map[string]int
}

func newSite(t *testing.T, files map[string]siteFile) *site {
	t.Helper()
	s := &site{hits: map[string]int{}}
	serve := func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		f, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", f.contentType)
		_, _ = w.Write(f.body)
	}
	s.base = serveTLS(t, trustedCA(t), http.HandlerFunc(serve))
	return s
}

// requests returns how many requests path received.
func (s *site) requests(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

// stallingURL returns the URL of an HTTPS server, trusted by the test
// binary, that never answers until the client gives up.
func stallingURL(t *testing.T) string {
	t.Helper()
	release := make(chan struct{})
	stall := func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}
	base := serveTLS(t, trustedCA(t), http.HandlerFunc(stall))
	t.Cleanup(func() { close(release) }) // runs before the server's Close
	return base + "/stall"
}

// vmcPEM returns a PEM VMC that ca issued, expiring at notAfter, whose
// logotype extension binds the SHA-256 digest of svg.
func vmcPEM(t *testing.T, ca *testCA, svg []byte, notAfter time.Time) []byte {
	t.Helper()
	digest := sha256.Sum256(svg)
	ext := buildLogotypeExtn(t, "image/svg+xml", "https://example.test/logo.svg", sha256OID,
		digest[:])
	der, _ := ca.issue(t, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "Example Mark"},
		NotBefore:          notAfter.Add(-48 * time.Hour),
		NotAfter:           notAfter,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{vmcEKUOID},
		ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier(logotypeOID), Value: ext}},
	})
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// goodDeployment returns a zone for example.test whose BIMI record points
// at a site serving validSVG and a VMC for it from the trusted root, and
// that site.
func goodDeployment(t *testing.T) (testZone, *site) {
	t.Helper()
	vmc := vmcPEM(t, trustedCA(t), []byte(validSVG), time.Now().Add(24*time.Hour))
	s := newSite(t, map[string]siteFile{
		"/logo.svg": {"image/svg+xml", []byte(validSVG)},
		"/vmc.pem":  {"application/x-pem-file", vmc},
	})
	return bimiZone(s.base+"/logo.svg", s.base+"/vmc.pem"), s
}

// bimiChecks returns the registered BIMI checks in registration order.
func bimiChecks(t *testing.T) []registry.Check {
	t.Helper()
	var out []registry.Check
	for _, c := range registry.All() {
		if strings.HasPrefix(c.ID(), "bimi.") {
			out = append(out, c)
		}
	}
	if len(out) != 8 {
		t.Fatalf("found %d registered BIMI checks, want 8", len(out))
	}
	return out
}

// runOne runs check on env and returns its only result.
func runOne(t *testing.T, check registry.Check, env *probe.Env) report.Result {
	t.Helper()
	res := check.Run(context.Background(), env)
	if len(res) != 1 {
		t.Fatalf("%s returned %d results, want 1: %+v", check.ID(), len(res), res)
	}
	return res[0]
}

// runSequential runs every BIMI check on env, one after another in
// registration order, and returns the results by check ID.
func runSequential(t *testing.T, env *probe.Env) map[string]report.Result {
	t.Helper()
	out := map[string]report.Result{}
	for _, c := range bimiChecks(t) {
		out[c.ID()] = runOne(t, c, env)
	}
	return out
}

// TestChecksAgreeAloneAndInFullRun runs each BIMI check alone on a fresh
// Env and compares its result with the one it gives in a full run, so no
// check depends on another having run first.
func TestChecksAgreeAloneAndInFullRun(t *testing.T) {
	zone, _ := goodDeployment(t)
	full := runSequential(t, newZoneEnv(t, "example.test", zone, 5*time.Second))
	for id, r := range full {
		if r.Status != report.Pass {
			t.Errorf("full run: %s = %s %q, want PASS", id, r.Status, r.Evidence)
		}
	}
	for _, c := range bimiChecks(t) {
		alone := runOne(t, c, newZoneEnv(t, "example.test", zone, 5*time.Second))
		if !reflect.DeepEqual(alone, full[c.ID()]) {
			t.Errorf("%s alone = %s %q; in a full run = %s %q", c.ID(),
				alone.Status, alone.Evidence, full[c.ID()].Status, full[c.ID()].Evidence)
		}
	}
}

// TestConcurrentRunMatchesSequential runs every BIMI check at once, as
// registry.Run does, and expects the sequential results each time. Each
// fetch happens once per scan however many checks need it.
func TestConcurrentRunMatchesSequential(t *testing.T) {
	zone, s := goodDeployment(t)
	want := runSequential(t, newZoneEnv(t, "example.test", zone, 5*time.Second))
	checks := bimiChecks(t)
	for round := range 5 {
		logos, vmcs := s.requests("/logo.svg"), s.requests("/vmc.pem")
		got := runConcurrently(checks, newZoneEnv(t, "example.test", zone, 5*time.Second))
		for i, res := range got {
			id := checks[i].ID()
			if len(res) != 1 || !reflect.DeepEqual(res[0], want[id]) {
				t.Errorf("round %d: %s = %+v, want %+v", round, id, res, want[id])
			}
		}
		if n := s.requests("/logo.svg") - logos; n != 1 {
			t.Errorf("round %d: the logo was fetched %d times, want once", round, n)
		}
		if n := s.requests("/vmc.pem") - vmcs; n != 1 {
			t.Errorf("round %d: the VMC was fetched %d times, want once", round, n)
		}
	}
}

// runConcurrently runs every check in checks on env at once and returns
// their results in the same order.
func runConcurrently(checks []registry.Check, env *probe.Env) [][]report.Result {
	got := make([][]report.Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Go(func() { got[i] = c.Run(context.Background(), env) })
	}
	wg.Wait()
	return got
}

// TestRecordLookedUpOncePerScan: bimi.txt and the checks that use the
// record share one TXT lookup, so they cannot disagree about the record.
func TestRecordLookedUpOncePerScan(t *testing.T) {
	deployment, _ := goodDeployment(t)
	zone := &countingZone{testZone: deployment, queries: map[string]int{}}
	runConcurrently(bimiChecks(t), newZoneEnv(t, "example.test", zone, 5*time.Second))
	if n := zone.count("default._bimi.example.test"); n != 1 {
		t.Errorf("default._bimi.example.test was queried %d times, want once", n)
	}
}

// TestFailingDeploymentHasUniqueIDs runs every BIMI check on a deployment
// that fails several ways at once: each check still gives one result, so
// every result ID is unique, as baseline diffs require.
func TestFailingDeploymentHasUniqueIDs(t *testing.T) {
	logo := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 32">` +
		`<script/><rect onclick="" onload=""/></svg>`
	s := newSite(t, map[string]siteFile{"/logo.svg": {"image/svg+xml", []byte(logo)}})
	zone := testZone{txt: map[string][]string{
		"default._bimi.example.test": {"v=BIMI1; l=" + s.base + "/logo.svg; a="},
		"_dmarc.example.test":        {"v=DMARC1; p=none; sp=none; pct=50; t=y"},
	}}
	env := newZoneEnv(t, "example.test", zone, 2*time.Second)
	var all []report.Result
	for _, rs := range runConcurrently(bimiChecks(t), env) {
		all = append(all, rs...)
	}
	if err := report.CheckUniqueIDs(all); err != nil {
		t.Error(err)
	}
	if len(all) != 8 {
		t.Errorf("got %d results from the 8 BIMI checks, want 8", len(all))
	}
}

// newRefusedResolverEnv returns an active Env whose resolver is a closed
// loopback port, so every DNS lookup fails without leaving the host.
func newRefusedResolverEnv(t *testing.T) *probe.Env {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	addr := pc.LocalAddr().String()
	if err := pc.Close(); err != nil {
		t.Fatalf("release loopback port %s: %v", addr, err)
	}
	return probe.NewEnv("example.test", 2*time.Second, true, addr)
}

// TestFetchChecksAfterFailedRecordLookup checks that a failed BIMI TXT
// lookup reads as "no record" to the checks that need the record.
func TestFetchChecksAfterFailedRecordLookup(t *testing.T) {
	env := newRefusedResolverEnv(t)
	cases := []struct {
		check      registry.Check
		wantStatus report.Status
	}{
		{check: svgFetchCheck{}, wantStatus: report.NotApplicable},
		{check: vmcFetchCheck{}, wantStatus: report.Info},
		{check: gmailGateCheck{}, wantStatus: report.NotApplicable},
	}
	for _, tc := range cases {
		t.Run(tc.check.ID(), func(t *testing.T) {
			r := runOne(t, tc.check, env)
			if r.Status != tc.wantStatus || !strings.Contains(r.Evidence, "no parsed BIMI record") {
				t.Errorf("got %s %q, want %s with no parsed BIMI record",
					r.Status, r.Evidence, tc.wantStatus)
			}
		})
	}
}

// TestFetchChecksWithoutURLs: a record without l= or a= fetches nothing,
// and the missing a=, which Gmail requires, fails bimi.txt alone.
func TestFetchChecksWithoutURLs(t *testing.T) {
	zone := testZone{txt: map[string][]string{"default._bimi.example.test": {"v=BIMI1; l=; a="}}}
	env := newZoneEnv(t, "example.test", zone, 2*time.Second)
	got := map[string]report.Result{}
	for _, c := range []registry.Check{svgFetchCheck{}, vmcFetchCheck{}} {
		got[c.ID()] = runOne(t, c, env)
	}
	checkResults(t, got, map[string]wantResult{
		"bimi.svg.fetch": {report.NotApplicable, "no l= URL in BIMI record"},
		"bimi.vmc.fetch": {report.NotApplicable, "a= URL not fetched: empty URL (see bimi.txt)"},
	})
}

// TestPassiveScanFetchesNothing: with --no-active every check that needs
// the logo or the VMC is N/A, and neither is fetched.
func TestPassiveScanFetchesNothing(t *testing.T) {
	zone, s := goodDeployment(t)
	env := newZoneEnv(t, "example.test", zone, 2*time.Second)
	env.Active = false
	got := map[string]report.Result{}
	want := map[string]wantResult{}
	for _, c := range []registry.Check{
		svgFetchCheck{}, svgProfileCheck{}, svgAspectCheck{},
		vmcFetchCheck{}, vmcChainCheck{}, vmcLogotypeCheck{},
	} {
		got[c.ID()] = runOne(t, c, env)
		want[c.ID()] = wantResult{report.NotApplicable, "skipped: --no-active"}
	}
	checkResults(t, got, want)
	if n := s.requests("/logo.svg") + s.requests("/vmc.pem"); n != 0 {
		t.Errorf("a passive scan made %d requests, want 0", n)
	}
}

// TestChecksAfterProducerPanic covers a producer that panics. registry.Run
// reports the panic against the check that ran the producer; every other
// check that needs the product must then report its absence rather than
// panic again.
func TestChecksAfterProducerPanic(t *testing.T) {
	zone, _ := goodDeployment(t)
	env := newZoneEnv(t, "example.test", zone, 2*time.Second)
	env.HTTP = nil // every fetch now panics
	for _, c := range []registry.Check{svgProfileCheck{}, vmcChainCheck{}} {
		if !panics(func() { c.Run(context.Background(), env) }) {
			t.Fatalf("%s did not panic without an HTTP client", c.ID())
		}
	}
	got := map[string]report.Result{}
	for _, c := range []registry.Check{
		svgFetchCheck{}, svgProfileCheck{}, svgAspectCheck{},
		vmcFetchCheck{}, vmcChainCheck{}, vmcLogotypeCheck{},
	} {
		got[c.ID()] = runOne(t, c, env)
	}
	const panicked = "check did not complete; see registry.panic"
	checkResults(t, got, map[string]wantResult{
		"bimi.svg.fetch":    {report.Info, panicked},
		"bimi.svg.profile":  {report.NotApplicable, "no SVG body cached"},
		"bimi.svg.aspect":   {report.NotApplicable, "no SVG body cached"},
		"bimi.vmc.fetch":    {report.Info, panicked},
		"bimi.vmc.chain":    {report.Info, panicked},
		"bimi.vmc.logotype": {report.Info, "no validated VMC leaf cached"},
	})
}

// panics reports whether f panics.
func panics(f func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	f()
	return false
}

// TestEnsureRecordReleasesEnv guards against per-Env state kept outside the
// Env: once a scan's Env is dropped, the BIMI record lookup must not keep it
// reachable.
func TestEnsureRecordReleasesEnv(t *testing.T) {
	ref := runEnsureRecord(t)
	runtime.GC()
	runtime.GC()
	if ref.Value() != nil {
		t.Error("Env still reachable after ensureRecord; it keeps per-Env state outside the Env")
	}
}

// runEnsureRecord looks the BIMI record up on a fresh Env and returns only
// a weak reference to it.
func runEnsureRecord(t *testing.T) weak.Pointer[probe.Env] {
	t.Helper()
	env := newRefusedResolverEnv(t)
	if rec := ensureRecord(context.Background(), env); rec != nil {
		t.Fatalf("ensureRecord = %+v although the lookup failed", rec)
	}
	return weak.Make(env)
}
