package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// testPKI is a tiny issuer/leaf pair used to forge OCSP responses and CRLs
// without ever touching the network. Issuer self-signs; leaf is signed by
// issuer; both keys are kept around so we can act as the responder.
type testPKI struct {
	issuerKey  *ecdsa.PrivateKey
	issuerCert *x509.Certificate
	leafKey    *ecdsa.PrivateKey
	leafCert   *x509.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	now := time.Now()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bedrock test issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("issuer cert: %v", err)
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(424242),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	return &testPKI{
		issuerKey:  issuerKey,
		issuerCert: issuerCert,
		leafKey:    leafKey,
		leafCert:   leafCert,
	}
}

// newOCSPResponse fabricates a signed OCSP response with the given status and
// freshness window. issuerKey is also the responder key (issuer-as-responder
// is the common case).
func (p *testPKI) newOCSPResponse(t *testing.T, status int, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: p.leafCert.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = thisUpdate
		tmpl.RevocationReason = ocsp.KeyCompromise
	}
	der, err := ocsp.CreateResponse(p.issuerCert, p.issuerCert, tmpl, p.issuerKey)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	return der
}

// findResult locates a Result by its ID; t.Fatal if absent.
func findResult(t *testing.T, results []report.Result, id string) report.Result {
	t.Helper()
	for _, r := range results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no result with ID %q in %d results", id, len(results))
	return report.Result{}
}

func TestOCSPCheck_NoActive(t *testing.T) {
	env := &probe.Env{Active: false, Timeout: time.Second}
	out := ocspCheck{}.Run(context.Background(), env)
	if len(out) != 3 {
		t.Fatalf("want 3 results, got %d", len(out))
	}
	for _, r := range out {
		if r.Status != report.NotApplicable {
			t.Errorf("%s: want N/A, got %s", r.ID, r.Status)
		}
	}
}

func TestCheckStaple_NoStaple(t *testing.T) {
	pki := newTestPKI(t)
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
	}
	r, parsed := checkStaple(state, pki.issuerCert)
	if r.Status != report.Fail {
		t.Errorf("want Fail, got %s", r.Status)
	}
	if parsed != nil {
		t.Errorf("want nil parsed response, got %#v", parsed)
	}
	if r.Remediation == "" || !strings.Contains(r.Remediation, "ssl_stapling") {
		t.Errorf("remediation should include nginx config; got %q", r.Remediation)
	}
}

func TestCheckStaple_GoodAndFresh(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	der := pki.newOCSPResponse(t, ocsp.Good, now.Add(-time.Hour), now.Add(24*time.Hour))
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
		OCSPResponse:     der,
	}
	r, parsed := checkStaple(state, pki.issuerCert)
	if r.Status != report.Pass {
		t.Errorf("want Pass, got %s (evidence=%q)", r.Status, r.Evidence)
	}
	if parsed == nil || parsed.Status != ocsp.Good {
		t.Errorf("want parsed Good response, got %#v", parsed)
	}
}

func TestCheckStaple_Stale(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	// ThisUpdate older than stapleStaleAfter (4 days), but NextUpdate in the future.
	der := pki.newOCSPResponse(t, ocsp.Good, now.Add(-7*24*time.Hour), now.Add(24*time.Hour))
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
		OCSPResponse:     der,
	}
	r, _ := checkStaple(state, pki.issuerCert)
	if r.Status != report.Warn {
		t.Errorf("want Warn for stale staple, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckStaple_Expired(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	// NextUpdate in the past → expired.
	der := pki.newOCSPResponse(t, ocsp.Good, now.Add(-2*time.Hour), now.Add(-time.Hour))
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
		OCSPResponse:     der,
	}
	r, _ := checkStaple(state, pki.issuerCert)
	if r.Status != report.Fail {
		t.Errorf("want Fail for expired staple, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckStaple_Revoked(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	der := pki.newOCSPResponse(t, ocsp.Revoked, now.Add(-time.Hour), now.Add(24*time.Hour))
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
		OCSPResponse:     der,
	}
	r, parsed := checkStaple(state, pki.issuerCert)
	if r.Status != report.Fail {
		t.Errorf("want Fail for revoked, got %s", r.Status)
	}
	if parsed == nil || parsed.Status != ocsp.Revoked {
		t.Errorf("want parsed revoked response, got %#v", parsed)
	}
	if !strings.Contains(r.Evidence, "REVOKED") {
		t.Errorf("evidence should mention REVOKED; got %q", r.Evidence)
	}
}

func TestCheckStaple_Unparseable(t *testing.T) {
	pki := newTestPKI(t)
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
		OCSPResponse:     []byte("not an OCSP response"),
	}
	r, parsed := checkStaple(state, pki.issuerCert)
	if r.Status != report.Fail {
		t.Errorf("want Fail for garbage staple, got %s", r.Status)
	}
	if parsed != nil {
		t.Errorf("want nil parsed, got %#v", parsed)
	}
}

func TestCheckStaple_NoIssuer(t *testing.T) {
	pki := newTestPKI(t)
	der := pki.newOCSPResponse(t, ocsp.Good, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert}, // only leaf, no intermediate
		OCSPResponse:     der,
	}
	r, _ := checkStaple(state, nil)
	if r.Status != report.Warn {
		t.Errorf("want Warn when issuer missing, got %s", r.Status)
	}
}

func TestCheckResponder_NoAIA(t *testing.T) {
	pki := newTestPKI(t)
	r := checkResponder(context.Background(), pki.leafCert, pki.issuerCert, nil)
	if r.Status != report.Info {
		t.Errorf("want Info when leaf has no AIA OCSP URL, got %s", r.Status)
	}
}

func TestCheckResponder_AgreesWithStaple(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()

	// Stand up a fake OCSP responder that returns a Good response.
	respBytes := pki.newOCSPResponse(t, ocsp.Good, now.Add(-time.Hour), now.Add(24*time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		// Drain the request body so we honor the protocol shape (we don't
		// validate it — ocsp.CreateRequest output is opaque to httptest).
		_, _ = io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	// Inject the responder URL onto the leaf.
	pki.leafCert.OCSPServer = []string{srv.URL}

	// Stapled response also Good — responder agrees.
	stapled, err := ocsp.ParseResponse(respBytes, pki.issuerCert)
	if err != nil {
		t.Fatalf("parse staple: %v", err)
	}

	r := checkResponder(context.Background(), pki.leafCert, pki.issuerCert, stapled)
	if r.Status != report.Pass {
		t.Errorf("want Pass when responder agrees with staple, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckResponder_DisagreesWithStaple(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()

	// Responder says Revoked.
	revokedBytes := pki.newOCSPResponse(t, ocsp.Revoked, now.Add(-time.Hour), now.Add(24*time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(revokedBytes)
	}))
	defer srv.Close()

	pki.leafCert.OCSPServer = []string{srv.URL}

	// Stapled response says Good.
	goodBytes := pki.newOCSPResponse(t, ocsp.Good, now.Add(-time.Hour), now.Add(24*time.Hour))
	stapled, err := ocsp.ParseResponse(goodBytes, pki.issuerCert)
	if err != nil {
		t.Fatalf("parse staple: %v", err)
	}

	r := checkResponder(context.Background(), pki.leafCert, pki.issuerCert, stapled)
	// Responder reporting Revoked beats staple-disagree warning — must Fail.
	if r.Status != report.Fail {
		t.Errorf("want Fail when responder reports Revoked, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckResponder_Unreachable(t *testing.T) {
	pki := newTestPKI(t)
	// Use a port we know nothing is listening on (and a tight timeout via ctx).
	pki.leafCert.OCSPServer = []string{"http://127.0.0.1:1/"}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := checkResponder(ctx, pki.leafCert, pki.issuerCert, nil)
	// Per spec: transport failure must be INFO, not FAIL.
	if r.Status != report.Info {
		t.Errorf("want Info on responder unreachable, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckCRL_NoCDP(t *testing.T) {
	pki := newTestPKI(t)
	r := checkCRL(context.Background(), pki.leafCert)
	if r.Status != report.Info {
		t.Errorf("want Info when leaf has no CDP, got %s", r.Status)
	}
}

func TestCheckCRL_LeafNotRevoked(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()

	// Build a CRL containing a different serial — leaf not on it.
	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(999), // not the leaf's serial
				RevocationTime: now.Add(-30 * time.Minute),
			},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, pki.issuerCert, pki.issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer srv.Close()

	pki.leafCert.CRLDistributionPoints = []string{srv.URL}
	r := checkCRL(context.Background(), pki.leafCert)
	if r.Status != report.Pass {
		t.Errorf("want Pass when leaf not on CRL, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckCRL_LeafRevoked(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()

	// Build a CRL that includes the leaf's serial.
	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   pki.leafCert.SerialNumber,
				RevocationTime: now.Add(-30 * time.Minute),
				ReasonCode:     1, // keyCompromise
			},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, pki.issuerCert, pki.issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer srv.Close()

	pki.leafCert.CRLDistributionPoints = []string{srv.URL}
	r := checkCRL(context.Background(), pki.leafCert)
	if r.Status != report.Fail {
		t.Errorf("want Fail when leaf is on CRL, got %s (evidence=%q)", r.Status, r.Evidence)
	}
	if r.Remediation == "" {
		t.Errorf("revoked leaf should carry a remediation")
	}
}

func TestCheckCRL_PEMFallback(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()

	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(3),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, pki.issuerCert, pki.issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	// Wrap as PEM — exercises the fallback branch in parseCRL.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemBytes)
	}))
	defer srv.Close()

	pki.leafCert.CRLDistributionPoints = []string{srv.URL}
	r := checkCRL(context.Background(), pki.leafCert)
	if r.Status != report.Pass {
		t.Errorf("want Pass for PEM-encoded CRL with empty list, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckCRL_Unfetchable(t *testing.T) {
	pki := newTestPKI(t)
	pki.leafCert.CRLDistributionPoints = []string{"http://127.0.0.1:1/crl"}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := checkCRL(ctx, pki.leafCert)
	if r.Status != report.Info {
		t.Errorf("want Info when CRL is unreachable, got %s", r.Status)
	}
}

func TestParseCRL_BadInput(t *testing.T) {
	if _, err := parseCRL([]byte("definitely not a CRL")); err == nil {
		t.Errorf("expected error parsing garbage")
	}
}

func TestOCSPStatusName(t *testing.T) {
	cases := map[int]string{
		ocsp.Good:    "Good",
		ocsp.Revoked: "Revoked",
		ocsp.Unknown: "Unknown",
		99:           "status(99)",
	}
	for in, want := range cases {
		if got := ocspStatusName(in); got != want {
			t.Errorf("ocspStatusName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestTimeoutFromContext(t *testing.T) {
	// No deadline → default 10s.
	if d := timeoutFromContext(context.Background()); d != 10*time.Second {
		t.Errorf("default timeout = %s, want 10s", d)
	}
	// Deadline in future → roughly the remaining duration.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := timeoutFromContext(ctx)
	if d <= 0 || d > 5*time.Second {
		t.Errorf("contextual timeout = %s, want >0 and ≤5s", d)
	}
	// Already-expired deadline → fall back to default (>0).
	ectx, ecancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer ecancel()
	if d := timeoutFromContext(ectx); d <= 0 {
		t.Errorf("expired-deadline timeout = %s, want positive fallback", d)
	}
}

// TestRunCheck_NoCachedState exercises the top-level Run with active=true but
// no cached TLS state — every result should be Info rather than crash.
func TestRunCheck_NoCachedState(t *testing.T) {
	env := &probe.Env{Active: true, Timeout: time.Second}
	// Manually init the cache map since we're constructing Env outside NewEnv.
	// CacheGet handles a nil map by returning ok=false, but CachePut would
	// panic — we don't call it here so this is fine.
	out := ocspCheck{}.Run(context.Background(), env)
	if len(out) != 3 {
		t.Fatalf("want 3 results, got %d", len(out))
	}
	staple := findResult(t, out, "web.ocsp.staple")
	if staple.Status != report.Info {
		t.Errorf("want Info staple when no cached state, got %s", staple.Status)
	}
}
