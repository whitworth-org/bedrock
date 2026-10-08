package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net"
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
	return p.signOCSP(t, tmpl)
}

// signOCSP signs tmpl with the issuer key, the issuer acting as responder.
func (p *testPKI) signOCSP(t *testing.T, tmpl ocsp.Response) []byte {
	t.Helper()
	der, err := ocsp.CreateResponse(p.issuerCert, p.issuerCert, tmpl, p.issuerKey)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	return der
}

// issue signs a certificate built from tmpl with the issuer key and returns
// it with its new private key.
func (p *testPKI) issue(
	t *testing.T, tmpl *x509.Certificate,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.issuerCert, &key.PublicKey, p.issuerKey)
	if err != nil {
		t.Fatalf("issue %q: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %q: %v", tmpl.Subject.CommonName, err)
	}
	return cert, key
}

// delegatedResponse returns a fresh Good response for the leaf, signed by a
// responder certificate the issuer issued with the given EKUs and validity.
// The responder certificate travels in the response (RFC 6960 §4.2.2.2).
func (p *testPKI) delegatedResponse(
	t *testing.T, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time,
) []byte {
	t.Helper()
	responder, key := p.issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: "bedrock test responder"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	})
	now := time.Now()
	der, err := ocsp.CreateResponse(p.issuerCert, responder, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: p.leafCert.SerialNumber,
		ThisUpdate:   now.Add(-time.Hour),
		NextUpdate:   now.Add(24 * time.Hour),
		Certificate:  responder,
	}, key)
	if err != nil {
		t.Fatalf("create delegated OCSP response: %v", err)
	}
	return der
}

// serveBody starts an HTTP server that answers every request with body.
func serveBody(t *testing.T, contentType string, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// closedLoopbackURL returns an http URL for a loopback port that was just
// released, so dialing it is refused.
func closedLoopbackURL(t *testing.T, path string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return "http://" + addr + path
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

// newLoopbackEnv returns an Env whose SSRF-safe dialer can reach httptest
// servers on 127.0.0.1. probe.SafeDial reads BEDROCK_ALLOW_PRIVATE_RESOLVER
// on every dial, and t.Setenv scopes it to the calling test, which therefore
// must not call t.Parallel.
func newLoopbackEnv(t *testing.T) *probe.Env {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	return &probe.Env{Timeout: time.Second, HTTP: probe.NewHTTP(time.Second)}
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
	pki.leafCert.OCSPServer = []string{"http://ocsp.test/"}
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
	}
	r, parsed := checkStaple(state, pki.leafCert, pki.issuerCert)
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
	r, parsed := checkStaple(state, pki.leafCert, pki.issuerCert)
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
	// ThisUpdate older than ocspStaleAfter (4 days), but NextUpdate in the future.
	der := pki.newOCSPResponse(t, ocsp.Good, now.Add(-7*24*time.Hour), now.Add(24*time.Hour))
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
		OCSPResponse:     der,
	}
	r, _ := checkStaple(state, pki.leafCert, pki.issuerCert)
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
	r, _ := checkStaple(state, pki.leafCert, pki.issuerCert)
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
	r, parsed := checkStaple(state, pki.leafCert, pki.issuerCert)
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
	r, parsed := checkStaple(state, pki.leafCert, pki.issuerCert)
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
	r, _ := checkStaple(state, pki.leafCert, nil)
	if r.Status != report.Warn {
		t.Errorf("want Warn when issuer missing, got %s", r.Status)
	}
}

// TestCheckStaple_NoOCSPURLIsNotApplicable: a CRL-only leaf names no OCSP
// responder, so no server can staple for it.
func TestCheckStaple_NoOCSPURLIsNotApplicable(t *testing.T) {
	pki := newTestPKI(t) // the test leaf carries no OCSP URL
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
	}
	r, parsed := checkStaple(state, pki.leafCert, pki.issuerCert)
	if r.Status != report.NotApplicable || r.Remediation != "" {
		t.Errorf("want N/A without remediation, got %s (evidence=%q, remediation=%q)",
			r.Status, r.Evidence, r.Remediation)
	}
	if parsed != nil {
		t.Errorf("want nil parsed response, got %#v", parsed)
	}
}

// TestCheckStaple_RejectsStaplesNotBoundToLeaf: a staple counts only when it
// names the leaf's serial, is signed by the issuer or by a responder the
// issuer certified for OCSP signing, and is not dated in the future.
func TestCheckStaple_RejectsStaplesNotBoundToLeaf(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	ocspSigning := []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cases := []struct {
		name   string
		staple []byte
		want   report.Status
	}{
		{
			name:   "delegated responder with the OCSP Signing EKU",
			staple: pki.delegatedResponse(t, ocspSigning, now.Add(-time.Hour), now.Add(time.Hour)),
			want:   report.Pass,
		},
		{
			name: "Good response for another serial",
			staple: pki.signOCSP(t, ocsp.Response{
				Status: ocsp.Good, SerialNumber: big.NewInt(999),
				ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
			}),
			want: report.Fail,
		},
		{
			name:   "signed by another leaf of the same issuer",
			staple: pki.delegatedResponse(t, serverAuth, now.Add(-time.Hour), now.Add(time.Hour)),
			want:   report.Fail,
		},
		{
			name: "delegated responder certificate expired",
			staple: pki.delegatedResponse(t, ocspSigning,
				now.Add(-2*time.Hour), now.Add(-time.Hour)),
			want: report.Fail,
		},
		{
			name:   "ThisUpdate in the future",
			staple: pki.newOCSPResponse(t, ocsp.Good, now.Add(time.Hour), now.Add(25*time.Hour)),
			want:   report.Fail,
		},
		{
			name:   "ThisUpdate ahead by less than the clock skew",
			staple: pki.newOCSPResponse(t, ocsp.Good, now.Add(time.Minute), now.Add(24*time.Hour)),
			want:   report.Pass,
		},
		{
			name: "NextUpdate passed by less than the clock skew",
			staple: pki.newOCSPResponse(t, ocsp.Good,
				now.Add(-time.Hour), now.Add(-time.Minute)),
			want: report.Pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &tls.ConnectionState{OCSPResponse: tc.staple}
			r, _ := checkStaple(state, pki.leafCert, pki.issuerCert)
			if r.Status != tc.want {
				t.Errorf("want %s, got %s (evidence=%q)", tc.want, r.Status, r.Evidence)
			}
		})
	}
}

func TestCheckResponder_NoAIA(t *testing.T) {
	pki := newTestPKI(t)
	env := &probe.Env{Timeout: time.Second, HTTP: probe.NewHTTP(time.Second)}
	r := checkResponder(context.Background(), env, pki.leafCert, pki.issuerCert, nil)
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

	env := newLoopbackEnv(t)
	r := checkResponder(context.Background(), env, pki.leafCert, pki.issuerCert, stapled)
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

	env := newLoopbackEnv(t)
	r := checkResponder(context.Background(), env, pki.leafCert, pki.issuerCert, stapled)
	// Responder reporting Revoked beats staple-disagree warning — must Fail.
	if r.Status != report.Fail {
		t.Errorf("want Fail when responder reports Revoked, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckResponder_Unreachable(t *testing.T) {
	pki := newTestPKI(t)
	// A closed local port (and a tight timeout via ctx); newLoopbackEnv lets
	// the dial reach it, so this exercises a refused connection rather than
	// the SSRF filter.
	pki.leafCert.OCSPServer = []string{closedLoopbackURL(t, "/")}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	env := newLoopbackEnv(t)
	r := checkResponder(ctx, env, pki.leafCert, pki.issuerCert, nil)
	// Per spec: transport failure must be INFO, not FAIL.
	if r.Status != report.Info {
		t.Errorf("want Info on responder unreachable, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

// TestCheckResponder_RejectsUnboundOrStaleReplies: over plain HTTP an
// on-path attacker can return a CA-signed reply for another serial, or an
// old Good reply from before a revocation. Neither may PASS; both are INFO
// because the domain operator does not run the responder.
func TestCheckResponder_RejectsUnboundOrStaleReplies(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cases := []struct {
		name  string
		reply []byte
	}{
		{"Good reply for another serial", pki.signOCSP(t, ocsp.Response{
			Status: ocsp.Good, SerialNumber: big.NewInt(999),
			ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
		})},
		{"signed by another leaf of the same issuer",
			pki.delegatedResponse(t, serverAuth, now.Add(-time.Hour), now.Add(time.Hour))},
		{"NextUpdate in the past",
			pki.newOCSPResponse(t, ocsp.Good, now.Add(-48*time.Hour), now.Add(-time.Hour))},
		{"ThisUpdate in the future",
			pki.newOCSPResponse(t, ocsp.Good, now.Add(time.Hour), now.Add(25*time.Hour))},
		{"ThisUpdate older than ocspStaleAfter",
			pki.newOCSPResponse(t, ocsp.Good, now.Add(-7*24*time.Hour), now.Add(24*time.Hour))},
		{"no NextUpdate",
			pki.newOCSPResponse(t, ocsp.Good, now.Add(-time.Hour), time.Time{})},
	}
	env := newLoopbackEnv(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveBody(t, "application/ocsp-response", tc.reply)
			pki.leafCert.OCSPServer = []string{srv.URL}
			r := checkResponder(context.Background(), env, pki.leafCert, pki.issuerCert, nil)
			if r.Status != report.Info {
				t.Errorf("want Info, got %s (evidence=%q)", r.Status, r.Evidence)
			}
		})
	}
}

func TestCheckCRL_NoCDP(t *testing.T) {
	pki := newTestPKI(t)
	env := &probe.Env{Timeout: time.Second, HTTP: probe.NewHTTP(time.Second)}
	r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
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
	env := newLoopbackEnv(t)
	r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
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
	env := newLoopbackEnv(t)
	r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
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
	env := newLoopbackEnv(t)
	r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
	if r.Status != report.Pass {
		t.Errorf("want Pass for PEM-encoded CRL with empty list, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestCheckCRL_Unfetchable(t *testing.T) {
	pki := newTestPKI(t)
	pki.leafCert.CRLDistributionPoints = []string{closedLoopbackURL(t, "/crl")}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	env := newLoopbackEnv(t)
	r := checkCRL(ctx, env, pki.leafCert, pki.issuerCert)
	if r.Status != report.Info {
		t.Errorf("want Info when CRL is unreachable, got %s", r.Status)
	}
}

// signCRL returns a DER CRL signed by the issuer that lists serials and
// expires at nextUpdate.
func (p *testPKI) signCRL(t *testing.T, nextUpdate time.Time, serials ...*big.Int) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(4),
		ThisUpdate: nextUpdate.Add(-48 * time.Hour),
		NextUpdate: nextUpdate,
	}
	for _, s := range serials {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: s, RevocationTime: tmpl.ThisUpdate})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, p.issuerCert, p.issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}

// TestCheckCRL_RejectsUnauthenticatedCRL: CRLs travel over plain HTTP, so a
// CRL signed by another key, or one past its NextUpdate, must neither PASS
// (hiding a revocation) nor FAIL (inventing one).
func TestCheckCRL_RejectsUnauthenticatedCRL(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	now := time.Now()
	cases := []struct {
		name string
		crl  []byte
	}{
		{"empty CRL signed by another CA", other.signCRL(t, now.Add(24*time.Hour))},
		{"CRL listing the leaf signed by another CA",
			other.signCRL(t, now.Add(24*time.Hour), pki.leafCert.SerialNumber)},
		{"issuer's CRL past its NextUpdate", pki.signCRL(t, now.Add(-time.Hour))},
	}
	env := newLoopbackEnv(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveBody(t, "application/pkix-crl", tc.crl)
			pki.leafCert.CRLDistributionPoints = []string{srv.URL}
			r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
			if r.Status != report.Info {
				t.Errorf("want Info, got %s (evidence=%q)", r.Status, r.Evidence)
			}
		})
	}
}

// TestCheckCRL_AllowsClockSkew: a CRL whose NextUpdate passed less than
// revocationSkew ago still counts, as bedrock's clock may run ahead of the CA's.
func TestCheckCRL_AllowsClockSkew(t *testing.T) {
	pki := newTestPKI(t)
	srv := serveBody(t, "application/pkix-crl", pki.signCRL(t, time.Now().Add(-time.Minute)))
	pki.leafCert.CRLDistributionPoints = []string{srv.URL}
	r := checkCRL(context.Background(), newLoopbackEnv(t), pki.leafCert, pki.issuerCert)
	if r.Status != report.Pass {
		t.Errorf("want Pass, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

// TestCheckCRL_NoIssuerIsInfo: without an issuer certificate nothing can
// authenticate the CRL, so the check is inconclusive.
func TestCheckCRL_NoIssuerIsInfo(t *testing.T) {
	pki := newTestPKI(t)
	srv := serveBody(t, "application/pkix-crl", pki.signCRL(t, time.Now().Add(24*time.Hour)))
	pki.leafCert.CRLDistributionPoints = []string{srv.URL}
	r := checkCRL(context.Background(), newLoopbackEnv(t), pki.leafCert, nil)
	if r.Status != report.Info {
		t.Errorf("want Info, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

// rawIDP encodes by hand, as RFC 5280 §5.2.5 lays it out, an Issuing
// Distribution Point whose fullName is uri, followed by the encoded fields
// in extra. Every length must stay under 128 bytes.
func rawIDP(uri string, extra ...byte) []byte {
	gn := append([]byte{0x86, byte(len(uri))}, uri...)     // [6] uniformResourceIdentifier
	full := append([]byte{0xa0, byte(len(gn))}, gn...)     // [0] fullName
	body := append([]byte{0xa0, byte(len(full))}, full...) // [0] distributionPoint
	body = append(body, extra...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// TestCheckCRL_Scope: an issuer-signed, current CRL counts only when its
// scope covers the leaf. A shard for another distribution point, a delta
// CRL, a CRL limited by certificate type or reason, an indirect CRL, one
// with a critical extension bedrock does not process and one not yet valid
// could each omit the leaf's revocation, so they are rejected as INFO.
func TestCheckCRL_Scope(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	crls := map[string][]byte{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(crls[r.URL.Path])
		}))
	base := "http://" + srv.Listener.Addr().String()
	critical := func(id asn1.ObjectIdentifier, value []byte) pkix.Extension {
		return pkix.Extension{Id: id, Critical: true, Value: value}
	}
	idp := func(path string, extra ...byte) pkix.Extension {
		return critical(oidIssuingDistributionPoint, rawIDP(base+path, extra...))
	}
	unknown := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	cases := []struct {
		path     string
		exts     []pkix.Extension
		revoked  bool // the CRL lists the leaf
		future   bool // ThisUpdate is an hour ahead
		want     report.Status
		evidence string
	}{
		{"/shard1.crl", []pkix.Extension{idp("/shard1.crl")}, true, false, report.Fail,
			"leaf serial 424242 is on CRL"},
		{"/shard3.crl", []pkix.Extension{idp("/shard3.crl")}, false, false, report.Pass,
			"leaf serial not present"},
		{"/users.crl", []pkix.Extension{critical(oidIssuingDistributionPoint,
			[]byte{0x30, 0x03, 0x81, 0x01, 0xff})}, false, false, report.Pass,
			"leaf serial not present"},
		{"/note.crl", []pkix.Extension{{Id: unknown, Value: []byte{0x05, 0x00}}}, false, false,
			report.Pass, "leaf serial not present"},
		{"/shard2.crl", []pkix.Extension{idp("/shard9.crl")}, false, false, report.Info,
			"rejected: issuing distribution point does not name " + base + "/shard2.crl"},
		{"/ca.crl", []pkix.Extension{idp("/ca.crl", 0x82, 0x01, 0xff)}, false, false,
			report.Info, "rejected: issuing distribution point excludes end-entity certificates"},
		{"/attr.crl", []pkix.Extension{idp("/attr.crl", 0x85, 0x01, 0xff)}, false, false,
			report.Info, "rejected: issuing distribution point excludes end-entity certificates"},
		{"/reasons.crl", []pkix.Extension{idp("/reasons.crl", 0x83, 0x02, 0x07, 0x80)}, false,
			false, report.Info, "rejected: issuing distribution point covers only some revocation"},
		{"/indirect.crl", []pkix.Extension{idp("/indirect.crl", 0x84, 0x01, 0xff)}, false, false,
			report.Info, "rejected: issuing distribution point marks an indirect CRL"},
		{"/bad.crl", []pkix.Extension{critical(oidIssuingDistributionPoint,
			[]byte{0x30, 0x03, 0x01})}, false, false, report.Info,
			"rejected: malformed issuing distribution point extension"},
		{"/delta.crl", []pkix.Extension{critical(oidDeltaCRLIndicator, []byte{0x02, 0x01, 0x03})},
			false, false, report.Info, "rejected: delta CRL"},
		{"/critical.crl", []pkix.Extension{critical(unknown, []byte{0x05, 0x00})}, false, false,
			report.Info, "rejected: unsupported critical extension 1.3.6.1.4.1.99999.1"},
		{"/future.crl", nil, false, true, report.Info, "rejected: not yet valid: ThisUpdate="},
	}
	for _, tc := range cases {
		tmpl := &x509.RevocationList{
			Number: big.NewInt(9), ThisUpdate: now.Add(-time.Hour),
			NextUpdate: now.Add(24 * time.Hour), ExtraExtensions: tc.exts,
		}
		if tc.future {
			tmpl.ThisUpdate = now.Add(time.Hour)
		}
		if tc.revoked {
			tmpl.RevokedCertificateEntries = []x509.RevocationListEntry{
				{SerialNumber: pki.leafCert.SerialNumber, RevocationTime: now.Add(-time.Hour)}}
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, pki.issuerCert, pki.issuerKey)
		if err != nil {
			t.Fatalf("create CRL %s: %v", tc.path, err)
		}
		crls[tc.path] = der
	}
	srv.Start()
	t.Cleanup(srv.Close)
	env := newLoopbackEnv(t)
	for _, tc := range cases {
		pki.leafCert.CRLDistributionPoints = []string{base + tc.path}
		r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
		if r.Status != tc.want || !strings.Contains(r.Evidence, tc.evidence) {
			t.Errorf("%s: got %s %q, want %s with %q", tc.path, r.Status, r.Evidence,
				tc.want, tc.evidence)
		}
	}
}

// TestCheckCRL_FetchFailuresAreInfo: a CRL that cannot be fetched or read
// whole leaves the leaf's status unknown, so the result is INFO naming why.
func TestCheckCRL_FetchFailuresAreInfo(t *testing.T) {
	pki := newTestPKI(t)
	huge := serveBody(t, "application/pkix-crl", make([]byte, 1<<20+1)).URL + "/big.crl"
	junk := serveBody(t, "application/pkix-crl", []byte("not a CRL")).URL + "/junk.crl"
	gone := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(gone.Close)
	cases := []struct{ url, evidence string }{
		{huge, "CRL " + huge + " exceeds the 1 MiB fetch cap; not checked"},
		{junk, "could not parse CRL " + junk + ": body is neither valid DER nor PEM"},
		{gone.URL + "/x.crl", "CRL " + gone.URL + "/x.crl returned HTTP 404"},
		{"http://bad host/x.crl", "could not build CRL request: "},
	}
	env := newLoopbackEnv(t)
	for _, tc := range cases {
		pki.leafCert.CRLDistributionPoints = []string{tc.url}
		r := checkCRL(context.Background(), env, pki.leafCert, pki.issuerCert)
		if r.Status != report.Info || !strings.HasPrefix(r.Evidence, tc.evidence) {
			t.Errorf("%s: got %s %q, want INFO starting %q", tc.url, r.Status, r.Evidence,
				tc.evidence)
		}
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

// TestRunCheck_NoCachedState exercises the top-level Run with active=true
// on a zero-value Env. With no target the shared handshake would dial the
// local host at ":443", which the SSRF dial guard refuses before connecting
// because the address names no IP. probe.IsProbeFailure does not count that
// refusal, so every result is INFO with the handshake error, as after a
// refused handshake, rather than a crash.
func TestRunCheck_NoCachedState(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	env := &probe.Env{Active: true, Timeout: time.Second}
	out := ocspCheck{}.Run(context.Background(), env)
	if len(out) != 3 {
		t.Fatalf("want 3 results, got %d", len(out))
	}
	for _, r := range out {
		if r.Status != report.Info ||
			!strings.HasPrefix(r.Evidence, "TLS handshake with :443 failed: ") ||
			!strings.Contains(r.Evidence, "ssrf dial: parse address") {
			t.Errorf("%s = %s %q, want INFO quoting the dial guard's refusal",
				r.ID, r.Status, r.Evidence)
		}
	}
}

// TestOCSPRun_FindsIssuerThroughHostTLS runs the whole check against a
// server whose chain a test CA issued, with a self-made "issuer" presented
// right after the leaf: the staple, responder reply and CRL that the real
// issuer signed all count, because the issuer comes from the chain hostTLS
// verified rather than from the order the server chose.
func TestOCSPRun_FindsIssuerThroughHostTLS(t *testing.T) {
	pki := newTestPKI(t)
	attacker := newTestPKI(t)
	trustTestCA(t, pki)
	env := tlsTestEnv(t)
	now := time.Now()
	good := pki.signOCSP(t, ocsp.Response{
		Status: ocsp.Good, SerialNumber: big.NewInt(4040),
		ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
	})
	leaf := loopbackLeaf() // serial 4040
	leaf.OCSPServer = []string{serveBody(t, "application/ocsp-response", good).URL}
	leaf.CRLDistributionPoints = []string{
		serveBody(t, "application/pkix-crl", pki.signCRL(t, now.Add(time.Hour))).URL,
	}
	cert := serverCert(t, pki, leaf, attacker.issuerCert, pki.issuerCert)
	cert.OCSPStaple = good
	port, _ := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	setPort(t, &tlsStatePort, port)

	out := ocspCheck{}.Run(context.Background(), env)
	for _, id := range []string{"web.ocsp.staple", "web.ocsp.responder", "web.crl.status"} {
		if r := findResult(t, out, id); r.Status != report.Pass {
			t.Errorf("%s: want PASS, got %s (evidence=%q)", id, r.Status, r.Evidence)
		}
	}
}

// TestOCSPRun_TakesIssuerFromVerifiedChain replays a chain-reorder attack:
// the server sends a self-made "issuer" right after the leaf and the real
// issuer after that. Go's verifier still builds leaf -> real issuer, so only
// the verified chain names the issuer, and a staple, responder reply or CRL
// that the self-made one signed must not count.
func TestOCSPRun_TakesIssuerFromVerifiedChain(t *testing.T) {
	pki := newTestPKI(t)
	attacker := newTestPKI(t)
	now := time.Now()
	goodFrom := func(signer *testPKI) []byte {
		return signer.signOCSP(t, ocsp.Response{
			Status: ocsp.Good, SerialNumber: pki.leafCert.SerialNumber,
			ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
		})
	}
	cases := []struct {
		name   string
		signer *testPKI
		want   map[string]report.Status
	}{
		{"signed by the verified issuer", pki, map[string]report.Status{
			"web.ocsp.staple": report.Pass, "web.ocsp.responder": report.Pass,
			"web.crl.status": report.Pass,
		}},
		{"signed by the served but unverified issuer", attacker, map[string]report.Status{
			"web.ocsp.staple": report.Fail, "web.ocsp.responder": report.Info,
			"web.crl.status": report.Info,
		}},
	}
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			responder := serveBody(t, "application/ocsp-response", goodFrom(tc.signer))
			crl := serveBody(t, "application/pkix-crl", tc.signer.signCRL(t, now.Add(time.Hour)))
			pki.leafCert.OCSPServer = []string{responder.URL}
			pki.leafCert.CRLDistributionPoints = []string{crl.URL}
			env := probe.NewEnv("leaf.test", time.Second, true, "")
			env.CachePut(tlsStateKey("leaf.test"), &tlsHandshake{
				state: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{
						pki.leafCert, attacker.issuerCert, pki.issuerCert,
					},
					OCSPResponse: goodFrom(tc.signer),
				},
				chains: [][]*x509.Certificate{{pki.leafCert, pki.issuerCert}},
			})
			out := ocspCheck{}.Run(context.Background(), env)
			for id, want := range tc.want {
				if r := findResult(t, out, id); r.Status != want {
					t.Errorf("%s: want %s, got %s (evidence=%q)", id, want, r.Status, r.Evidence)
				}
			}
		})
	}
}

// TestOCSPRun_UnverifiedChainIsNotApplicable: without a verified chain
// nothing binds OCSP or CRL data to an issuer, so all three results are
// N/A, pointing at web.cert.*.
func TestOCSPRun_UnverifiedChainIsNotApplicable(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	env := probe.NewEnv("leaf.test", time.Second, true, "")
	env.CachePut(tlsStateKey("leaf.test"), &tlsHandshake{
		state: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
			OCSPResponse: pki.newOCSPResponse(t, ocsp.Good,
				now.Add(-time.Hour), now.Add(24*time.Hour)),
		},
		verifyErr: x509.UnknownAuthorityError{Cert: pki.leafCert},
	})
	out := ocspCheck{}.Run(context.Background(), env)
	if len(out) != 3 {
		t.Fatalf("want 3 results, got %d", len(out))
	}
	for _, r := range out {
		if r.Status != report.NotApplicable || r.Evidence != "TLS chain invalid; see web.cert.*" {
			t.Errorf("%s: got %s %q, want N/A pointing at web.cert.*", r.ID, r.Status, r.Evidence)
		}
	}
}
