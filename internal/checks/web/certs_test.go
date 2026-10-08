package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestRunCert_InspectsTheServedCertificate: runCert inspects the
// certificate the target itself serves, over a pure TLS handshake, even an
// untrusted one. Because it speaks no HTTP, a redirect on the host cannot
// divert cert inspection to another host's certificate — the
// cross-host-redirect false positive (e.g. on-running.com -> www.on.com
// once yielded the on.com cert).
func TestRunCert_InspectsTheServedCertificate(t *testing.T) {
	env := tlsTestEnv(t)
	srv := startTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("cert inspection sent an HTTP request: %s %s", r.Method, r.URL)
		http.Redirect(w, r, "https://other.example/", http.StatusFound)
	}), nil, false)
	setPort(t, &tlsStatePort, portOf(srv.Listener.Addr()))

	out := runCert(context.Background(), env)
	if r := findResult(t, out, "web.cert.chain"); r.Status != report.Fail ||
		!strings.Contains(r.Evidence, "unknown authority") {
		t.Errorf("web.cert.chain = %s %q, want FAIL for the untrusted chain", r.Status, r.Evidence)
	}
	served := srv.Certificate()
	want := fmt.Sprintf("expires in %d days (%s)",
		int(time.Until(served.NotAfter).Hours()/24), served.NotAfter.Format(time.RFC3339))
	if r := findResult(t, out, "web.cert.expiry"); r.Evidence != want {
		t.Errorf("web.cert.expiry evidence = %q, want the served leaf's %q", r.Evidence, want)
	}
}

// TestRunCert_GradesTheRecordedVerification: web.cert.chain grades the
// verification hostTLS recorded for the target, so a chain from a trusted
// CA passes and an expired or wrong-host one fails as it always has, along
// with the matching leaf check.
func TestRunCert_GradesTheRecordedVerification(t *testing.T) {
	expired := loopbackLeaf()
	expired.NotBefore, expired.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	wrongHost := loopbackLeaf()
	wrongHost.DNSNames, wrongHost.IPAddresses = []string{"other.test"}, nil
	cases := []struct {
		name  string
		leaf  *x509.Certificate
		chain string // evidence of a failing web.cert.chain, or "" for PASS
		leafR string // the leaf check that fails with it
	}{
		{"valid chain", loopbackLeaf(), "", ""},
		{"expired leaf", expired, "certificate has expired", "web.cert.expiry"},
		{"wrong host", wrongHost, "doesn't contain any IP SANs", "web.cert.san"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pki := newTestPKI(t)
			trustTestCA(t, pki)
			env := tlsTestEnv(t)
			port, _ := serveTLS(t, &tls.Config{
				Certificates: []tls.Certificate{serverCert(t, pki, tc.leaf)},
			})
			setPort(t, &tlsStatePort, port)

			assertCertVerdicts(t, runCert(context.Background(), env), tc.chain, tc.leafR)
		})
	}
}

// assertCertVerdicts checks that every result in out passes except, when
// chain is set, web.cert.chain, which fails naming chain, and the leaf
// check leafR.
func assertCertVerdicts(t *testing.T, out []report.Result, chain, leafR string) {
	t.Helper()
	failing := map[string]bool{leafR: leafR != "", "web.cert.chain": chain != ""}
	for _, r := range out {
		want := report.Pass
		if failing[r.ID] {
			want = report.Fail
		}
		if r.Status != want {
			t.Errorf("%s = %s %q, want %s", r.ID, r.Status, r.Evidence, want)
		}
	}
	if r := findResult(t, out, "web.cert.chain"); !strings.Contains(r.Evidence, chain) {
		t.Errorf("web.cert.chain evidence = %q, want it to name %q", r.Evidence, chain)
	}
}

// TestRunCertValidatesCachedStateAgainstTarget confirms runCert inspects the
// shared handshake's state against env.Target: a leaf whose SAN covers the
// target passes the hostname check.
func TestRunCertValidatesCachedStateAgainstTarget(t *testing.T) {
	leaf := selfSignedLeaf(t, "target.example")
	env := probe.NewEnv("target.example", time.Second, true, "")
	env.CachePut(tlsStateKey("target.example"), &tlsHandshake{
		state:     &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}},
		verifyErr: x509.UnknownAuthorityError{Cert: leaf},
	})

	san := findResult(t, runCert(context.Background(), env), "web.cert.san")
	if san.Status != report.Pass {
		t.Errorf("web.cert.san = %v, want Pass; evidence=%q", san.Status, san.Evidence)
	}
}

// selfSignedLeaf builds a self-signed ECDSA leaf whose SAN covers dnsName.
func selfSignedLeaf(t *testing.T, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return leaf
}
