package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestDialCertStateReturnsServedLeaf verifies dialCertState captures the exact
// certificate served by the host it dials, over a pure TLS handshake, and does
// so even for an untrusted (self-signed) cert. Because it speaks no HTTP, an
// HTTP-layer redirect on the host cannot divert cert inspection to a different
// host's certificate — the cross-host-redirect false positive this fixes
// (e.g. on-running.com -> www.on.com previously yielded the on.com cert).
func TestDialCertStateReturnsServedLeaf(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		// Never invoked: a pure TLS probe sends no HTTP request, so whatever
		// redirect this host would serve cannot reach cert inspection.
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")
	state, err := dialCertState(context.Background(), addr, "example.com", 5*time.Second)
	if err != nil {
		t.Fatalf("dialCertState: %v", err)
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates captured")
	}
	if !state.PeerCertificates[0].Equal(srv.Certificate()) {
		t.Errorf("captured leaf is not the certificate the dialed host served")
	}
}

// TestRunCertValidatesCachedStateAgainstTarget confirms runCert inspects the
// TLS state it holds against env.Target: a cached leaf whose SAN covers the
// target passes the hostname check (independent of the racy fallback path).
func TestRunCertValidatesCachedStateAgainstTarget(t *testing.T) {
	leaf := selfSignedLeaf(t, "target.example")
	env := probe.NewEnv("target.example", time.Second, true, "")
	env.CachePut(probe.CacheKeyTLSCxn, &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
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
