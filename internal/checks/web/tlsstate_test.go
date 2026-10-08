package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestHostTLS_OneHandshakePerHost: the TLS profile, certificate, OCSP and
// CT checks and direct callers, 20 in all and released together, share one
// handshake per host.
func TestHostTLS_OneHandshakePerHost(t *testing.T) {
	pki := newTestPKI(t)
	trustTestCA(t, pki)
	env := tlsTestEnv(t)
	port, accepts := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert(t, pki, loopbackLeaf())},
	})
	setPort(t, &tlsStatePort, port)

	ctx := context.Background()
	consumers := []func(){
		func() { runTLS(ctx, env) },
		func() { runCert(ctx, env) },
		func() { ocspCheck{}.Run(ctx, env) },
		func() { runCTSCTs(ctx, env) },
		func() { hostTLS(ctx, env, "localhost") },
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			consumers[i%len(consumers)]()
		}()
	}
	close(start)
	wg.Wait()

	if n := accepts.Load(); n != 2 {
		t.Errorf("20 consumers of 127.0.0.1 and localhost made %d handshakes, want 2", n)
	}
	if h := hostTLS(ctx, env, "127.0.0.1"); h.err != nil || h.verifyErr != nil {
		t.Errorf("shared handshake: err %v, verifyErr %v; want a verified chain",
			h.err, h.verifyErr)
	}
}

// TestHostTLS_RecordsChainVerification: the handshake itself skips
// verification, so it completes for any chain; whether the chain verifies
// for the host is recorded separately, along with the chain it built,
// which names the leaf's issuer.
func TestHostTLS_RecordsChainVerification(t *testing.T) {
	cases := []struct {
		name string
		// serve returns the certificate the server presents, given the
		// trusted root, and the issuer verification must find, or nil when
		// the chain must not verify.
		serve func(t *testing.T, root *testPKI) (tls.Certificate, *x509.Certificate)
	}{
		{"leaf issued by the trusted root",
			func(t *testing.T, root *testPKI) (tls.Certificate, *x509.Certificate) {
				return serverCert(t, root, loopbackLeaf()), root.issuerCert
			}},
		{"leaf issued by a served intermediate",
			func(t *testing.T, root *testPKI) (tls.Certificate, *x509.Certificate) {
				inter := intermediateCA(t, root)
				return serverCert(t, inter, loopbackLeaf()), inter.issuerCert
			}},
		{"intermediate not served",
			func(t *testing.T, root *testPKI) (tls.Certificate, *x509.Certificate) {
				cert := serverCert(t, intermediateCA(t, root), loopbackLeaf())
				cert.Certificate = cert.Certificate[:1]
				return cert, nil
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newTestPKI(t)
			trustTestCA(t, root)
			cert, wantIssuer := tc.serve(t, root)
			env := tlsTestEnv(t)
			port, _ := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}})
			setPort(t, &tlsStatePort, port)

			h := hostTLS(context.Background(), env, "127.0.0.1")
			if h.err != nil {
				t.Fatalf("handshake failed: %v", h.err)
			}
			if len(h.state.VerifiedChains) != 0 {
				t.Errorf("state.VerifiedChains has %d chains; the handshake must not verify",
					len(h.state.VerifiedChains))
			}
			assertRecordedIssuer(t, h, wantIssuer)
		})
	}
	t.Run("self-signed certificate", func(t *testing.T) {
		env := tlsTestEnv(t)
		srv := startTLSServer(t, http.NotFoundHandler(), nil, false)
		setPort(t, &tlsStatePort, portOf(srv.Listener.Addr()))

		h := hostTLS(context.Background(), env, "127.0.0.1")
		if h.err != nil {
			t.Fatalf("handshake failed: %v", h.err)
		}
		assertRecordedIssuer(t, h, nil)
		if !h.state.PeerCertificates[0].Equal(srv.Certificate()) {
			t.Error("recorded leaf is not the certificate the server presented")
		}
	})
}

// assertRecordedIssuer checks that h's chain verified with want as the
// leaf's issuer or, when want is nil, failed to verify for lack of a
// trusted issuer.
func assertRecordedIssuer(t *testing.T, h *tlsHandshake, want *x509.Certificate) {
	t.Helper()
	if want == nil {
		var unknown x509.UnknownAuthorityError
		if !errors.As(h.verifyErr, &unknown) || len(h.chains) != 0 {
			t.Errorf("verifyErr %v, chains %v; want an unknown-authority error and no chain",
				h.verifyErr, h.chains)
		}
		return
	}
	if h.verifyErr != nil {
		t.Fatalf("verifyErr %v, want a verified chain", h.verifyErr)
	}
	if issuer := h.verifiedIssuer(); issuer == nil || !issuer.Equal(want) {
		t.Errorf("verifiedIssuer() = %v, want %v", issuer, want.Subject)
	}
}

func TestVerifyServedChain_NoCertificate(t *testing.T) {
	_, err := verifyServedChain(&tls.ConnectionState{}, "example.com")
	if err == nil || err.Error() != "the server presented no certificate" {
		t.Errorf("verifyServedChain(no certificates) = %v, want the no-certificate error", err)
	}
}

// TestHostTLS_FailedHandshake: a handshake that could not complete leaves
// every consumer inconclusive; one the target refused or broke off is
// an answer, graded as before: FAIL for the profile and certificate checks,
// INFO for the revocation and CT checks, which web.tls.profile covers.
func TestHostTLS_FailedHandshake(t *testing.T) {
	const short = 200 * time.Millisecond
	cases := []struct {
		name, override string
		port           func(t *testing.T) string
		timeout        time.Duration
		detail         string
		inconclusive   bool
	}{
		{"blocked by the SSRF denylist", "",
			func(t *testing.T) string { addr, _ := tarpitListener(t); return portOf(addr) },
			short, "ssrf dial: refusing 127.0.0.1", true},
		{"timed out", "1",
			func(t *testing.T) string { addr, _ := tarpitListener(t); return portOf(addr) },
			short, "context deadline exceeded", true},
		{"reset after accept", "1",
			func(t *testing.T) string { return portOf(resetListener(t)) },
			short, resetText(), true},
		{"connection refused", "1", closedPort, refusedDialTimeout, "refused", false},
		{"plain HTTP listener", "1",
			func(t *testing.T) string {
				srv := httptest.NewServer(http.NotFoundHandler())
				t.Cleanup(srv.Close)
				return portOf(srv.Listener.Addr())
			},
			short, "first record does not look like a TLS handshake", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tlsTestEnv(t)
			env.Timeout = tc.timeout
			t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", tc.override)
			port := tc.port(t)
			setPort(t, &tlsStatePort, port)

			got := runTLSConsumers(context.Background(), env)
			if len(got) != len(tlsConsumerIDs) {
				t.Errorf("got results %v, want exactly %v", got, tlsConsumerIDs)
			}
			for _, id := range tlsConsumerIDs {
				r := got[id]
				if tc.inconclusive {
					assertInconclusive(t, r, tc.detail)
					continue
				}
				assertHandshakeAnswer(t, r, "127.0.0.1:"+port, tc.detail)
			}
		})
	}
}

// TestHostTLS_RejectedHandshakeIsNotRetried: a handshake the server
// rejects is graded from one connection, quoting the server's own error;
// nothing is retried with other settings.
func TestHostTLS_RejectedHandshakeIsNotRetried(t *testing.T) {
	env := tlsTestEnv(t)
	port, accepts := serveTLS(t, &tls.Config{}) // no certificate, so every handshake fails
	setPort(t, &tlsStatePort, port)

	got := runTLSConsumers(context.Background(), env)
	for _, id := range tlsConsumerIDs {
		assertHandshakeAnswer(t, got[id], "127.0.0.1:"+port, "remote error: tls: ")
	}
	if n := accepts.Load(); n != 1 {
		t.Errorf("the TLS consumers made %d connections, want 1", n)
	}
}

// TestHostTLS_CancelReturnsPromptly: cancelling the scan interrupts the
// shared handshake instead of waiting out the per-operation timeout, and
// every consumer reports it as inconclusive. The cancel waits for the
// ClientHello so that it lands mid-handshake on every platform: on Windows
// the DNS lookups that come first wait out their timeout, because Go
// ignores ICMP port-unreachable replies to UDP there.
func TestHostTLS_CancelReturnsPromptly(t *testing.T) {
	env := tlsTestEnv(t)
	env.Timeout = 5 * time.Second
	port, hello := helloTarpit(t, 1)
	setPort(t, &tlsStatePort, port)

	ctx, assertPrompt := cancelOnHello(t, hello)
	got := runTLSConsumers(ctx, env)
	assertPrompt()
	if len(got) != len(tlsConsumerIDs) {
		t.Errorf("got results %v, want exactly %v", got, tlsConsumerIDs)
	}
	for _, id := range tlsConsumerIDs {
		assertInconclusive(t, got[id], "context canceled")
	}
}

// helloTarpit accepts connections on 127.0.0.1 and never answers them;
// hello is closed once n of them have sent their first bytes, their
// ClientHellos.
func helloTarpit(t *testing.T, n int) (port string, hello <-chan struct{}) {
	t.Helper()
	ln := listenLoopback(t)
	arrived := make(chan struct{})
	var waiting atomic.Int64
	waiting.Store(int64(n))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := conn.Read(make([]byte, 1)); err == nil && waiting.Add(-1) == 0 {
					close(arrived)
				}
				_, _ = io.Copy(io.Discard, conn) // until the prober hangs up
			}()
		}
	}()
	return portOf(ln.Addr()), arrived
}

// cancelOnHello returns a context that is cancelled once hello is closed,
// so the cancel lands mid-handshake however long the dials take; a cancel
// during a dial reports "operation was canceled" instead. Call assertPrompt
// once the probe returns: it checks that the cancel happened and that the
// probe returned within two seconds of it.
func cancelOnHello(
	t *testing.T, hello <-chan struct{},
) (ctx context.Context, assertPrompt func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cancelled := make(chan time.Time, 1)
	go func() {
		select {
		case <-hello:
			cancelled <- time.Now()
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		t.Helper()
		select {
		case at := <-cancelled:
			if elapsed := time.Since(at); elapsed > 2*time.Second {
				t.Errorf("returned %v after the cancel, want promptly", elapsed)
			}
		default:
			t.Error("the probe returned before every ClientHello arrived")
		}
	}
}

// TestHostTLS_ProducerPanicked: when the check that ran the handshake
// panicked, the outcome is unknown, so every other consumer is inconclusive
// and points at the registry.panic result.
func TestHostTLS_ProducerPanicked(t *testing.T) {
	env := tlsTestEnv(t)
	env.CachePut(tlsStateKey("127.0.0.1"), "not a handshake") // what Shared yields as nil
	got := runTLSConsumers(context.Background(), env)
	for _, id := range tlsConsumerIDs {
		assertInconclusive(t, got[id], "TLS handshake with 127.0.0.1 did not complete in "+
			"another check; see its registry.panic result")
	}
}

// tlsConsumerIDs are the results runTLSConsumers returns for 127.0.0.1
// when the shared handshake fails.
var tlsConsumerIDs = []string{
	"web.tls.profile.127.0.0.1", "web.cert.chain", "web.ocsp.staple",
	"web.ocsp.responder", "web.crl.status", "web.ct.scts",
}

// runTLSConsumers runs every check that reads the apex's shared handshake
// and returns their results by ID.
func runTLSConsumers(ctx context.Context, env *probe.Env) map[string]report.Result {
	var all []report.Result
	all = append(all, runTLS(ctx, env)...)
	all = append(all, runCert(ctx, env)...)
	all = append(all, ocspCheck{}.Run(ctx, env)...)
	all = append(all, runCTSCTs(ctx, env))
	byID := make(map[string]report.Result, len(all))
	for _, r := range all {
		byID[r.ID] = r
	}
	return byID
}

// assertHandshakeAnswer checks r, a consumer's result after the target
// refused or broke off the handshake with addr: the profile and certificate
// checks FAIL with remediation, the others are INFO, and each quotes the
// handshake error naming detail.
func assertHandshakeAnswer(t *testing.T, r report.Result, addr, detail string) {
	t.Helper()
	status, remediation := report.Info, ""
	switch r.ID {
	case "web.tls.profile.127.0.0.1":
		status, remediation = report.Fail, tlsHandshakeRemediation("127.0.0.1")
	case "web.cert.chain":
		status, remediation = report.Fail, certFetchRemediation("127.0.0.1")
	}
	prefix := "TLS handshake with " + addr + " failed: "
	if r.Status != status || !strings.HasPrefix(r.Evidence, prefix) ||
		!strings.Contains(r.Evidence, detail) || r.Remediation != remediation {
		t.Errorf("%s = %s %q (remediation %q), want %s %q...%q (remediation %q)",
			r.ID, r.Status, r.Evidence, r.Remediation, status, prefix, detail, remediation)
	}
}

// tlsTestEnv is activeLoopbackEnv with a resolver that refuses every query,
// so candidateHosts finds no www host. It sets an environment variable, so
// callers must not call t.Parallel.
func tlsTestEnv(t *testing.T) *probe.Env {
	t.Helper()
	env := activeLoopbackEnv(t)
	env.DNS = probe.NewDNS("127.0.0.1:"+closedPort(t), time.Second)
	return env
}

// trustTestCA makes pki's issuer the only root hostTLS trusts for the rest
// of the test.
func trustTestCA(t *testing.T, pki *testPKI) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(pki.issuerCert)
	old := tlsRoots
	tlsRoots = pool
	t.Cleanup(func() { tlsRoots = old })
}

// loopbackLeaf returns a template for a server certificate valid for
// 127.0.0.1 and localhost from an hour ago for 90 days, which passes every
// web.cert.* check.
func loopbackLeaf() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(4040),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// intermediateCA returns a CA that root issued, for issuing leaves from.
func intermediateCA(t *testing.T, root *testPKI) *testPKI {
	t.Helper()
	cert, key := root.issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(5050),
		Subject:               pkix.Name{CommonName: "bedrock test intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	return &testPKI{issuerKey: key, issuerCert: cert}
}

// serverCert issues a leaf from tmpl and returns it as a server
// certificate presenting the leaf followed by extra, by default pki's
// issuer.
func serverCert(
	t *testing.T, pki *testPKI, tmpl *x509.Certificate, extra ...*x509.Certificate,
) tls.Certificate {
	t.Helper()
	leaf, key := pki.issue(t, tmpl)
	if len(extra) == 0 {
		extra = []*x509.Certificate{pki.issuerCert}
	}
	chain := [][]byte{leaf.Raw}
	for _, c := range extra {
		chain = append(chain, c.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
}

// serveTLS completes TLS handshakes with cfg on a 127.0.0.1 port and counts
// the connections it accepted.
func serveTLS(t *testing.T, cfg *tls.Config) (port string, accepts *atomic.Int32) {
	t.Helper()
	return serveConns(t, func(conn net.Conn) {
		srv := tls.Server(conn, cfg)
		_ = srv.Handshake()
		_ = srv.Close()
	})
}

// serveConns hands each connection it accepts on a 127.0.0.1 port to
// handle, which must close it, and counts the connections.
func serveConns(t *testing.T, handle func(net.Conn)) (port string, accepts *atomic.Int32) {
	t.Helper()
	ln := listenLoopback(t)
	accepts = new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			go handle(conn)
		}
	}()
	return portOf(ln.Addr()), accepts
}
