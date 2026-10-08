package web

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestTLSFingerprint_OneCapturePerHost: the JA3S and JA4S checks, released
// together, share one ServerHello capture per host.
func TestTLSFingerprint_OneCapturePerHost(t *testing.T) {
	env := tlsTestEnv(t)
	port, accepts := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert(t, newTestPKI(t), loopbackLeaf())},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			time.Sleep(100 * time.Millisecond) // both checks ask before this capture ends
			return nil, nil
		},
	})
	setPort(t, &fingerprintPort, port)

	var ja3s, ja4s []report.Result
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { <-start; ja3s = runTLSFingerprintJA3S(context.Background(), env) })
	wg.Go(func() { <-start; ja4s = runTLSFingerprintJA4S(context.Background(), env) })
	close(start)
	wg.Wait()

	if n := accepts.Load(); n != 1 {
		t.Errorf("JA3S and JA4S made %d connections to 127.0.0.1, want 1", n)
	}
	for _, out := range [][]report.Result{ja3s, ja4s} {
		if len(out) != 1 || out[0].Status != report.Info ||
			!strings.Contains(out[0].Evidence, "cipher=0x1301") {
			t.Errorf("fingerprint = %+v, want one INFO result for the TLS 1.3 capture", out)
		}
	}
}

// TestTLSFingerprint_CaptureFailures: a capture that could not complete, or
// whose ServerHello bedrock could not parse, says nothing about the server
// and is inconclusive; a refused connection is an answer and stays a
// FAIL. Both fingerprints report the same failure.
func TestTLSFingerprint_CaptureFailures(t *testing.T) {
	tarpit := func(t *testing.T) string { addr, _ := tarpitListener(t); return portOf(addr) }
	const short = 200 * time.Millisecond
	cases := []struct {
		name, override string
		port           func(t *testing.T) string
		timeout        time.Duration
		status         report.Status
		detail         string
	}{
		{"blocked by the SSRF denylist", "", tarpit, short, wantInconclusive,
			"ssrf dial: refusing 127.0.0.1"},
		{"timed out", "1", tarpit, short, wantInconclusive, "tlsfp: handshake 127.0.0.1:"},
		{"reset after accept", "1", func(t *testing.T) string { return portOf(resetListener(t)) },
			short, wantInconclusive, resetText()},
		{"ServerHello split across records", "1", splitServerHelloPort, short, wantInconclusive,
			"exceeds record body"},
		{"connection refused", "1", closedPort, refusedDialTimeout, report.Fail, "refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tlsTestEnv(t)
			env.Timeout = tc.timeout
			t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", tc.override)
			setPort(t, &fingerprintPort, tc.port(t))

			for _, kind := range []string{"ja3s", "ja4s"} {
				out := runTLSFingerprint(context.Background(), env, kind)
				if len(out) != 1 {
					t.Fatalf("%s: got %d results, want 1: %+v", kind, len(out), out)
				}
				assertCaptureFailure(t, out[0], tc.status, tc.detail)
			}
		})
	}
}

// TestTLSFingerprint_FailedCaptureIsShared: a failed capture is not
// repeated for the second fingerprint.
func TestTLSFingerprint_FailedCaptureIsShared(t *testing.T) {
	env := tlsTestEnv(t)
	env.Timeout = 200 * time.Millisecond
	addr, accepted := tarpitListener(t)
	setPort(t, &fingerprintPort, portOf(addr))

	runTLSFingerprintJA3S(context.Background(), env)
	runTLSFingerprintJA4S(context.Background(), env)
	if n := accepted.Load(); n != 1 {
		t.Errorf("JA3S and JA4S made %d connections to the unresponsive server, want 1", n)
	}
}

// TestTLSFingerprint_ProducerPanicked: when the check that captured the
// ServerHello panicked, the other is inconclusive and points at the
// registry.panic result.
func TestTLSFingerprint_ProducerPanicked(t *testing.T) {
	env := tlsTestEnv(t)
	env.CachePut(probe.CacheKeyTLSFingerprint+":127.0.0.1", "not a capture")
	out := runTLSFingerprintJA4S(context.Background(), env)
	if len(out) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(out), out)
	}
	assertInconclusive(t, out[0], "ServerHello capture from 127.0.0.1 did not complete in "+
		"another check; see its registry.panic result")
}

// assertCaptureFailure checks r, a fingerprint result for a failed capture:
// inconclusive naming detail, or a FAIL quoting it.
func assertCaptureFailure(t *testing.T, r report.Result, status report.Status, detail string) {
	t.Helper()
	if status == wantInconclusive {
		assertInconclusive(t, r, detail)
		return
	}
	if r.Status != status || !strings.HasPrefix(r.Evidence, "capture failed: tlsfp: dial ") ||
		!strings.Contains(r.Evidence, detail) {
		t.Errorf("%s = %s %q, want %s quoting %q", r.ID, r.Status, r.Evidence, status, detail)
	}
}

// splitServerHelloPort returns the port of a relay to a TLS server that
// delivers the server's first record, its ServerHello, as two records. That
// is valid TLS, which the handshake reassembles, but the fingerprint parser
// reads only the first record.
func splitServerHelloPort(t *testing.T) string {
	t.Helper()
	backend, _ := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert(t, newTestPKI(t), loopbackLeaf())},
	})
	port, _ := serveConns(t, func(client net.Conn) {
		defer func() { _ = client.Close() }()
		server, err := net.Dial("tcp", "127.0.0.1:"+backend)
		if err != nil {
			return
		}
		defer func() { _ = server.Close() }()
		go func() { _, _ = io.Copy(server, client) }()
		if splitFirstRecord(client, server) == nil {
			_, _ = io.Copy(client, server)
		}
	})
	return port
}

// splitFirstRecord reads one TLS record from src and writes its body to dst
// as two records.
func splitFirstRecord(dst io.Writer, src io.Reader) error {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(src, hdr); err != nil {
		return err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(src, body); err != nil {
		return err
	}
	half := len(body) / 2
	for _, part := range [][]byte{body[:half], body[half:]} {
		rec := binary.BigEndian.AppendUint16(slices.Clone(hdr[:3]), uint16(len(part)))
		if _, err := dst.Write(append(rec, part...)); err != nil {
			return err
		}
	}
	return nil
}
