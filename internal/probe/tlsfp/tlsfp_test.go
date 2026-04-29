package tlsfp_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe/tlsfp"
)

// TestCaptureAgainstHTTPTestServer drives a real TLS handshake against an
// in-process httptest TLS server, captures the wire bytes, and verifies that
// JA3S and JA4S come out non-empty and well-formed.
func TestCaptureAgainstHTTPTestServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv URL: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}

	// Vanilla dialer — httptest.NewTLSServer listens on 127.0.0.1, which
	// SafeDialContext (correctly) blocks. The check wiring uses the safe
	// dialer in production; this test exercises the parser/compute path.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}

	res, err := tlsfp.Capture(context.Background(), host, port, dial, 5*time.Second)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}

	if res.NegotiatedTLS == 0 {
		t.Error("NegotiatedTLS is zero")
	}
	if res.Cipher == 0 {
		t.Error("Cipher is zero")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(res.JA3S) {
		t.Errorf("JA3S %q is not 32 hex chars", res.JA3S)
	}
	if !regexp.MustCompile(`^t[0-9a-z]{2}\d{2}[0-9a-z]{2}_[0-9a-f]{4}_[0-9a-f]{12}$`).MatchString(res.JA4S) {
		t.Errorf("JA4S %q does not match expected shape", res.JA4S)
	}
	// httptest's default cert offers TLS 1.3 in modern Go; ensure we got
	// something at least 1.2.
	if res.NegotiatedTLS < 0x0303 {
		t.Errorf("NegotiatedTLS = 0x%04x, expected ≥ 0x0303", res.NegotiatedTLS)
	}
}

func TestCaptureNilDialer(t *testing.T) {
	t.Parallel()
	_, err := tlsfp.Capture(context.Background(), "example.com", "443", nil, time.Second)
	if err == nil {
		t.Fatal("expected error for nil dialer")
	}
}

func TestCaptureDialFailure(t *testing.T) {
	t.Parallel()
	failingDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, net.ErrClosed
	}
	_, err := tlsfp.Capture(context.Background(), "example.com", "443", failingDial, time.Second)
	if err == nil {
		t.Fatal("expected dial error to surface")
	}
}
