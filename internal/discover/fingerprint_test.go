package discover

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
)

// TestFingerprintHostsAt drives fingerprintHostsAt against an in-process TLS
// server and confirms it produces JA3S + JA4S INFO results for the host. The
// SafeDialContext blocks loopback by default; BEDROCK_ALLOW_PRIVATE_RESOLVER=1
// (the same hermetic-test knob the resolver uses) opens 127.0.0.1.
func TestFingerprintHostsAt(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")

	srv := httptest.NewTLSServer(http.HandlerFunc(noBody))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	env := &probe.Env{Timeout: 5 * time.Second}

	out := fingerprintHostsAt(context.Background(), env, []string{host}, port)
	if len(out) != 2 {
		t.Fatalf("expected 2 results (ja3s + ja4s), got %d: %+v", len(out), out)
	}

	wantIDs := []string{
		"subdomain.tls.fingerprint.ja3s." + host,
		"subdomain.tls.fingerprint.ja4s." + host,
	}
	for i, r := range out {
		if r.ID != wantIDs[i] {
			t.Errorf("result[%d] id = %q, want %q", i, r.ID, wantIDs[i])
		}
		if r.Status.String() != "INFO" {
			t.Errorf("result[%d] status = %v, want INFO", i, r.Status)
		}
		if r.Category != category {
			t.Errorf("result[%d] category = %q, want %q", i, r.Category, category)
		}
		if r.Evidence == "" {
			t.Errorf("result[%d] empty evidence", i)
		}
	}
	// Sanity: JA3S evidence carries a 32-char md5 hex; JA4S evidence carries
	// the FoxIO-format prefix "JA4S=t".
	if !strings.Contains(out[0].Evidence, "JA3S=") {
		t.Errorf("JA3S result evidence missing JA3S=: %q", out[0].Evidence)
	}
	if !strings.Contains(out[1].Evidence, "JA4S=t") {
		t.Errorf("JA4S result evidence missing JA4S=t: %q", out[1].Evidence)
	}
}

func TestFingerprintHostsEmptyInput(t *testing.T) {
	t.Parallel()
	got := fingerprintHosts(context.Background(),
		&probe.Env{Timeout: time.Second}, nil)
	if len(got) != 0 {
		t.Errorf("expected 0 results for empty input, got %d", len(got))
	}
}

func TestFingerprintHostsSilentOnDialFailure(t *testing.T) {
	t.Parallel()
	// 192.0.2.0/24 is RFC 5737 TEST-NET-1 — always unreachable, never
	// blocked by SafeDialContext. Short timeout keeps the test fast.
	got := fingerprintHosts(context.Background(),
		&probe.Env{Timeout: 100 * time.Millisecond},
		[]string{"192.0.2.1"})
	if len(got) != 0 {
		t.Errorf("expected silent on dial failure, got %d results: %+v", len(got), got)
	}
}

func TestFingerprintHostsRespectsContextCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := fingerprintHosts(ctx,
		&probe.Env{Timeout: time.Second},
		[]string{"192.0.2.1", "192.0.2.2"})
	if len(got) != 0 {
		t.Errorf("expected 0 results for cancelled ctx, got %d", len(got))
	}
}

func noBody(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func splitHostPort(t *testing.T, raw string) (string, string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split %q: %v", u.Host, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("port %q is not numeric: %v", port, err)
	}
	return strings.Trim(host, "[]"), port
}
