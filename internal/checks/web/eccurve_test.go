package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestBuildCurveResult_Pass verifies that any modern-baseline curve being
// accepted yields a PASS regardless of which non-modern curves succeed.
func TestBuildCurveResult_Pass(t *testing.T) {
	cases := []map[tls.CurveID]bool{
		// X25519 alone is sufficient for modern baseline.
		{tls.X25519: true, tls.CurveP256: false, tls.CurveP384: false, tls.CurveP521: false},
		// P-256 alone is sufficient.
		{tls.X25519: false, tls.CurveP256: true, tls.CurveP384: false, tls.CurveP521: false},
		// Modern + non-modern still PASS.
		{tls.X25519: true, tls.CurveP256: true, tls.CurveP384: true, tls.CurveP521: true},
	}
	for i, m := range cases {
		got := buildCurveResult("example.com", m, nil)
		if got.Status != report.Pass {
			t.Errorf("case %d: status = %s, want PASS (evidence=%q)", i, got.Status, got.Evidence)
		}
		if got.Remediation != "" {
			t.Errorf("case %d: remediation set on PASS: %q", i, got.Remediation)
		}
	}
}

// TestBuildCurveResult_Warn verifies that only-non-modern curves yields WARN
// with a remediation hint pointing at modern groups.
func TestBuildCurveResult_Warn(t *testing.T) {
	cases := []map[tls.CurveID]bool{
		{tls.X25519: false, tls.CurveP256: false, tls.CurveP384: true, tls.CurveP521: false},
		{tls.X25519: false, tls.CurveP256: false, tls.CurveP384: false, tls.CurveP521: true},
		{tls.X25519: false, tls.CurveP256: false, tls.CurveP384: true, tls.CurveP521: true},
	}
	for i, m := range cases {
		got := buildCurveResult("example.com", m, nil)
		if got.Status != report.Warn {
			t.Errorf("case %d: status = %s, want WARN (evidence=%q)", i, got.Status, got.Evidence)
		}
		if got.Remediation == "" {
			t.Errorf("case %d: remediation empty on WARN", i)
		}
		if !strings.Contains(strings.ToLower(got.Remediation), "x25519") {
			t.Errorf("case %d: remediation should mention X25519, got %q", i, got.Remediation)
		}
	}
}

// TestBuildCurveResult_Fail verifies that no curves accepted yields FAIL
// with a remediation explaining ECDHE is required.
func TestBuildCurveResult_Fail(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.X25519:    false,
		tls.CurveP256: false,
		tls.CurveP384: false,
		tls.CurveP521: false,
	}
	got := buildCurveResult("example.com", m, nil)
	if got.Status != report.Fail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}
	if got.Remediation == "" {
		t.Fatal("remediation empty on FAIL")
	}
	if !strings.Contains(strings.ToLower(got.Remediation), "ecdhe") {
		t.Errorf("remediation should mention ECDHE, got %q", got.Remediation)
	}
}

// TestBuildCurveResult_Evidence checks the human-readable evidence string
// reflects accepted and rejected curves in canonical probe order.
func TestBuildCurveResult_Evidence(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.X25519:    true,
		tls.CurveP256: true,
		tls.CurveP384: false,
		tls.CurveP521: false,
	}
	got := buildCurveResult("example.com", m, nil)
	// Canonical order: X25519, P-256, P-384, P-521.
	wantSubstrings := []string{
		"accepted: X25519, P-256",
		"rejected: P-384, P-521",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(got.Evidence, s) {
			t.Errorf("evidence %q missing %q", got.Evidence, s)
		}
	}
}

// TestBuildCurveResult_EvidenceNoneAccepted verifies the (none) sentinel
// is used when no curves are accepted.
func TestBuildCurveResult_EvidenceNoneAccepted(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.X25519:    false,
		tls.CurveP256: false,
		tls.CurveP384: false,
		tls.CurveP521: false,
	}
	got := buildCurveResult("example.com", m, nil)
	if !strings.Contains(got.Evidence, "accepted: (none)") {
		t.Errorf("evidence should report (none), got %q", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "rejected: X25519, P-256, P-384, P-521") {
		t.Errorf("evidence should list every probed curve as rejected, got %q", got.Evidence)
	}
}

// TestHasModernBaseline covers each candidate independently. The baseline
// is X25519 OR P-256 — P-384 and P-521 alone do not satisfy modern.
func TestHasModernBaseline(t *testing.T) {
	cases := []struct {
		name   string
		in     map[tls.CurveID]bool
		expect bool
	}{
		{"x25519 only", map[tls.CurveID]bool{tls.X25519: true}, true},
		{"p256 only", map[tls.CurveID]bool{tls.CurveP256: true}, true},
		{"p384 only", map[tls.CurveID]bool{tls.CurveP384: true}, false},
		{"p521 only", map[tls.CurveID]bool{tls.CurveP521: true}, false},
		{"none", map[tls.CurveID]bool{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasModernBaseline(tc.in); got != tc.expect {
				t.Errorf("hasModernBaseline(%v) = %v, want %v", tc.in, got, tc.expect)
			}
		})
	}
}

// TestPartitionCurves verifies canonical ordering of the partitioned slices
// regardless of map iteration order (Go randomizes map iteration).
func TestPartitionCurves(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.CurveP521: true,
		tls.X25519:    false,
		tls.CurveP384: true,
		tls.CurveP256: false,
	}
	acc, rej, unprobed := partitionCurves(m)
	wantAcc := []string{"P-384", "P-521"} // canonical order: X25519, P-256, P-384, P-521
	wantRej := []string{"X25519", "P-256"}
	if !equalStrings(acc, wantAcc) {
		t.Errorf("accepted = %v, want %v", acc, wantAcc)
	}
	if !equalStrings(rej, wantRej) {
		t.Errorf("rejected = %v, want %v", rej, wantRej)
	}
	if len(unprobed) != 0 {
		t.Errorf("unprobed = %v, want none", unprobed)
	}
}

// curveNameByID returns the name probeCurves gives id, so tests need not
// mirror the probeCurves list.
func curveNameByID(id tls.CurveID) string {
	for _, c := range probeCurves {
		if c.id == id {
			return c.name
		}
	}
	return fmt.Sprintf("curve(0x%04x)", uint16(id))
}

func TestCurveNameByID(t *testing.T) {
	cases := map[tls.CurveID]string{
		tls.X25519:    "X25519",
		tls.CurveP256: "P-256",
		tls.CurveP384: "P-384",
		tls.CurveP521: "P-521",
	}
	for id, want := range cases {
		if got := curveNameByID(id); got != want {
			t.Errorf("curveNameByID(%v) = %q, want %q", id, got, want)
		}
	}
	// Unknown curve falls through to the hex sentinel.
	if got := curveNameByID(tls.CurveID(0xBEEF)); !strings.Contains(got, "0xbeef") {
		t.Errorf("unknown curve fallback = %q, want contains 0xbeef", got)
	}
}

// TestECCurveCheck_NoActive ensures the --no-active short-circuit fires
// without any network I/O.
func TestECCurveCheck_NoActive(t *testing.T) {
	env := probe.NewEnv("example.com", time.Second, false /* active */, "")
	results := runECCurves(context.Background(), env)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != report.NotApplicable {
		t.Errorf("status = %s, want N/A", r.Status)
	}
	if !strings.Contains(r.Evidence, "no-active") {
		t.Errorf("evidence should mention no-active, got %q", r.Evidence)
	}
}

// TestBuildCurveResult_ProbeErrors: a curve whose probe could not complete
// has no verdict. A modern curve that answered still passes; otherwise the
// result is inconclusive, since the unprobed curve might be accepted.
func TestBuildCurveResult_ProbeErrors(t *testing.T) {
	probeErr := errors.New("P-256 handshake: i/o timeout")
	pass := buildCurveResult("example.com", map[tls.CurveID]bool{tls.X25519: true}, probeErr)
	if pass.Status != report.Pass ||
		pass.Evidence != "accepted: X25519; not determined: P-256, P-384, P-521" {
		t.Errorf("modern curve accepted = %s %q, want PASS listing the unprobed curves",
			pass.Status, pass.Evidence)
	}
	unknown := buildCurveResult("example.com",
		map[tls.CurveID]bool{tls.X25519: false, tls.CurveP384: true}, probeErr)
	assertInconclusive(t, unknown, "P-256 handshake: i/o timeout")
}

// TestECCurves_ProbeOutcomes runs the curve check against loopback servers.
// Certificates are web.cert's business, so a self-signed server still gets
// a curve verdict; a reset or a refused SSRF dial leaves the curves
// undetermined; a refused connection keeps the rejects-every-curve FAIL.
func TestECCurves_ProbeOutcomes(t *testing.T) {
	t.Run("self-signed server", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		srv := startTLSServer(t, http.NotFoundHandler(), &tls.Config{
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}, false)
		setPort(t, &ecCurvePort, portOf(srv.Listener.Addr()))
		r := runECCurves(context.Background(), env)[0]
		if r.Status != report.Pass ||
			r.Evidence != "accepted: X25519, P-256; rejected: P-384, P-521" {
			t.Errorf("got %s %q, want PASS with P-384 and P-521 rejected", r.Status, r.Evidence)
		}
	})
	t.Run("reset after accept", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		setPort(t, &ecCurvePort, portOf(resetListener(t)))
		assertInconclusive(t, runECCurves(context.Background(), env)[0], resetText())
	})
	t.Run("refused port", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		env.Timeout = refusedDialTimeout
		setPort(t, &ecCurvePort, closedPort(t))
		r := runECCurves(context.Background(), env)[0]
		if r.Status != report.Fail ||
			r.Evidence != "accepted: (none); rejected: X25519, P-256, P-384, P-521" {
			t.Errorf("got %s %q, want FAIL rejecting every curve", r.Status, r.Evidence)
		}
	})
	t.Run("loopback without override", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
		addr, accepted := tarpitListener(t)
		setPort(t, &ecCurvePort, portOf(addr))
		assertInconclusive(t, runECCurves(context.Background(), env)[0],
			"ssrf dial: refusing 127.0.0.1")
		if n := accepted.Load(); n != 0 {
			t.Errorf("the denylist let %d connections through", n)
		}
	})
}

// TestECCurves_CancelReturnsPromptly: cancelling the scan interrupts
// handshakes in flight instead of waiting out the per-operation timeout.
// The cancel waits for every curve's ClientHello, since the evidence names
// the first curve's error.
func TestECCurves_CancelReturnsPromptly(t *testing.T) {
	env := activeLoopbackEnv(t)
	env.Timeout = 5 * time.Second
	port, hello := helloTarpit(t, len(probeCurves))
	setPort(t, &ecCurvePort, port)

	ctx, assertPrompt := cancelOnHello(t, hello)
	r := runECCurves(ctx, env)[0]
	assertPrompt()
	assertInconclusive(t, r, "context canceled")
}

// wantInconclusive is the status checkutil.Inconclusive assigns.
var wantInconclusive = checkutil.Inconclusive(report.Result{}, errors.New("probe")).Status

// assertInconclusive fails unless r is a checkutil.Inconclusive result whose
// evidence names detail.
func assertInconclusive(t *testing.T, r report.Result, detail string) {
	t.Helper()
	if r.Status != wantInconclusive || !strings.HasPrefix(r.Evidence, "could not determine: ") ||
		!strings.Contains(r.Evidence, detail) || r.Remediation != "" {
		t.Errorf("%s = %s %q (remediation %q), want inconclusive naming %q",
			r.ID, r.Status, r.Evidence, r.Remediation, detail)
	}
}

// activeLoopbackEnv is newLoopbackEnv aimed at 127.0.0.1 with active
// probing on. It sets an environment variable, so callers must not call
// t.Parallel.
func activeLoopbackEnv(t *testing.T) *probe.Env {
	t.Helper()
	env := newLoopbackEnv(t)
	env.Target, env.Active = "127.0.0.1", true
	return env
}

// setPort sets a probe's port variable for the rest of the test.
func setPort(t *testing.T, seam *string, port string) {
	t.Helper()
	old := *seam
	*seam = port
	t.Cleanup(func() { *seam = old })
}

func portOf(addr net.Addr) string { return strconv.Itoa(addr.(*net.TCPAddr).Port) }

// refusedDialTimeout is the per-operation timeout for probes of a closed
// loopback port: Windows takes about two seconds to report the refusal.
const refusedDialTimeout = 10 * time.Second

// resetText is the text of this platform's error for a connection the peer
// reset: Windows says "An existing connection was forcibly closed by the
// remote host".
func resetText() string {
	if runtime.GOOS == "windows" {
		return "forcibly closed"
	}
	return "connection reset"
}

// closedPort returns a loopback port that was just released, so a dial to
// it is refused.
func closedPort(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(closedLoopbackURL(t, "/"))
	if err != nil {
		t.Fatalf("parse closed loopback URL: %v", err)
	}
	return u.Port()
}

// startTLSServer starts an HTTPS server for h on 127.0.0.1 with httptest's
// self-signed certificate, cfg's other settings, h2 offered via ALPN when
// h2 is true, and handshake errors unlogged.
func startTLSServer(t *testing.T, h http.Handler, cfg *tls.Config, h2 bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = cfg
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// tarpitListener accepts connections on 127.0.0.1 and never answers, so a
// probe of it ends only by timeout or cancellation. accepted counts the
// connections it took.
func tarpitListener(t *testing.T) (addr net.Addr, accepted *atomic.Int32) {
	t.Helper()
	ln := listenLoopback(t)
	accepted = new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				_, _ = io.Copy(io.Discard, conn) // until the prober hangs up
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr(), accepted
}

// resetListener accepts connections on 127.0.0.1, reads the client's first
// flight and resets the connection.
func resetListener(t *testing.T) net.Addr {
	t.Helper()
	ln := listenLoopback(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = conn.Read(make([]byte, 4096))
				_ = conn.(*net.TCPConn).SetLinger(0) // Close now sends RST
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr()
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// equalStrings is a tiny helper to keep test diagnostics readable.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
