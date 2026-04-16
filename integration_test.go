// integration_test.go is the top-level golden-file integration test for
// granite-scan. It exercises the full check registry end-to-end against a
// fake resolver, with no outbound network required.
//
// Approach:
//
//   - Spin up an in-process UDP DNS server bound to 127.0.0.1 on a random
//     port. The server returns NXDOMAIN for every query, modelling a
//     domain that has published nothing at all. (This is the canonical
//     "empty domain" fixture; other fixtures can register canned RRs.)
//   - Build a probe.Env with --no-active so HTTP / SMTP / VMC fetches are
//     skipped (they would otherwise need their own fakes — out of scope
//     for this golden-empty fixture).
//   - Run the full registry, render the report as text, and diff against
//     testdata/golden/<name>.txt.
//
// Run with `go test -update` to refresh the golden file after intentional
// output-format changes.
//
// Why this path (vs. a smoke test that shells out to `go run .`):
//
//   - Determinism: a real DNS server with controlled answers gives
//     reproducible bytes. A black-hole resolver yields timeout error
//     strings whose wording depends on the OS.
//   - Speed: <1s in practice; no compile step.
//   - In-process: no PATH dependence, no goroutine leak from a child
//     process, full access to the same packages a unit test sees.
//
// Why an UDP server (vs. fake DoH): the production code parses
// "host:port" specs into UDP upstreams via probe.NewEnv with no
// modification needed. A DoH fake would require either a self-signed
// cert the production DoH client can't trust, or a production-code
// accommodation we'd rather avoid.

package main_test

import (
	"context"
	"flag"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"

	// Side-effect imports register checks with the global registry. Mirror
	// main.go so the integration test sees the same check set.
	_ "granite-scan/internal/checks/bimi"
	_ "granite-scan/internal/checks/dns"
	_ "granite-scan/internal/checks/dnssec"
	_ "granite-scan/internal/checks/email"
	_ "granite-scan/internal/checks/web"
	_ "granite-scan/internal/discover"
)

// updateGolden, when set, rewrites the golden file from the rendered
// output. Use sparingly — golden updates should be intentional.
var updateGolden = flag.Bool("update", false, "rewrite golden files instead of comparing")

// fakeDNSHandler answers every query with NXDOMAIN. Equivalent to a domain
// that has published nothing.
type fakeDNSHandler struct{}

func (fakeDNSHandler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = mdns.RcodeNameError // NXDOMAIN
	_ = w.WriteMsg(resp)
}

// startFakeDNS binds 127.0.0.1:0 UDP and runs an NXDOMAIN-only server on
// it. Returns the host:port spec and a shutdown func.
func startFakeDNS(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: fakeDNSHandler{}}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		_ = srv.Shutdown()
		_ = pc.Close()
		t.Fatal("fake DNS server did not start within 2s")
	}
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// normalizeOutput strips bits of rendered output that vary across runs
// (timestamps, the random NXDOMAIN test resolver port, etc.) so the golden
// comparison stays stable. Add patterns here when new sources of churn
// surface — but always prefer keeping the rendered bytes deterministic.
func normalizeOutput(s, resolverSpec string) string {
	// The fake resolver listens on a random port; rendered evidence may
	// embed it (e.g. "lookup error: dial 127.0.0.1:54321: connection
	// refused"). Mask any occurrence of the port we just allocated.
	if _, port, err := net.SplitHostPort(resolverSpec); err == nil {
		s = strings.ReplaceAll(s, ":"+port, ":<resolver-port>")
	}
	// RFC3339 timestamps (cert expiry etc.) — none should appear under
	// --no-active, but defensively scrub any that do.
	tsRe := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
	s = tsRe.ReplaceAllString(s, "<ts>")
	return s
}

// TestIntegrationEmpty runs the full registry against test.invalid with a
// fake NXDOMAIN-only resolver and --no-active. The rendered text output is
// compared byte-for-byte against testdata/golden/empty.txt.
//
// This is the canonical regression guard for renderer + check wiring: any
// new check that's registered will show up in the golden diff and force a
// deliberate `-update`.
func TestIntegrationEmpty(t *testing.T) {
	resolverSpec, shutdown := startFakeDNS(t)
	defer shutdown()

	target := "test.invalid"
	env := probe.NewEnv(target, 2*time.Second, false /* active */, resolverSpec)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := registry.Run(ctx, env)
	if len(results) == 0 {
		t.Fatal("registry returned zero results — checks may not have registered")
	}

	rep := report.Report{Target: target, Results: results}

	var sb strings.Builder
	if err := report.Render(&sb, rep, report.FormatText, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := normalizeOutput(sb.String(), resolverSpec)

	goldenPath := filepath.Join("testdata", "golden", "empty.txt")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote golden %s (%d bytes)", goldenPath, len(got))
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run `go test -update` to seed)", goldenPath, err)
	}
	if got != string(want) {
		// Show a small diff hint: first divergent line + counts.
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(string(want), "\n")
		divergence := firstDivergence(gotLines, wantLines)
		t.Fatalf("golden mismatch at %s\n  first divergence: %s\n  got=%d lines, want=%d lines\n  rerun with `go test -update` to refresh after intentional changes",
			goldenPath, divergence, len(gotLines), len(wantLines))
	}
}

func firstDivergence(got, want []string) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			return "line " + itoa(i+1) + "\n    got:  " + got[i] + "\n    want: " + want[i]
		}
	}
	if len(got) != len(want) {
		return "different line counts (got=" + itoa(len(got)) + ", want=" + itoa(len(want)) + ")"
	}
	return "(none)"
}

// itoa avoids importing strconv just for one int→string conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
