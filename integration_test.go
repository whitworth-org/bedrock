// integration_test.go is the top-level golden-file integration test for
// bedrock. It exercises the full check registry end-to-end against a
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
//   - Run the full registry and render the JSON report, then run bedrock
//     itself, in process, with stdout on a terminal, and diff each output
//     against its golden file: testdata/golden/<name>.json and
//     testdata/golden/<name>.human.txt.
//
// Run with `go test -update` to refresh the golden files after intentional
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

package main

import (
	"context"
	"flag"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// updateGolden, when set, rewrites the golden file from the rendered
// output. Use sparingly — golden updates should be intentional.
var updateGolden = flag.Bool("update", false, "rewrite golden files instead of comparing")

// fakeDNSHandler answers every query with NXDOMAIN. Equivalent to a domain
// that has published nothing. It counts the queries it answers, so a test
// can tell whether a scan ran, and runs onQuery, when set, before answering.
type fakeDNSHandler struct {
	queries *atomic.Int64
	onQuery func()
}

func (h fakeDNSHandler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	h.queries.Add(1)
	if h.onQuery != nil {
		h.onQuery()
	}
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = mdns.RcodeNameError // NXDOMAIN
	_ = w.WriteMsg(resp)
}

// startFakeDNS binds 127.0.0.1:0 UDP and runs an NXDOMAIN-only server on
// it that calls onQuery, if not nil, before each answer. Returns the
// host:port spec, the count of queries answered so far, and a shutdown func.
func startFakeDNS(t *testing.T, onQuery func()) (string, *atomic.Int64, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	queries := new(atomic.Int64)
	handler := fakeDNSHandler{queries: queries, onQuery: onQuery}
	srv := &mdns.Server{PacketConn: pc, Handler: handler}
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
	return pc.LocalAddr().String(), queries, func() { _ = srv.Shutdown() }
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
// fake NXDOMAIN-only resolver and --no-active, then compares both renderings
// byte for byte with their goldens: the JSON document with
// testdata/golden/empty.json, and the terminal report that run writes for
// the same scan, without colour or elapsed time, with
// testdata/golden/empty.human.txt.
//
// This is the canonical regression guard for renderer + check wiring: any
// new check that's registered will show up in the golden diff and force a
// deliberate `-update`.
func TestIntegrationEmpty(t *testing.T) {
	// Hermetic test binds a UDP resolver on 127.0.0.1 — bypass the
	// production SSRF denylist that rejects loopback resolvers.
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")

	resolverSpec, _, shutdown := startFakeDNS(t, nil)
	defer shutdown()

	target := "test.invalid"
	env := probe.NewEnv(target, 2*time.Second, false /* active */, resolverSpec)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := registry.Run(ctx, env, nil)
	if len(results) == 0 {
		t.Fatal("registry returned zero results — checks may not have registered")
	}

	rep := report.Report{Target: target, Results: results, Summary: report.Summarize(results)}

	var js strings.Builder
	if err := report.RenderJSON(&js, rep); err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	checkGolden(t, "empty.json", normalizeOutput(js.String(), resolverSpec))

	code, human, _ := runOn(t, terminal, pipe, noColor, scanArgs(resolverSpec)...)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 for a report with FAILs", code)
	}
	checkGolden(t, "empty.human.txt", normalizeOutput(human, resolverSpec))
}

// checkGolden compares got with testdata/golden/<name>, or rewrites that
// file when -update is set.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote golden %s (%d bytes)", path, len(got))
		return
	}
	want := readGolden(t, name)
	if got != want {
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(want, "\n")
		t.Errorf("golden mismatch at %s\n  first divergence: %s\n  got=%d lines, want=%d lines\n"+
			"  rerun with `go test -update` to refresh after intentional changes",
			path, firstDivergence(gotLines, wantLines), len(gotLines), len(wantLines))
	}
}

// readGolden returns the contents of testdata/golden/<name>.
func readGolden(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run `go test -update` to seed)", path, err)
	}
	return string(want)
}

func firstDivergence(got, want []string) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			return "line " + strconv.Itoa(i+1) + "\n    got:  " + got[i] + "\n    want: " + want[i]
		}
	}
	if len(got) != len(want) {
		return "different line counts (got=" + strconv.Itoa(len(got)) +
			", want=" + strconv.Itoa(len(want)) + ")"
	}
	return "(none)"
}
