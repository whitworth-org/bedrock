package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// axfrTestTimeout is the per-operation timeout of these tests, so a probe's
// whole budget is axfrBudget times it.
const axfrTestTimeout = 300 * time.Millisecond

const (
	testSOA = "example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. " +
		"1 7200 3600 1209600 3600"
	testA = "www.example.test. 300 IN A 192.0.2.1"
)

// TestAXFR_Outcomes grades one nameserver's answer. Any record beyond the
// SOA fails, even when the answer is otherwise malformed or ends early; a
// DNS-level refusal, a closed connection and an SOA-only answer pass, the
// last even when the server then goes quiet; a probe that got no
// answer is inconclusive.
func TestAXFR_Outcomes(t *testing.T) {
	soa, a := mustRR(t, testSOA), mustRR(t, testA)
	cases := []struct {
		name     string
		serve    func(*miekg.Conn, *miekg.Msg)
		status   report.Status
		title    string
		evidence string
	}{
		{"REFUSED", answer(miekg.RcodeRefused), report.Pass,
			"AXFR refused at ", "no RRs returned; dns: bad xfr rcode: 5"},
		{"NOTAUTH", answer(miekg.RcodeNotAuth), report.Pass,
			"AXFR refused at ", "no RRs returned; dns: bad xfr rcode: 9"},
		{"NOERROR without records", answer(miekg.RcodeSuccess), report.Pass,
			"AXFR refused at ", "no RRs returned; dns: no SOA"},
		{"closed without answering", func(*miekg.Conn, *miekg.Msg) {}, report.Pass,
			"AXFR refused at ", "no RRs returned; EOF"},
		{"SOA only", answer(miekg.RcodeSuccess, []miekg.RR{soa}), report.Pass,
			"AXFR returned only the SOA at ", "returned only the SOA record (1 RR(s))"},
		{"SOA then silence", stallAfter([]miekg.RR{soa}), report.Pass,
			"AXFR returned only the SOA at ", "returned only the SOA record (1 RR(s))"},
		{"full zone", answer(miekg.RcodeSuccess, []miekg.RR{soa, a}, []miekg.RR{a, soa}),
			report.Fail, "AXFR allowed at ", "transferred 4 RRs from 127.0.0.1:"},
		{"data before any SOA", answer(miekg.RcodeSuccess, []miekg.RR{a, a, a}),
			report.Fail, "AXFR allowed at ", "received 3 RR(s) from 127.0.0.1:"},
		{"REFUSED carrying data", answer(miekg.RcodeRefused, []miekg.RR{a, a, a}),
			report.Fail, "AXFR allowed at ", "received 3 RR(s) from 127.0.0.1:"},
		{"data then silence", stallAfter([]miekg.RR{soa, a}), report.Fail,
			"AXFR allowed at ", "received 2 RR(s) from 127.0.0.1:"},
		{"silent server", stallAfter(nil), wantInconclusive,
			"AXFR probe — ", "could not determine: AXFR from 127.0.0.1:"},
		{"reset after the query", resetAfterQuery, wantInconclusive,
			"AXFR probe — ", resetText()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, env := axfrEnv(t, "ns1.example.test.")
			startAXFRServer(t, tc.serve)
			r := runOneAXFR(t, env)
			if r.ID != "dns.axfr.ns1.example.test" || r.Status != tc.status ||
				!strings.HasPrefix(r.Title, tc.title+"ns1.example.test") ||
				!strings.Contains(r.Evidence, tc.evidence) {
				t.Errorf("got %s %s %q %q, want %s %q... with evidence containing %q",
					r.ID, r.Status, r.Title, r.Evidence, tc.status, tc.title, tc.evidence)
			}
			wantRemediation := tc.status == report.Fail
			if (r.Remediation != "") != wantRemediation {
				t.Errorf("remediation %q, want one only on FAIL", r.Remediation)
			}
			if strings.Contains(r.Evidence, "->") {
				t.Errorf("evidence %q names the local socket address", r.Evidence)
			}
		})
	}
}

// TestAXFR_TrickleEndsAtBudget: a server that answers with the SOA and then
// sends an empty message more often than the read timeout keeps miekg's
// reader alive forever; the per-nameserver budget must end the probe, and a
// probe cut short with only the SOA is inconclusive.
func TestAXFR_TrickleEndsAtBudget(t *testing.T) {
	_, env := axfrEnv(t, "ns1.example.test.")
	startAXFRServer(t, trickle(mustRR(t, testSOA), 50*time.Millisecond))
	baseline := runtime.NumGoroutine()

	start := time.Now()
	r := runOneAXFR(t, env)
	if elapsed := time.Since(start); elapsed > 3*axfrBudget*axfrTestTimeout {
		t.Errorf("probe took %v, want it ended near its %v budget", elapsed,
			axfrBudget*axfrTestTimeout)
	}
	want := fmt.Sprintf("did not finish within %v", axfrBudget*axfrTestTimeout)
	if r.Status != wantInconclusive || !strings.Contains(r.Evidence, want) {
		t.Errorf("got %s %q, want inconclusive naming %q", r.Status, r.Evidence, want)
	}
	assertGoroutinesReturn(t, baseline)
}

// TestAXFR_CapStopsTransferAndReleasesReader: a server streaming records
// without end fails at the record cap with remediation, and stopping early
// leaves no goroutine behind: miekg's reader blocks on an unbuffered send,
// so the probe must keep receiving until the reader exits.
func TestAXFR_CapStopsTransferAndReleasesReader(t *testing.T) {
	_, env := axfrEnv(t, "ns1.example.test.")
	startAXFRServer(t, flood(mustRR(t, testSOA), mustRR(t, testA)))
	baseline := runtime.NumGoroutine()

	r := runOneAXFR(t, env)
	want := fmt.Sprintf("AXFR allowed: more than %d RRs received from 127.0.0.1:", maxAXFRRRs)
	if r.Status != report.Fail || !strings.HasPrefix(r.Evidence, want) ||
		strings.Contains(r.Evidence, "refused") || r.Remediation != axfrRemediation {
		t.Errorf("got %s %q (remediation %q), want FAIL %q... with remediation",
			r.Status, r.Evidence, r.Remediation, want)
	}
	assertGoroutinesReturn(t, baseline)
}

// TestAXFR_CancelIsInconclusive: cancelling the scan interrupts the running
// transfer and the queued probes promptly, and an interrupted probe is
// inconclusive rather than a verdict.
func TestAXFR_CancelIsInconclusive(t *testing.T) {
	_, env := axfrEnv(t, testNameservers(6)...)
	env.Timeout = 5 * time.Second
	startAXFRServer(t, stallAfter(nil))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	results := runAXFR(ctx, env)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("returned %v after the cancel, want promptly", elapsed)
	}
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6: %+v", len(results), results)
	}
	for _, r := range results {
		if r.Status != wantInconclusive ||
			!strings.HasPrefix(r.Evidence, "could not determine: ") ||
			!strings.Contains(r.Evidence, "canceled") {
			t.Errorf("%s = %s %q, want inconclusive naming the cancellation",
				r.ID, r.Status, r.Evidence)
		}
	}
}

// TestAXFR_CancelAfterZoneDataFails: zone data received before the scan is
// cancelled is still a leak, and the evidence names the cancellation, not
// the budget.
func TestAXFR_CancelAfterZoneDataFails(t *testing.T) {
	_, env := axfrEnv(t, "ns1.example.test.")
	env.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := []miekg.RR{mustRR(t, testSOA), mustRR(t, testA)}
	startAXFRServer(t, func(co *miekg.Conn, q *miekg.Msg) {
		if co.WriteMsg(reply(q, miekg.RcodeSuccess, data)) == nil {
			time.AfterFunc(50*time.Millisecond, cancel) // once the prober has read it
		}
		_, _ = io.Copy(io.Discard, co.Conn)
	})

	results := runAXFR(ctx, env)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	want := "received 2 RR(s) from 127.0.0.1:"
	if r := results[0]; r.Status != report.Fail || !strings.Contains(r.Evidence, want) ||
		!strings.HasSuffix(r.Evidence, "before the transfer ended: context canceled") {
		t.Errorf("got %s %q, want FAIL naming %q and the cancellation", r.Status, r.Evidence, want)
	}
}

// TestAXFRTransfer_QueryNotSent: a connection that fails before the AXFR
// query is written leaves the server unasked, which is inconclusive.
func TestAXFRTransfer_QueryNotSent(t *testing.T) {
	client, server := net.Pipe()
	_ = server.Close()
	env := &probe.Env{Target: "example.test", Timeout: time.Second}

	out := axfrTransfer(context.Background(), env, client, "192.0.2.1:53")
	r := gradeTransfer(report.Result{ID: "dns.axfr.ns1.example.test"}, "ns1.example.test", out)

	want := "could not determine: AXFR from 192.0.2.1:53: " + io.ErrClosedPipe.Error()
	if out.rrs != 0 || r.Status != wantInconclusive || r.Evidence != want {
		t.Errorf("got %d RRs and %s %q, want inconclusive %q", out.rrs, r.Status, r.Evidence, want)
	}
}

// TestAXFR_DialOutcomes: the SSRF denylist covers the AXFR dial, and its
// refusal is inconclusive; a refused connection is a PASS.
func TestAXFR_DialOutcomes(t *testing.T) {
	t.Run("loopback without override", func(t *testing.T) {
		_, env := axfrEnv(t, "ns1.example.test.")
		accepted := startAXFRServer(t, answer(miekg.RcodeSuccess, []miekg.RR{mustRR(t, testA)}))
		t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
		r := runOneAXFR(t, env)
		if r.Status != wantInconclusive ||
			!strings.Contains(r.Evidence, "ssrf dial: refusing 127.0.0.1: loopback") {
			t.Errorf("got %s %q, want inconclusive naming the SSRF refusal", r.Status, r.Evidence)
		}
		if n := accepted.Load(); n != 0 {
			t.Errorf("the denylist let %d connections through", n)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		_, env := axfrEnv(t, "ns1.example.test.")
		env.Timeout = refusedDialTimeout
		setAXFRPort(t, closedLoopbackPort(t))
		r := runOneAXFR(t, env)
		if r.Status != report.Pass || r.Title != "AXFR refused at ns1.example.test" ||
			!strings.Contains(r.Evidence, "refused") {
			t.Errorf("got %s %q %q, want PASS for a refused connection",
				r.Status, r.Title, r.Evidence)
		}
	})
}

// TestAXFRDialFailed: a refused connection passes whichever platform's errno
// reports it; any other dial failure is inconclusive.
func TestAXFRDialFailed(t *testing.T) {
	connectErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	for _, tc := range []struct {
		name   string
		err    error
		status report.Status
	}{
		{"refused", connectErr(syscall.ECONNREFUSED), report.Pass},
		// 10061 is WSAECONNREFUSED, the errno of a refused connect on Windows.
		{"refused on Windows", connectErr(syscall.Errno(10061)), report.Pass},
		{"reset", connectErr(syscall.ECONNRESET), wantInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := axfrDialFailed(context.Background(), report.Result{},
				"ns1.example.test", "192.0.2.53:53", tc.err)
			if r.Status != tc.status {
				t.Errorf("got %s %q %q, want %s", r.Status, r.Title, r.Evidence, tc.status)
			}
		})
	}
}

// TestAXFR_LookupOutcomes: a nameserver whose address lookup times out is
// inconclusive; one that does not exist is N/A.
func TestAXFR_LookupOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rcode    int
		status   report.Status
		evidence string
	}{
		{"lookup timeout", fakeNoReply, wantInconclusive,
			"could not determine: resolve ns1.example.test to IPv4: "},
		{"NXDOMAIN", miekg.RcodeNameError, report.NotApplicable, "could not resolve NS to IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, env := axfrEnv(t, "ns1.example.test.")
			fake.setRcode("ns1.example.test.", tc.rcode)
			accepted := startAXFRServer(t, answer(miekg.RcodeRefused))
			r := runOneAXFR(t, env)
			if r.Status != tc.status || !strings.HasPrefix(r.Evidence, tc.evidence) {
				t.Errorf("got %s %q, want %s %q...", r.Status, r.Evidence, tc.status, tc.evidence)
			}
			if n := accepted.Load(); n != 0 {
				t.Errorf("dialled %d times without an address", n)
			}
		})
	}
}

// TestAXFR_DedupesNameservers: names that differ only in letter case are one
// nameserver, probed once under one ID.
func TestAXFR_DedupesNameservers(t *testing.T) {
	_, env := axfrEnv(t, "NS1.example.test.", "ns1.example.test.")
	accepted := startAXFRServer(t, answer(miekg.RcodeRefused))
	results := runAXFR(context.Background(), env)
	if err := report.CheckUniqueIDs(results); err != nil {
		t.Error(err)
	}
	if len(results) != 1 || results[0].ID != "dns.axfr.ns1.example.test" {
		t.Errorf("got %+v, want one dns.axfr.ns1.example.test result", results)
	}
	if n := accepted.Load(); n != 1 {
		t.Errorf("probed %d times, want once", n)
	}
}

// TestAXFR_BoundsNameserverFanout: a large NS RRset is probed at most
// maxAXFRServers deep and axfrConcurrency wide, and the skipped names are
// reported rather than silently dropped.
func TestAXFR_BoundsNameserverFanout(t *testing.T) {
	names := testNameservers(12)
	fake, env := axfrEnv(t, names...)
	var active, peak atomic.Int32
	accepted := startAXFRServer(t, func(co *miekg.Conn, q *miekg.Msg) {
		storeMax(&peak, active.Add(1))
		time.Sleep(100 * time.Millisecond)
		active.Add(-1)
		answer(miekg.RcodeRefused)(co, q)
	})

	results := runAXFR(context.Background(), env)
	if err := report.CheckUniqueIDs(results); err != nil {
		t.Error(err)
	}
	assertSkipNote(t, results, trimDots(names[maxAXFRServers:]))
	if n := accepted.Load(); n != maxAXFRServers {
		t.Errorf("probed %d nameservers, want %d", n, maxAXFRServers)
	}
	if p := peak.Load(); p > axfrConcurrency || p < 2 {
		t.Errorf("peak concurrent probes = %d, want 2..%d", p, axfrConcurrency)
	}
	for _, ns := range names[maxAXFRServers:] {
		if n := fake.queryCount(ns, miekg.TypeA); n != 0 {
			t.Errorf("looked up skipped nameserver %s %d times", ns, n)
		}
	}
}

// TestAXFR_PanicReachesCaller: a panic while probing one nameserver reaches
// the check's goroutine, where the registry turns it into a result, rather
// than ending the scan.
func TestAXFR_PanicReachesCaller(t *testing.T) {
	env := &probe.Env{Target: "example.test", Timeout: time.Second} // nil DNS panics
	got := func() (r any) {
		defer func() { r = recover() }()
		probeNameservers(context.Background(), env, []string{"ns1.example.test"})
		return nil
	}()
	if got == nil {
		t.Fatal("probeNameservers returned; want the probe's panic")
	}
}

func TestAXFRSkipped_BoundsTheList(t *testing.T) {
	hosts := trimDots(testNameservers(15))
	got := axfrSkipped(hosts).Evidence
	want := "not probed: " + strings.Join(hosts[:10], ", ") + ", and 5 more"
	if got != want {
		t.Errorf("evidence = %q, want %q", got, want)
	}
}

// wantInconclusive is the status checkutil.Inconclusive assigns.
const wantInconclusive = report.Warn

// axfrEnv starts a fake resolver that delegates example.test to the given
// nameservers, each with the address 127.0.0.1, and returns it with an
// active Env that resolves through it.
func axfrEnv(t *testing.T, nameservers ...string) (*fakeDNS, *probe.Env) {
	t.Helper()
	fake := newFakeDNS(t)
	for _, ns := range nameservers {
		fake.add(t, "example.test. 300 IN NS "+ns, ns+" 300 IN A 127.0.0.1")
	}
	return fake, fake.env(t, "example.test", axfrTestTimeout)
}

// runOneAXFR runs the check, which must return one result within ten
// seconds.
func runOneAXFR(t *testing.T, env *probe.Env) report.Result {
	t.Helper()
	done := make(chan []report.Result, 1)
	go func() { done <- runAXFR(context.Background(), env) }()
	select {
	case results := <-done:
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1: %+v", len(results), results)
		}
		return results[0]
	case <-time.After(10 * time.Second):
		t.Fatal("runAXFR did not return within 10s")
	}
	return report.Result{}
}

// assertSkipNote checks that results are maxAXFRServers probes followed by
// the INFO note naming the skipped nameservers.
func assertSkipNote(t *testing.T, results []report.Result, skipped []string) {
	t.Helper()
	if len(results) != maxAXFRServers+1 {
		t.Fatalf("got %d results, want %d probes and one skip note", len(results), maxAXFRServers+1)
	}
	note := results[maxAXFRServers]
	want := "not probed: " + strings.Join(skipped, ", ")
	if note.ID != "dns.axfr" || note.Status != report.Info || note.Evidence != want {
		t.Errorf("skip note = %s %s %q, want dns.axfr INFO %q",
			note.ID, note.Status, note.Evidence, want)
	}
}

// assertGoroutinesReturn fails unless the goroutine count falls back to
// baseline within two seconds.
func assertGoroutinesReturn(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Errorf("%d goroutines remain after the probe, want the baseline %d", n, baseline)
	}
}

// storeMax raises v to n when n is larger.
func storeMax(v *atomic.Int32, n int32) {
	for {
		old := v.Load()
		if n <= old || v.CompareAndSwap(old, n) {
			return
		}
	}
}

// startAXFRServer stands in for every nameserver: a TCP listener on
// 127.0.0.1 that the AXFR port seam points at for the rest of the test.
// serve answers the query read from each connection, which closes when
// serve returns. It returns the count of accepted connections.
func startAXFRServer(t *testing.T, serve func(*miekg.Conn, *miekg.Msg)) *atomic.Int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("AXFR server: listen on 127.0.0.1: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	setAXFRPort(t, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	accepted := new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer func() { _ = conn.Close() }()
				co := &miekg.Conn{Conn: conn}
				if q, err := co.ReadMsg(); err == nil {
					serve(co, q)
				}
			}()
		}
	}()
	return accepted
}

func setAXFRPort(t *testing.T, port string) {
	t.Helper()
	old := axfrPort
	axfrPort = port
	t.Cleanup(func() { axfrPort = old })
}

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

// closedLoopbackPort returns a loopback port that was just released, so a
// dial to it is refused.
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

// answer sends one message per batch, each with rcode, then closes.
func answer(rcode int, batches ...[]miekg.RR) func(*miekg.Conn, *miekg.Msg) {
	return func(co *miekg.Conn, q *miekg.Msg) {
		for _, rrs := range batches {
			if co.WriteMsg(reply(q, rcode, rrs)) != nil {
				return
			}
		}
		if len(batches) == 0 {
			_ = co.WriteMsg(reply(q, rcode, nil))
		}
	}
}

// stallAfter sends rrs, if any, in one NOERROR message and then waits for
// the prober to hang up.
func stallAfter(rrs []miekg.RR) func(*miekg.Conn, *miekg.Msg) {
	return func(co *miekg.Conn, q *miekg.Msg) {
		if rrs != nil && co.WriteMsg(reply(q, miekg.RcodeSuccess, rrs)) != nil {
			return
		}
		_, _ = io.Copy(io.Discard, co.Conn)
	}
}

// trickle sends the SOA and then an empty message every interval until the
// prober hangs up.
func trickle(soa miekg.RR, interval time.Duration) func(*miekg.Conn, *miekg.Msg) {
	return func(co *miekg.Conn, q *miekg.Msg) {
		msg := reply(q, miekg.RcodeSuccess, []miekg.RR{soa})
		for co.WriteMsg(msg) == nil {
			time.Sleep(interval)
			msg = reply(q, miekg.RcodeSuccess, nil)
		}
	}
}

// flood sends the SOA and then a thousand records per message until the
// prober hangs up.
func flood(soa, rr miekg.RR) func(*miekg.Conn, *miekg.Msg) {
	return func(co *miekg.Conn, q *miekg.Msg) {
		rrs := make([]miekg.RR, 1000)
		for i := range rrs {
			rrs[i] = rr
		}
		first := reply(q, miekg.RcodeSuccess, append([]miekg.RR{soa}, rrs[1:]...))
		if co.WriteMsg(first) != nil {
			return
		}
		next := reply(q, miekg.RcodeSuccess, rrs)
		next.Compress = true
		buf, err := next.Pack()
		if err != nil {
			return
		}
		for {
			if _, err := co.Write(buf); err != nil {
				return
			}
		}
	}
}

func resetAfterQuery(co *miekg.Conn, _ *miekg.Msg) {
	_ = co.Conn.(*net.TCPConn).SetLinger(0) // Close now sends RST
}

func reply(q *miekg.Msg, rcode int, rrs []miekg.RR) *miekg.Msg {
	m := new(miekg.Msg)
	m.SetReply(q)
	m.Rcode = rcode
	m.Answer = rrs
	return m
}

func mustRR(t *testing.T, line string) miekg.RR {
	t.Helper()
	rr, err := miekg.NewRR(line)
	if err != nil {
		t.Fatalf("parse RR %q: %v", line, err)
	}
	return rr
}

// testNameservers returns n nameserver FQDNs in example.test, in sorted
// order.
func testNameservers(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("ns%02d.example.test.", i+1)
	}
	return names
}

func trimDots(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimSuffix(n, ".")
	}
	return out
}
