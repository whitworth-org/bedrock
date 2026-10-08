package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// dropFirstHandler answers DNS queries but silently drops the first dropN of
// them (no reply at all), simulating lost UDP datagrams or a throttled
// upstream. It counts every query it receives so a test can assert that a
// retransmission actually reached the wire.
type dropFirstHandler struct {
	mu     sync.Mutex
	seen   int
	dropN  int
	answer mdns.RR
}

func (h *dropFirstHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seen
}

func (h *dropFirstHandler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	h.mu.Lock()
	h.seen++
	drop := h.seen <= h.dropN
	h.mu.Unlock()
	if drop {
		return // no reply — the client must time out this attempt and retry
	}
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Answer = append(resp.Answer, h.answer)
	_ = w.WriteMsg(resp)
}

// TestExchangeRetransmitsDroppedDatagram proves that with a comfortable budget
// a single dropped UDP datagram is retransmitted within the same budget and the
// lookup still succeeds. Without the retransmit the first (dropped) attempt
// would consume the whole timeout and the lookup would FAIL spuriously.
func TestExchangeRetransmitsDroppedDatagram(t *testing.T) {
	rr, err := mdns.NewRR("flaky.test. 60 IN A 192.0.2.7")
	if err != nil {
		t.Fatalf("build RR: %v", err)
	}
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &dropFirstHandler{dropN: 1, answer: rr}
	spec := startUDPResolver(t, h)

	// 4s == minRetransmitBudget → two 2s attempts. Attempt 1 is dropped and
	// times out at 2s; attempt 2 is answered immediately.
	d := NewDNS(spec, minRetransmitBudget)
	ips, err := d.LookupA(context.Background(), "flaky.test")
	if err != nil {
		t.Fatalf("lookup after one dropped datagram should succeed, got %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatalf("unexpected answer: %v", ips)
	}
	if got := h.count(); got != 2 {
		t.Fatalf("expected 2 queries on the wire (1 dropped + 1 answered), got %d", got)
	}
}

// TestExchangeSingleAttemptBelowThreshold confirms that a small --timeout is
// NOT carved into sub-attempts: one dropped datagram surfaces as a failure
// rather than being retried, so a deliberately tight budget keeps its original
// single-attempt semantics.
func TestExchangeSingleAttemptBelowThreshold(t *testing.T) {
	rr, err := mdns.NewRR("flaky.test. 60 IN A 192.0.2.7")
	if err != nil {
		t.Fatalf("build RR: %v", err)
	}
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &dropFirstHandler{dropN: 1, answer: rr}
	spec := startUDPResolver(t, h)

	// Below minRetransmitBudget (4s) → exactly one attempt; the dropped
	// datagram yields a timeout with no retry. 2s leaves slow CI machines
	// ample time to get the query onto the wire before the client gives up,
	// so the h.count() assertion below stays reliable.
	d := NewDNS(spec, 2*time.Second)
	if _, err := d.LookupA(context.Background(), "flaky.test"); err == nil {
		t.Fatal("below-threshold budget must not retry; expected a timeout error")
	}
	if got := h.count(); got != 1 {
		t.Fatalf("expected exactly 1 query (no retransmit), got %d", got)
	}
}

// failoverDNS returns a client for system resolvers at addrs, as NewDNS("")
// builds one from resolv.conf, which cannot express the loopback ports
// these tests listen on.
func failoverDNS(timeout time.Duration, addrs ...string) *DNS {
	d := &DNS{failover: true, timeout: timeout}
	for i, addr := range addrs {
		d.upstreams = append(d.upstreams, upstream{
			label: fmt.Sprintf("system-%d", i+1), addr: addr, protocol: protoUDP,
		})
	}
	return d
}

// failoverInstantFail is a resolver address whose dial fails at once on
// every platform: the port is out of range.
const failoverInstantFail = "127.0.0.1:99999"

// failoverHealthy starts a resolver that answers www.example.test A.
func failoverHealthy(t *testing.T) string {
	t.Helper()
	spec, zone := newFakeUDPResolver(t)
	zone.Add(t, "www.example.test. 60 IN A 192.0.2.7")
	return spec
}

// TestSystemResolversFailOver pins failover across system resolvers: a
// silent first resolver hands the query to the second after half the
// budget, one that fails at once hands it over at once, and the lookup
// succeeds within the budget either way.
func TestSystemResolversFailOver(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	cases := []struct {
		desc   string
		first  string
		within time.Duration
	}{
		{"silent", startUDPResolver(t, &rcodeHandler{silent: true}), minRetransmitBudget},
		{"instant error", failoverInstantFail, minRetransmitBudget / 4},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			d := failoverDNS(minRetransmitBudget, c.first, failoverHealthy(t))

			start := time.Now()
			ips, err := d.LookupA(context.Background(), "www.example.test")

			if err != nil || fmt.Sprint(ips) != "[192.0.2.7]" {
				t.Fatalf("LookupA = %v, %v; want the second resolver's answer", ips, err)
			}
			if elapsed := time.Since(start); elapsed >= c.within {
				t.Errorf("failover took %v, want under %v", elapsed, c.within)
			}
		})
	}
}

// TestSystemResolversFailOverReachesEveryResolver: several system
// resolvers share the budget equally, so silent ones ahead of a healthy one
// still leave it time to answer, with three resolvers and with a budget
// under minRetransmitBudget.
func TestSystemResolversFailOverReachesEveryResolver(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	silent := func() string { return startUDPResolver(t, &rcodeHandler{silent: true}) }
	cases := []struct {
		desc    string
		timeout time.Duration
		addrs   []string
	}{
		{"two resolvers, 3s budget", 3 * time.Second, []string{silent(), failoverHealthy(t)}},
		{"three resolvers, 4s budget", minRetransmitBudget,
			[]string{silent(), silent(), failoverHealthy(t)}},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			d := failoverDNS(c.timeout, c.addrs...)
			ips, err := d.LookupA(context.Background(), "www.example.test")
			if err != nil || fmt.Sprint(ips) != "[192.0.2.7]" {
				t.Fatalf("LookupA = %v, %v; want the last resolver's answer", ips, err)
			}
		})
	}
}

// TestAttemptBudget pins how the budget is split: a lone upstream gets two
// attempts only from minRetransmitBudget up, and several upstreams an equal
// share each, never under minFailoverAttempt nor over the whole budget.
func TestAttemptBudget(t *testing.T) {
	cases := []struct {
		n          int
		timeout    time.Duration
		perAttempt time.Duration
		attempts   int
	}{
		{1, 2 * time.Second, 2 * time.Second, 1},
		{1, 4 * time.Second, 2 * time.Second, 2},
		{2, 3 * time.Second, 1500 * time.Millisecond, 1},
		{3, 6 * time.Second, 2 * time.Second, 1},
		{3, 2 * time.Second, time.Second, 1},
		{2, 500 * time.Millisecond, 500 * time.Millisecond, 1},
	}
	for _, c := range cases {
		d := &DNS{timeout: c.timeout}
		perAttempt, attempts := d.attemptBudget(c.n)
		if perAttempt != c.perAttempt || attempts != c.attempts {
			t.Errorf("attemptBudget(%d) with %v = %v, %d; want %v, %d", c.n, c.timeout,
				perAttempt, attempts, c.perAttempt, c.attempts)
		}
	}
}

// TestSERVFAILDoesNotFailOver pins that a parsed reply ends the walk across
// system resolvers, even a SERVFAIL: the next resolver is never asked.
func TestSERVFAILDoesNotFailOver(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	second := &rcodeHandler{rcode: mdns.RcodeSuccess}
	d := failoverDNS(minRetransmitBudget,
		startUDPResolver(t, &rcodeHandler{rcode: mdns.RcodeServerFailure}),
		startUDPResolver(t, second))

	_, err := d.LookupA(context.Background(), "www.example.test")

	var rcodeErr *RcodeError
	if !errors.As(err, &rcodeErr) || rcodeErr.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("want the first resolver's SERVFAIL, got %v", err)
	}
	if n := len(second.queries()); n != 0 {
		t.Errorf("second resolver saw %d queries, want 0", n)
	}
}

// TestResolversListDoesNotFailOver pins that --resolvers keeps sending
// normal lookups to its first entry only.
func TestResolversListDoesNotFailOver(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	second := &rcodeHandler{rcode: mdns.RcodeSuccess}
	d, err := NewMultiDNS([]string{"192.0.2.1", startUDPResolver(t, second)},
		minRetransmitBudget)
	if err != nil {
		t.Fatalf("NewMultiDNS: %v", err)
	}
	// parseUpstream rejects an out-of-range port, so the first entry takes
	// the instant-fail address only after parsing.
	d.upstreams[0].addr = failoverInstantFail

	if _, err := d.LookupA(context.Background(), "www.example.test"); err == nil {
		t.Fatal("want the first entry's dial error")
	}
	if n := len(second.queries()); n != 0 {
		t.Errorf("second entry saw %d queries, want 0", n)
	}
}

// TestSystemResolverTimeoutNamesLabel pins that a timeout against a system
// resolver names it as system-1 and carries no IP address or port.
func TestSystemResolverTimeoutNamesLabel(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	addr := startUDPResolver(t, &rcodeHandler{silent: true})
	d := failoverDNS(time.Second, addr)

	_, err := d.LookupA(context.Background(), "www.example.test")

	if err == nil || !strings.HasPrefix(err.Error(), "system-1: ") || !IsProbeFailure(err) {
		t.Fatalf("want a system-1 timeout, got %v", err)
	}
	host, port, _ := net.SplitHostPort(addr)
	if strings.Contains(err.Error(), host) || strings.Contains(err.Error(), port) {
		t.Errorf("error %q carries a network address", err)
	}
}

// useResolvConf points NewDNS at path for the rest of the test.
func useResolvConf(t *testing.T, path string) {
	t.Helper()
	old := resolvConfPath
	resolvConfPath = path
	t.Cleanup(func() { resolvConfPath = old })
}

// TestNewDNSReadsSystemResolvers pins how NewDNS("") reads resolv.conf:
// every nameserver in order, labelled by position, with failover on. The
// tests above exercise failover on a client built the same way.
func TestNewDNSReadsSystemResolvers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	conf := "nameserver 192.0.2.1\nnameserver 2001:db8::1\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatalf("write resolv.conf: %v", err)
	}
	useResolvConf(t, path)

	d := NewDNS("", time.Second)

	want := []upstream{
		{label: "system-1", addr: "192.0.2.1:53", protocol: protoUDP},
		{label: "system-2", addr: "[2001:db8::1]:53", protocol: protoUDP},
	}
	if d.setupErr != nil || !d.failover || !slices.Equal(d.upstreams, want) {
		t.Errorf("NewDNS(\"\") = upstreams %+v, failover %v, error %v; want %+v with failover",
			d.upstreams, d.failover, d.setupErr, want)
	}
}

// TestMissingResolvConf pins the error a host without resolv.conf, such as
// Windows, gets from every query and from NewMultiDNS(nil).
func TestMissingResolvConf(t *testing.T) {
	useResolvConf(t, filepath.Join(t.TempDir(), "resolv.conf"))
	ctx := context.Background()
	d := NewDNS("", time.Second)

	_, errLookup := d.LookupTXT(ctx, "example.test")
	_, errExchange := d.ExchangeWithDO(ctx, "example.test", mdns.TypeDS)
	all := d.ExchangeAllWithDO(ctx, "example.test", mdns.TypeA)
	_, errMulti := NewMultiDNS(nil, time.Second)

	for _, err := range []error{errLookup, errExchange, all[0].Err, errMulti} {
		if err == nil || err.Error() != "no system resolver found; pass --resolver" {
			t.Errorf("got error %v, want the pass --resolver error", err)
		}
	}
}

// TestUnreadableResolvConf pins that a resolv.conf that cannot be opened
// also yields an error that says what to do.
func TestUnreadableResolvConf(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	useResolvConf(t, filepath.Join(file, "resolv.conf")) // a path through a file

	_, err := NewMultiDNS(nil, time.Second)

	if err == nil || !strings.HasSuffix(err.Error(), "; pass --resolver") {
		t.Errorf("got error %v, want one ending with the pass --resolver hint", err)
	}
}

// TestResolvConfReadOnce pins that NewDNS reads resolv.conf once: a file
// that appears later is not picked up, and concurrent first lookups do not
// race (run with -race).
func TestResolvConfReadOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	useResolvConf(t, path)
	d := NewDNS("", time.Second)
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.1\n"), 0o600); err != nil {
		t.Fatalf("write resolv.conf: %v", err)
	}

	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() { _, errs[i] = d.LookupA(context.Background(), "example.test") })
	}
	wg.Wait()

	for _, err := range errs {
		if !errors.Is(err, errNoSystemResolver) {
			t.Errorf("got error %v, want the error from construction", err)
		}
	}
}

// TestHealthCountsPrimaryQueries pins the counters behind the run-level
// resolver check: each query on the primary path counts as sent, as replied
// when a DNS message came back whatever its rcode, and as answered when
// that rcode is NOERROR or NXDOMAIN.
func TestHealthCountsPrimaryQueries(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	ctx := context.Background()
	d := NewDNS(failoverHealthy(t), time.Second)

	_, _ = d.LookupA(ctx, "www.example.test")    // NOERROR
	_, _ = d.LookupA(ctx, "absent.example.test") // NXDOMAIN
	_ = d.ExchangeAllWithDO(ctx, "www.example.test", mdns.TypeA)
	wantHealth(t, d, "NOERROR and NXDOMAIN", [3]int{2, 2, 2})

	dead := failoverDNS(time.Second, failoverInstantFail)
	_, _ = dead.LookupA(ctx, "www.example.test")
	wantHealth(t, dead, "no reply", [3]int{1, 0, 0})

	for _, rcode := range []int{mdns.RcodeServerFailure, mdns.RcodeRefused} {
		failing := NewDNS(startUDPResolver(t, &rcodeHandler{rcode: rcode}), time.Second)
		_, _ = failing.LookupA(ctx, "www.example.test")
		wantHealth(t, failing, mdns.RcodeToString[rcode], [3]int{1, 1, 0})
	}
}

// wantHealth reports an error unless d.Health(), read after the queries
// described by after, returns want: the sent, replied and answered counts.
func wantHealth(t *testing.T, d *DNS, after string, want [3]int) {
	t.Helper()
	s, r, a := d.Health()
	if [3]int{s, r, a} != want {
		t.Errorf("Health() after %s = %d sent, %d replied, %d answered; want %d, %d, %d",
			after, s, r, a, want[0], want[1], want[2])
	}
}
