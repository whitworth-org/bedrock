package probe

import (
	"context"
	"net"
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

func startFlakyResolver(t *testing.T, h mdns.Handler) (spec string, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		_ = srv.Shutdown()
		t.Fatal("flaky DNS server did not start within 2s")
	}
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
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
	spec, cleanup := startFlakyResolver(t, h)
	defer cleanup()

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
	spec, cleanup := startFlakyResolver(t, h)
	defer cleanup()

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
