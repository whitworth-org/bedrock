package dns

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
)

// fakeNoReply is the rcode that makes fakeDNS drop a query, so the lookup
// times out.
const fakeNoReply = -1

// fakeDNS is this package's in-process resolver: a miekg/dns UDP server on
// 127.0.0.1 that answers from a zone map. A name without records answers
// NXDOMAIN and a name without records of the asked type answers NODATA,
// unless setRcode overrides the name or setTypeRcode one type at it;
// setDelay slows a name's answers. It counts the queries it receives and,
// per type, the most it held at once while delaying their answers.
type fakeDNS struct {
	addr string // host:port of the UDP listener

	mu       sync.Mutex
	records  map[fakeQuestion][]miekg.RR
	names    map[string]bool
	rcodes   map[string]int
	trcodes  map[fakeQuestion]int
	delays   map[string]time.Duration
	queries  map[fakeQuestion]int
	inFlight map[uint16]int
	peak     map[uint16]int
}

// fakeQuestion keys the zone map and the query counter.
type fakeQuestion struct {
	name  string // lower-case FQDN
	qtype uint16
}

func fakeKey(name string, qtype uint16) fakeQuestion {
	return fakeQuestion{name: strings.ToLower(miekg.Fqdn(name)), qtype: qtype}
}

// newFakeDNS starts a fakeDNS that serves until the test ends.
func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	f := &fakeDNS{
		records:  map[fakeQuestion][]miekg.RR{},
		names:    map[string]bool{},
		rcodes:   map[string]int{},
		trcodes:  map[fakeQuestion]int{},
		delays:   map[string]time.Duration{},
		queries:  map[fakeQuestion]int{},
		inFlight: map[uint16]int{},
		peak:     map[uint16]int{},
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake DNS: listen udp on 127.0.0.1: %v", err)
	}
	f.addr = pc.LocalAddr().String()
	started := make(chan struct{})
	srv := &miekg.Server{PacketConn: pc, Handler: f, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fake DNS: server did not start within 2s")
	}
	return f
}

// env returns an active-probing Env for target that resolves through f. It
// sets BEDROCK_ALLOW_PRIVATE_RESOLVER so the loopback resolver is accepted,
// so callers must not call t.Parallel.
func (f *fakeDNS) env(t *testing.T, target string, timeout time.Duration) *probe.Env {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	return probe.NewEnv(target, timeout, true, f.addr)
}

// add parses each zone-file line into an RR and serves it.
func (f *fakeDNS) add(t *testing.T, lines ...string) {
	t.Helper()
	for _, line := range lines {
		rr, err := miekg.NewRR(line)
		if err != nil {
			t.Fatalf("fake DNS: parse RR %q: %v", line, err)
		}
		key := fakeKey(rr.Header().Name, rr.Header().Rrtype)
		f.mu.Lock()
		f.records[key] = append(f.records[key], rr)
		f.names[key.name] = true
		f.mu.Unlock()
	}
}

// setRcode makes every query for name answer rcode with no records, or go
// unanswered when rcode is fakeNoReply.
func (f *fakeDNS) setRcode(name string, rcode int) {
	f.mu.Lock()
	f.rcodes[fakeKey(name, 0).name] = rcode
	f.mu.Unlock()
}

// setTypeRcode is setRcode for the queries of one type only.
func (f *fakeDNS) setTypeRcode(name string, qtype uint16, rcode int) {
	f.mu.Lock()
	f.trcodes[fakeKey(name, qtype)] = rcode
	f.mu.Unlock()
}

// setDelay makes every answer for name wait d before it is sent. The server
// answers each query on its own goroutine, so delayed answers overlap.
func (f *fakeDNS) setDelay(name string, d time.Duration) {
	f.mu.Lock()
	f.delays[fakeKey(name, 0).name] = d
	f.mu.Unlock()
}

// queryCount returns how many queries for name and qtype f has received.
func (f *fakeDNS) queryCount(name string, qtype uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[fakeKey(name, qtype)]
}

// peakInFlight returns the most queries of qtype f has delayed at once.
func (f *fakeDNS) peakInFlight(qtype uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peak[qtype]
}

// ServeDNS answers req from the zone map.
func (f *fakeDNS) ServeDNS(w miekg.ResponseWriter, req *miekg.Msg) {
	resp := new(miekg.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Compress = true // keeps a dozen NS records inside a 512-byte UDP reply
	if len(req.Question) != 1 {
		resp.Rcode = miekg.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}
	key := fakeKey(req.Question[0].Name, req.Question[0].Qtype)
	f.mu.Lock()
	f.queries[key]++
	rcode, overridden := f.rcodes[key.name]
	if r, ok := f.trcodes[key]; ok {
		rcode, overridden = r, true
	}
	exists := f.names[key.name]
	delay := f.delays[key.name]
	resp.Answer = append(resp.Answer, f.records[key]...)
	f.inFlight[key.qtype]++
	f.peak[key.qtype] = max(f.peak[key.qtype], f.inFlight[key.qtype])
	f.mu.Unlock()
	time.Sleep(delay)
	// Leave the count before answering, so a query the answer prompts is
	// never counted beside the one it follows.
	f.mu.Lock()
	f.inFlight[key.qtype]--
	f.mu.Unlock()
	switch {
	case overridden && rcode == fakeNoReply:
		return
	case overridden:
		resp.Answer = nil
		resp.Rcode = rcode
	case !exists:
		resp.Rcode = miekg.RcodeNameError
	}
	_ = w.WriteMsg(resp)
}
