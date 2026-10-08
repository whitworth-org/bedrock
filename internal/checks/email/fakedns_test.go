// fakedns_test.go serves canned DNS answers from an in-process UDP server on
// 127.0.0.1 (the same technique as the top-level golden integration test),
// so the email checks run end to end without leaving the host.

package email

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
)

// A-query behaviors for cannedZone.
const (
	aNXDomain = "nxdomain" // name does not exist (RFC 8020 semantics)
	aNoData   = "nodata"   // NOERROR with an empty answer section
	aWildcard = "wildcard" // every A query resolves (wildcard zone)
)

// noReply as a cannedZone rcode drops the query, so the client times out.
const noReply = -1

// cannedZone answers queries from fixed records. Owner names are lowercase
// without the trailing dot. An owner "*.<parent>" stands in for every name
// below <parent> without an entry of its own, and "*" for every name. A
// query for a name with no entry gets NXDOMAIN, except that A queries
// follow aMode.
type cannedZone struct {
	txt   map[string][]string // TXT values
	mx    map[string][]string // MX RDATA, e.g. "10 mx.example.com."
	a     map[string][]string // IPv4 addresses
	tlsa  map[string][]string // TLSA RDATA, e.g. "3 1 1 <hex>"
	aMode string              // A answer for names absent from a
	rcode map[string]int      // rcode sent with no records, or noReply
	delay time.Duration       // wait before answering each query
	stats *zoneStats          // counts the queries when set
}

func (z cannedZone) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	defer z.stats.begin(name, q.Qtype)()
	time.Sleep(z.delay)

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Compress = true
	if rcode, ok := lookupOwner(z.rcode, name); ok {
		if rcode == noReply {
			return
		}
		resp.Rcode = rcode
	} else {
		resp.Answer, resp.Rcode = z.answer(q, name)
	}
	_ = w.WriteMsg(resp)
}

// answer returns the records that answer q for name, and the rcode.
func (z cannedZone) answer(q mdns.Question, name string) ([]mdns.RR, int) {
	hdr := mdns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: mdns.ClassINET, Ttl: 60}
	switch q.Qtype {
	case mdns.TypeTXT:
		vals, ok := lookupOwner(z.txt, name)
		if !ok {
			return nil, mdns.RcodeNameError
		}
		var rrs []mdns.RR
		for _, v := range vals {
			rrs = append(rrs, &mdns.TXT{Hdr: hdr, Txt: []string{v}})
		}
		return rrs, mdns.RcodeSuccess
	case mdns.TypeA:
		if _, ok := lookupOwner(z.a, name); !ok {
			return z.unlistedA(hdr)
		}
		return z.parsed(z.a, q, name)
	case mdns.TypeMX:
		return z.parsed(z.mx, q, name)
	case mdns.TypeTLSA:
		return z.parsed(z.tlsa, q, name)
	}
	return nil, mdns.RcodeNameError
}

// unlistedA answers an A query for a name absent from z.a, per z.aMode.
func (z cannedZone) unlistedA(hdr mdns.RR_Header) ([]mdns.RR, int) {
	switch z.aMode {
	case aWildcard:
		return []mdns.RR{&mdns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, 1)}}, mdns.RcodeSuccess
	case aNoData:
		return nil, mdns.RcodeSuccess
	}
	return nil, mdns.RcodeNameError
}

// parsed builds q's answer from the RDATA strings that records holds for
// name. RDATA that does not parse yields SERVFAIL, which startCannedDNS
// rules out up front.
func (z cannedZone) parsed(records map[string][]string, q mdns.Question, name string) (
	[]mdns.RR, int,
) {
	rdata, ok := lookupOwner(records, name)
	if !ok {
		return nil, mdns.RcodeNameError
	}
	var rrs []mdns.RR
	for _, rd := range rdata {
		rr, err := parseRR(q.Name, q.Qtype, rd)
		if err != nil {
			return nil, mdns.RcodeServerFailure
		}
		rrs = append(rrs, rr)
	}
	return rrs, mdns.RcodeSuccess
}

func parseRR(owner string, qtype uint16, rdata string) (mdns.RR, error) {
	return mdns.NewRR(mdns.Fqdn(owner) + " 60 IN " + mdns.TypeToString[qtype] + " " + rdata)
}

// lookupOwner returns m's entry for name: its own, else that of the nearest
// "*.<ancestor>" owner, else that of "*".
func lookupOwner[V any](m map[string]V, name string) (V, bool) {
	if v, ok := m[name]; ok {
		return v, true
	}
	for parent, more := name, true; more; {
		_, parent, more = strings.Cut(parent, ".")
		wildcard := "*"
		if more {
			wildcard += "." + parent
		}
		if v, ok := m[wildcard]; ok {
			return v, true
		}
	}
	var zero V
	return zero, false
}

// zoneStats counts the queries a cannedZone answers and gauges how many it
// holds at once.
type zoneStats struct {
	mu       sync.Mutex
	queries  map[string]int // by statsKey
	inFlight int
	peak     int
}

func statsKey(name string, qtype uint16) string {
	return name + " " + mdns.TypeToString[qtype]
}

// begin records a query for name and returns the func that ends it.
func (s *zoneStats) begin(name string, qtype uint16) (end func()) {
	if s == nil {
		return func() {}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queries == nil {
		s.queries = map[string]int{}
	}
	s.queries[statsKey(name, qtype)]++
	s.inFlight++
	s.peak = max(s.peak, s.inFlight)
	return func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}
}

// count returns how many qtype queries for name (lowercase, no trailing
// dot) the zone received.
func (s *zoneStats) count(name string, qtype uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[statsKey(name, qtype)]
}

// maxInFlight returns the most queries the zone held at once.
func (s *zoneStats) maxInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

// startCannedDNS serves zone until the test ends and returns the resolver
// address to hand to probe.NewEnv (see serveDNS).
func startCannedDNS(t *testing.T, zone cannedZone) string {
	t.Helper()
	checkRDATA(t, zone)
	return serveDNS(t, zone)
}

// serveDNS serves h on 127.0.0.1 until the test ends and returns the
// resolver address to hand to probe.NewEnv. It sets
// BEDROCK_ALLOW_PRIVATE_RESOLVER, which lets probe.NewEnv accept the
// loopback resolver and lets probes dial loopback, so tests that use it must
// not call t.Parallel.
func serveDNS(t *testing.T, h mdns.Handler) string {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
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
		_ = pc.Close()
		t.Fatal("canned DNS server did not start within 2s")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// checkRDATA fails the test when any RDATA string in zone does not parse.
func checkRDATA(t *testing.T, zone cannedZone) {
	t.Helper()
	typed := map[uint16]map[string][]string{
		mdns.TypeMX: zone.mx, mdns.TypeA: zone.a, mdns.TypeTLSA: zone.tlsa,
	}
	for qtype, records := range typed {
		for owner, rdata := range records {
			for _, rd := range rdata {
				if _, err := parseRR(owner, qtype, rd); err != nil {
					t.Fatalf("canned zone %s %s %q: %v", owner, mdns.TypeToString[qtype], rd, err)
				}
			}
		}
	}
}

// newCannedEnv starts a canned DNS server for the zone and returns a
// passive Env with a 2s timeout pointed at it.
func newCannedEnv(t *testing.T, target string, zone cannedZone) *probe.Env {
	t.Helper()
	return probe.NewEnv(target, 2*time.Second, false, startCannedDNS(t, zone))
}
