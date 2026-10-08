package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// ansHandler answers every query with the same rcode and sections, whatever
// the question, so a test controls exactly what a lookup receives.
type ansHandler struct {
	rcode      int
	answer, ns []mdns.RR
}

func (h ansHandler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetRcode(req, h.rcode)
	resp.Answer = h.answer
	resp.Ns = h.ns
	_ = w.WriteMsg(resp)
}

// ansDNS returns a client for a loopback resolver serving h.
func ansDNS(t *testing.T, h ansHandler) *DNS {
	t.Helper()
	t.Setenv(allowPrivateResolverEnv, "1")
	return NewDNS(startUDPResolver(t, h), 2*time.Second)
}

func ansRRs(t *testing.T, lines ...string) []mdns.RR {
	t.Helper()
	rrs := make([]mdns.RR, 0, len(lines))
	for _, line := range lines {
		rr, err := mdns.NewRR(line)
		if err != nil {
			t.Fatalf("parse RR %q: %v", line, err)
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

// ansLookups runs every Lookup* method for name and returns each result
// with its error, formatted, keyed by record type.
func ansLookups(d *DNS, name string) map[string]string {
	ctx := context.Background()
	show := func(v any, err error) string { return fmt.Sprint(v, " ", err) }
	return map[string]string{
		"A":     show(d.LookupA(ctx, name)),
		"AAAA":  show(d.LookupAAAA(ctx, name)),
		"TXT":   show(d.LookupTXT(ctx, name)),
		"MX":    show(d.LookupMX(ctx, name)),
		"NS":    show(d.LookupNS(ctx, name)),
		"SOA":   show(d.LookupSOA(ctx, name)),
		"CAA":   show(d.LookupCAA(ctx, name)),
		"CNAME": show(d.LookupCNAME(ctx, name)),
	}
}

// TestLookupsFollowCNAMEChain pins that a lookup of an alias returns the
// records owned by the end of its CNAME chain, only of the queried type,
// and ignores records owned by names outside the chain. LookupCNAME alone
// returns the first hop, and LookupSOA reports the alias, which owns no SOA.
func TestLookupsFollowCNAMEChain(t *testing.T) {
	d := ansDNS(t, ansHandler{answer: ansRRs(t,
		"www.example.test. 60 IN CNAME edge.cdn.test.",
		"edge.cdn.test. 60 IN CNAME pop.cdn.test.",
		"pop.cdn.test. 60 IN A 192.0.2.10",
		"pop.cdn.test. 60 IN AAAA 2001:db8::10",
		`pop.cdn.test. 60 IN TXT "v=spf1 " "-all"`,
		"pop.cdn.test. 60 IN MX 10 mx.cdn.test.",
		"pop.cdn.test. 60 IN NS ns.cdn.test.",
		"pop.cdn.test. 60 IN SOA ns.cdn.test. hostmaster.cdn.test. 7 3600 600 86400 300",
		`pop.cdn.test. 60 IN CAA 0 issue "ca.test"`,
		"planted.test. 60 IN A 192.0.2.99",
		`planted.test. 60 IN TXT "planted"`,
	)})

	got := ansLookups(d, "www.example.test")

	want := map[string]string{
		"A":     "[192.0.2.10] <nil>",
		"AAAA":  "[2001:db8::10] <nil>",
		"TXT":   "[v=spf1 -all] <nil>",
		"MX":    "[{10 mx.cdn.test}] <nil>",
		"NS":    "[ns.cdn.test] <nil>",
		"SOA":   "<nil> www.example.test is an alias (CNAME to edge.cdn.test)",
		"CAA":   "[{0 issue ca.test}] <nil>",
		"CNAME": "edge.cdn.test <nil>",
	}
	for rrtype, w := range want {
		if got[rrtype] != w {
			t.Errorf("Lookup%s = %s, want %s", rrtype, got[rrtype], w)
		}
	}
}

// ansChain returns a chain of hops CNAMEs from n0.test to n<hops>.test and
// an A record owned by the last name.
func ansChain(hops int) []string {
	var lines []string
	for i := range hops {
		lines = append(lines, fmt.Sprintf("n%d.test. 60 IN CNAME n%d.test.", i, i+1))
	}
	return append(lines, fmt.Sprintf("n%d.test. 60 IN A 192.0.2.1", hops))
}

// TestLookupChainLimits pins the hop cap: a chain of maxCNAMEHops aliases is
// followed, while a longer chain and a loop yield no records.
func TestLookupChainLimits(t *testing.T) {
	cases := []struct {
		desc   string
		answer []string
		want   string
	}{
		{"8 hops", ansChain(maxCNAMEHops), "[192.0.2.1]"},
		{"9 hops", ansChain(maxCNAMEHops + 1), "[]"},
		{"loop", []string{
			"n0.test. 60 IN CNAME n1.test.",
			"n1.test. 60 IN CNAME n0.test.",
			"n0.test. 60 IN A 192.0.2.1",
			"n1.test. 60 IN A 192.0.2.2",
		}, "[]"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			d := ansDNS(t, ansHandler{answer: ansRRs(t, c.answer...)})

			ips, err := d.LookupA(context.Background(), "n0.test")

			if err != nil || fmt.Sprint(ips) != c.want {
				t.Fatalf("LookupA = %v, %v; want %s", ips, err, c.want)
			}
		})
	}
}

// TestLookupSOAAuthority pins that the SOA in a NODATA reply's authority
// section answers only for names at or below its owner.
func TestLookupSOAAuthority(t *testing.T) {
	const soa = " 60 IN SOA ns1.zone.test. hostmaster.zone.test. 7 3600 600 86400 300"
	cases := []struct {
		desc   string
		answer []string
		owner  string
		wantNS string // "" means no SOA
	}{
		{"zone apex", nil, "www.example.test.", "ns1.zone.test"},
		{"enclosing zone", nil, "example.test.", "ns1.zone.test"},
		{"root zone", nil, ".", "ns1.zone.test"},
		{"unrelated zone", nil, "attacker.test.", ""},
		{"zone below the name", nil, "sub.www.example.test.", ""},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			d := ansDNS(t, ansHandler{
				answer: ansRRs(t, c.answer...),
				ns:     ansRRs(t, c.owner+soa),
			})

			got, err := d.LookupSOA(context.Background(), "www.example.test")

			if err != nil {
				t.Fatalf("LookupSOA: %v", err)
			}
			if gotNS := soaNS(got); gotNS != c.wantNS {
				t.Errorf("LookupSOA returned the SOA of %q, want %q", gotNS, c.wantNS)
			}
		})
	}
}

// TestLookupSOAAlias pins that an alias owns no SOA: LookupSOA reports the
// CNAME whether the reply carries the target zone's SOA in the answer or
// in the authority section.
func TestLookupSOAAlias(t *testing.T) {
	const cdnSOA = "cdn.test. 60 IN SOA ns.cdn.test. hostmaster.cdn.test. 7 3600 600 86400 300"
	cases := map[string]ansHandler{
		"target is a zone apex": {answer: ansRRs(t,
			"www.example.test. 60 IN CNAME cdn.test.", cdnSOA)},
		"target is inside a zone": {
			answer: ansRRs(t, "www.example.test. 60 IN CNAME edge.cdn.test."),
			ns:     ansRRs(t, cdnSOA),
		},
	}
	for desc, h := range cases {
		t.Run(desc, func(t *testing.T) {
			d := ansDNS(t, h)

			soa, err := d.LookupSOA(context.Background(), "www.example.test")

			var alias *AliasError
			if soa != nil || !errors.As(err, &alias) || alias.Name != "www.example.test" {
				t.Errorf("LookupSOA = %v, %v; want an *AliasError for www.example.test", soa, err)
			}
		})
	}
}

func soaNS(s *SOA) string {
	if s == nil {
		return ""
	}
	return s.NS
}

// TestLookupRcodeErrors pins how every Lookup* reports a failed rcode other
// than NXDOMAIN: an *RcodeError, of which only SERVFAIL and REFUSED mean the
// probe could not complete.
func TestLookupRcodeErrors(t *testing.T) {
	cases := []struct {
		rcode        int
		name         string
		probeFailure bool
	}{
		{mdns.RcodeServerFailure, "SERVFAIL", true},
		{mdns.RcodeRefused, "REFUSED", true},
		{mdns.RcodeFormatError, "FORMERR", false},
		{mdns.RcodeNotImplemented, "NOTIMP", false},
		{12, "rcode 12", false}, // unassigned
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := ansDNS(t, ansHandler{rcode: c.rcode})
			want := " resolver answered " + c.name

			for rrtype, got := range ansLookups(d, "example.test") {
				if !strings.HasSuffix(got, want) {
					t.Errorf("Lookup%s = %s, want an error ending %q", rrtype, got, want)
				}
			}
			_, err := d.LookupTXT(context.Background(), "example.test")
			var rcodeErr *RcodeError
			if !errors.As(err, &rcodeErr) || rcodeErr.Rcode != c.rcode {
				t.Fatalf("LookupTXT error = %v, want *RcodeError{%d}", err, c.rcode)
			}
			if got := IsProbeFailure(err); got != c.probeFailure {
				t.Errorf("IsProbeFailure(%v) = %v, want %v", err, got, c.probeFailure)
			}
		})
	}
}

// TestLookupNXDOMAIN pins that NXDOMAIN keeps its sentinel error, graded as
// an answer rather than a probe that could not complete.
func TestLookupNXDOMAIN(t *testing.T) {
	d := ansDNS(t, ansHandler{rcode: mdns.RcodeNameError})

	_, err := d.LookupA(context.Background(), "absent.example.test")

	if !errors.Is(err, ErrNXDOMAIN) || IsProbeFailure(err) {
		t.Errorf("got %v (probe failure %v), want ErrNXDOMAIN graded as an answer",
			err, IsProbeFailure(err))
	}
}

// ansBigTXT is the TXT payload ansReply carries: three 200-byte strings.
var ansBigTXT = []string{
	strings.Repeat("a", 200), strings.Repeat("b", 200), strings.Repeat("c", 200),
}

// ansReply is a NOERROR reply to req carrying one TXT record of ansBigTXT.
func ansReply(req *mdns.Msg) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = []mdns.RR{&mdns.TXT{
		Hdr: mdns.RR_Header{
			Name: req.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60,
		},
		Txt: ansBigTXT,
	}}
	return resp
}

// ansCutReply sends the first half of ansReply, as when a datagram larger
// than the client's buffer is cut short: the header and question parse,
// the answer does not.
func ansCutReply(w mdns.ResponseWriter, req *mdns.Msg) {
	wire, err := ansReply(req).Pack()
	if err != nil {
		return
	}
	_, _ = w.Write(wire[:len(wire)/2])
}

// TestExchangeCutReplyReturnsNoMessage pins that a reply that fails to parse
// never reaches the caller, not even partly parsed: a TCP answer cut inside
// its answer section yields an error and no message.
func TestExchangeCutReplyReturnsNoMessage(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	pc, l := listenUDPAndTCP(t)
	serve(t, &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(replyTruncated)})
	serve(t, &mdns.Server{Listener: l, Handler: mdns.HandlerFunc(ansCutReply)})
	d := NewDNS(pc.LocalAddr().String(), time.Second)
	ctx := context.Background()

	resp, err := d.Exchange(ctx, "big.example.test", mdns.TypeTXT)
	all := d.ExchangeAllWithDO(ctx, "big.example.test", mdns.TypeTXT)

	if resp != nil || err == nil {
		t.Errorf("Exchange = (%v, %v), want no message and an error", resp, err)
	}
	if len(all) != 1 || all[0].Msg != nil || all[0].Err == nil {
		t.Errorf("ExchangeAllWithDO = %+v, want one error without a message", all)
	}
}

// TestUnparsableUDPReplyRetriedOverTCP pins the fallback for a datagram that
// does not parse: the query is sent again over TCP rather than failing.
func TestUnparsableUDPReplyRetriedOverTCP(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	pc, l := listenUDPAndTCP(t)
	serve(t, &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(ansCutReply)})
	serve(t, &mdns.Server{Listener: l, Handler: mdns.HandlerFunc(
		func(w mdns.ResponseWriter, req *mdns.Msg) { _ = w.WriteMsg(ansReply(req)) })})
	d := NewDNS(pc.LocalAddr().String(), time.Second)

	txt, err := d.LookupTXT(context.Background(), "big.example.test")

	if err != nil || len(txt) != 1 || txt[0] != strings.Join(ansBigTXT, "") {
		t.Fatalf("want the full TXT record over TCP, got %d records, err %v", len(txt), err)
	}
}

// ansOPTRecorder answers NOERROR and records each query's EDNS0 OPT record
// as "<UDP size> do=<DO bit>", or "no OPT".
type ansOPTRecorder struct {
	mu   sync.Mutex
	opts []string
}

func (h *ansOPTRecorder) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	seen := "no OPT"
	if opt := req.IsEdns0(); opt != nil {
		seen = fmt.Sprintf("%d do=%v", opt.UDPSize(), opt.Do())
	}
	h.mu.Lock()
	h.opts = append(h.opts, seen)
	h.mu.Unlock()
	resp := new(mdns.Msg)
	resp.SetReply(req)
	_ = w.WriteMsg(resp)
}

// TestQueriesAdvertiseEDNSBuffer pins the EDNS0 OPT record every query
// carries: a 1232-byte UDP buffer, with DO set only where it is asked for.
func TestQueriesAdvertiseEDNSBuffer(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &ansOPTRecorder{}
	d := NewDNS(startUDPResolver(t, h), time.Second)
	ctx := context.Background()

	_, _ = d.LookupTXT(ctx, "example.test")
	_, _ = d.Exchange(ctx, "example.test", mdns.TypeA)
	_, _ = d.ExchangeWithDO(ctx, "example.test", mdns.TypeDNSKEY)
	_ = d.ExchangeAllCheckingDisabled(ctx, ".", mdns.TypeDNSKEY)

	h.mu.Lock()
	defer h.mu.Unlock()
	want := []string{"1232 do=false", "1232 do=false", "1232 do=true", "1232 do=true"}
	if !slices.Equal(h.opts, want) {
		t.Errorf("queries carried OPT %q, want %q", h.opts, want)
	}
}

// ansNoEDNS answers like a server that does not implement EDNS: FORMERR to
// a query carrying an OPT record, and one A record otherwise. It records
// each query it gets as "OPT" or "no OPT".
type ansNoEDNS struct {
	mu   sync.Mutex
	seen []string
}

func (h *ansNoEDNS) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	seen := "no OPT"
	if req.IsEdns0() != nil {
		seen = "OPT"
		resp.SetRcode(req, mdns.RcodeFormatError)
	} else {
		resp.SetReply(req)
		resp.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{
				Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60,
			},
			A: net.IPv4(192, 0, 2, 1),
		}}
	}
	h.mu.Lock()
	h.seen = append(h.seen, seen)
	h.mu.Unlock()
	_ = w.WriteMsg(resp)
}

// TestFORMERRRetriedWithoutEDNS: a server that rejects the OPT record with
// FORMERR is asked once more without it (RFC 6891 §7), so lookups still get
// an answer. A DNSSEC query needs EDNS for its DO bit, so it keeps the
// FORMERR.
func TestFORMERRRetriedWithoutEDNS(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &ansNoEDNS{}
	d := NewDNS(startUDPResolver(t, h), time.Second)
	ctx := context.Background()

	ips, err := d.LookupA(ctx, "example.test")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(192, 0, 2, 1)) {
		t.Errorf("LookupA = %v, %v; want 192.0.2.1", ips, err)
	}
	resp, err := d.ExchangeWithDO(ctx, "example.test", mdns.TypeDNSKEY)
	if err != nil || resp.Rcode != mdns.RcodeFormatError {
		t.Errorf("ExchangeWithDO = %v, %v; want the FORMERR", resp, err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if want := []string{"OPT", "no OPT", "OPT"}; !slices.Equal(h.seen, want) {
		t.Errorf("server got queries %q, want %q", h.seen, want)
	}
}

// TestDoHErrorOmitsURL pins that a DoH failure names the upstream by its
// label: the URL's userinfo, path and query, which can carry credentials,
// stay out of the error.
func TestDoHErrorOmitsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close() // no response at all
		}
	}))
	defer srv.Close()
	d := dohDNS(srv)
	d.upstreams[0].addr = strings.Replace(srv.URL, "://", "://alice:hunter2@", 1) +
		"/acct-7f3a/dns-query?token=s3cret"

	_, err := d.LookupA(context.Background(), "example.test")

	if err == nil || !strings.HasPrefix(err.Error(), "fake-doh: ") {
		t.Fatalf("want an error labelled fake-doh, got %v", err)
	}
	for _, secret := range []string{"alice", "hunter2", "acct-7f3a", "s3cret"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q leaks %q from the DoH URL", err, secret)
		}
	}
}

// TestDoHBodyErrorOmitsAddresses pins that a DoH connection reset while the
// response body is read leaves the local and server addresses out of the
// error.
func TestDoHBodyErrorOmitsAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0) // reset rather than close
		}
		_ = conn.Close()
	}))
	defer srv.Close()
	d := dohDNS(srv)

	_, err := d.LookupA(context.Background(), "example.test")

	if err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("want an error without loopback addresses, got %v", err)
	}
}
