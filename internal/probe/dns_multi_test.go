package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// rcodeHandler answers every query with a fixed rcode and AD bit, and records
// the header flags of each query it receives so tests can assert what went on
// the wire.
type rcodeHandler struct {
	rcode  int
	ad     bool
	silent bool // never reply: simulates a black-holed upstream

	mu   sync.Mutex
	seen []queryFlags
}

type queryFlags struct {
	do, cd, rd bool
	opcode     int
}

// sentinelQuery is the query header RFC 8509 §2.1 needs (OPCODE QUERY, CD=0)
// plus the RD and DO bits that let a validating resolver report AD.
var sentinelQuery = queryFlags{do: true, cd: false, rd: true, opcode: mdns.OpcodeQuery}

func (h *rcodeHandler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	h.mu.Lock()
	h.seen = append(h.seen, flagsOf(req))
	h.mu.Unlock()
	if h.silent {
		return
	}
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Rcode = h.rcode
	resp.AuthenticatedData = h.ad
	_ = w.WriteMsg(resp)
}

func (h *rcodeHandler) queries() []queryFlags {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]queryFlags(nil), h.seen...)
}

func flagsOf(m *mdns.Msg) queryFlags {
	opt := m.IsEdns0()
	return queryFlags{
		do:     opt != nil && opt.Do(),
		cd:     m.CheckingDisabled,
		rd:     m.RecursionDesired,
		opcode: m.Opcode,
	}
}

// TestExchangeAllWithDOPerUpstream proves each upstream is queried once with
// OPCODE QUERY, DO=1, CD=0, RD=1, that results come back in upstream order,
// that SERVFAIL is a response rather than an error, and that a silent
// upstream fails in its own slot without affecting the others.
func TestExchangeAllWithDOPerUpstream(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	cases := []struct {
		h     *rcodeHandler
		check func(MultiResp) bool
		want  string
	}{
		{
			h:     &rcodeHandler{rcode: mdns.RcodeNameError, ad: true},
			check: isReply(mdns.RcodeNameError, true),
			want:  "NXDOMAIN+AD",
		},
		{
			h:     &rcodeHandler{rcode: mdns.RcodeServerFailure},
			check: isReply(mdns.RcodeServerFailure, false),
			want:  "SERVFAIL reply",
		},
		{
			h:     &rcodeHandler{silent: true},
			check: func(r MultiResp) bool { return r.Err != nil },
			want:  "an error",
		},
	}
	specs := make([]string, len(cases))
	for i, c := range cases {
		specs[i] = startUDPResolver(t, c.h)
	}
	d, err := NewMultiDNS(specs, time.Second)
	if err != nil {
		t.Fatalf("NewMultiDNS: %v", err)
	}

	got := d.ExchangeAllWithDO(context.Background(), "root-key-sentinel-is-ta-20326.", mdns.TypeA)

	if len(got) != len(cases) {
		t.Fatalf("want %d responses, got %d", len(cases), len(got))
	}
	for i, c := range cases {
		if got[i].Upstream != specs[i] || !c.check(got[i]) {
			t.Errorf("slot %d: got %+v, want %s from %s", i, got[i], c.want, specs[i])
		}
		assertQueriedOnce(t, c.h, sentinelQuery)
	}
}

func isReply(rcode int, ad bool) func(MultiResp) bool {
	return func(r MultiResp) bool {
		return r.Err == nil && r.Msg != nil && r.Msg.Rcode == rcode && r.Msg.AuthenticatedData == ad
	}
}

func assertQueriedOnce(t *testing.T, h *rcodeHandler, want queryFlags) {
	t.Helper()
	if qs := h.queries(); len(qs) != 1 || qs[0] != want {
		t.Errorf("upstream saw queries %+v, want exactly one with %+v", qs, want)
	}
}

// TestExchangeAllCheckingDisabledSetsCD pins the root DNSKEY query the
// sentinel check sends to every upstream: DO=1 and CD=1, so a resolver that
// cannot validate still returns the RRset and its RRSIGs.
func TestExchangeAllCheckingDisabledSetsCD(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &rcodeHandler{rcode: mdns.RcodeSuccess}
	d, err := NewMultiDNS([]string{startUDPResolver(t, h)}, time.Second)
	if err != nil {
		t.Fatalf("NewMultiDNS: %v", err)
	}

	got := d.ExchangeAllCheckingDisabled(context.Background(), ".", mdns.TypeDNSKEY)

	if len(got) != 1 || !isReply(mdns.RcodeSuccess, false)(got[0]) {
		t.Fatalf("want one NOERROR response, got %+v", got)
	}
	assertQueriedOnce(t, h, queryFlags{do: true, cd: true, rd: true, opcode: mdns.OpcodeQuery})
}

// TestExchangeCheckingDisabledSetsCD pins the DS, DNSKEY and SOA queries of
// the DNSSEC chain check: DO=1 and CD=1, so a validating resolver returns a
// bogus zone's records, and the reply comes back whatever its rcode.
func TestExchangeCheckingDisabledSetsCD(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &rcodeHandler{rcode: mdns.RcodeServerFailure}
	d := NewDNS(startUDPResolver(t, h), time.Second)

	resp, err := d.ExchangeCheckingDisabled(context.Background(), "example.test.", mdns.TypeDS)

	if err != nil || resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("want the SERVFAIL reply, got resp=%v err=%v", resp, err)
	}
	assertQueriedOnce(t, h, queryFlags{do: true, cd: true, rd: true, opcode: mdns.OpcodeQuery})
}

// TestExchangeAllWithDOSpecError returns the deferred resolver-spec error in
// a single MultiResp.
func TestExchangeAllWithDOSpecError(t *testing.T) {
	d := NewDNS(" ", time.Second)

	got := d.ExchangeAllWithDO(context.Background(), "example.test.", mdns.TypeA)

	if len(got) != 1 || got[0].Err == nil || got[0].Msg != nil {
		t.Fatalf("want a single error response, got %+v", got)
	}
}

// TestExchangeDoesNotRetransmitSERVFAIL pins that the timeout retransmit
// never repeats a query the upstream answered, even with SERVFAIL: the RFC
// 8509 sentinel reads SERVFAIL as a signal, and RFC 2308 §7 lets resolvers
// cache it, so a retry adds load without changing the answer.
func TestExchangeDoesNotRetransmitSERVFAIL(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	h := &rcodeHandler{rcode: mdns.RcodeServerFailure}
	spec := startUDPResolver(t, h)
	d := NewDNS(spec, minRetransmitBudget) // budget large enough to allow a retry

	const name = "root-key-sentinel-not-ta-20326."
	resp, err := d.ExchangeWithDO(context.Background(), name, mdns.TypeA)

	if err != nil || resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL response, got resp=%v err=%v", resp, err)
	}
	if n := len(h.queries()); n != 1 {
		t.Fatalf("SERVFAIL must not be retransmitted; upstream saw %d queries", n)
	}
}

// TestDoHServfailIsAResponse pins RFC 8484 §4.2.1 handling: a DoH server
// returns HTTP 200 with a SERVFAIL message body, and the client must surface
// it as a response with Rcode 2, not as a transport error.
func TestDoHServfailIsAResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, dohMaxResponse))
		req := new(mdns.Msg)
		if err != nil || req.Unpack(body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		wire, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer srv.Close()
	d := dohDNS(srv)

	got := d.ExchangeAllWithDO(context.Background(), "root-key-sentinel-not-ta-20326.", mdns.TypeA)

	if len(got) != 1 || got[0].Err != nil || got[0].Msg.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("want a SERVFAIL response over DoH, got %+v", got)
	}
}

// TestDoHResponseSizeCap pins the 64 KiB cap on a DoH response body: one
// byte over is refused as oversize, while a body at the cap is read whole.
func TestDoHResponseSizeCap(t *testing.T) {
	cases := []struct {
		size     int
		oversize bool
	}{{dohMaxResponse + 1, true}, {dohMaxResponse, false}}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(make([]byte, c.size))
		}))

		_, err := dohDNS(srv).LookupA(context.Background(), "example.test")
		srv.Close()

		refused := err != nil && strings.Contains(err.Error(), "exceeds 64 KiB cap")
		if refused != c.oversize {
			t.Errorf("%d-byte body: got %v, want refused as oversize: %v", c.size, err, c.oversize)
		}
	}
}

// TestTCPFallbackServfailIsAResponse covers the truncation path: a UDP reply
// with TC=1 sends the query again over TCP, and that SERVFAIL must come back
// as a response.
func TestTCPFallbackServfailIsAResponse(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	pc, l := listenUDPAndTCP(t)
	tcp := &rcodeHandler{rcode: mdns.RcodeServerFailure}
	serve(t, &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(replyTruncated)})
	serve(t, &mdns.Server{Listener: l, Handler: tcp})
	d := NewDNS(pc.LocalAddr().String(), time.Second)

	const name = "root-key-sentinel-not-ta-20326."
	got := d.ExchangeAllWithDO(context.Background(), name, mdns.TypeA)

	if len(got) != 1 || !isReply(mdns.RcodeServerFailure, false)(got[0]) {
		t.Fatalf("want a SERVFAIL response over TCP, got %+v", got)
	}
	assertQueriedOnce(t, tcp, sentinelQuery)
}

func replyTruncated(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Truncated = true
	_ = w.WriteMsg(resp)
}

// listenUDPAndTCP binds a loopback UDP socket and a TCP listener on the same
// port, as a resolver that moves truncated answers to TCP needs.
func listenUDPAndTCP(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for range 5 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		l, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, l
		}
		_ = pc.Close()
	}
	t.Fatal("no loopback port was free for both UDP and TCP")
	return nil, nil
}

// TestDoTServfailIsAResponse covers the DoT transport: a SERVFAIL over TLS
// must come back as a response, as it does over UDP, TCP and DoH.
func TestDoTServfailIsAResponse(t *testing.T) {
	cert, roots := loopbackCert(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	h := &rcodeHandler{rcode: mdns.RcodeServerFailure}
	serve(t, &mdns.Server{Listener: l, Net: "tcp-tls", Handler: h})
	d := &DNS{
		timeout:   2 * time.Second,
		upstreams: []upstream{{label: "fake-dot", addr: l.Addr().String(), protocol: protoDoT}},
		dotClient: &mdns.Client{Net: "tcp-tls", Timeout: 2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}
	d.once.Do(func() {}) // keep the injected dotClient

	got := d.ExchangeAllWithDO(context.Background(), "root-key-sentinel-not-ta-20326.", mdns.TypeA)

	if len(got) != 1 || !isReply(mdns.RcodeServerFailure, false)(got[0]) {
		t.Fatalf("want a SERVFAIL response over DoT, got %+v", got)
	}
	assertQueriedOnce(t, h, sentinelQuery)
}

// loopbackCert borrows httptest's self-signed certificate, which is valid for
// 127.0.0.1, and returns it with a pool that trusts it.
func loopbackCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv.TLS.Certificates[0], roots
}
