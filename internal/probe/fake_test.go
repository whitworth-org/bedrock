// fake_test.go provides in-process fakes for the DNS resolver. The fakes
// exist so tests can drive checks deterministically without making a single
// outbound network request. They live in `package probe` so they can build
// up a *DNS using internal fields (upstreams, the sync.Once, the http
// client used by DoH) without any production-code accommodation.
//
// Two flavors are provided:
//
//   - newFakeUDPResolver: a real miekg/dns UDP server bound to 127.0.0.1
//     on a random port (startUDPResolver serves any handler that way). This
//     is the path the project's root-level integration_test.go uses
//     indirectly: it just spawns its own UDP resolver via the same
//     primitives. It is the cleanest fake because the production
//     NewDNS(spec, ...) parses the host:port spec normally.
//
//   - newFakeDoHDNS: builds a *DNS directly with a DoH upstream pointed at
//     an httptest.Server (plain HTTP). Achieves a pure-process fake without
//     opening UDP sockets — useful for environments where binding UDP is
//     restricted. Requires reaching into unexported probe fields, which is
//     why this code is in the probe package itself.
//
// The integration test at the repo root cannot import _test.go symbols
// from this package (Go's package boundary). It instead uses the same
// in-process miekg/dns UDP server pattern. Keeping the canonical
// implementation here documents the technique and gives the probe package
// a self-contained way to exercise its own resolver paths.

package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// fakeZone is the canned answer set used by the fake resolvers. Map key is
// "<lowercased-fqdn>|<RR type symbolic name>"; value is the list of RRs to
// return. A miss is replied as NXDOMAIN by default.
type fakeZone struct {
	mu      sync.RWMutex
	answers map[string][]mdns.RR
}

func newFakeZone() *fakeZone {
	return &fakeZone{answers: map[string][]mdns.RR{}}
}

// Add seeds the zone with one or more RRs. RRs are parsed as zone-file
// strings; the fakeZone derives the question name and type from each RR.
func (z *fakeZone) Add(t *testing.T, rrText string) {
	t.Helper()
	rr, err := mdns.NewRR(rrText)
	if err != nil {
		t.Fatalf("fakeZone.Add: parse %q: %v", rrText, err)
	}
	hdr := rr.Header()
	key := zoneKey(hdr.Name, hdr.Rrtype)
	z.mu.Lock()
	z.answers[key] = append(z.answers[key], rr)
	z.mu.Unlock()
}

func (z *fakeZone) lookup(name string, qtype uint16) []mdns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.answers[zoneKey(name, qtype)]
}

func zoneKey(name string, qtype uint16) string {
	return strings.ToLower(mdns.Fqdn(name)) + "|" + fmt.Sprint(qtype)
}

// handler implements miekg/dns.Handler against the fakeZone.
type fakeHandler struct{ z *fakeZone }

func (h fakeHandler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if len(req.Question) == 0 {
		_ = w.WriteMsg(resp)
		return
	}
	q := req.Question[0]
	rrs := h.z.lookup(q.Name, q.Qtype)
	if len(rrs) == 0 {
		// NXDOMAIN — distinct from NODATA. Checks treat both equivalently
		// for "no such record" semantics.
		resp.Rcode = mdns.RcodeNameError
		_ = w.WriteMsg(resp)
		return
	}
	resp.Answer = append(resp.Answer, rrs...)
	_ = w.WriteMsg(resp)
}

// newFakeUDPResolver starts a real miekg/dns UDP server on 127.0.0.1 on a
// random free port. Returns the host:port spec usable directly with
// probe.NewDNS / probe.NewEnv, and a zone you can seed with answers BEFORE or
// AFTER the server starts. The server shuts down when the test ends.
func newFakeUDPResolver(t *testing.T) (spec string, zone *fakeZone) {
	t.Helper()
	zone = newFakeZone()
	return startUDPResolver(t, fakeHandler{z: zone}), zone
}

// startUDPResolver serves h on a random loopback UDP port until the test
// ends and returns the host:port spec.
func startUDPResolver(t *testing.T, h mdns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	serve(t, &mdns.Server{PacketConn: pc, Handler: h})
	return pc.LocalAddr().String()
}

// serve starts srv, waits until it accepts queries, and shuts it down when
// the test ends.
func serve(t *testing.T, srv *mdns.Server) {
	t.Helper()
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not start within 2s")
	}
}

// newFakeDoHDNS builds a *DNS that talks DoH to a plaintext httptest server.
// We construct the DNS struct manually so we can pre-set the unexported
// httpClient (we need to use the test server's client which trusts itself
// and tolerates plain-HTTP DoH). Calling sync.Once.Do up-front consumes the
// guard so subsequent calls to ensureClients() are no-ops and our injected
// httpClient survives.
func newFakeDoHDNS(t *testing.T) (*DNS, *fakeZone, func()) {
	t.Helper()
	zone := newFakeZone()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decode the wire-format DNS query, dispatch through fakeHandler,
		// then re-encode the response. Mirrors the RFC 8484 contract.
		buf := make([]byte, 0, 4096)
		const maxBody = 1 << 16
		// Read at most maxBody bytes — DoH messages are small.
		tmp := make([]byte, 4096)
		for {
			n, err := r.Body.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if len(buf) > maxBody {
					http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
					return
				}
			}
			if err != nil {
				break
			}
		}
		req := new(mdns.Msg)
		if err := req.Unpack(buf); err != nil {
			http.Error(w, "bad msg", http.StatusBadRequest)
			return
		}
		// Reuse fakeHandler's logic by constructing a tiny in-memory writer.
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		if len(req.Question) > 0 {
			q := req.Question[0]
			rrs := zone.lookup(q.Name, q.Qtype)
			if len(rrs) == 0 {
				resp.Rcode = mdns.RcodeNameError
			} else {
				resp.Answer = append(resp.Answer, rrs...)
			}
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))

	return dohDNS(srv), zone, srv.Close
}

// dohDNS returns a *DNS whose only upstream is the DoH server srv, reached
// with srv's own client so that a test server's certificate is trusted.
func dohDNS(srv *httptest.Server) *DNS {
	d := &DNS{
		timeout:    2 * time.Second,
		upstreams:  []upstream{{label: "fake-doh", addr: srv.URL, protocol: protoDoH}},
		httpClient: srv.Client(),
	}
	// Burn the once so a real ensureClients call won't overwrite httpClient.
	d.once.Do(func() {})
	return d
}

// ---- tests that exercise the fakes themselves ----

func TestFakeUDPResolver_NXDOMAINByDefault(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	spec, _ := newFakeUDPResolver(t)

	d := NewDNS(spec, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := d.LookupTXT(ctx, "absent.test.invalid.")
	if err != ErrNXDOMAIN {
		t.Fatalf("want ErrNXDOMAIN, got %v", err)
	}
}

func TestFakeUDPResolver_SeededAnswers(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	spec, zone := newFakeUDPResolver(t)

	zone.Add(t, `txt.test.invalid. 60 IN TXT "hello world"`)
	zone.Add(t, `mx.test.invalid.  60 IN MX  10 mail.test.invalid.`)
	zone.Add(t, `ns.test.invalid.  60 IN NS  ns1.test.invalid.`)
	zone.Add(t, `ns.test.invalid.  60 IN NS  ns2.test.invalid.`)

	d := NewDNS(spec, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	txt, err := d.LookupTXT(ctx, "txt.test.invalid.")
	if err != nil {
		t.Fatalf("TXT: %v", err)
	}
	if len(txt) != 1 || txt[0] != "hello world" {
		t.Fatalf("TXT: got %v", txt)
	}

	mx, err := d.LookupMX(ctx, "mx.test.invalid.")
	if err != nil {
		t.Fatalf("MX: %v", err)
	}
	if len(mx) != 1 || mx[0].Preference != 10 || mx[0].Host != "mail.test.invalid" {
		t.Fatalf("MX: got %+v", mx)
	}

	ns, err := d.LookupNS(ctx, "ns.test.invalid.")
	if err != nil {
		t.Fatalf("NS: %v", err)
	}
	if len(ns) != 2 {
		t.Fatalf("NS: want 2, got %d (%v)", len(ns), ns)
	}
}

func TestFakeDoHDNS_NXDOMAINByDefault(t *testing.T) {
	d, _, cleanup := newFakeDoHDNS(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := d.LookupTXT(ctx, "absent.test.invalid.")
	if err != ErrNXDOMAIN {
		t.Fatalf("want ErrNXDOMAIN, got %v", err)
	}
}

func TestFakeDoHDNS_SeededAnswers(t *testing.T) {
	d, zone, cleanup := newFakeDoHDNS(t)
	defer cleanup()

	zone.Add(t, `txt.test.invalid. 60 IN TXT "doh works"`)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	txt, err := d.LookupTXT(ctx, "txt.test.invalid.")
	if err != nil {
		t.Fatalf("TXT: %v", err)
	}
	if len(txt) != 1 || txt[0] != "doh works" {
		t.Fatalf("TXT: got %v", txt)
	}
}
