package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// cancelBudget is the timeout these tests give each lookup. Its first
// attempt lasts at least half of it, far longer than cancelBound, so a
// lookup returns within cancelBound only when the cancellation ends it.
const cancelBudget = 5 * time.Second

// cancelBound is how soon after its cancellation a lookup must return.
const cancelBound = time.Second

// blackHole reports each query that reaches it on queried and never
// answers. It serves DNS over UDP, TCP and TLS, and DoH.
type blackHole struct{ queried chan struct{} }

func newBlackHole() blackHole { return blackHole{queried: make(chan struct{}, 1)} }

func (h blackHole) arrived() {
	select {
	case h.queried <- struct{}{}:
	default: // an arrival is already pending
	}
}

func (h blackHole) ServeDNS(mdns.ResponseWriter, *mdns.Msg) { h.arrived() }

func (h blackHole) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	// Only once the body is read does the server watch for the client
	// leaving, which ends r.Context().
	_, _ = io.Copy(io.Discard, r.Body)
	h.arrived()
	<-r.Context().Done()
}

// lookupCancelledInFlight starts d.LookupA and cancels it once queried
// reports that the query reached the server. It fails the test unless the
// lookup then returns within cancelBound with "<upstream>: context
// canceled": the context's error rather than a socket error, from upstream,
// the resolver the lookup was waiting on.
func lookupCancelledInFlight(t *testing.T, d *DNS, queried <-chan struct{}, upstream string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := d.LookupA(ctx, "www.example.test")
		done <- err
	}()
	select {
	case <-queried:
	case err := <-done:
		t.Fatalf("lookup returned %v before the query reached the server", err)
	}
	cancel()
	cancelled := time.Now()
	err := <-done
	if elapsed := time.Since(cancelled); elapsed > cancelBound {
		t.Errorf("lookup returned %v after the cancel, want within %v",
			elapsed.Round(time.Millisecond), cancelBound)
	}
	want := upstream + ": " + context.Canceled.Error()
	if !errors.Is(err, context.Canceled) || err.Error() != want {
		t.Errorf("lookup error = %v, want %q", err, want)
	}
}

// TestLookupCancelEndsUDPQuery pins that cancelling a lookup whose query is
// on the wire ends it at once with the context's error rather than when the
// attempt times out, and that Health does not count the query against the
// resolver.
func TestLookupCancelEndsUDPQuery(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	h := newBlackHole()
	spec := startUDPResolver(t, h)
	d := NewDNS(spec, cancelBudget)

	lookupCancelledInFlight(t, d, h.queried, spec)

	wantHealth(t, d, "a cancelled lookup", [3]int{0, 0, 0})
}

// TestLookupCancelEndsTCPRetry is TestLookupCancelEndsUDPQuery for the query
// that a truncated UDP reply sends again over TCP.
func TestLookupCancelEndsTCPRetry(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	pc, l := listenUDPAndTCP(t)
	h := newBlackHole()
	serve(t, &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(replyTruncated)})
	serve(t, &mdns.Server{Listener: l, Handler: h})
	spec := pc.LocalAddr().String()
	d := NewDNS(spec, cancelBudget)

	lookupCancelledInFlight(t, d, h.queried, spec)

	wantHealth(t, d, "a cancelled lookup", [3]int{0, 0, 0})
}

// TestLookupCancelEndsDoTQuery is TestLookupCancelEndsUDPQuery over DoT.
func TestLookupCancelEndsDoTQuery(t *testing.T) {
	cert, roots := loopbackCert(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	h := newBlackHole()
	serve(t, &mdns.Server{Listener: l, Net: "tcp-tls", Handler: h})
	d := &DNS{
		timeout:   cancelBudget,
		upstreams: []upstream{{label: "fake-dot", addr: l.Addr().String(), protocol: protoDoT}},
		dotClient: &mdns.Client{Net: "tcp-tls", Timeout: cancelBudget,
			TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}
	d.once.Do(func() {}) // keep the injected dotClient

	lookupCancelledInFlight(t, d, h.queried, "fake-dot")

	wantHealth(t, d, "a cancelled lookup", [3]int{0, 0, 0})
}

// TestLookupCancelEndsDoHQuery is TestLookupCancelEndsUDPQuery over DoH.
func TestLookupCancelEndsDoHQuery(t *testing.T) {
	h := newBlackHole()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	d := dohDNS(srv)
	d.timeout = cancelBudget

	lookupCancelledInFlight(t, d, h.queried, "fake-doh")

	wantHealth(t, d, "a cancelled lookup", [3]int{0, 0, 0})
}

// TestLookupCancelDoesNotFailOver pins that a cancelled lookup ends at the
// system resolver it was waiting on: the next one, which would answer, is
// never asked.
func TestLookupCancelDoesNotFailOver(t *testing.T) {
	h := newBlackHole()
	d := failoverDNS(cancelBudget, startUDPResolver(t, h), failoverHealthy(t))

	lookupCancelledInFlight(t, d, h.queried, "system-1")

	wantHealth(t, d, "a cancelled lookup", [3]int{0, 0, 0})
}
