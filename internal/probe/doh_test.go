package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func dohQuery() *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion("example.com.", mdns.TypeA)
	return m
}

// dohHandler answers every request, whatever its method or body, with the
// same valid DNS response under media type ct, so a test can tell whether a
// request reached it.
func dohHandler(t *testing.T, ct string) http.HandlerFunc {
	t.Helper()
	answer := dohQuery()
	answer.Response = true
	wire, err := answer.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(wire)
	}
}

// TestDoHDoesNotFollowRedirects: a 3xx from the DoH server is an error, so
// a query is never moved to another server or to plaintext http://, and
// the redirect target never sees it.
func TestDoHDoesNotFollowRedirects(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	var reached atomic.Int32
	answer := dohHandler(t, "application/dns-message")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		answer(w, r)
	}))
	defer target.Close()

	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		redirect := httptest.NewTLSServer(http.RedirectHandler(target.URL+"/dns-query", code))
		client := newDoHClient(2 * time.Second)
		trustTestServer(client.Transport, redirect)
		_, err := dohExchange(context.Background(), client, redirect.URL+"/dns-query", dohQuery())
		redirect.Close()
		if err == nil {
			t.Errorf("dohExchange followed a %d to %s", code, target.URL)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the redirect target received %d queries, want 0", n)
	}
}

// TestDoHRequiresDNSMessageMediaType: the media type must be exactly
// application/dns-message; parameters, even malformed ones, are ignored.
func TestDoHRequiresDNSMessageMediaType(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	cases := []struct {
		contentType string
		ok          bool
	}{
		{"application/dns-message", true},
		{"Application/DNS-Message", true},
		{"application/dns-message; charset=utf-8", true},
		{"application/dns-message; =malformed", true},
		{"application/dns-messagey", false},
		{"application/dns-message-json", false},
		{"application/dns-json", false},
		{"text/html", false},
		{"", false},
	}
	client := newDoHClient(2 * time.Second)
	for _, c := range cases {
		srv := httptest.NewServer(dohHandler(t, c.contentType))
		_, err := dohExchange(context.Background(), client, srv.URL, dohQuery())
		srv.Close()
		if (err == nil) != c.ok {
			t.Errorf("Content-Type %q: dohExchange error = %v, want accepted %v",
				c.contentType, err, c.ok)
		}
	}
}

// TestDoHReusesConnections: sequential queries share one connection instead
// of paying a TCP and TLS handshake each.
func TestDoHReusesConnections(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewUnstartedServer(dohHandler(t, "application/dns-message"))
	srv.EnableHTTP2 = true
	conns := countConns(srv)
	srv.StartTLS()
	defer srv.Close()
	client := newDoHClient(2 * time.Second)
	trustTestServer(client.Transport, srv)

	for i := range 20 {
		if _, err := dohExchange(context.Background(), client, srv.URL, dohQuery()); err != nil {
			t.Fatalf("query %d: %v", i+1, err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("20 queries opened %d connections, want 1", n)
	}
}

// TestDoHResendsQueryOnClosedIdleConnection: when a server drops a kept-alive
// connection just as the next query arrives on it, as an idle timeout does,
// the query is sent again on a new connection instead of failing with EOF.
func TestDoHResendsQueryOnClosedIdleConnection(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	answer := dohHandler(t, "application/dns-message")
	var seen sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, reused := seen.LoadOrStore(r.RemoteAddr, true); reused {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		answer(w, r)
	}))
	defer srv.Close()
	client := newDoHClient(2 * time.Second)

	for i := range 2 {
		if _, err := dohExchange(context.Background(), client, srv.URL, dohQuery()); err != nil {
			t.Fatalf("query %d: %v", i+1, err)
		}
	}
}

// TestDoHBoundsResponseHeaders: a DoH server cannot make the client buffer
// megabytes of response headers.
func TestDoHBoundsResponseHeaders(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	answer := dohHandler(t, "application/dns-message")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Filler", strings.Repeat("a", 300<<10))
		answer(w, r)
	}))
	defer srv.Close()

	_, err := dohExchange(context.Background(), newDoHClient(2*time.Second), srv.URL, dohQuery())
	if err == nil {
		t.Error("dohExchange accepted a 300 KiB response header")
	}
}
