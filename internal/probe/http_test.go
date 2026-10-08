package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// redirector answers /r?to=<url> with a 302 to <url> and any other request
// with 200 "ok".
var redirector = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if to := r.URL.Query().Get("to"); to != "" {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	_, _ = io.WriteString(w, "ok")
})

// chainURL returns a URL that redirects through each hop in turn and ends
// at the last one. Every hop but the last must serve redirector.
func chainURL(hops ...string) string {
	target := hops[len(hops)-1]
	for i := len(hops) - 2; i >= 0; i-- {
		target = hops[i] + "/r?to=" + url.QueryEscape(target)
	}
	return target
}

// requestedURLs returns the URL of every request that following
// chainURL(hops...) sends, oldest first.
func requestedURLs(hops []string) []string {
	urls := make([]string, len(hops))
	for i := range hops {
		urls[i] = chainURL(hops[i:]...)
	}
	return urls
}

func urlStrings(urls []*url.URL) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = u.String()
	}
	return out
}

// trustTestServer makes tr trust the certificate that httptest TLS servers
// present.
func trustTestServer(tr http.RoundTripper, srv *httptest.Server) {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr.(*http.Transport).TLSClientConfig.RootCAs = pool
}

// countConns makes the unstarted srv count the connections it accepts.
func countConns(srv *httptest.Server) *atomic.Int32 {
	var n atomic.Int32
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			n.Add(1)
		}
	}
	return &n
}

// trackOpenConns makes the unstarted srv count the connections it holds
// open.
func trackOpenConns(srv *httptest.Server) *atomic.Int32 {
	var open atomic.Int32
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}
	return &open
}

type fetcher struct {
	name  string
	fetch func(target string) (*Response, error)
}

// fetchers returns Get, Do and DoStrict as GETs of a URL.
func fetchers(h *HTTP) (get, do, doStrict fetcher) {
	ctx := context.Background()
	send := func(name string, do func(*http.Request) (*Response, error)) fetcher {
		return fetcher{name, func(target string) (*Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				return nil, err
			}
			return do(req)
		}}
	}
	get = fetcher{"Get", func(target string) (*Response, error) { return h.Get(ctx, target) }}
	return get, send("Do", h.Do), send("DoStrict", h.DoStrict)
}

// startRedirectors serves redirector over plain HTTP and over TLS until the
// test ends. It returns both base URLs and an HTTP that trusts the TLS one.
func startRedirectors(t *testing.T) (plain, secure string, h *HTTP) {
	t.Helper()
	plainSrv := httptest.NewServer(redirector)
	t.Cleanup(plainSrv.Close)
	secureSrv := httptest.NewTLSServer(redirector)
	t.Cleanup(secureSrv.Close)
	h = NewHTTP(2 * time.Second)
	trustTestServer(h.client.Transport, secureSrv)
	return plainSrv.URL, secureSrv.URL, h
}

type redirectCase struct {
	name string
	hops []string
	via  []fetcher
}

// TestRedirectsRefuseDowngradeAtAnyHop: an https-to-http hop is refused
// wherever it falls in the chain, including chains that start on plain
// http.
func TestRedirectsRefuseDowngradeAtAnyHop(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	plain, secure, h := startRedirectors(t)
	get, do, doStrict := fetchers(h)

	cases := []redirectCase{
		{"http-https-http-https",
			[]string{plain, secure, plain, secure + "/final"}, []fetcher{get, do}},
		{"https-https-http",
			[]string{secure, secure, plain + "/final"}, []fetcher{get, do, doStrict}},
	}
	for _, c := range cases {
		for _, f := range c.via {
			_, err := f.fetch(chainURL(c.hops...))
			if err == nil || !strings.Contains(err.Error(), "downgraded from https to http") {
				t.Errorf("%s(%s) = %v, want the https-to-http hop refused", f.name, c.name, err)
			}
		}
	}
}

// TestRedirectsFollowHTTPSChainsInOrder: a chain that stays on https once it
// reaches it is followed, and every request it took is recorded, oldest
// first.
func TestRedirectsFollowHTTPSChainsInOrder(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	plain, secure, h := startRedirectors(t)
	get, do, doStrict := fetchers(h)
	final := secure + "/final"

	cases := []redirectCase{
		{"http-https-https", []string{plain, secure, final}, []fetcher{get, do}},
		{"https-https-https", []string{secure, secure, final}, []fetcher{get, do, doStrict}},
	}
	for _, c := range cases {
		want := requestedURLs(c.hops)
		for _, f := range c.via {
			resp, err := f.fetch(chainURL(c.hops...))
			if err != nil {
				t.Errorf("%s(%s): %v", f.name, c.name, err)
				continue
			}
			got := urlStrings(resp.RedirectCh)
			if !slices.Equal(got, want) || resp.URL.String() != final || !resp.Verified {
				t.Errorf("%s(%s) ended at %s via %v (verified %v), want %s via %v",
					f.name, c.name, resp.URL, got, resp.Verified, final, want)
			}
		}
	}
}

// TestRedirectsStopAfterEightHops: a redirect loop gets the original request
// and eight followed hops, and Get does not start the loop over with its
// diagnostic retry, because the failure has nothing to do with TLS.
func TestRedirectsStopAfterEightHops(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer srv.Close()
	get, do, _ := fetchers(NewHTTP(2 * time.Second))

	for _, f := range []fetcher{get, do} {
		requests.Store(0)
		_, err := f.fetch(srv.URL)
		if err == nil || !strings.Contains(err.Error(), "too many redirects") {
			t.Errorf("%s(redirect loop) = %v, want too many redirects", f.name, err)
		}
		if n := requests.Load(); n != 9 {
			t.Errorf("%s(redirect loop) sent %d requests, want 9", f.name, n)
		}
	}
}

// TestGetStrictDoesNotFollowRedirects: RFC 8461 §3.3 forbids following
// redirects for an MTA-STS policy fetch, so GetStrict returns the 3xx.
func TestGetStrictDoesNotFollowRedirects(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	var followed atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			followed.Add(1)
		}
		http.Redirect(w, r, "/moved", http.StatusFound)
	}))
	defer srv.Close()
	h := NewHTTP(2 * time.Second)
	trustTestServer(h.client.Transport, srv)

	resp, err := h.GetStrict(context.Background(), srv.URL+"/policy")
	if err != nil {
		t.Fatalf("GetStrict: %v", err)
	}
	if resp.Status != http.StatusFound || len(resp.RedirectCh) != 1 || followed.Load() != 0 {
		t.Errorf("GetStrict = %d after %d requests (%d to the target), want the 302 unfollowed",
			resp.Status, len(resp.RedirectCh), followed.Load())
	}
}

// TestStrictHelpersRefusePlainHTTP: GetStrict and DoStrict refuse an http://
// URL before connecting, so nothing goes out in cleartext.
func TestStrictHelpersRefusePlainHTTP(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewUnstartedServer(redirector)
	conns := countConns(srv)
	srv.Start()
	defer srv.Close()
	h := NewHTTP(2 * time.Second)

	if _, err := h.GetStrict(context.Background(), srv.URL); err == nil {
		t.Errorf("GetStrict(%s) succeeded, want an https error", srv.URL)
	}
	_, _, doStrict := fetchers(h)
	if _, err := doStrict.fetch(srv.URL); err == nil {
		t.Errorf("DoStrict(%s) succeeded, want an https error", srv.URL)
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("strict helpers opened %d connections to an http:// URL, want 0", n)
	}
}

// TestResponseHeadersAreBounded: response headers, which checks echo into
// evidence, are capped well below net/http's 10 MiB default.
func TestResponseHeadersAreBounded(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kib, _ := strconv.Atoi(r.URL.Query().Get("kib"))
		w.Header().Set("X-Filler", strings.Repeat("a", kib<<10))
	}))
	defer srv.Close()
	get, do, _ := fetchers(NewHTTP(2 * time.Second))

	for _, f := range []fetcher{get, do} {
		if _, err := f.fetch(srv.URL + "/?kib=100"); err != nil {
			t.Errorf("%s with a 100 KiB header: %v", f.name, err)
		}
		if _, err := f.fetch(srv.URL + "/?kib=300"); err == nil {
			t.Errorf("%s accepted a 300 KiB header", f.name)
		}
	}
}

// TestHTTPClosesConnectionsAfterEachCall: no connection outlives the call
// that opened it, so a server cannot pile up sockets and goroutines across
// a run by holding idle connections open.
func TestHTTPClosesConnectionsAfterEachCall(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewUnstartedServer(redirector)
	open := trackOpenConns(srv)
	srv.Start()
	defer srv.Close()
	get, do, _ := fetchers(NewHTTP(2 * time.Second))

	for range 10 {
		for _, f := range []fetcher{get, do} {
			if _, err := f.fetch(srv.URL); err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
		}
	}
	// The server notices each close asynchronously.
	deadline := time.Now().Add(2 * time.Second)
	for open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Errorf("%d connections still open after 20 calls returned, want 0", n)
	}
}

// TestGetDoesNotRetryRefusedConnection: a refused connection is an answer
// from the target, not a TLS failure, so Get dials once.
func TestGetDoesNotRetryRefusedConnection(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	var dials atomic.Int32
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		ConnectStart: func(string, string) { dials.Add(1) },
	})

	if _, err := NewHTTP(time.Second).Get(ctx, "https://"+addr); err == nil {
		t.Fatal("Get against a closed port must fail")
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("Get dialed a refusing port %d times, want 1", n)
	}
}

// TestGetDoesNotRetryHandshakeTimeout: a handshake that timed out is not a
// TLS failure, so Get dials once even though ctx is still live. The 100 ms
// handshake timeout expires well before the 300 ms client budget, and ctx
// never does.
func TestGetDoesNotRetryHandshakeTimeout(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	port := listenLoopback(t)
	var dials atomic.Int32
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		ConnectStart: func(string, string) { dials.Add(1) },
	})

	_, err := NewHTTP(100*time.Millisecond).Get(ctx, "https://127.0.0.1:"+port)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("Get against a server that never answers returned %v, want a timeout", err)
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("Get dialed %d times after its handshake timed out, want 1", n)
	}
}

// startTLS10 starts srv with TLS 1.0 as its only protocol version.
func startTLS10(srv *httptest.Server) {
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}
	srv.StartTLS()
}

// TestGetDiagnosticRetryOnlyAfterFailedHandshake: Get takes its unverified
// diagnostic retry exactly once when the verified handshake fails, and
// marks that response unverified without its body; verified and plain-HTTP
// responses keep their body and take one connection.
func TestGetDiagnosticRetryOnlyAfterFailedHandshake(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	cases := []struct {
		name     string
		start    func(*httptest.Server)
		trust    bool
		verified bool
		body     string
		conns    int32
	}{
		{"plain http", (*httptest.Server).Start, false, true, "ok", 1},
		{"trusted certificate", (*httptest.Server).StartTLS, true, true, "ok", 1},
		{"untrusted certificate", (*httptest.Server).StartTLS, false, false, "", 2},
		{"TLS 1.0 only", startTLS10, true, false, "", 2},
	}
	for _, c := range cases {
		srv := httptest.NewUnstartedServer(redirector)
		srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
		conns := countConns(srv)
		c.start(srv)
		h := NewHTTP(2 * time.Second)
		if c.trust {
			trustTestServer(h.client.Transport, srv)
		}

		resp, err := h.Get(context.Background(), srv.URL)
		srv.Close()
		if err != nil {
			t.Errorf("%s: Get: %v", c.name, err)
			continue
		}
		if resp.Status != http.StatusOK || resp.Verified != c.verified ||
			string(resp.Body) != c.body {
			t.Errorf("%s: Get = HTTP %d, Verified %v, body %q; want 200, %v, %q",
				c.name, resp.Status, resp.Verified, resp.Body, c.verified, c.body)
		}
		if n := conns.Load(); n != c.conns {
			t.Errorf("%s: Get opened %d connections, want %d", c.name, n, c.conns)
		}
	}
}

// TestGetDiagnosticRetryLeavesBodyUnread: the diagnostic retry returns once
// the headers arrive, without waiting for a body it would only throw away.
func TestGetDiagnosticRetryLeavesBodyUnread(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done() // the body never comes
		}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failure
	srv.StartTLS()
	defer srv.Close()

	resp, err := NewHTTP(time.Second).Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get waited for the unverified body: %v", err)
	}
	if resp.Status != http.StatusOK || resp.Verified || resp.Body != nil {
		t.Errorf("Get = HTTP %d, Verified %v, body %q; want 200, false, nil",
			resp.Status, resp.Verified, resp.Body)
	}
}

// resetConn aborts the connection behind w with a TCP reset.
func resetConn(t *testing.T, w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}

// TestGetDoesNotRetryAfterVerifiedHandshake: a connection reset after a
// verified handshake is reported as an error. It is not retried without
// verification, which would turn it into a degraded, body-less success.
func TestGetDoesNotRetryAfterVerifiedHandshake(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	var reset atomic.Bool
	resetFirst := func(w http.ResponseWriter, _ *http.Request) {
		if reset.CompareAndSwap(false, true) {
			resetConn(t, w)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(resetFirst))
	conns := countConns(srv)
	srv.StartTLS()
	defer srv.Close()
	h := NewHTTP(2 * time.Second)
	trustTestServer(h.client.Transport, srv)

	resp, err := h.Get(context.Background(), srv.URL)
	if err == nil {
		t.Errorf("Get after a reset = HTTP %d with body %q, want the reset reported",
			resp.Status, resp.Body)
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("Get opened %d connections, want 1", n)
	}
}

// TestGetSkipsDiagnosticRetryOnceContextIsDone: when the caller gives up as
// the handshake fails, Get returns that failure without starting its
// diagnostic retry on the dead context.
func TestGetSkipsDiagnosticRetryOnceContextIsDone(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewUnstartedServer(redirector)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failure
	srv.StartTLS()
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Get's own hook runs before this one, so Get has seen the handshake
	// failure by the time the context is cancelled.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				cancel()
			}
		},
	})

	_, err := NewHTTP(2*time.Second).Get(ctx, srv.URL)
	if err == nil || strings.Contains(err.Error(), "diagnostic retry") {
		t.Errorf("Get = %v, want the handshake failure without a diagnostic retry", err)
	}
}

// TestGetSurfacesDiagnosticRetryFailure locks in that when both the verified
// fetch and the insecure diagnostic retry fail, Get reports both failures
// instead of silently dropping the retry's error.
func TestGetSurfacesDiagnosticRetryFailure(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	// Answering every connection with plain text fails the TLS handshake of
	// the verified fetch and of the diagnostic retry alike.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "HTTP/1.0 400 Bad Request\r\n\r\n")
			_ = c.Close()
		}
	}()

	_, err = NewHTTP(time.Second).Get(context.Background(), "https://"+l.Addr().String())
	if err == nil {
		t.Fatal("Get against a server that does not speak TLS must fail")
	}
	if !strings.Contains(err.Error(), "insecure diagnostic retry also failed") {
		t.Errorf("error should carry the retry failure; got %q", err.Error())
	}
}

// TestGetFlagsTruncatedBody: a body over the cap is cut to maxBodyBytes and
// flagged; one exactly at the cap is complete.
func TestGetFlagsTruncatedBody(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = w.Write(make([]byte, n))
	}))
	defer srv.Close()
	h := NewHTTP(2 * time.Second)

	for _, n := range []int{maxBodyBytes, maxBodyBytes + 1} {
		resp, err := h.Get(context.Background(), fmt.Sprintf("%s/?n=%d", srv.URL, n))
		if err != nil {
			t.Fatalf("Get(%d bytes): %v", n, err)
		}
		wantLen, wantTruncated := min(n, maxBodyBytes), n > maxBodyBytes
		if len(resp.Body) != wantLen || resp.Truncated != wantTruncated {
			t.Errorf("Get(%d bytes) = %d bytes, Truncated %v; want %d bytes, Truncated %v",
				n, len(resp.Body), resp.Truncated, wantLen, wantTruncated)
		}
	}
}
