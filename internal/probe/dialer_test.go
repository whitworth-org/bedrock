package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// TestDialControlDenylist pins each denylisted range, and the embedded IPv4
// address of each IPv6 transition form, by running addresses through the
// check the dialer applies before every connect.
func TestDialControlDenylist(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	const (
		private  = "private (RFC 1918)"
		metadata = "a cloud metadata endpoint"
	)
	cases := []struct {
		addr   string
		reason string // "" means the address is allowed
	}{
		{"10.1.2.3", private},
		{"172.16.0.1", private},
		{"172.31.255.255", private},
		{"192.168.1.1", private},
		{"127.0.0.1", "loopback"},
		{"127.255.255.254", "loopback"},
		{"::1", "loopback"},
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"0.1.2.3", "a this-network address (RFC 1122)"},
		{"100.64.0.1", "CGNAT (RFC 6598)"},
		{"100.127.255.254", "CGNAT (RFC 6598)"},
		{"169.254.1.1", "link-local"},
		{"fe80::1", "link-local"},
		{"fe80::1%eth0", "link-local"},
		{"fc00::1", "unique local (RFC 4193)"},
		{"fd12:3456::1", "unique local (RFC 4193)"},
		{"fec0::1", "site-local (RFC 3879)"},
		{"192.0.0.1", "reserved for IETF protocol assignments (RFC 6890)"},
		{"192.0.0.170", "reserved for IETF protocol assignments (RFC 6890)"},
		{"240.0.0.1", "reserved (RFC 1112)"},
		{"255.255.255.255", "broadcast"},
		{"224.0.0.1", "multicast"},
		{"239.255.255.250", "multicast"},
		{"ff02::1", "multicast"},
		{"169.254.169.254", metadata},
		{"fd00:ec2::254", metadata},
		{"100.100.100.200", metadata},
		{"168.63.129.16", metadata},
		{"::ffff:10.1.2.3", private},
		{"::ffff:169.254.169.254", metadata},
		{"::a01:203", private + " via IPv4-compatible (10.1.2.3)"},
		{"64:ff9b::a01:203", private + " via NAT64 (10.1.2.3)"},
		{"64:ff9b::a9fe:a9fe", metadata + " via NAT64 (169.254.169.254)"},
		{"64:ff9b:1::a01:203", private + " via NAT64 (10.1.2.3)"},
		{"2002:a01:203::1", private + " via 6to4 (10.1.2.3)"},
		{"2001:0:4136:e378:8000:63bf:f5fe:fdfc", private + " via Teredo (10.1.2.3)"},
		{"2001:0:a01:203::fefe:fefe", private + " via Teredo server (10.1.2.3)"},
		// Allowed: the 198.18.0.0/15 benchmarking range, public addresses, the
		// boundaries of the denied ranges, and transition forms that embed
		// public IPv4.
		{"198.18.0.1", ""},
		{"198.19.255.254", ""},
		{"1.1.1.1", ""},
		{"2606:4700:4700::1111", ""},
		{"192.0.2.1", ""},
		{"11.0.0.1", ""},
		{"172.32.0.1", ""},
		{"100.128.0.1", ""},
		{"169.255.0.1", ""},
		{"192.0.1.1", ""},
		{"223.255.255.255", ""},
		{"64:ff9b::101:101", ""},
		{"2002:101:101::1", ""},
		{"2001:0:4136:e378:8000:63bf:fefe:fefe", ""},
	}
	for _, c := range cases {
		err := dialControl(context.Background(), "tcp", net.JoinHostPort(c.addr, "443"), nil)
		var blocked *BlockedAddrError
		switch {
		case c.reason == "" && err != nil:
			t.Errorf("%s: want allowed, got %v", c.addr, err)
		case c.reason != "" && (!errors.As(err, &blocked) || blocked.Reason != c.reason):
			t.Errorf("%s: want refusal %q, got %v", c.addr, c.reason, err)
		}
	}
}

// TestDialControlFailsClosed: input the denylist cannot classify is refused.
func TestDialControlFailsClosed(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	if err := dialControl(context.Background(), "unix", "/tmp/bedrock.sock", nil); err == nil {
		t.Error("dialControl accepted an address that is not ip:port")
	}
	var blocked *BlockedAddrError
	if err := CheckDialAddr(netip.Addr{}); !errors.As(err, &blocked) {
		t.Errorf("CheckDialAddr(zero Addr) = %v, want a *BlockedAddrError", err)
	}
}

// TestParseUpstreamUsesDenylist: --resolver literals go through the same
// denylist, so wrapped and reserved addresses are refused while
// 198.18.0.0/15 stays usable.
func TestParseUpstreamUsesDenylist(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	denied := []string{"64:ff9b::a00:1", "[2002:a00:1::1]:53", "192.0.0.1", "240.0.0.1"}
	for _, spec := range denied {
		if _, err := parseUpstream(spec); err == nil {
			t.Errorf("parseUpstream(%q) accepted a denylisted resolver", spec)
		}
	}
	if _, err := parseUpstream("198.18.0.53"); err != nil {
		t.Errorf("parseUpstream(198.18.0.53): %v", err)
	}
}

// useDialResolver makes SafeDial resolve names with the pure-Go resolver,
// sending its queries through dial, until the test ends.
func useDialResolver(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	dialResolver = &net.Resolver{PreferGo: true, Dial: dial}
	t.Cleanup(func() { dialResolver = nil })
}

// useFakeDialResolver points SafeDial's name resolution at a fake DNS
// server that answers rrs and NXDOMAIN for everything else.
func useFakeDialResolver(t *testing.T, rrs ...string) {
	t.Helper()
	spec, zone := newFakeUDPResolver(t)
	for _, rr := range rrs {
		zone.Add(t, rr)
	}
	useDialResolver(t, func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, spec)
	})
}

// exemptDialAddr lets SafeDial reach addr, and only addr, among denylisted
// addresses until the test ends.
func exemptDialAddr(t *testing.T, addr string) {
	t.Helper()
	dialExemptAddr = netip.MustParseAddr(addr)
	t.Cleanup(func() { dialExemptAddr = netip.Addr{} })
}

// listenLoopback listens on 127.0.0.1 until the test ends and returns the
// port. The kernel completes handshakes, so nothing needs to call Accept.
func listenLoopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", l.Addr(), err)
	}
	return port
}

// dialTCP calls SafeDial for host:port with a two-second budget.
func dialTCP(host, port string) (net.Conn, error) {
	return SafeDial(context.Background(), "tcp", net.JoinHostPort(host, port), 2*time.Second)
}

// TestSafeDialSkipsDenylistedAddresses resolves names through a fake DNS
// server: the denylist refuses each blocked answer just before connect and
// the dial moves on to the next answer, while a name with only blocked
// answers fails with *BlockedAddrError.
func TestSafeDialSkipsDenylistedAddresses(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	port := listenLoopback(t)
	exemptDialAddr(t, "127.0.0.1")
	// Go's resolver sorts answers by RFC 6724, which would move 127.0.0.1
	// ahead of 169.254.169.254. 127.0.0.2 ties with it, so the refused
	// 127.0.0.2 keeps its place in front.
	useFakeDialResolver(t,
		"mixed.example. 60 IN A 127.0.0.2",
		"mixed.example. 60 IN A 127.0.0.1",
		"blocked.example. 60 IN A 169.254.169.254",
		"blocked.example. 60 IN A 10.0.0.1",
	)

	conn, err := dialTCP("mixed.example", port)
	if err != nil {
		t.Fatalf("SafeDial(mixed.example): %v", err)
	}
	if got, want := conn.RemoteAddr().String(), net.JoinHostPort("127.0.0.1", port); got != want {
		t.Errorf("SafeDial(mixed.example) connected to %s, want %s", got, want)
	}
	_ = conn.Close()

	_, err = dialTCP("blocked.example", port)
	var blocked *BlockedAddrError
	if !errors.As(err, &blocked) {
		t.Fatalf("SafeDial(blocked.example) = %v, want a *BlockedAddrError", err)
	}
}

// TestSafeDialFallsBackAcrossAddresses: when the first answer refuses the
// connection the dial tries the next one, as browsers do. ::1 sorts first
// and nothing listens there.
func TestSafeDialFallsBackAcrossAddresses(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	port := listenLoopback(t)
	useFakeDialResolver(t,
		"dual.example. 60 IN AAAA ::1",
		"dual.example. 60 IN A 127.0.0.1",
	)

	conn, err := dialTCP("dual.example", port)
	if err != nil {
		t.Fatalf("SafeDial(dual.example): %v", err)
	}
	_ = conn.Close()
}

// TestSafeDialBoundsNameResolution: http.Transport dials with a context that
// has no deadline, so the timeout alone must stop a lookup that never
// returns.
func TestSafeDialBoundsNameResolution(t *testing.T) {
	useDialResolver(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	const timeout = 200 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := SafeDial(context.Background(), "tcp", "stalled.example:443", timeout)
		done <- err
	}()
	select {
	case err := <-done:
		if !IsProbeFailure(err) {
			t.Errorf("SafeDial(stalled.example) = %v, want a timeout", err)
		}
	case <-time.After(10 * timeout):
		t.Fatalf("SafeDial(stalled.example) still resolving after %v with a %v timeout",
			10*timeout, timeout)
	}
}

// TestSafeDialErrorsOmitResolverAddress: the pure-Go resolver names the
// nameserver in its errors; SafeDial drops it so evidence never carries the
// operator's resolver address.
func TestSafeDialErrorsOmitResolverAddress(t *testing.T) {
	useFakeDialResolver(t)

	_, err := dialTCP("missing.example", "443")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("SafeDial(missing.example) = %v, want a *net.DNSError", err)
	}
	if dnsErr.Server != "" || !dnsErr.IsNotFound {
		t.Errorf("SafeDial(missing.example) = %+v, want NXDOMAIN without a server", *dnsErr)
	}
}

// TestScrubNetErrorDropsOperatorAddresses: neither the local socket address
// nor the resolver address survives, whether the resolver address is in
// DNSError.Server or in the text of a socket error, and the classification
// and the caller's error are unchanged.
func TestScrubNetErrorDropsOperatorAddresses(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 5), Port: 54321}
	cases := []error{
		&net.OpError{Op: "dial", Net: "tcp", Source: local, Err: &net.DNSError{
			Err: "no such host", Name: "x.example", Server: "10.1.2.3:53", IsNotFound: true,
		}},
		&net.DNSError{
			Err:  "read udp 192.168.1.5:54321->10.1.2.3:53: i/o timeout",
			Name: "x.example", Server: "10.1.2.3:53", IsTimeout: true, IsTemporary: true,
		},
	}
	for _, err := range cases {
		got := scrubNetError(err)
		for _, addr := range []string{"10.1.2.3", "192.168.1.5"} {
			if strings.Contains(got.Error(), addr) {
				t.Errorf("scrubNetError(%q) = %q, still names %s", err, got, addr)
			}
		}
		if IsProbeFailure(got) != IsProbeFailure(err) {
			t.Errorf("scrubNetError(%q) changed IsProbeFailure", err)
		}
		if !strings.Contains(err.Error(), "10.1.2.3") {
			t.Errorf("scrubNetError modified its argument: %q", err)
		}
	}
}

// headerTimeoutError mirrors net/http's transport timeouts, which implement
// net.Error but wrap neither context.DeadlineExceeded nor
// os.ErrDeadlineExceeded.
type headerTimeoutError struct{}

func (headerTimeoutError) Error() string   { return "net/http: timeout awaiting response headers" }
func (headerTimeoutError) Timeout() bool   { return true }
func (headerTimeoutError) Temporary() bool { return true }

// sysErr is a failed connect as the net package reports it.
func sysErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

// Winsock errnos, the values Windows returns where Unix returns
// syscall.ECONNRESET and friends.
const (
	winNetUnreach  = syscall.Errno(10051)
	winConnReset   = syscall.Errno(10054)
	winTimedOut    = syscall.Errno(10060)
	winConnRefused = syscall.Errno(10061)
	winHostUnreach = syscall.Errno(10065)
)

func TestIsProbeFailure(t *testing.T) {
	// *url.Error is a net.Error whose Timeout() cannot see through %w, so
	// these cases need the deadline sentinels to be matched by errors.Is.
	urlErr := func(cause error) error {
		return &url.Error{Op: "Get", URL: "https://x.example/", Err: cause}
	}
	wrapped := func(cause error) error { return urlErr(fmt.Errorf("read body: %w", cause)) }
	blocked := &BlockedAddrError{Addr: netip.MustParseAddr("10.0.0.1"), Reason: "private"}
	dnsErr := func(text string, notFound, timeout, temporary bool) error {
		return &net.DNSError{
			Err: text, Name: "x.example",
			IsNotFound: notFound, IsTimeout: timeout, IsTemporary: temporary,
		}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped context deadline", wrapped(context.DeadlineExceeded), true},
		{"i/o timeout", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"wrapped i/o timeout", wrapped(os.ErrDeadlineExceeded), true},
		{"transport timeout", urlErr(headerTimeoutError{}), true},
		{"SSRF refusal", &net.OpError{Op: "dial", Net: "tcp", Err: blocked}, true},
		{"connection reset", fmt.Errorf("smtp: %w", sysErr(syscall.ECONNRESET)), true},
		{"network unreachable", sysErr(syscall.ENETUNREACH), true},
		{"host unreachable", sysErr(syscall.EHOSTUNREACH), true},
		{"connection reset on Windows", fmt.Errorf("smtp: %w", sysErr(winConnReset)), true},
		{"network unreachable on Windows", sysErr(winNetUnreach), true},
		{"host unreachable on Windows", sysErr(winHostUnreach), true},
		{"connect timed out on Windows", sysErr(winTimedOut), true},
		{"temporary DNS failure", dnsErr("server misbehaving", false, false, true), true},
		{"DNS timeout", dnsErr("i/o timeout", false, true, false), true},
		{"connection refused", sysErr(syscall.ECONNREFUSED), false},
		{"connection refused on Windows", sysErr(winConnRefused), false},
		{"NXDOMAIN", dnsErr("no such host", true, false, false), false},
		{"NXDOMAIN marked temporary", dnsErr("no such host", true, false, true), false},
		{"malformed DNS answer", dnsErr("cannot unmarshal", false, false, false), false},
		{"cancelled", context.Canceled, false},
		{"TLS failure", errors.New("tls: handshake failure"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := IsProbeFailure(c.err); got != c.want {
			t.Errorf("IsProbeFailure(%s: %v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

// TestIsConnRefused: a refused connect is recognised by its Unix and its
// Winsock errno, however wrapped, and no other failure is.
func TestIsConnRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"refused", sysErr(syscall.ECONNREFUSED), true},
		{"wrapped refused on Windows", fmt.Errorf("dial: %w", sysErr(winConnRefused)), true},
		{"reset", sysErr(syscall.ECONNRESET), false},
		{"reset on Windows", sysErr(winConnReset), false},
		{"timeout", context.DeadlineExceeded, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := IsConnRefused(c.err); got != c.want {
			t.Errorf("IsConnRefused(%s: %v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

// TestHTTPDialsThroughDenylist: every HTTP entry point refuses a loopback
// server while the override is unset, and a client built then reaches the
// server once the override is set, because each dial reads it.
func TestHTTPDialsThroughDenylist(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv(allowPrivateResolverEnv, "")
	h := NewHTTP(time.Second)
	ctx := context.Background()
	send := func(do func(*http.Request) (*Response, error)) func() (*Response, error) {
		return func() (*Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			if err != nil {
				return nil, err
			}
			return do(req)
		}
	}
	calls := []struct {
		name  string
		fetch func() (*Response, error)
	}{
		{"Get", func() (*Response, error) { return h.Get(ctx, srv.URL) }},
		{"GetStrict", func() (*Response, error) { return h.GetStrict(ctx, srv.URL) }},
		{"Do", send(h.Do)},
		{"DoStrict", send(h.DoStrict)},
	}
	for _, c := range calls {
		var blocked *BlockedAddrError
		if _, err := c.fetch(); !errors.As(err, &blocked) {
			t.Errorf("%s(%s) = %v, want a *BlockedAddrError", c.name, srv.URL, err)
		}
	}

	t.Setenv(allowPrivateResolverEnv, "1")
	resp, err := h.Get(ctx, srv.URL)
	if err != nil {
		t.Fatalf("Get(%s) with the override: %v", srv.URL, err)
	}
	if resp.Status != http.StatusNoContent {
		t.Errorf("Get(%s) status = %d, want %d", srv.URL, resp.Status, http.StatusNoContent)
	}
}

// TestHTTPRefusesRedirectToDenylistedAddress: an allowed server cannot
// redirect a probe to an internal address.
func TestHTTPRefusesRedirectToDenylistedAddress(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	exemptDialAddr(t, "127.0.0.1")
	srv := httptest.NewServer(http.RedirectHandler("http://127.0.0.2/", http.StatusFound))
	defer srv.Close()

	_, err := NewHTTP(time.Second).Get(context.Background(), srv.URL)
	var blocked *BlockedAddrError
	if !errors.As(err, &blocked) || blocked.Addr != netip.MustParseAddr("127.0.0.2") {
		t.Errorf("Get(%s), redirected to 127.0.0.2, = %v, want 127.0.0.2 refused", srv.URL, err)
	}
}

// TestDoHClientUsesDenylist: DoH queries dial through SafeDial.
func TestDoHClientUsesDenylist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv(allowPrivateResolverEnv, "")
	m := new(mdns.Msg)
	m.SetQuestion("example.com.", mdns.TypeA)

	_, err := dohExchange(context.Background(), newDoHClient(time.Second), srv.URL, m)
	var blocked *BlockedAddrError
	if !errors.As(err, &blocked) {
		t.Fatalf("dohExchange(%s) = %v, want a *BlockedAddrError", srv.URL, err)
	}
}
