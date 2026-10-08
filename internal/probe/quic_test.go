package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// startQUICListener accepts QUIC connections on 127.0.0.1 until the test
// ends. It returns the port and a client TLS config that trusts the
// listener's certificate, which covers example.com.
func startQUICListener(t *testing.T) (string, *tls.Config) {
	t.Helper()
	cert, roots := loopbackCert(t)
	const alpn = "bedrock-test"
	ln, err := quic.ListenAddr("127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", ln.Addr(), err)
	}
	return port, &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{alpn}}
}

// dialQUICFor calls DialQUIC for host:port with a two-second budget and
// returns the address it connected to.
func dialQUICFor(t *testing.T, host, port string, clientTLS *tls.Config) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := DialQUIC(ctx, net.JoinHostPort(host, port), clientTLS, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	return conn.RemoteAddr().String(), nil
}

// TestDialQUICSkipsDenylistedAddresses: the HTTP/3 dial hook refuses each
// denylisted answer and dials an allowed one, and a name with only
// denylisted answers fails with *BlockedAddrError before any packet is sent.
func TestDialQUICSkipsDenylistedAddresses(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	port, clientTLS := startQUICListener(t)
	exemptDialAddr(t, "127.0.0.1")
	useFakeDialResolver(t,
		"mixed.example. 60 IN A 127.0.0.2",
		"mixed.example. 60 IN A 127.0.0.1",
		"blocked.example. 60 IN A 169.254.169.254",
		"blocked.example. 60 IN A 10.0.0.1",
	)

	got, err := dialQUICFor(t, "mixed.example", port, clientTLS)
	if err != nil {
		t.Fatalf("DialQUIC(mixed.example): %v", err)
	}
	if want := net.JoinHostPort("127.0.0.1", port); got != want {
		t.Errorf("DialQUIC(mixed.example) connected to %s, want %s", got, want)
	}

	_, err = dialQUICFor(t, "blocked.example", port, clientTLS)
	var blocked *BlockedAddrError
	if !errors.As(err, &blocked) {
		t.Errorf("DialQUIC(blocked.example) = %v, want a *BlockedAddrError", err)
	}
}

// TestDialQUICPrefersIPv4: a QUIC dial does not fall back to a second
// address, so the hook picks the IPv4 answer as quic-go's own resolver
// does, although Go sorts ::1 first. An IPv4-mapped IPv6 answer counts as
// IPv4.
func TestDialQUICPrefersIPv4(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	port, clientTLS := startQUICListener(t)
	useFakeDialResolver(t,
		"dual.example. 60 IN AAAA ::1",
		"dual.example. 60 IN A 127.0.0.1",
		"mapped.example. 60 IN AAAA ::1",
		"mapped.example. 60 IN AAAA ::ffff:127.0.0.1",
	)

	for _, host := range []string{"dual.example", "mapped.example"} {
		got, err := dialQUICFor(t, host, port, clientTLS)
		if err != nil {
			t.Errorf("DialQUIC(%s): %v", host, err)
			continue
		}
		if want := net.JoinHostPort("127.0.0.1", port); got != want {
			t.Errorf("DialQUIC(%s) connected to %s, want %s", host, got, want)
		}
	}
}

// TestDialQUICErrorsOmitResolverAddress: as with SafeDial, a failed lookup
// is reported without the operator's resolver address.
func TestDialQUICErrorsOmitResolverAddress(t *testing.T) {
	useFakeDialResolver(t)

	_, err := dialQUICFor(t, "missing.example", "443", &tls.Config{})
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || dnsErr.Server != "" || !dnsErr.IsNotFound {
		t.Errorf("DialQUIC(missing.example) = %v, want NXDOMAIN without a server", err)
	}
}

// TestDialQUICRejectsAddressWithoutPort: the hook needs host:port and says
// which address it could not use.
func TestDialQUICRejectsAddressWithoutPort(t *testing.T) {
	_, err := DialQUIC(context.Background(), "example.com", &tls.Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), `"example.com"`) {
		t.Errorf(`DialQUIC("example.com") = %v, want an error naming the address`, err)
	}
}
