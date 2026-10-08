package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/quic-go/quic-go"
)

// DialQUIC is an http3.Transport Dial hook that applies the SSRF denylist,
// which quic-go's own resolver and dialer skip. It resolves the host of
// addr, drops every address CheckDialAddr refuses, and dials the first
// remaining IPv4 address, else the first remaining address, as quic-go's
// resolver prefers IPv4: a QUIC dial has no fallback to a second address.
// tlsCfg carries the SNI. Errors carry neither the local socket address nor
// the resolver's address.
func DialQUIC(
	ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config,
) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("quic dial %q: %w", addr, err)
	}
	resolver := dialResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", scrubNetError(err))
	}
	ip, err := allowedQUICAddr(addrs)
	if err != nil {
		return nil, fmt.Errorf("dial udp %s: %w", addr, err)
	}
	conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip.String(), port), tlsCfg, cfg)
	if err != nil {
		return nil, scrubNetError(err)
	}
	return conn, nil
}

// allowedQUICAddr returns the address DialQUIC dials: the first IPv4
// address the denylist allows, else the first allowed address. When the
// denylist refuses every address it returns the last refusal.
func allowedQUICAddr(addrs []netip.Addr) (netip.Addr, error) {
	refusal := errors.New("no addresses to dial")
	var allowed []netip.Addr
	for _, a := range addrs {
		if err := CheckDialAddr(a); err != nil {
			refusal = err
			continue
		}
		// The pure-Go resolver returns hosts-file IPv4 entries as
		// IPv4-mapped IPv6 addresses.
		allowed = append(allowed, a.Unmap())
	}
	if len(allowed) == 0 {
		return netip.Addr{}, refusal
	}
	if i := slices.IndexFunc(allowed, netip.Addr.Is4); i >= 0 {
		return allowed[i], nil
	}
	return allowed[0], nil
}
