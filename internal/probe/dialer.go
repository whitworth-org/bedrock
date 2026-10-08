package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// dialResolver resolves host names for SafeDial; nil means
// net.DefaultResolver. Only tests replace it.
var dialResolver *net.Resolver

// dialExemptAddr is one address CheckDialAddr allows despite the denylist,
// so a test can stand a loopback listener in for a public host while every
// other address stays refused. Production code never sets it.
var dialExemptAddr netip.Addr

// SafeDial connects to addr like net.Dialer.DialContext but refuses every
// destination on the SSRF denylist (see CheckDialAddr). The check runs on
// each resolved address just before connect, so DNS rebinding cannot swap
// in a private address after the check, and a refused or unreachable
// address falls back to the next one (IPv6 and IPv4 race per RFC 6555).
// timeout bounds name resolution and connection together, even when ctx
// has no deadline. Errors carry neither the local socket address nor the
// resolver's address.
func SafeDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout:        timeout,
		Resolver:       dialResolver,
		ControlContext: dialControl,
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, scrubNetError(err)
	}
	return conn, nil
}

// dialControl applies CheckDialAddr to the concrete address the dialer is
// about to connect to.
func dialControl(_ context.Context, _, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("ssrf dial: parse address %q: %w", address, err)
	}
	return CheckDialAddr(ap.Addr())
}

// CheckDialAddr returns a *BlockedAddrError when a is on the SSRF denylist.
// Setting BEDROCK_ALLOW_PRIVATE_RESOLVER to a non-empty value disables the
// check for hermetic tests and labs; it is read on every call, so a test's
// t.Setenv applies to that test only.
func CheckDialAddr(a netip.Addr) error {
	if os.Getenv(allowPrivateResolverEnv) != "" || (a.IsValid() && a == dialExemptAddr) {
		return nil
	}
	if reason, blocked := blockedAddrReason(a); blocked {
		return &BlockedAddrError{Addr: a, Reason: reason}
	}
	return nil
}

// BlockedAddrError reports a destination the SSRF denylist refused.
type BlockedAddrError struct {
	Addr   netip.Addr // the refused destination
	Reason string     // why it is denied, e.g. "private (RFC 1918)"
}

// Error names the refused address and the reason.
func (e *BlockedAddrError) Error() string {
	return fmt.Sprintf("ssrf dial: refusing %s: %s", e.Addr, e.Reason)
}

// blockedAddrReason reports why a is on the SSRF denylist. An IPv4-mapped
// address is checked as IPv4, and an IPv6 transition address is also
// checked by the IPv4 address its traffic is delivered to.
func blockedAddrReason(a netip.Addr) (string, bool) {
	if !a.IsValid() {
		return "invalid IP", true
	}
	a = a.WithZone("").Unmap()
	if reason, ok := deniedRangeReason(a); ok {
		return reason, true
	}
	for _, w := range ipv4Wrappers {
		if !w.prefix.Contains(a) {
			continue
		}
		v4 := embeddedIPv4(a, w.offset, w.xor)
		if reason, ok := deniedRangeReason(v4); ok {
			return fmt.Sprintf("%s via %s (%s)", reason, w.kind, v4), true
		}
	}
	return "", false
}

func deniedRangeReason(a netip.Addr) (string, bool) {
	for _, r := range deniedRanges {
		if r.prefix.Contains(a) {
			return r.reason, true
		}
	}
	return "", false
}

func embeddedIPv4(a netip.Addr, offset int, xor byte) netip.Addr {
	b := a.As16()
	var v4 [4]byte
	for i := range v4 {
		v4[i] = b[offset+i] ^ xor
	}
	return netip.AddrFrom4(v4)
}

const metadataReason = "a cloud metadata endpoint"

// deniedRanges is the SSRF denylist; the first matching prefix names the
// reason. 198.18.0.0/15 stays allowed: proxy tools with a fake-IP mode
// resolve every name into it.
var deniedRanges = []struct {
	prefix netip.Prefix
	reason string
}{
	// Metadata endpoints precede the ranges that contain them so that they
	// report the specific reason.
	{netip.MustParsePrefix("169.254.169.254/32"), metadataReason}, // AWS, GCP, Azure, OCI
	{netip.MustParsePrefix("fd00:ec2::254/128"), metadataReason},  // AWS over IPv6
	{netip.MustParsePrefix("100.100.100.200/32"), metadataReason}, // Alibaba Cloud
	{netip.MustParsePrefix("168.63.129.16/32"), metadataReason},   // Azure WireServer
	{netip.MustParsePrefix("0.0.0.0/32"), "unspecified"},
	{netip.MustParsePrefix("::/128"), "unspecified"},
	{netip.MustParsePrefix("0.0.0.0/8"), "a this-network address (RFC 1122)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("::1/128"), "loopback"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private (RFC 1918)"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private (RFC 1918)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private (RFC 1918)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "CGNAT (RFC 6598)"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("fc00::/7"), "unique local (RFC 4193)"},
	{netip.MustParsePrefix("fec0::/10"), "site-local (RFC 3879)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved for IETF protocol assignments (RFC 6890)"},
	{netip.MustParsePrefix("255.255.255.255/32"), "broadcast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved (RFC 1112)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
}

// ipv4Wrappers are IPv6 prefixes whose addresses carry the IPv4 address
// their traffic is delivered to. NAT64 addresses are decoded as /96 (RFC
// 6052 §2.2); other NAT64 prefix lengths and network-specific prefixes
// cannot be recognised from the address alone.
var ipv4Wrappers = []struct {
	prefix netip.Prefix
	kind   string
	offset int  // byte offset of the IPv4 address
	xor    byte // Teredo stores its client address bit-inverted (RFC 4380 §4)
}{
	{netip.MustParsePrefix("::/96"), "IPv4-compatible", 12, 0},
	{netip.MustParsePrefix("64:ff9b::/96"), "NAT64", 12, 0},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "NAT64", 12, 0},
	{netip.MustParsePrefix("2002::/16"), "6to4", 2, 0},
	{netip.MustParsePrefix("2001::/32"), "Teredo", 12, 0xff},
	{netip.MustParsePrefix("2001::/32"), "Teredo server", 4, 0},
}

// scrubNetError returns err without the local socket address of a
// *net.OpError or the resolver address of a *net.DNSError, so reports do
// not carry the operator's network addresses. Pass the error as the net
// package returned it: wrapping renders the addresses into text first. It
// copies rather than edits: the resolver shares one *net.DNSError among
// concurrent lookups.
func scrubNetError(err error) error {
	switch e := err.(type) {
	case *net.OpError:
		scrubbed := *e
		scrubbed.Source = nil
		scrubbed.Err = scrubNetError(e.Err)
		return &scrubbed
	case *net.DNSError:
		scrubbed := *e
		scrubbed.Server = ""
		// A socket failure talking to the resolver arrives as the text
		// "<op> <net> <local>-><server>: <cause>"; keep only the cause.
		if e.Server != "" {
			if _, cause, found := strings.Cut(e.Err, e.Server+": "); found {
				scrubbed.Err = cause
			}
		}
		return &scrubbed
	}
	return err
}

// Winsock error numbers. On Windows the syscall package's ECONNREFUSED,
// ECONNRESET and friends are invented values that no socket call returns,
// and syscall.Errno.Is does not map these onto them.
const (
	wsaeNetUnreach  = syscall.Errno(10051)
	wsaeConnReset   = syscall.Errno(10054)
	wsaeTimedOut    = syscall.Errno(10060)
	wsaeConnRefused = syscall.Errno(10061)
	wsaeHostUnreach = syscall.Errno(10065)
)

// probeFailureCauses are the errors IsProbeFailure treats as a probe that
// could not complete. A refused connection is deliberately absent: it is an
// answer from the target.
var probeFailureCauses = []error{
	context.DeadlineExceeded,
	os.ErrDeadlineExceeded,
	syscall.ECONNRESET,
	syscall.ENETUNREACH,
	syscall.EHOSTUNREACH,
	wsaeConnReset,
	wsaeNetUnreach,
	wsaeHostUnreach,
	wsaeTimedOut,
}

// IsConnRefused reports whether err says the target refused the
// connection, on any platform.
func IsConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeConnRefused)
}

// IsProbeFailure reports whether err means the probe could not complete,
// so the target's posture is unknown rather than failing: a timeout, an
// SSRF denylist refusal, a reset connection, an unreachable network or
// host, a temporary or timed-out DNS failure, or a resolver that answered
// SERVFAIL or REFUSED. A refused connection and a name that does not exist
// are answers from the target and return false.
func IsProbeFailure(err error) bool {
	var blocked *BlockedAddrError
	if errors.As(err, &blocked) {
		return true
	}
	if failed, ok := resolverFailure(err); ok {
		return failed
	}
	for _, cause := range probeFailureCauses {
		if errors.Is(err, cause) {
			return true
		}
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// resolverFailure classifies an error from a name lookup: ok reports
// whether err is one, and failed whether it says the resolver could not
// answer: a timeout, a temporary failure, SERVFAIL or REFUSED.
func resolverFailure(err error) (failed, ok bool) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound && (dnsErr.IsTimeout || dnsErr.IsTemporary), true
	}
	var rcodeErr *RcodeError
	if errors.As(err, &rcodeErr) {
		rcode := rcodeErr.Rcode
		return rcode == dns.RcodeServerFailure || rcode == dns.RcodeRefused, true
	}
	return false, false
}
