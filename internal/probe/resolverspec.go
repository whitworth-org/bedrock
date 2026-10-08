package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// allowPrivateResolverEnv, when set to a non-empty value, bypasses the
// validateResolverHost denylist. Intended for hermetic tests and lab
// environments where resolvers bind to 127.0.0.1 / RFC 1918 addresses.
// Production callers must leave this unset.
const allowPrivateResolverEnv = "BEDROCK_ALLOW_PRIVATE_RESOLVER"

// upstream is one resolved DNS endpoint. A DNS instance can hold several,
// which the dnssec.sentinel check probes one by one.
type upstream struct {
	label    string // human-readable and safe to report, e.g. "cloudflare-udp", "1.1.1.1:53"
	addr     string // host:port for udp/tcp/dot; URL for doh
	protocol protocol
}

type protocol int

const (
	protoUDP protocol = iota // miekg/dns Net="udp" (TCP fallback on truncate)
	protoDoT                 // miekg/dns Net="tcp-tls"
	protoDoH                 // RFC 8484, POST application/dns-message
)

func (p protocol) String() string {
	switch p {
	case protoUDP:
		return "udp"
	case protoDoT:
		return "dot"
	case protoDoH:
		return "doh"
	default:
		return "?"
	}
}

// resolverPreset is a named recursive resolver shortcut. Selecting a preset
// like "cloudflare" or "cloudflare-dot" or "cloudflare-doh" picks the right
// host + protocol for the operator without making them remember IPs.
type resolverPreset struct {
	udp string // host:port for plain UDP/TCP
	dot string // host:port for DNS-over-TLS
	doh string // URL for DNS-over-HTTPS
}

// presets are the popular open recursive resolvers. Operators can extend
// trivially by passing host:port directly.
var presets = map[string]resolverPreset{
	"cloudflare": {
		udp: "1.1.1.1:53",
		dot: "1.1.1.1:853",
		doh: "https://cloudflare-dns.com/dns-query",
	},
	"google": {
		udp: "8.8.8.8:53",
		dot: "8.8.8.8:853",
		doh: "https://dns.google/dns-query",
	},
	"quad9": {
		udp: "9.9.9.9:53",
		dot: "9.9.9.9:853",
		doh: "https://dns.quad9.net/dns-query",
	},
	"opendns": {
		udp: "208.67.222.222:53",
		dot: "208.67.222.222:853",
		doh: "https://doh.opendns.com/dns-query",
	},
}

// parseUpstream interprets a single resolver spec. Accepted forms:
//
//	cloudflare                → preset, UDP
//	cloudflare-dot            → preset, DoT
//	cloudflare-doh            → preset, DoH
//	1.2.3.4                   → UDP, port 53
//	1.2.3.4:5353              → UDP, custom port
//	udp://1.2.3.4[:port]      → UDP, explicit (tcp:// is an alias)
//	tls://dns.example[:port]  → DoT, explicit (dot:// is an alias)
//	https://example/dns-query → DoH, explicit URL (doh:// is an alias)
//
// Schemes are case-insensitive. An IPv6 address takes a port only in
// brackets, as in [2001:db8::53]:5353; unbracketed, the whole spec is the
// address. A malformed spec is an error whatever BEDROCK_ALLOW_PRIVATE_RESOLVER
// says, and an error names a DoH upstream by its label, never by its URL.
func parseUpstream(spec string) (upstream, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return upstream{}, fmt.Errorf("empty resolver spec")
	}
	if up, ok := presetUpstream(s); ok {
		// Presets point at vetted public resolvers; skip validation.
		return up, nil
	}
	up, host, err := specUpstream(s)
	if err != nil {
		return upstream{}, err
	}
	if err := validateResolverHost(up, host); err != nil {
		return upstream{}, err
	}
	return up, nil
}

// presetUpstream returns the upstream a preset name selects, such as
// "cloudflare" or "quad9-dot". The label names the transport: plain DNS can
// be answered by an interceptor on the path rather than the named provider.
func presetUpstream(s string) (upstream, bool) {
	name, suffix := strings.ToLower(s), ""
	if i := strings.LastIndex(name, "-"); i > 0 {
		switch name[i+1:] {
		case "dot", "doh", "udp", "tcp":
			name, suffix = name[:i], name[i+1:]
		}
	}
	p, ok := presets[name]
	switch {
	case !ok:
		return upstream{}, false
	case suffix == "dot":
		return upstream{label: name + "-dot", addr: p.dot, protocol: protoDoT}, true
	case suffix == "doh":
		return upstream{label: name + "-doh", addr: p.doh, protocol: protoDoH}, true
	}
	return upstream{label: name + "-udp", addr: p.udp, protocol: protoUDP}, true
}

// specUpstream parses a spec that is not a preset: scheme://... or a bare
// host[:port], which means UDP. It also returns the host to validate.
func specUpstream(s string) (upstream, string, error) {
	scheme, rest, explicit := strings.Cut(s, "://")
	if !explicit {
		return hostUpstream(s, s, "53", protoUDP)
	}
	switch strings.ToLower(scheme) {
	case "https", "doh":
		return dohUpstream(rest)
	case "tls", "dot":
		return hostUpstream(s, rest, "853", protoDoT)
	case "udp", "tcp":
		return hostUpstream(s, rest, "53", protoUDP)
	}
	return upstream{}, "", fmt.Errorf(
		"unsupported resolver scheme %q (want udp, tcp, tls, dot, https or doh)", scheme)
}

// hostUpstream builds a UDP or DoT upstream labelled label from hostport,
// adding defaultPort when it has none. It also returns the host.
func hostUpstream(label, hostport, defaultPort string, p protocol) (upstream, string, error) {
	if strings.Contains(hostport, "/") {
		return upstream{}, "", fmt.Errorf("resolver %q: want host[:port], with no path", label)
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port. An IPv6 address may still be in brackets.
		host, port = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), defaultPort
	}
	if host == "" {
		return upstream{}, "", fmt.Errorf("resolver %q: missing host", label)
	}
	if err := checkHost(host); err != nil {
		return upstream{}, "", fmt.Errorf("resolver %q: %w", label, err)
	}
	if err := checkPort(port); err != nil {
		return upstream{}, "", fmt.Errorf("resolver %q: %w", label, err)
	}
	return upstream{label: label, addr: net.JoinHostPort(host, port), protocol: p}, host, nil
}

// dohUpstream builds a DoH upstream from a URL without its scheme. It also
// returns the URL's host.
func dohUpstream(rest string) (upstream, string, error) {
	addr := "https://" + rest
	u, err := url.Parse(addr)
	if err != nil {
		// A *url.Error repeats the URL, whose userinfo and path can carry
		// credentials; keep only the cause.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return upstream{}, "", fmt.Errorf("doh url: %w", err)
	}
	label := dohLabel(u)
	if u.Hostname() == "" {
		return upstream{}, "", fmt.Errorf("doh upstream %s: missing host", label)
	}
	if err := checkHost(u.Hostname()); err != nil {
		return upstream{}, "", fmt.Errorf("doh upstream %s: %w", label, err)
	}
	if port := u.Port(); port != "" {
		if err := checkPort(port); err != nil {
			return upstream{}, "", fmt.Errorf("doh upstream %s: %w", label, err)
		}
	}
	return upstream{label: label, addr: addr, protocol: protoDoH}, u.Hostname(), nil
}

// hostNameChars are the characters a DNS host name is written with.
const hostNameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."

// checkHost rejects a host that is neither an IP address nor written with
// the characters of a DNS name, such as the host of 192.0.2.53:53:53. The
// zone of an IPv6 address names an interface and takes the same characters.
func checkHost(host string) error {
	name := host
	if addr, err := netip.ParseAddr(host); err == nil {
		name = addr.Zone()
	}
	notNameChar := func(r rune) bool { return !strings.ContainsRune(hostNameChars, r) }
	if strings.ContainsFunc(name, notNameChar) {
		return fmt.Errorf("malformed host %q (want a DNS name or IP address)", host)
	}
	return nil
}

// checkPort rejects a port that is not a number from 1 to 65535.
func checkPort(port string) error {
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("invalid port %q (want 1-65535)", port)
	}
	return nil
}

// validateResolverHost rejects an upstream whose host is localhost or an
// address on the SSRF denylist (see blockedAddrReason), and a DoT or DoH
// upstream whose host is an IP literal: RFC 8310 §7.3 has the client check
// the server certificate against a DNS name. parseUpstream calls it while
// NewDNS / NewMultiDNS set up, not at each query.
//
// Setting the BEDROCK_ALLOW_PRIVATE_RESOLVER environment variable to a
// non-empty value disables all checks — use for hermetic tests only.
func validateResolverHost(up upstream, host string) error {
	if os.Getenv(allowPrivateResolverEnv) != "" {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("resolver %s points at localhost", up.label)
	}
	addr, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		// A host name is not resolved here, which would take a lookup
		// before the scan. DoH dials go through SafeDial, which refuses
		// denylisted addresses; UDP and DoT dial the name unchecked.
		return nil
	case up.protocol != protoUDP:
		return fmt.Errorf("%s upstream must use a DNS name, not an IP literal: %s",
			up.protocol, addr)
	}
	if reason, blocked := blockedAddrReason(addr); blocked {
		return fmt.Errorf("resolver %s is %s", addr, reason)
	}
	return nil
}

// dohLabel names a DoH upstream by scheme and host only: reports carry the
// label, and a DoH URL's userinfo and path can hold credentials or an
// account identifier.
func dohLabel(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}
