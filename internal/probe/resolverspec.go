package probe

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// allowPrivateResolverEnv, when set to a non-empty value, bypasses the
// validateResolverHost denylist. Intended for hermetic tests and lab
// environments where resolvers bind to 127.0.0.1 / RFC 1918 addresses.
// Production callers must leave this unset.
const allowPrivateResolverEnv = "BEDROCK_ALLOW_PRIVATE_RESOLVER"

// upstream is one resolved DNS endpoint. Multiple upstreams within a single
// DNS instance let us run propagation checks across providers.
type upstream struct {
	label    string // human-readable, e.g. "cloudflare", "1.1.1.1:53"
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
//	cloudflare              → preset, UDP
//	cloudflare-dot          → preset, DoT
//	cloudflare-doh          → preset, DoH
//	1.2.3.4                 → UDP, port 53
//	1.2.3.4:5353            → UDP, custom port
//	tls://1.1.1.1:853       → DoT, explicit
//	https://example/dns-query → DoH, explicit URL
func parseUpstream(spec string) (upstream, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return upstream{}, fmt.Errorf("empty resolver spec")
	}

	var up upstream
	// Explicit scheme prefixes win.
	switch {
	case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "doh://"):
		u := strings.TrimPrefix(strings.TrimPrefix(s, "doh://"), "https://")
		// re-add https:// for actual fetches
		up = upstream{label: s, addr: "https://" + u, protocol: protoDoH}
	case strings.HasPrefix(s, "tls://"), strings.HasPrefix(s, "dot://"):
		host := strings.TrimPrefix(strings.TrimPrefix(s, "dot://"), "tls://")
		up = upstream{label: s, addr: hostWithPort(host, "853"), protocol: protoDoT}
	case strings.HasPrefix(s, "udp://"), strings.HasPrefix(s, "tcp://"):
		host := strings.TrimPrefix(strings.TrimPrefix(s, "tcp://"), "udp://")
		up = upstream{label: s, addr: hostWithPort(host, "53"), protocol: protoUDP}
	default:
		// Preset names with optional protocol suffix.
		low := strings.ToLower(s)
		name, suffix := low, ""
		if i := strings.LastIndex(low, "-"); i > 0 {
			switch low[i+1:] {
			case "dot", "doh", "udp", "tcp":
				name, suffix = low[:i], low[i+1:]
			}
		}
		if p, ok := presets[name]; ok {
			switch suffix {
			case "", "udp", "tcp":
				// Presets point at vetted public resolvers; skip validation.
				return upstream{label: name, addr: p.udp, protocol: protoUDP}, nil
			case "dot":
				return upstream{label: name + "-dot", addr: p.dot, protocol: protoDoT}, nil
			case "doh":
				return upstream{label: name + "-doh", addr: p.doh, protocol: protoDoH}, nil
			}
		}
		// Bare host or host:port → UDP.
		up = upstream{label: s, addr: hostWithPort(s, "53"), protocol: protoUDP}
	}

	if err := validateResolverHost(up); err != nil {
		return upstream{}, err
	}
	return up, nil
}

// validateResolverHost rejects upstreams whose host is loopback, private,
// link-local, ULA, CGNAT, or the cloud-metadata literal. Applied to all
// protocols; DoH URLs must also not use an IP literal (so the ServerName
// can be compared against the cert SAN). Callers always wrap parseUpstream
// so this runs during NewDNS / NewMultiDNS setup — NOT at each query.
//
// Setting the BEDROCK_ALLOW_PRIVATE_RESOLVER environment variable to a
// non-empty value disables all checks — use for hermetic tests only.
func validateResolverHost(up upstream) error {
	if os.Getenv(allowPrivateResolverEnv) != "" {
		return nil
	}
	switch up.protocol {
	case protoDoH:
		u, err := url.Parse(up.addr)
		if err != nil {
			return fmt.Errorf("parse doh url %q: %w", up.addr, err)
		}
		host := u.Hostname()
		if host == "" {
			return fmt.Errorf("doh url missing host: %s", up.addr)
		}
		if ip := net.ParseIP(host); ip != nil {
			return fmt.Errorf("doh url host must be a DNS name, not an IP literal: %s", host)
		}
		if strings.EqualFold(host, "localhost") {
			return fmt.Errorf("doh url points at localhost: %s", up.addr)
		}
		return nil
	case protoDoT:
		host, _, err := net.SplitHostPort(up.addr)
		if err != nil {
			host = up.addr
		}
		if ip := net.ParseIP(host); ip != nil {
			// RFC 8310 §7.3: a DoT ServerName must be a DNS name so the
			// client can verify against the SAN. IP-literal DoT upstreams
			// are insecure.
			return fmt.Errorf("dot upstream must use a DNS name, not an IP literal: %s", host)
		}
		if strings.EqualFold(host, "localhost") {
			return fmt.Errorf("dot upstream points at localhost: %s", up.addr)
		}
		return nil
	default: // UDP / TCP plain
		host, _, err := net.SplitHostPort(up.addr)
		if err != nil {
			host = up.addr
		}
		if strings.EqualFold(host, "localhost") {
			return fmt.Errorf("resolver points at localhost: %s", up.addr)
		}
		if ip := net.ParseIP(host); ip != nil {
			if reason, blocked := blockedIPReason(ip); blocked {
				return fmt.Errorf("resolver %s is %s", ip.String(), reason)
			}
			return nil
		}
		// Hostname: we cannot resolve here without triggering DNS via the
		// resolver we are still constructing, so defer the IP check to
		// first use. The dialer enforces the denylist at dial time.
		return nil
	}
}

func hostWithPort(s, defaultPort string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, defaultPort)
}
