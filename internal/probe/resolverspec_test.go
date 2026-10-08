package probe

import (
	"net"
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

// TestParseUpstreamLabels pins the labels reports show for each spec form:
// they name the transport and never carry a DoH URL's userinfo, path or
// query, while the address keeps the full URL for the request itself.
func TestParseUpstreamLabels(t *testing.T) {
	cases := []struct {
		spec, label, addr string
	}{
		{"cloudflare", "cloudflare-udp", "1.1.1.1:53"},
		{"Google-TCP", "google-udp", "8.8.8.8:53"},
		{"quad9-dot", "quad9-dot", "9.9.9.9:853"},
		{"opendns-doh", "opendns-doh", "https://doh.opendns.com/dns-query"},
		{
			"https://user:s3cr3t@doh.example/dns-query/profile-abc123?id=7",
			"https://doh.example",
			"https://user:s3cr3t@doh.example/dns-query/profile-abc123?id=7",
		},
		{
			"doh://doh.example:8443/dns-query",
			"https://doh.example:8443",
			"https://doh.example:8443/dns-query",
		},
		{"192.0.2.53:5353", "192.0.2.53:5353", "192.0.2.53:5353"},
	}
	for _, c := range cases {
		up, err := parseUpstream(c.spec)
		if err != nil {
			t.Errorf("parseUpstream(%q): %v", c.spec, err)
			continue
		}
		if up.label != c.label || up.addr != c.addr {
			t.Errorf("parseUpstream(%q) = label %q addr %q, want label %q addr %q",
				c.spec, up.label, up.addr, c.label, c.addr)
		}
	}
}

// TestConfigUpstreamsLabels names system resolvers by position, so reports
// never carry the local network addresses read from resolv.conf.
func TestConfigUpstreamsLabels(t *testing.T) {
	conf := &mdns.ClientConfig{Servers: []string{"192.168.1.1", "2001:db8::53"}, Port: "53"}

	ups, err := configUpstreams(conf)
	if err != nil {
		t.Fatalf("configUpstreams: %v", err)
	}

	want := []upstream{
		{label: "system-1", addr: "192.168.1.1:53", protocol: protoUDP},
		{label: "system-2", addr: "[2001:db8::53]:53", protocol: protoUDP},
	}
	if !slices.Equal(ups, want) {
		t.Errorf("configUpstreams = %+v, want %+v", ups, want)
	}
}

func TestConfigUpstreamsEmpty(t *testing.T) {
	if _, err := configUpstreams(&mdns.ClientConfig{Port: "53"}); err == nil {
		t.Error("configUpstreams with no servers: want an error")
	}
}

// TestParseUpstreamRejectsMalformedSpecs: a spec that cannot name a
// resolver is an error even with the denylist off, so a typo stops the run
// at startup instead of failing every lookup.
func TestParseUpstreamRejectsMalformedSpecs(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	malformed := []string{
		"", "   ", "UDP://", "udp://", "tls://", "tcp://:53", ":53", "dns.example:",
		"192.0.2.53:0", "192.0.2.53:70000", "dns.example:abc", "udp://192.0.2.53:0",
		"tls://dns.example:70000", "192.0.2.53:53:53", "[dns:example]:53",
		"0]0", "::%]0", "dns example", "dns!example:53", "tls://dns$example",
		"dns.example/dns-query", "tls://dns.example/dns-query", "dot://dns.example:853/x",
		"foo://dns.example", "quic://dns.example", "sdns://AQcAAAAAAAAAAAAAAAAAAAAA",
		"http://dns.example/dns-query", "https://", "https:///dns-query",
		"https://dns.example:0/dns-query", "https://dns.example:70000/dns-query",
		"https://dns.example:port/dns-query", "https://dns!example/q",
	}
	for _, spec := range malformed {
		if up, err := parseUpstream(spec); err == nil {
			t.Errorf("parseUpstream(%q) = %+v, want an error", spec, up)
		}
	}
}

// TestParseUpstreamNamesPaths: a UDP or DoT spec with a path, as when a DoH
// URL path follows tls://, gets an error that says so.
func TestParseUpstreamNamesPaths(t *testing.T) {
	specs := []string{
		"tls://dns.example:853/dns-query", "dns.example/dns-query", "udp://192.0.2.53/x",
	}
	for _, spec := range specs {
		_, err := parseUpstream(spec)
		if err == nil || !strings.Contains(err.Error(), "want host[:port], with no path") {
			t.Errorf("parseUpstream(%q) = %v, want the no-path error", spec, err)
		}
	}
}

// TestParseUpstreamNamesUnsupportedSchemes: a scheme bedrock does not speak
// is named in the error, with the schemes it does.
func TestParseUpstreamNamesUnsupportedSchemes(t *testing.T) {
	cases := []struct{ spec, scheme string }{
		{"quic://dns.example", "quic"},
		{"sdns://AQcAAAAA", "sdns"},
		{"HTTP://dns.example/q", "HTTP"},
	}
	for _, c := range cases {
		_, err := parseUpstream(c.spec)
		want := `unsupported resolver scheme "` + c.scheme +
			`" (want udp, tcp, tls, dot, https or doh)`
		if err == nil || err.Error() != want {
			t.Errorf("parseUpstream(%q) = %v, want %s", c.spec, err, want)
		}
	}
}

// TestParseUpstreamAcceptedForms pins the forms that parse: schemes in any
// case, default ports, and IPv6 addresses with or without brackets.
func TestParseUpstreamAcceptedForms(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	cases := []struct {
		spec, label, addr string
		protocol          protocol
	}{
		{"UDP://192.0.2.53", "UDP://192.0.2.53", "192.0.2.53:53", protoUDP},
		{"Tcp://192.0.2.53:5353", "Tcp://192.0.2.53:5353", "192.0.2.53:5353", protoUDP},
		{"TLS://dns.example", "TLS://dns.example", "dns.example:853", protoDoT},
		{"Dot://dns.example:8853", "Dot://dns.example:8853", "dns.example:8853", protoDoT},
		{
			"HTTPS://dns.example/dns-query", "https://dns.example",
			"https://dns.example/dns-query", protoDoH,
		},
		{"DoH://dns.example/q", "https://dns.example", "https://dns.example/q", protoDoH},
		{"2001:db8::53", "2001:db8::53", "[2001:db8::53]:53", protoUDP},
		{"[2001:db8::53]", "[2001:db8::53]", "[2001:db8::53]:53", protoUDP},
		{"[2001:db8::53]:5353", "[2001:db8::53]:5353", "[2001:db8::53]:5353", protoUDP},
		{"dns.example:65535", "dns.example:65535", "dns.example:65535", protoUDP},
		{"dns-1_a.example.", "dns-1_a.example.", "dns-1_a.example.:53", protoUDP},
		{" 192.0.2.53 ", "192.0.2.53", "192.0.2.53:53", protoUDP},
	}
	for _, c := range cases {
		up, err := parseUpstream(c.spec)
		want := upstream{label: c.label, addr: c.addr, protocol: c.protocol}
		if err != nil || up != want {
			t.Errorf("parseUpstream(%q) = %+v, %v; want %+v", c.spec, up, err, want)
		}
	}
}

// TestParseUpstreamDenylist: with the denylist on, every spec form refuses
// localhost and denylisted addresses, DoT and DoH refuse IP literals, and
// presets and public resolvers parse. BEDROCK_ALLOW_PRIVATE_RESOLVER lifts
// all of these checks.
func TestParseUpstreamDenylist(t *testing.T) {
	refused := []string{
		"127.0.0.1", "10.0.0.1:53", "172.16.0.1", "192.168.1.1", "100.64.0.1",
		"169.254.169.254", "[fe80::1%en0]:53", "fd00::53", "::1", "::ffff:127.0.0.1",
		"localhost", "LOCALHOST:53", "udp://10.0.0.1", "tcp://127.0.0.1:5353",
		"tls://127.0.0.1", "tls://1.1.1.1:853", "dot://[2606:4700:4700::1111]",
		"tls://localhost", "https://127.0.0.1/dns-query", "https://[::1]/dns-query",
		"https://1.1.1.1/dns-query", "https://localhost/dns-query",
	}
	allowed := []string{
		"192.0.2.53", "198.18.0.53", "dns.example", "tls://dns.example",
		"https://dns.example/dns-query", "cloudflare", "cloudflare-dot", "google-doh",
		"quad9", "opendns-dot",
	}

	t.Setenv(allowPrivateResolverEnv, "")
	for _, spec := range refused {
		if _, err := parseUpstream(spec); err == nil {
			t.Errorf("parseUpstream(%q) accepted a private or IP-literal resolver", spec)
		}
	}
	for _, spec := range allowed {
		if _, err := parseUpstream(spec); err != nil {
			t.Errorf("parseUpstream(%q): %v", spec, err)
		}
	}

	t.Setenv(allowPrivateResolverEnv, "1")
	for _, spec := range refused {
		if _, err := parseUpstream(spec); err != nil {
			t.Errorf("parseUpstream(%q) with %s set: %v", spec, allowPrivateResolverEnv, err)
		}
	}
}

// TestParseUpstreamErrorsOmitDoHSecrets: an error about a DoH spec names
// the upstream by scheme and host, never by its userinfo or path, which
// can carry credentials.
func TestParseUpstreamErrorsOmitDoHSecrets(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "")
	specs := []string{
		"https://u:p@localhost/tok", "https://u:p@127.0.0.1/tok",
		"https://u:p@doh.example:0/tok", "https://u:p@doh.example:port/tok",
		"https://u:p@doh!example/tok", "https://u:p@/tok", "https://u:p@doh.example%zz/tok",
		"doh://u:p@doh.example:70000/tok", "htps://u:p@doh.example/tok",
	}
	for _, spec := range specs {
		_, err := parseUpstream(spec)
		if err == nil {
			t.Errorf("parseUpstream(%q) accepted a bad DoH spec", spec)
			continue
		}
		for _, secret := range []string{"u:p", "p@", "/tok"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("parseUpstream(%q) error %q carries %q", spec, err, secret)
			}
		}
	}
}

// FuzzParseUpstream: parseUpstream never panics, a DoH label carries no
// userinfo, path, query or fragment, and a UDP or DoT address splits into
// a host and a port from 1 to 65535.
func FuzzParseUpstream(f *testing.F) {
	seeds := []string{
		"cloudflare-doh", "192.0.2.53:5353", "[2001:db8::53]", "tls://dns.example",
		"https://u:p@doh.example:8443/dns-query?x=1#f", "udp://", "quic://x", "[a:b]:53",
		"0]0", "::%]0",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Setenv(allowPrivateResolverEnv, "1")
	f.Fuzz(func(t *testing.T, spec string) {
		up, err := parseUpstream(spec)
		if err != nil {
			return
		}
		if up.protocol == protoDoH {
			if strings.ContainsAny(strings.TrimPrefix(up.label, "https://"), "@/?#") {
				t.Errorf("parseUpstream(%q): DoH label %q carries more than a host", spec, up.label)
			}
			return
		}
		_, port, err := net.SplitHostPort(up.addr)
		if err != nil || checkPort(port) != nil {
			t.Errorf("parseUpstream(%q): address %q is not host:port", spec, up.addr)
		}
	})
}
