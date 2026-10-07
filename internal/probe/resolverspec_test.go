package probe

import (
	"slices"
	"testing"

	mdns "github.com/miekg/dns"
)

// TestParseUpstreamLabels pins the labels reports show for each spec form:
// they name the transport and never carry a DoH URL's userinfo, path or
// query, while the address keeps the full URL for the request itself.
func TestParseUpstreamLabels(t *testing.T) {
	// Labels do not depend on host validation; skipping it lets the
	// unparsable URL reach dohLabel.
	t.Setenv(allowPrivateResolverEnv, "1")
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
		{"https://doh.example:port/dns-query", "doh upstream", "https://doh.example:port/dns-query"},
		{"https:///dns-query", "doh upstream", "https:///dns-query"},
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
