package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS is the resolver primitive every check calls. It wraps miekg/dns so we
// can request arbitrary RR types (TLSA, CAA, DS, DNSKEY, RRSIG, ...) and
// optionally point at a specific resolver via --resolver.
//
// Per-name LRU caching is intentionally NOT done here — checks share parsed
// records via Env.cache, and an in-memory record cache would mask resolver
// quirks the tool is meant to surface.
type DNS struct {
	server  string // host:port; "" means system resolver
	timeout time.Duration

	clientOnce sync.Once
	client     *dns.Client
}

// NewDNS returns a DNS client. server may be "" (use the OS resolvers from
// /etc/resolv.conf) or "host:port" (UDP first, fall back to TCP on truncation).
func NewDNS(server string, timeout time.Duration) *DNS {
	return &DNS{server: server, timeout: timeout}
}

func (d *DNS) cli() *dns.Client {
	d.clientOnce.Do(func() {
		d.client = &dns.Client{
			Net:     "udp",
			Timeout: d.timeout,
		}
	})
	return d.client
}

// servers returns the resolver list to try in order.
func (d *DNS) servers() ([]string, error) {
	if d.server != "" {
		return []string{normalizeServer(d.server)}, nil
	}
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	if len(conf.Servers) == 0 {
		return nil, errors.New("no system resolvers configured")
	}
	out := make([]string, len(conf.Servers))
	for i, s := range conf.Servers {
		out[i] = net.JoinHostPort(s, conf.Port)
	}
	return out, nil
}

func normalizeServer(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// Exchange sends a single query and returns the raw response. Used by checks
// that need full RR access (DNSSEC), CAA bytes, etc. Honors the env timeout.
// On UDP truncation, retries over TCP automatically.
func (d *DNS) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	servers, err := d.servers()
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	var lastErr error
	for _, srv := range servers {
		resp, err := d.exchangeOnce(ctx, m, srv, "udp")
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.Truncated {
			resp, err = d.exchangeOnce(ctx, m, srv, "tcp")
			if err != nil {
				lastErr = err
				continue
			}
		}
		return resp, nil
	}
	return nil, lastErr
}

func (d *DNS) exchangeOnce(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error) {
	c := *d.cli()
	c.Net = network
	resp, _, err := c.ExchangeContext(ctx, m, server)
	return resp, err
}

// ExchangeWithDO performs an exchange with the DNSSEC OK bit set, requesting
// RRSIG records alongside the answer. Used by the DNSSEC checks.
func (d *DNS) ExchangeWithDO(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	servers, err := d.servers()
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO bit

	var lastErr error
	for _, srv := range servers {
		resp, err := d.exchangeOnce(ctx, m, srv, "udp")
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.Truncated {
			resp, err = d.exchangeOnce(ctx, m, srv, "tcp")
			if err != nil {
				lastErr = err
				continue
			}
		}
		return resp, nil
	}
	return nil, lastErr
}

// LookupTXT returns concatenated TXT strings per record. Each TXT record can
// span multiple character-strings; per RFC 7208 §3.3 / RFC 6376 §3.6.2.2,
// these are concatenated with NO separator.
func (d *DNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// MX is a simplified MX record.
type MX struct {
	Preference uint16
	Host       string // FQDN, trailing-dot trimmed
}

func (d *DNS) LookupMX(ctx context.Context, name string) ([]MX, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	var out []MX
	for _, rr := range resp.Answer {
		if m, ok := rr.(*dns.MX); ok {
			out = append(out, MX{Preference: m.Preference, Host: strings.TrimSuffix(m.Mx, ".")})
		}
	}
	return out, nil
}

func (d *DNS) LookupNS(ctx context.Context, name string) ([]string, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	var out []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	return out, nil
}

func (d *DNS) LookupA(ctx context.Context, name string) ([]net.IP, error) {
	return d.lookupAddr(ctx, name, dns.TypeA)
}

func (d *DNS) LookupAAAA(ctx context.Context, name string) ([]net.IP, error) {
	return d.lookupAddr(ctx, name, dns.TypeAAAA)
}

func (d *DNS) lookupAddr(ctx context.Context, name string, qtype uint16) ([]net.IP, error) {
	resp, err := d.Exchange(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	var out []net.IP
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A)
		case *dns.AAAA:
			out = append(out, v.AAAA)
		}
	}
	return out, nil
}

// SOA is a simplified SOA record. Minimum is the negative-cache TTL per RFC 2308.
type SOA struct {
	NS      string
	Mbox    string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (d *DNS) LookupSOA(ctx context.Context, name string) (*SOA, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeSOA)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	for _, rr := range append(resp.Answer, resp.Ns...) {
		if s, ok := rr.(*dns.SOA); ok {
			return &SOA{
				NS:      strings.TrimSuffix(s.Ns, "."),
				Mbox:    strings.TrimSuffix(s.Mbox, "."),
				Serial:  s.Serial,
				Refresh: s.Refresh,
				Retry:   s.Retry,
				Expire:  s.Expire,
				Minimum: s.Minttl,
			}, nil
		}
	}
	return nil, nil
}

// CAA mirrors miekg/dns CAA fields with fewer surprises.
type CAA struct {
	Flag  uint8
	Tag   string
	Value string
}

func (d *DNS) LookupCAA(ctx context.Context, name string) ([]CAA, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	var out []CAA
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, CAA{Flag: c.Flag, Tag: c.Tag, Value: c.Value})
		}
	}
	return out, nil
}

// TLSA mirrors miekg/dns TLSA fields.
type TLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string // hex
}

func (d *DNS) LookupTLSA(ctx context.Context, name string) ([]TLSA, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeTLSA)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}
	var out []TLSA
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			out = append(out, TLSA{
				Usage:        t.Usage,
				Selector:     t.Selector,
				MatchingType: t.MatchingType,
				Certificate:  t.Certificate,
			})
		}
	}
	return out, nil
}

// LookupCNAME returns the immediate CNAME target for name, or "" if there is none.
// Does NOT chase chains — the caller decides whether to follow.
func (d *DNS) LookupCNAME(ctx context.Context, name string) (string, error) {
	resp, err := d.Exchange(ctx, name, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return "", ErrNXDOMAIN
	}
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return strings.TrimSuffix(c.Target, "."), nil
		}
	}
	return "", nil
}

// ErrNXDOMAIN is returned by Lookup* helpers when the resolver returns NXDOMAIN.
// Distinguishable from "no records of this type" (NOERROR + empty answer).
var ErrNXDOMAIN = errors.New("NXDOMAIN")
