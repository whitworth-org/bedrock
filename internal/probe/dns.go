package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS is the resolver primitive every check calls. It wraps miekg/dns so we
// can request arbitrary RR types (TLSA, CAA, DS, DNSKEY, RRSIG, ...) and
// optionally point at one or more specific resolvers via --resolver /
// --resolvers.
//
// Per-name LRU caching is intentionally NOT done here — checks share parsed
// records via Env.cache, and an in-memory record cache would mask resolver
// quirks the tool is meant to surface.
type DNS struct {
	upstreams []upstream // primary at index 0; additional entries for propagation
	timeout   time.Duration
	// specErr captures a parse failure from NewDNS so the first lookup can
	// return a clean error rather than silently falling back to system DNS
	// after a bad explicit spec.
	specErr error

	udpClient  *dns.Client
	tcpClient  *dns.Client
	dotClient  *dns.Client
	httpClient *http.Client // for DoH

	once sync.Once
}

// NewDNS returns a DNS client. server may be:
//
//   - ""                          — use the OS resolvers from /etc/resolv.conf (UDP)
//   - "host:port" or "host"       — UDP plaintext to that address
//   - "cloudflare" / "google" / "quad9" / "opendns"           — preset, UDP
//   - "<preset>-dot" / "<preset>-doh"                          — preset over DoT/DoH
//   - "tls://host[:port]" / "https://host/path"                — explicit
//
// Parse errors are deferred to the first lookup so NewDNS never aborts
// startup: an invalid spec just means every query returns that error.
func NewDNS(server string, timeout time.Duration) *DNS {
	d := &DNS{timeout: timeout}
	if up, ok := systemOrSpec(server); ok {
		d.upstreams = up
	} else if server != "" {
		// Remember the parse error so the first lookup can surface it.
		if _, err := parseUpstream(server); err != nil {
			d.specErr = err
		}
	}
	return d
}

// NewMultiDNS returns a DNS client that knows about multiple upstreams.
// The first upstream is used for all normal lookups; the full list is
// exposed via ExchangeAll for the dns.propagation check.
func NewMultiDNS(specs []string, timeout time.Duration) (*DNS, error) {
	if len(specs) == 0 {
		return NewDNS("", timeout), nil
	}
	d := &DNS{timeout: timeout}
	for _, s := range specs {
		up, err := parseUpstream(s)
		if err != nil {
			return nil, err
		}
		d.upstreams = append(d.upstreams, up)
	}
	return d, nil
}

// Upstreams returns the labels of every configured upstream, in order.
// Used by the propagation check to title evidence.
func (d *DNS) Upstreams() []string {
	out := make([]string, 0, len(d.upstreams))
	for _, u := range d.upstreams {
		out = append(out, u.label)
	}
	return out
}

func (d *DNS) ensureClients() {
	d.once.Do(func() {
		d.udpClient = &dns.Client{Net: "udp", Timeout: d.timeout}
		d.tcpClient = &dns.Client{Net: "tcp", Timeout: d.timeout}
		d.dotClient = &dns.Client{Net: "tcp-tls", Timeout: d.timeout}
		d.httpClient = newDoHClient(d.timeout)
	})
}

// systemOrSpec returns the upstream list for spec; falls back to system
// resolvers (UDP) when spec is empty. Hidden behind a (slice, bool) so
// startup failures don't crash NewDNS — they surface on first lookup.
func systemOrSpec(spec string) ([]upstream, bool) {
	if spec == "" {
		ups, err := systemUpstreams()
		if err != nil {
			return nil, false
		}
		return ups, true
	}
	up, err := parseUpstream(spec)
	if err != nil {
		return nil, false
	}
	return []upstream{up}, true
}

func systemUpstreams() ([]upstream, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	if len(conf.Servers) == 0 {
		return nil, errors.New("no system resolvers configured")
	}
	out := make([]upstream, 0, len(conf.Servers))
	for _, s := range conf.Servers {
		addr := net.JoinHostPort(s, conf.Port)
		out = append(out, upstream{label: addr, addr: addr, protocol: protoUDP})
	}
	return out, nil
}

func (d *DNS) ensureUpstreams() error {
	if len(d.upstreams) > 0 {
		return nil
	}
	// If NewDNS saw an invalid explicit spec, surface that error now rather
	// than silently falling back to system DNS.
	if d.specErr != nil {
		return d.specErr
	}
	ups, err := systemUpstreams()
	if err != nil {
		return err
	}
	d.upstreams = ups
	return nil
}

// Exchange sends a single query to the primary upstream and returns the raw
// response. UDP truncation falls back to TCP automatically.
func (d *DNS) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if err := d.ensureUpstreams(); err != nil {
		return nil, err
	}
	d.ensureClients()
	m := buildQuery(name, qtype, false)
	return d.exchangeOnUpstream(ctx, m, d.upstreams[0])
}

// ExchangeWithDO performs an exchange with the DNSSEC OK bit set, requesting
// RRSIG records alongside the answer. Used by the DNSSEC checks.
func (d *DNS) ExchangeWithDO(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if err := d.ensureUpstreams(); err != nil {
		return nil, err
	}
	d.ensureClients()
	m := buildQuery(name, qtype, true)
	return d.exchangeOnUpstream(ctx, m, d.upstreams[0])
}

// MultiResp is one upstream's answer in a propagation query.
type MultiResp struct {
	Upstream string
	Msg      *dns.Msg
	Err      error
}

// ExchangeAll runs the same query against every configured upstream in
// parallel and returns one MultiResp per upstream, in upstream order. Used
// by the dns.propagation check. Goroutine fan-out is capped at 16 so a
// large --resolvers list cannot trip rate limits or starve the host.
func (d *DNS) ExchangeAll(ctx context.Context, name string, qtype uint16) []MultiResp {
	if err := d.ensureUpstreams(); err != nil {
		return []MultiResp{{Err: err}}
	}
	d.ensureClients()
	m := buildQuery(name, qtype, false)
	out := make([]MultiResp, len(d.upstreams))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, u := range d.upstreams {
		wg.Add(1)
		go func(i int, u upstream) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i] = MultiResp{Upstream: u.label, Err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			resp, err := d.exchangeOnUpstream(ctx, m.Copy(), u)
			out[i] = MultiResp{Upstream: u.label, Msg: resp, Err: err}
		}(i, u)
	}
	wg.Wait()
	return out
}

func buildQuery(name string, qtype uint16, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	if do {
		m.SetEdns0(4096, true)
	}
	return m
}

// answerMatches returns true when rr's owner name equals the queried name
// after canonical FQDN normalisation. Defence against a resolver (or
// path-injection via a compromised recursive) returning off-name answers
// that a check would otherwise trust.
func answerMatches(rr dns.RR, queried string) bool {
	if rr == nil || rr.Header() == nil {
		return false
	}
	return dns.CanonicalName(rr.Header().Name) == dns.CanonicalName(dns.Fqdn(queried))
}

func (d *DNS) exchangeOnUpstream(ctx context.Context, m *dns.Msg, u upstream) (*dns.Msg, error) {
	// Tight per-upstream deadline so a single slow resolver cannot consume
	// the caller's whole budget when we fan out across upstreams.
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	switch u.protocol {
	case protoDoH:
		return dohExchange(ctx, d.httpClient, u.addr, m)
	case protoDoT:
		resp, _, err := d.dotClient.ExchangeContext(ctx, m, u.addr)
		return resp, err
	default:
		resp, _, err := d.udpClient.ExchangeContext(ctx, m, u.addr)
		if err != nil {
			return nil, err
		}
		if resp != nil && resp.Truncated {
			resp, _, err = d.tcpClient.ExchangeContext(ctx, m, u.addr)
		}
		return resp, err
	}
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
		if !answerMatches(rr, name) {
			continue
		}
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// MX is a simplified MX record.
type MX struct {
	Preference uint16
	Host       string
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
		if !answerMatches(rr, name) {
			continue
		}
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
		if !answerMatches(rr, name) {
			continue
		}
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
		if !answerMatches(rr, name) {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A)
		case *dns.AAAA:
			out = append(out, v.AAAA)
		}
	}
	return out, nil
}

// SOA is a simplified SOA record.
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
	// Answer section: filter by owner name. Authority section: accept as-is
	// per the SOA fallback semantics (NXDOMAIN / NODATA replies carry the
	// zone SOA in Ns which may legitimately have a different owner name).
	for _, rr := range resp.Answer {
		if !answerMatches(rr, name) {
			continue
		}
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
	for _, rr := range resp.Ns {
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
		if !answerMatches(rr, name) {
			continue
		}
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
	Certificate  string
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
		if !answerMatches(rr, name) {
			continue
		}
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

// LookupCNAME returns the immediate CNAME target for name, or "" if there is
// none. Does NOT chase chains — the caller decides whether to follow.
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
		if !answerMatches(rr, name) {
			continue
		}
		if c, ok := rr.(*dns.CNAME); ok {
			return strings.TrimSuffix(c.Target, "."), nil
		}
	}
	return "", nil
}

// ErrNXDOMAIN is returned by Lookup* helpers when the resolver returns NXDOMAIN.
// Distinguishable from "no records of this type" (NOERROR + empty answer).
var ErrNXDOMAIN = errors.New("NXDOMAIN")
