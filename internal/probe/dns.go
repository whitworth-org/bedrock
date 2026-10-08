package probe

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DNS is the resolver primitive every check calls. It wraps miekg/dns so we
// can request arbitrary RR types (TLSA, CAA, DS, DNSKEY, RRSIG, ...) and
// optionally point at one or more specific resolvers via --resolver /
// --resolvers.
//
// The Lookup* methods return the records of the queried type that answer
// for the name, following a CNAME chain in the answer section. They return
// ErrNXDOMAIN when the name does not exist and an *RcodeError for any other
// rcode but NOERROR. The Exchange* methods return the reply whatever its
// rcode.
//
// Per-name LRU caching is intentionally NOT done here — checks share parsed
// records via Env.cache, and an in-memory record cache would mask resolver
// quirks the tool is meant to surface.
type DNS struct {
	upstreams []upstream // primary at index 0; the ExchangeAll* methods reach them all
	// failover lets the primary path move on to the next upstream when one
	// sends no reply. Only the system resolvers fail over.
	failover bool
	timeout  time.Duration
	// setupErr is why the constructor found no upstream: an invalid spec or
	// no system resolver. Every query returns it.
	setupErr error

	udpClient  *dns.Client
	tcpClient  *dns.Client
	dotClient  *dns.Client
	httpClient *http.Client // for DoH

	once sync.Once

	sent, replied, answered atomic.Int64 // primary-path queries, for Health
}

// resolvConfPath is the system resolver configuration NewDNS reads. Tests
// point it at a temporary file.
var resolvConfPath = "/etc/resolv.conf"

// errNoSystemResolver means there is no system resolver configuration to
// read, as on Windows, which has no resolv.conf.
var errNoSystemResolver = errors.New("no system resolver found; pass --resolver")

// NewDNS returns a DNS client. server may be:
//
//   - ""                          — the OS resolvers from /etc/resolv.conf (UDP), in order
//   - "host:port" or "host"       — UDP plaintext to that address
//   - "cloudflare" / "google" / "quad9" / "opendns"           — preset, UDP
//   - "<preset>-dot" / "<preset>-doh"                          — preset over DoT/DoH
//   - "tls://host[:port]" / "https://host/path"                — explicit
//
// The system configuration is read once, here. Errors are deferred to the
// first lookup so NewDNS never aborts startup: an invalid spec or a missing
// system resolver just means every query returns that error.
func NewDNS(server string, timeout time.Duration) *DNS {
	if server == "" {
		ups, err := systemUpstreams()
		return &DNS{upstreams: ups, failover: true, timeout: timeout, setupErr: err}
	}
	up, err := parseUpstream(server)
	if err != nil {
		return &DNS{timeout: timeout, setupErr: err}
	}
	return &DNS{upstreams: []upstream{up}, timeout: timeout}
}

// NewMultiDNS returns a DNS client that knows about multiple upstreams.
// The first upstream serves every normal lookup; ExchangeAllWithDO and
// ExchangeAllCheckingDisabled query them all, as the dnssec.sentinel check
// does. Without specs it uses the system resolvers, as NewDNS("") does, and
// fails when there are none.
func NewMultiDNS(specs []string, timeout time.Duration) (*DNS, error) {
	if len(specs) == 0 {
		d := NewDNS("", timeout)
		if d.setupErr != nil {
			return nil, d.setupErr
		}
		return d, nil
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

func (d *DNS) ensureClients() {
	d.once.Do(func() {
		d.udpClient = &dns.Client{Net: "udp", Timeout: d.timeout}
		d.tcpClient = &dns.Client{Net: "tcp", Timeout: d.timeout}
		d.dotClient = &dns.Client{Net: "tcp-tls", Timeout: d.timeout}
		d.httpClient = newDoHClient(d.timeout)
	})
}

// systemUpstreams reads the nameservers listed in resolvConfPath.
func systemUpstreams() ([]upstream, error) {
	conf, err := dns.ClientConfigFromFile(resolvConfPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoSystemResolver
	}
	if err != nil {
		return nil, fmt.Errorf("read system resolver config: %w; pass --resolver", err)
	}
	return configUpstreams(conf)
}

// configUpstreams lists conf's nameservers in order. Their labels are
// positional (system-1, system-2, ...) so a shared report does not carry the
// operator's local network addresses.
func configUpstreams(conf *dns.ClientConfig) ([]upstream, error) {
	if len(conf.Servers) == 0 {
		return nil, errNoSystemResolver
	}
	out := make([]upstream, 0, len(conf.Servers))
	for i, s := range conf.Servers {
		out = append(out, upstream{
			label:    fmt.Sprintf("system-%d", i+1),
			addr:     net.JoinHostPort(s, conf.Port),
			protocol: protoUDP,
		})
	}
	return out, nil
}

// ready returns the constructor's setup error, if any, and otherwise
// creates the transport clients on first use.
func (d *DNS) ready() error {
	if d.setupErr != nil {
		return d.setupErr
	}
	d.ensureClients()
	return nil
}

// Exchange sends a single query on the primary path and returns the raw
// response, whatever its rcode. UDP truncation falls back to TCP
// automatically. A FORMERR, which a server that does not implement EDNS
// sends back for the query's OPT record (RFC 6891 §7), is followed by the
// same query without one.
func (d *DNS) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	resp, err := d.exchangePrimary(ctx, buildQuery(name, qtype, false))
	if err != nil || resp.Rcode != dns.RcodeFormatError {
		return resp, err
	}
	plain := buildQuery(name, qtype, false)
	plain.Extra = nil // drop the OPT record
	return d.exchangePrimary(ctx, plain)
}

// ExchangeWithDO performs an exchange with the DNSSEC OK bit set, requesting
// RRSIG records alongside the answer. Used by the DNSSEC checks.
func (d *DNS) ExchangeWithDO(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return d.exchangePrimary(ctx, buildQuery(name, qtype, true))
}

// ExchangeCheckingDisabled is ExchangeWithDO with the Checking Disabled bit
// also set (RFC 4035 §3.2.2): a validating resolver returns the records and
// their RRSIGs even when they fail validation, so the DNSSEC chain check can
// say why a zone is bogus instead of seeing only SERVFAIL.
func (d *DNS) ExchangeCheckingDisabled(
	ctx context.Context, name string, qtype uint16,
) (*dns.Msg, error) {
	m := buildQuery(name, qtype, true)
	m.CheckingDisabled = true
	return d.exchangePrimary(ctx, m)
}

// Health reports how many queries the primary path has sent, how many got
// a DNS message back whatever its rcode, and how many of those answered:
// NOERROR or NXDOMAIN. Queries sent with none answered mean no configured
// resolver could serve the scan, whether it sent no reply or only SERVFAIL,
// REFUSED and other errors.
func (d *DNS) Health() (sent, replied, answered int) {
	return int(d.sent.Load()), int(d.replied.Load()), int(d.answered.Load())
}

// exchangePrimary sends m to the first upstream or, with failover, to each
// upstream in turn (see exchangeOn). An error names the upstream it came
// from by label, never by address.
func (d *DNS) exchangePrimary(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if err := d.ready(); err != nil {
		return nil, err
	}
	ups := d.upstreams[:1]
	if d.failover {
		ups = d.upstreams
	}
	d.sent.Add(1)
	resp, u, err := d.exchangeOn(ctx, m, ups)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u.label, err)
	}
	d.replied.Add(1)
	if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
		d.answered.Add(1)
	}
	return resp, nil
}

// MultiResp is one upstream's answer to a query sent to every upstream.
type MultiResp struct {
	Upstream string
	Msg      *dns.Msg
	Err      error
}

// ExchangeAllWithDO runs the same query, with the DNSSEC OK bit set so
// validating upstreams report the AD bit (RFC 6840 §5.8), against every
// configured upstream in parallel. It returns one MultiResp per upstream, in
// upstream order; an upstream's SERVFAIL comes back as a MultiResp whose Msg
// has Rcode 2 and whose Err is nil.
func (d *DNS) ExchangeAllWithDO(ctx context.Context, name string, qtype uint16) []MultiResp {
	return d.exchangeAll(ctx, buildQuery(name, qtype, true))
}

// ExchangeAllCheckingDisabled is ExchangeAllWithDO with the Checking Disabled
// bit also set (RFC 4035 §3.2.2): a validating upstream returns the records
// and their RRSIGs without validating them, so it answers even when it
// cannot validate.
func (d *DNS) ExchangeAllCheckingDisabled(
	ctx context.Context, name string, qtype uint16,
) []MultiResp {
	m := buildQuery(name, qtype, true)
	m.CheckingDisabled = true
	return d.exchangeAll(ctx, m)
}

// exchangeAll sends m to every upstream. Each call caps its own fan-out at 16
// concurrent queries so a large --resolvers list cannot trip rate limits or
// starve the host; concurrent calls do not share the cap.
func (d *DNS) exchangeAll(ctx context.Context, m *dns.Msg) []MultiResp {
	if err := d.ready(); err != nil {
		return []MultiResp{{Err: err}}
	}
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
			resp, _, err := d.exchangeOn(ctx, m.Copy(), []upstream{u})
			out[i] = MultiResp{Upstream: u.label, Msg: resp, Err: err}
		}(i, u)
	}
	wg.Wait()
	return out
}

// ednsUDPSize is the UDP payload size every query advertises: big enough for
// most TXT answers, small enough to avoid IP fragmentation (DNS Flag Day
// 2020). A larger answer comes back truncated and moves to TCP.
const ednsUDPSize = 1232

func buildQuery(name string, qtype uint16, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(ednsUDPSize, do)
	return m
}

// minRetransmitBudget is the smallest per-operation timeout at which
// exchangeOn asks a lone upstream twice, half the budget each time. Below
// it, a single full-budget attempt runs so a deliberately small --timeout is
// never carved into slices too short for a healthy resolver to answer.
const minRetransmitBudget = 4 * time.Second

// minFailoverAttempt is the shortest attempt exchangeOn gives each of
// several upstreams, for the same reason.
const minFailoverAttempt = time.Second

// exchangeOn sends m to ups in order until one of them sends back a DNS
// message, whatever its rcode. It returns the upstream that answered or, on
// failure, the one that failed last. All attempts share the budget
// d.timeout, split by attemptBudget.
func (d *DNS) exchangeOn(
	ctx context.Context, m *dns.Msg, ups []upstream,
) (*dns.Msg, upstream, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	perAttempt, attempts := d.attemptBudget(len(ups))

	var resp *dns.Msg
	var u upstream
	var err error
	for i := range attempts * len(ups) {
		u = ups[i%len(ups)]
		actx, acancel := context.WithTimeout(ctx, perAttempt)
		resp, err = d.exchangeOnce(actx, m, u)
		acancel()
		// A lone upstream is asked again only after a timeout, which may be a
		// lost datagram. With several, any failure moves on to the next.
		if err == nil || ctx.Err() != nil || (len(ups) == 1 && !isTransientNetErr(err)) {
			break
		}
	}
	return resp, u, err
}

// attemptBudget splits d.timeout among exchangeOn's attempts at n upstreams.
// A dropped UDP datagram or a transiently throttled resolver (Cloudflare's
// 1.1.1.1 rate-limits aggressive probing) otherwise surfaces as a spurious
// lookup FAIL. DNS queries are idempotent, so a lone upstream with a
// comfortable budget is asked twice, recovering a lost datagram without
// adding wall-clock on the fast-answer path. Several upstreams get an equal
// share each, so a silent one hands over in time for every later one to be
// asked, unless that share would fall below minFailoverAttempt.
func (d *DNS) attemptBudget(n int) (perAttempt time.Duration, attempts int) {
	switch {
	case n > 1:
		return min(max(d.timeout/time.Duration(n), minFailoverAttempt), d.timeout), 1
	case d.timeout >= minRetransmitBudget:
		return d.timeout / 2, 2
	}
	return d.timeout, 1
}

// exchangeOnce sends m to u once. On failure it returns no message, since
// one that failed to parse may be incomplete, and an error stripped of
// network addresses and of any DoH URL (see scrubResolverError).
func (d *DNS) exchangeOnce(ctx context.Context, m *dns.Msg, u upstream) (*dns.Msg, error) {
	var resp *dns.Msg
	var err error
	switch u.protocol {
	case protoDoH:
		resp, err = dohExchange(ctx, d.httpClient, u.addr, m)
	case protoDoT:
		resp, _, err = d.dotClient.ExchangeContext(ctx, m, u.addr)
	default:
		resp, err = d.exchangeUDP(ctx, m, u.addr)
	}
	if err != nil {
		return nil, scrubResolverError(err)
	}
	return resp, nil
}

// exchangeUDP sends m over UDP, and again over TCP when the reply is
// truncated or does not parse, as when a datagram larger than the
// advertised buffer is cut short.
func (d *DNS) exchangeUDP(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	resp, _, err := d.udpClient.ExchangeContext(ctx, m, addr)
	if err == nil && !resp.Truncated {
		return resp, nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return nil, err // no reply arrived
	}
	resp, _, err = d.tcpClient.ExchangeContext(ctx, m, addr)
	return resp, err
}

// scrubResolverError strips what an exchange error says about the network
// path: the local socket and the upstream's address, which for a system
// resolver is on the operator's network, and a DoH URL, whose userinfo and
// path can carry credentials. Callers name the upstream by its label.
func scrubResolverError(err error) error {
	if urlErr, ok := err.(*url.Error); ok {
		err = urlErr.Err
	}
	err = scrubNetError(err)
	if opErr, ok := err.(*net.OpError); ok {
		opErr.Addr = nil // a copy: scrubNetError copies every *net.OpError
	}
	return err
}

// isTransientNetErr reports whether err is a transient network condition worth
// retransmitting an idempotent DNS query for: a timeout (a dropped datagram or
// a throttled upstream) or another temporary net.Error. A caller cancellation
// is deliberately NOT transient — that is a shutdown signal, not a lost packet.
func isTransientNetErr(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// RcodeError is returned by the Lookup* methods when the resolver answers
// with an rcode other than NOERROR or NXDOMAIN, such as SERVFAIL or REFUSED.
// Such an answer says nothing about whether the record exists.
type RcodeError struct {
	Rcode int
}

// Error names the rcode, e.g. "resolver answered SERVFAIL".
func (e *RcodeError) Error() string {
	if name, ok := dns.RcodeToString[e.Rcode]; ok {
		return "resolver answered " + name
	}
	return fmt.Sprintf("resolver answered rcode %d", e.Rcode)
}

// lookup sends a query on the primary path. It returns the reply when the
// rcode is NOERROR, ErrNXDOMAIN for NXDOMAIN and an *RcodeError otherwise.
func (d *DNS) lookup(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	resp, err := d.Exchange(ctx, name, qtype)
	switch {
	case err != nil:
		return nil, err
	case resp.Rcode == dns.RcodeNameError:
		return nil, ErrNXDOMAIN
	case resp.Rcode != dns.RcodeSuccess:
		return nil, &RcodeError{Rcode: resp.Rcode}
	}
	return resp, nil
}

// maxCNAMEHops bounds the CNAME chain that answers follows; a longer chain,
// or a loop, yields no records.
const maxCNAMEHops = 8

// chainEnd returns the canonical name that owns the records answering a
// query for name: name itself, or the end of the CNAME chain that starts at
// name in answer. It returns "" when the chain is longer than maxCNAMEHops
// or loops.
func chainEnd(answer []dns.RR, name string) string {
	targets := make(map[string]string)
	for _, rr := range answer {
		if c, ok := rr.(*dns.CNAME); ok {
			targets[dns.CanonicalName(c.Hdr.Name)] = dns.CanonicalName(c.Target)
		}
	}
	owner := dns.CanonicalName(name)
	for range maxCNAMEHops + 1 {
		target, ok := targets[owner]
		if !ok {
			return owner
		}
		owner = target
	}
	return ""
}

// answers returns the records of type T in resp's answer section that are
// owned by the end of name's CNAME chain (see chainEnd). Every hop of that
// chain links back to name, so records owned by any other name are ignored:
// a resolver cannot slip in records for a name nobody asked about.
func answers[T dns.RR](resp *dns.Msg, name string) []T {
	owner := chainEnd(resp.Answer, name)
	var out []T
	for _, rr := range resp.Answer {
		if rec, ok := rr.(T); ok && dns.CanonicalName(rr.Header().Name) == owner {
			out = append(out, rec)
		}
	}
	return out
}

// LookupTXT returns concatenated TXT strings per record. Each TXT record can
// span multiple character-strings; per RFC 7208 §3.3 / RFC 6376 §3.6.2.2,
// these are concatenated with NO separator.
func (d *DNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resp, err := d.lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range answers[*dns.TXT](resp, name) {
		out = append(out, strings.Join(t.Txt, ""))
	}
	return out, nil
}

// MX is a simplified MX record.
type MX struct {
	Preference uint16
	Host       string
}

// LookupMX returns name's MX records, hosts without the trailing dot.
func (d *DNS) LookupMX(ctx context.Context, name string) ([]MX, error) {
	resp, err := d.lookup(ctx, name, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	var out []MX
	for _, m := range answers[*dns.MX](resp, name) {
		out = append(out, MX{Preference: m.Preference, Host: strings.TrimSuffix(m.Mx, ".")})
	}
	return out, nil
}

// LookupNS returns name's nameserver hosts without the trailing dot.
func (d *DNS) LookupNS(ctx context.Context, name string) ([]string, error) {
	resp, err := d.lookup(ctx, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ns := range answers[*dns.NS](resp, name) {
		out = append(out, strings.TrimSuffix(ns.Ns, "."))
	}
	return out, nil
}

// LookupA returns name's IPv4 addresses.
func (d *DNS) LookupA(ctx context.Context, name string) ([]net.IP, error) {
	resp, err := d.lookup(ctx, name, dns.TypeA)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range answers[*dns.A](resp, name) {
		out = append(out, a.A)
	}
	return out, nil
}

// LookupAAAA returns name's IPv6 addresses.
func (d *DNS) LookupAAAA(ctx context.Context, name string) ([]net.IP, error) {
	resp, err := d.lookup(ctx, name, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range answers[*dns.AAAA](resp, name) {
		out = append(out, a.AAAA)
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

// AliasError reports that a name owns a CNAME, so it owns no SOA: any SOA
// in the reply belongs to the alias target's zone (RFC 1034 §3.6.2).
type AliasError struct {
	Name   string // the queried name
	Target string // the CNAME's target, without the trailing dot
}

// Error names the alias and its target.
func (e *AliasError) Error() string {
	return fmt.Sprintf("%s is an alias (CNAME to %s)", e.Name, e.Target)
}

// LookupSOA returns the SOA record that answers for name. Without one, it
// falls back to the SOA in the authority section of a NODATA reply, but
// only when name is at or below that SOA's owner, so another zone's SOA is
// never reported for name. It returns nil when neither exists, and an
// *AliasError when name is a CNAME.
func (d *DNS) LookupSOA(ctx context.Context, name string) (*SOA, error) {
	resp, err := d.lookup(ctx, name, dns.TypeSOA)
	if err != nil {
		return nil, err
	}
	if target := cnameAt(resp.Answer, name); target != "" {
		return nil, &AliasError{Name: name, Target: target}
	}
	if soas := answers[*dns.SOA](resp, name); len(soas) > 0 {
		return soaFrom(soas[0]), nil
	}
	for _, rr := range resp.Ns {
		if s, ok := rr.(*dns.SOA); ok && dns.IsSubDomain(s.Hdr.Name, dns.Fqdn(name)) {
			return soaFrom(s), nil
		}
	}
	return nil, nil
}

func soaFrom(s *dns.SOA) *SOA {
	return &SOA{
		NS:      strings.TrimSuffix(s.Ns, "."),
		Mbox:    strings.TrimSuffix(s.Mbox, "."),
		Serial:  s.Serial,
		Refresh: s.Refresh,
		Retry:   s.Retry,
		Expire:  s.Expire,
		Minimum: s.Minttl,
	}
}

// CAA mirrors miekg/dns CAA fields with fewer surprises.
type CAA struct {
	Flag  uint8
	Tag   string
	Value string
}

// LookupCAA returns the CAA records at name.
func (d *DNS) LookupCAA(ctx context.Context, name string) ([]CAA, error) {
	resp, err := d.lookup(ctx, name, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	var out []CAA
	for _, c := range answers[*dns.CAA](resp, name) {
		out = append(out, CAA{Flag: c.Flag, Tag: c.Tag, Value: c.Value})
	}
	return out, nil
}

// LookupCNAME returns the immediate CNAME target for name, or "" if there is
// none. Does NOT chase chains — the caller decides whether to follow.
func (d *DNS) LookupCNAME(ctx context.Context, name string) (string, error) {
	resp, err := d.lookup(ctx, name, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	return cnameAt(resp.Answer, name), nil
}

// cnameAt returns the target, without the trailing dot, of the CNAME that
// name owns in rrs, or "" when it owns none.
func cnameAt(rrs []dns.RR, name string) string {
	owner := dns.CanonicalName(name)
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok && dns.CanonicalName(c.Hdr.Name) == owner {
			return strings.TrimSuffix(c.Target, ".")
		}
	}
	return ""
}

// ErrNXDOMAIN is returned by Lookup* helpers when the resolver returns NXDOMAIN.
// Distinguishable from "no records of this type" (NOERROR + empty answer).
var ErrNXDOMAIN = errors.New("NXDOMAIN")
