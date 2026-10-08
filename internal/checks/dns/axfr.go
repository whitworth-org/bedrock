package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// axfrPort is the port the AXFR probe dials; only tests change it.
var axfrPort = "53"

const (
	// maxAXFRServers and axfrConcurrency bound the probe of a hostile NS
	// RRset: at most 8 nameservers, 4 at a time.
	maxAXFRServers  = 8
	axfrConcurrency = 4
	// axfrBudget is how many per-operation timeouts one nameserver's probe
	// may take in all: the address lookup, the dial and the whole transfer.
	axfrBudget = 2
	// maxAXFRRRs bounds the records counted from one server.
	maxAXFRRRs = 50000
)

// axfrRemediation is server configuration, not a zone file, so its comments
// use '#'.
const axfrRemediation = `# BIND
allow-transfer { none; };           # disable AXFR globally
# or restrict to a TSIG key:
# allow-transfer { key transfer-key; };

# NSD
provide-xfr: 0.0.0.0/0 NOKEY        # remove; only list specific peers

# Knot DNS
acl: []                              # remove transfer ACLs from the zone block`

// runAXFR attempts an AXFR of the target zone from each authoritative NS
// over TCP. RFC 5936 §6 makes the zone privileged data, so a server that
// sends any record beyond the SOA is a Fail. A refused connection, a DNS
// error rcode, a connection closed unanswered and an answer holding only
// the SOA, which carries no zone data, are a Pass. A probe that could not
// complete, including one the scan's cancellation interrupted, is
// inconclusive.
//
// We don't add a new module for this — miekg/dns is already in go.mod and
// the probe package didn't expose a transfer helper.
func runAXFR(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID:       "dns.axfr",
			Category: category,
			Title:    "AXFR refusal probe",
			Status:   report.NotApplicable,
			Evidence: "skipped: --no-active",
			RFCRefs:  []string{"RFC 5936 §6"},
		}}
	}

	ns, err := nameserverList(ctx, env)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{checkutil.Inconclusive(report.Result{
			ID:       "dns.axfr",
			Category: category,
			Title:    "AXFR refusal probe",
			RFCRefs:  []string{"RFC 5936 §6"},
		}, err)}
	}
	if len(ns) == 0 {
		return []report.Result{{
			ID:       "dns.axfr",
			Category: category,
			Title:    "AXFR refusal probe",
			Status:   report.NotApplicable,
			Evidence: "no NS records to probe",
			RFCRefs:  []string{"RFC 5936 §6"},
		}}
	}
	if len(ns) <= maxAXFRServers {
		return probeNameservers(ctx, env, ns)
	}
	return append(probeNameservers(ctx, env, ns[:maxAXFRServers]),
		axfrSkipped(ns[maxAXFRServers:]))
}

// probeNameservers probes each host, axfrConcurrency at a time, and returns
// the results in hosts order.
func probeNameservers(ctx context.Context, env *probe.Env, hosts []string) []report.Result {
	results := make([]report.Result, len(hosts))
	checkutil.ForEach(len(hosts), axfrConcurrency, func(i int) {
		results[i] = axfrProbe(ctx, env, hosts[i])
	})
	return results
}

// axfrSkipped names the nameservers beyond maxAXFRServers, which are not
// probed.
func axfrSkipped(hosts []string) report.Result {
	return report.Result{
		ID:       "dns.axfr",
		Category: category,
		Title:    fmt.Sprintf("AXFR probe limited to %d nameservers", maxAXFRServers),
		Status:   report.Info,
		Evidence: "not probed: " + checkutil.ListBounded(hosts, ", "),
		RFCRefs:  []string{"RFC 5936 §6"},
	}
}

// axfrOutcome is what one AXFR attempt received.
type axfrOutcome struct {
	addr     string // the server's host:port
	rrs      int    // records received, SOAs included
	data     int    // records other than SOAs
	capped   bool   // the transfer was cut off at maxAXFRRRs
	cutShort bool   // the probe's budget or the scan's cancellation ended the stream
	err      error  // why the stream ended; nil when the closing SOA arrived
}

// add counts the records of one envelope. Records that arrive with an
// error count too: the server sent them.
func (o *axfrOutcome) add(ev *miekg.Envelope) {
	o.rrs += len(ev.RR)
	for _, rr := range ev.RR {
		if rr.Header().Rrtype != miekg.TypeSOA {
			o.data++
		}
	}
	if ev.Error != nil {
		o.err = ev.Error
	}
}

// unfinished reports whether the probe ended without an answer to grade:
// its budget or the scan's cancellation cut the stream short, or a network
// failure ended it before any record arrived. A server that sent the SOA
// and then went quiet or dropped the connection has answered with the SOA
// alone.
func (o *axfrOutcome) unfinished() bool {
	return o.cutShort || (o.rrs == 0 && o.err != nil && !serverEnded(o.err))
}

// axfrProbe probes one nameserver, a name from uniqueNameservers, within
// axfrBudget per-operation timeouts.
func axfrProbe(ctx context.Context, env *probe.Env, nsHost string) report.Result {
	res := report.Result{
		ID:       "dns.axfr." + nsHost,
		Category: category,
		Title:    "AXFR probe — " + nsHost,
		RFCRefs:  []string{"RFC 5936 §6"},
	}
	budget := axfrBudget * env.Timeout
	pctx, cancel := context.WithTimeoutCause(ctx, budget,
		fmt.Errorf("did not finish within %s", budget))
	defer cancel()

	ips, err := env.DNS.LookupA(pctx, nsHost)
	if err != nil && checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(res, fmt.Errorf("resolve %s to IPv4: %w", nsHost, err))
	}
	if len(ips) == 0 {
		res.Status = report.NotApplicable
		res.Evidence = "could not resolve NS to IPv4"
		return res
	}
	addr := net.JoinHostPort(ips[0].String(), axfrPort)
	conn, err := probe.SafeDial(pctx, "tcp", addr, env.Timeout)
	if err != nil {
		return axfrDialFailed(ctx, res, nsHost, addr, err)
	}
	out := axfrTransfer(pctx, env, conn, addr)
	if out.err != nil && pctx.Err() != nil {
		// pctx ending closed the connection under miekg's reader, whose
		// error then says only "use of closed network connection".
		out.err = context.Cause(pctx)
		out.cutShort = true
	}
	return gradeTransfer(res, nsHost, out)
}

// axfrDialFailed grades a dial to addr that failed with err. A refused
// connection is the server declining the transfer, a Pass; any other
// failure means the server was never asked.
func axfrDialFailed(
	ctx context.Context, res report.Result, nsHost, addr string, err error,
) report.Result {
	if ctx.Err() != nil || !probe.IsConnRefused(err) {
		return checkutil.Inconclusive(res, err)
	}
	res.Title = "AXFR refused at " + nsHost
	res.Status = report.Pass
	res.Evidence = fmt.Sprintf("dial/transfer to %s rejected: %s", addr, err)
	return res
}

// axfrTransfer asks the server on conn for the target zone and counts the
// records it sends. Closing conn when ctx ends is what bounds the transfer:
// miekg's reader resets its read deadline before every message, so a
// server trickling messages would otherwise hold it open forever.
func axfrTransfer(ctx context.Context, env *probe.Env, conn net.Conn, addr string) axfrOutcome {
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	q := new(miekg.Msg)
	q.SetAxfr(miekg.Fqdn(env.Target))
	//nolint:forbidigo // runs over conn, which probe.SafeDial opened past the SSRF denylist
	tr := &miekg.Transfer{Conn: &miekg.Conn{Conn: conn}, ReadTimeout: env.Timeout}
	envelopes, err := tr.In(q, addr)
	if err != nil {
		return axfrOutcome{addr: addr, err: err}
	}
	out := axfrOutcome{addr: addr}
	// Receive until miekg closes the channel, past the cap too: its reader
	// blocks on an unbuffered send, so leaving early would strand it.
	for ev := range envelopes {
		out.add(ev)
		if out.rrs > maxAXFRRRs && !out.capped {
			out.capped = true
			_ = conn.Close() // fails the reader's next read, which ends the stream
		}
	}
	return out
}

// gradeTransfer grades what the server sent. Any record beyond the SOA is
// a Fail. A probe left without an answer is unfinished. An answer holding
// only the SOA is a Pass, and so is a DNS error or a closed
// connection before any record.
func gradeTransfer(res report.Result, nsHost string, out axfrOutcome) report.Result {
	switch {
	case out.capped || out.data > 0:
		return axfrLeak(res, nsHost, out)
	case out.unfinished():
		return checkutil.Inconclusive(res,
			fmt.Errorf("AXFR from %s: %w", out.addr, netCause(out.err)))
	case out.rrs > 0:
		res.Title = "AXFR returned only the SOA at " + nsHost
		res.Evidence = fmt.Sprintf("AXFR from %s returned only the SOA record (%d RR(s)) "+
			"and no zone data", out.addr, out.rrs)
	default:
		res.Title = "AXFR refused at " + nsHost
		res.Evidence = "no RRs returned"
		if out.err != nil {
			res.Evidence += "; " + out.err.Error()
		}
	}
	res.Status = report.Pass
	return res
}

// axfrLeak is the Fail for a server that sent zone data.
func axfrLeak(res report.Result, nsHost string, out axfrOutcome) report.Result {
	res.Title = "AXFR allowed at " + nsHost + " (zone leak)"
	res.Status = report.Fail
	res.Remediation = axfrRemediation
	switch {
	case out.capped:
		res.Evidence = fmt.Sprintf("AXFR allowed: more than %d RRs received from %s; "+
			"transfer stopped at the cap", maxAXFRRRs, out.addr)
	case out.err == nil:
		res.Evidence = fmt.Sprintf("transferred %d RRs from %s — full zone publicly exposed",
			out.rrs, out.addr)
	default:
		res.Evidence = fmt.Sprintf("AXFR allowed: received %d RR(s) from %s before the "+
			"transfer ended: %s", out.rrs, out.addr, netCause(out.err))
	}
	return res
}

// serverEnded reports whether err ended the stream with something the
// server sent: a DNS-level error (an error rcode, an answer without the
// SOA, a mismatched ID or an unparseable message) or a closed connection.
func serverEnded(err error) bool {
	var dnsErr *miekg.Error
	return errors.As(err, &dnsErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// netCause drops the socket addresses a *net.OpError renders, so evidence
// does not carry the operator's local address.
func netCause(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err
	}
	return err
}
