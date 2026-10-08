package email

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// smtpPort is the port the STARTTLS probe dials; only tests change it.
var smtpPort = "25"

// smtpRootCAs verifies the certificate an MX presents after STARTTLS; nil
// means the system roots. Only tests set it.
var smtpRootCAs *x509.CertPool

// Bounds on an SMTP reply, so a hostile MX cannot stream one into memory or
// the report. RFC 5321 §4.5.3.1.5 caps a reply line at 512 octets with its
// CRLF; an EHLO reply has one line per extension, about a dozen in practice.
const (
	maxReplyLineBytes = 512
	maxReplyLines     = 100
)

// replyLine matches an SMTP reply line without its CRLF (RFC 5321 §4.2): the
// code, then " " (last line) or "-" (more follow) and text, or the code alone.
var replyLine = regexp.MustCompile(`^([2-5][0-9][0-9])(?:([ -])(.*))?$`)

// starttlsBudget is how many per-operation timeouts one MX's STARTTLS probe
// may take in all; each of its steps, the dial, three SMTP replies and the
// TLS handshake, also gets one of its own.
const starttlsBudget = 3

// errNoSTARTTLS means the EHLO reply did not list the STARTTLS extension.
var errNoSTARTTLS = errors.New("did not advertise STARTTLS")

// runSTARTTLS probes each MX on port 25 to confirm STARTTLS is advertised in
// the EHLO response (RFC 3207 §2). Active probe — skipped under --no-active.
func runSTARTTLS(ctx context.Context, env *probe.Env) []report.Result {
	const title = "STARTTLS advertised by MX"
	refs := []string{"RFC 3207 §2", "RFC 5321"}

	mxs, err := targetMX(ctx, env)
	if err != nil {
		res := report.Result{
			ID: "email.smtp.starttls", Category: category, Title: title, RFCRefs: refs,
		}
		return []report.Result{checkutil.Inconclusive(res, err)}
	}
	hosts, skipped := mxHosts(mxs)
	if len(hosts) == 0 {
		return []report.Result{{
			ID:       "email.smtp.starttls",
			Category: category,
			Title:    title,
			Status:   report.NotApplicable,
			Evidence: "no usable MX records",
			RFCRefs:  refs,
		}}
	}

	if !env.Active {
		return []report.Result{{
			ID:       "email.smtp.starttls",
			Category: category,
			Title:    title,
			Status:   report.NotApplicable,
			Evidence: "skipped: --no-active",
			RFCRefs:  refs,
		}}
	}

	results := probeMXHosts(ctx, hosts, func(ctx context.Context, host string) report.Result {
		return probeSTARTTLS(ctx, env, host, refs)
	})
	if len(skipped) > 0 {
		results = append(results, skippedMXResult("email.smtp.starttls", title, skipped, refs))
	}
	return results
}

// probeSTARTTLS connects to mxHost, checks that its EHLO reply advertises
// STARTTLS and completes the TLS handshake, verifying the certificate
// against mxHost. Each step gets its own --timeout and the whole probe
// starttlsBudget of them; cancelling ctx or running out of budget closes
// the connection. A step that could not complete is inconclusive; a wrong
// reply code, a malformed or oversized reply and a missing STARTTLS FAIL.
func probeSTARTTLS(ctx context.Context, env *probe.Env, mxHost string, refs []string) report.Result {
	res := report.Result{
		ID:       "email.smtp.starttls." + mxHost,
		Category: category,
		Title:    "STARTTLS advertised by " + mxHost,
		RFCRefs:  refs,
	}
	budget := starttlsBudget * env.Timeout
	ctx, cancel := context.WithTimeoutCause(ctx, budget,
		fmt.Errorf("probe did not finish within %s", budget))
	defer cancel()
	conn, err := probe.SafeDial(ctx, "tcp", net.JoinHostPort(mxHost, smtpPort), env.Timeout)
	if err != nil {
		return dialFailed(ctx, res, mxHost, err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	s := &smtpSession{
		conn: conn, r: bufio.NewReaderSize(conn, maxReplyLineBytes), timeout: env.Timeout,
	}
	if err := s.negotiate(ctx, mxHost); err != nil {
		if !serverAnswered(err) {
			return checkutil.Inconclusive(res, err)
		}
		res.Status, res.Evidence = report.Fail, err.Error()
		res.Remediation = starttlsRemediation(mxHost)
		return res
	}

	// The relay accepted STARTTLS, which is what this check measures, so a
	// handshake that fails, as on a bad certificate, is a Warn.
	_ = conn.SetDeadline(time.Now().Add(env.Timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: mxHost,
		MinVersion: tls.VersionTLS12,
		RootCAs:    smtpRootCAs,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		err = fmt.Errorf("STARTTLS advertised but TLS handshake to %s failed: %w",
			mxHost, ioErr(ctx, err))
		if checkutil.Incomplete(ctx, err) {
			return checkutil.Inconclusive(res, err)
		}
		res.Status, res.Evidence = report.Warn, err.Error()
		return res
	}
	res.Status = report.Pass
	res.Evidence = fmt.Sprintf("STARTTLS advertised, handshake ok (%s)",
		tls.VersionName(tlsConn.ConnectionState().Version))
	return res
}

// dialFailed grades a failed connection to mxHost. A reset, unreachable or
// timed-out connection is inconclusive, because a network that filters
// outbound TCP/25, as many clouds and ISPs do, fails it the same way; so
// are an SSRF denylist refusal, a temporary DNS failure and the scan
// ending. A refused connection and a host name that does not exist FAIL.
func dialFailed(ctx context.Context, res report.Result, mxHost string, err error) report.Result {
	err = fmt.Errorf("dial %s failed: %w", net.JoinHostPort(mxHost, smtpPort), err)
	switch {
	case connectFailed(err):
		return checkutil.Inconclusive(res,
			fmt.Errorf("%w; outbound TCP/25 may be blocked on this network", err))
	case checkutil.Incomplete(ctx, err):
		return checkutil.Inconclusive(res, err)
	}
	res.Status, res.Evidence = report.Fail, err.Error()
	res.Remediation = starttlsRemediation(mxHost)
	return res
}

// connectFailed reports whether err is a TCP connect that was reset,
// unreachable or timed out, as opposed to a refused connect, a failed name
// lookup or an SSRF denylist refusal.
func connectFailed(err error) bool {
	var blocked *probe.BlockedAddrError
	var dnsErr *net.DNSError
	if errors.As(err, &blocked) || errors.As(err, &dnsErr) {
		return false
	}
	return probe.IsProbeFailure(err)
}

// serverAnswered reports whether err is the MX's own answer, which grades
// the MX, rather than a step that could not complete.
func serverAnswered(err error) bool {
	var replyErr *textproto.Error
	var protoErr textproto.ProtocolError
	return errors.As(err, &replyErr) || errors.As(err, &protoErr) || errors.Is(err, errNoSTARTTLS)
}

// smtpSession is the plaintext phase of an SMTP session with one MX.
type smtpSession struct {
	conn    net.Conn
	r       *bufio.Reader // holds one reply line at most; see readReply
	timeout time.Duration // per step
}

// negotiate reads the banner, sends EHLO, checks that the reply advertises
// STARTTLS and sends STARTTLS. The error names the step that failed.
func (s *smtpSession) negotiate(ctx context.Context, host string) error {
	if _, err := s.step(ctx, "", 220); err != nil {
		return fmt.Errorf("no 220 banner from %s: %w", host, err)
	}
	// EHLO with a literal name: bedrock is not the sending host.
	ehlo, err := s.step(ctx, "EHLO bedrock.local", 250)
	if err != nil {
		return fmt.Errorf("EHLO failed at %s: %w", host, err)
	}
	if !slices.ContainsFunc(ehlo, isSTARTTLS) {
		return fmt.Errorf("EHLO response from %s %w", host, errNoSTARTTLS)
	}
	if _, err := s.step(ctx, "STARTTLS", 220); err != nil {
		return fmt.Errorf("STARTTLS not accepted by %s: %w", host, err)
	}
	return nil
}

// step sends cmd, unless it is empty, and reads the reply within s.timeout.
// It returns the reply's text lines, or a *textproto.Error when the reply
// code is not want.
func (s *smtpSession) step(ctx context.Context, cmd string, want int) ([]string, error) {
	_ = s.conn.SetDeadline(time.Now().Add(s.timeout))
	if cmd != "" {
		if _, err := io.WriteString(s.conn, cmd+"\r\n"); err != nil {
			return nil, ioErr(ctx, err)
		}
	}
	code, lines, err := readReply(s.r)
	if err != nil {
		return nil, ioErr(ctx, err)
	}
	if code != want {
		return nil, &textproto.Error{Code: code, Msg: report.ClipValue(lines[0])}
	}
	return lines, nil
}

// readReply reads one SMTP reply and returns its code and text lines. A
// line longer than r's buffer, which holds maxReplyLineBytes, a reply
// longer than maxReplyLines lines and a malformed line are each a
// textproto.ProtocolError.
func readReply(r *bufio.Reader) (int, []string, error) {
	var code string
	var lines []string
	for range maxReplyLines {
		raw, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return 0, nil, textproto.ProtocolError(
				fmt.Sprintf("reply line longer than %d bytes", r.Size()))
		}
		if err != nil {
			return 0, nil, err
		}
		line := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		m := replyLine.FindStringSubmatch(line)
		// RFC 5321 §4.2.1: every line of a reply carries the same code.
		if m == nil || (code != "" && m[1] != code) {
			return 0, nil, textproto.ProtocolError("malformed reply line " +
				strconv.Quote(report.ClipValue(line)))
		}
		code = m[1]
		lines = append(lines, m[3])
		if m[2] != "-" {
			n, _ := strconv.Atoi(code)
			return n, lines, nil
		}
	}
	return 0, nil, textproto.ProtocolError(fmt.Sprintf("reply longer than %d lines", maxReplyLines))
}

func isSTARTTLS(capability string) bool {
	return strings.EqualFold(strings.TrimSpace(capability), "STARTTLS")
}

// ioErr returns why an I/O call on an MX connection failed: ctx's cause
// once ctx has ended, because the scan was cancelled or the probe ran out of
// budget, since that closes the connection; and otherwise err without the
// socket addresses a *net.OpError names, as the local one is on the
// operator's network.
func ioErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err
	}
	return err
}

func starttlsRemediation(mx string) string {
	return fmt.Sprintf("Configure %s to advertise the STARTTLS ESMTP keyword (RFC 3207). "+
		"On Postfix: smtpd_tls_security_level=may. On Exim: tls_advertise_hosts=*.",
		report.InlineValue(mx))
}
