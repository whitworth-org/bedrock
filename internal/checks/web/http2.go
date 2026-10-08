package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// http2Port is the port the ALPN probe dials; only tests change it.
var http2Port = "443"

// runHTTP2 verifies that the target's HTTPS listener advertises HTTP/2 via
// ALPN (RFC 7301). HTTP/2 (RFC 9113, originally RFC 7540) requires ALPN for
// negotiation over TLS, so this is the only authoritative way to check support
// without a real h2 client. We do not issue a request — the TLS handshake's
// negotiated protocol is sufficient evidence.
func runHTTP2(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID:       "web.http2",
			Category: category,
			Title:    "HTTP/2 advertised via ALPN",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 9113", "RFC 7301"},
		}}
	}

	dctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	addr := net.JoinHostPort(env.Target, http2Port)
	rawConn, err := probe.SafeDial(dctx, "tcp", addr, env.Timeout)
	if err != nil {
		return []report.Result{http2ProbeFailed(dctx, "TCP dial to "+addr, err,
			http2DialRemediation(addr))}
	}
	defer func() { _ = rawConn.Close() }()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: env.Target,
		MinVersion: tls.VersionTLS12,
		// Offer h2 first so a server that supports both will pick it. ALPN
		// (RFC 7301) lets the server choose; we record whatever it negotiates.
		NextProtos: []string{"h2", "http/1.1"},
		// A capability probe: it reads only the negotiated protocol,
		// nothing it receives is trusted, and web.cert.* grades the
		// certificate.
		InsecureSkipVerify: true, //nolint:gosec // G402: capability probe; see above
	})
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return []report.Result{http2ProbeFailed(dctx, "TLS handshake to "+addr, err,
			http2HandshakeRemediation(env.Target))}
	}
	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	_ = tlsConn.Close()

	status, evidence, remediation := classifyHTTP2ALPN(negotiated)
	res := report.Result{
		ID:       "web.http2",
		Category: category,
		Title:    "HTTP/2 advertised via ALPN",
		Status:   status,
		Evidence: evidence,
		RFCRefs:  []string{"RFC 9113", "RFC 7540", "RFC 7301"},
	}
	if remediation != "" {
		res.Remediation = remediation
	}
	return []report.Result{res}
}

// http2ProbeFailed grades an ALPN probe whose step, run under ctx, ended in
// err: Inconclusive when the probe could not complete, otherwise FAIL with
// remediation.
func http2ProbeFailed(
	ctx context.Context, step string, err error, remediation string,
) report.Result {
	err = fmt.Errorf("%s failed: %w", step, err)
	res := report.Result{
		ID:       "web.http2",
		Category: category,
		Title:    "HTTP/2 advertised via ALPN",
		RFCRefs:  []string{"RFC 9113", "RFC 7301"},
	}
	if checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(res, err)
	}
	res.Status = report.Fail
	res.Evidence = err.Error()
	res.Remediation = remediation
	return res
}

func http2DialRemediation(addr string) string {
	return "ensure an HTTPS listener is reachable on " + report.InlineValue(addr)
}

func http2HandshakeRemediation(host string) string {
	return "ensure " + report.InlineValue(host) + " completes a TLS 1.2 or later handshake on :443"
}

// classifyHTTP2ALPN maps an ALPN-negotiated protocol string to a Status,
// human-readable evidence, and (when not Pass) a remediation snippet.
// Extracted so it can be unit-tested without a live TLS handshake.
func classifyHTTP2ALPN(negotiated string) (status report.Status, evidence string, remediation string) {
	switch negotiated {
	case "h2":
		return report.Pass, "HTTP/2 negotiated via ALPN (h2)", ""
	case "http/1.1":
		return report.Warn,
			"server only supports HTTP/1.1; HTTP/2 not advertised",
			"enable HTTP/2 on your TLS server (nginx: listen 443 ssl http2; Apache: Protocols h2 http/1.1)"
	default:
		// Empty string means the server didn't pick an ALPN protocol at all.
		// Anything else is an unexpected protocol we still want to flag.
		ev := "no ALPN protocol negotiated; HTTP/2 not advertised"
		if negotiated != "" {
			ev = "unexpected ALPN protocol negotiated (" + negotiated + "); HTTP/2 not advertised"
		}
		return report.Warn,
			ev,
			"enable HTTP/2 on your TLS server (nginx: listen 443 ssl http2; Apache: Protocols h2 http/1.1)"
	}
}

func init() { registry.Register(checkutil.Wrap("web.http2", category, runHTTP2)) }
