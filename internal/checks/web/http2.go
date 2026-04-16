package web

import (
	"context"
	"crypto/tls"
	"net"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
)

// http2Check verifies that the target's HTTPS listener advertises HTTP/2 via
// ALPN (RFC 7301). HTTP/2 (RFC 9113, originally RFC 7540) requires ALPN for
// negotiation over TLS, so this is the only authoritative way to check support
// without a real h2 client. We do not issue a request — the TLS handshake's
// negotiated protocol is sufficient evidence.
type http2Check struct{}

func (http2Check) ID() string       { return "web.http2" }
func (http2Check) Category() string { return category }

func (http2Check) Run(ctx context.Context, env *probe.Env) []report.Result {
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

	addr := net.JoinHostPort(env.Target, "443")
	d := &net.Dialer{Timeout: env.Timeout}
	rawConn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return []report.Result{{
			ID:          "web.http2",
			Category:    category,
			Title:       "HTTP/2 advertised via ALPN",
			Status:      report.Fail,
			Evidence:    "TCP dial to " + addr + " failed: " + err.Error(),
			Remediation: "ensure an HTTPS listener is reachable on " + addr,
			RFCRefs:     []string{"RFC 9113", "RFC 7301"},
		}}
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: env.Target,
		MinVersion: tls.VersionTLS12,
		// Offer h2 first so a server that supports both will pick it. ALPN
		// (RFC 7301) lets the server choose; we record whatever it negotiates.
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return []report.Result{{
			ID:          "web.http2",
			Category:    category,
			Title:       "HTTP/2 advertised via ALPN",
			Status:      report.Fail,
			Evidence:    "TLS handshake to " + addr + " failed: " + err.Error(),
			Remediation: "ensure " + env.Target + " presents a valid TLS certificate on :443",
			RFCRefs:     []string{"RFC 9113", "RFC 7301"},
		}}
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

func init() { registry.Register(http2Check{}) }
