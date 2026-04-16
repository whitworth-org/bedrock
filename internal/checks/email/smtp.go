package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

type starttlsCheck struct{}

func (starttlsCheck) ID() string       { return "email.smtp.starttls" }
func (starttlsCheck) Category() string { return category }

// Run probes each MX on port 25 to confirm STARTTLS is advertised in the
// EHLO response (RFC 3207 §2). Active probe — skipped under --no-active.
func (starttlsCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	refs := []string{"RFC 3207 §2", "RFC 5321"}

	mxs, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID:       "email.smtp.starttls",
			Category: category,
			Title:    "STARTTLS advertised by MX",
			Status:   report.NotApplicable,
			Evidence: "MX lookup failed: " + err.Error(),
			RFCRefs:  refs,
		}}
	}
	if len(mxs) == 0 || isNullMX(mxs) {
		return []report.Result{{
			ID:       "email.smtp.starttls",
			Category: category,
			Title:    "STARTTLS advertised by MX",
			Status:   report.NotApplicable,
			Evidence: "no usable MX records",
			RFCRefs:  refs,
		}}
	}

	if !env.Active {
		return []report.Result{{
			ID:       "email.smtp.starttls",
			Category: category,
			Title:    "STARTTLS advertised by MX",
			Status:   report.NotApplicable,
			Evidence: "skipped: --no-active",
			RFCRefs:  refs,
		}}
	}

	var results []report.Result
	for _, mx := range mxs {
		results = append(results, probeSTARTTLS(ctx, env, mx.Host, refs))
	}
	return results
}

func probeSTARTTLS(ctx context.Context, env *probe.Env, mxHost string, refs []string) report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	id := "email.smtp.starttls." + mxHost
	title := "STARTTLS advertised by " + mxHost

	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(mxHost, "25"))
	if err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "dial " + mxHost + ":25 failed: " + err.Error(),
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}
	defer conn.Close()
	// Bound the entire SMTP exchange by the env timeout.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	tp := textproto.NewConn(conn)
	defer tp.Close()

	// Read banner (220).
	if _, _, err := tp.ReadResponse(220); err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no 220 banner from " + mxHost + ": " + err.Error(),
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}

	// EHLO with our hostname (use a literal — we are not the actual sender).
	if err := tp.PrintfLine("EHLO bedrock.local"); err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "EHLO write failed: " + err.Error(),
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}
	_, ehloMsg, err := tp.ReadResponse(250)
	if err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "EHLO failed at " + mxHost + ": " + err.Error(),
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}

	// EHLO response is multi-line; each line is one capability.
	advertised := false
	for _, line := range strings.Split(ehloMsg, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
			advertised = true
			break
		}
	}
	if !advertised {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "EHLO response from " + mxHost + " did not advertise STARTTLS",
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}

	// Issue STARTTLS and try to complete the handshake — verify the cert
	// against mxHost via the system trust store.
	if err := tp.PrintfLine("STARTTLS"); err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "STARTTLS write failed: " + err.Error(),
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "STARTTLS not accepted by " + mxHost + ": " + err.Error(),
			Remediation: starttlsRemediation(mxHost),
			RFCRefs:     refs,
		}
	}

	// Promote to TLS. Verification errors are reported as Warn (the relay
	// accepted STARTTLS but presents a bad cert) — STARTTLS itself was
	// advertised, which is what this check measures.
	tlsCfg := &tls.Config{
		ServerName: mxHost,
		MinVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, tlsCfg)
	hsCtx, hsCancel := env.WithTimeout(ctx)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "STARTTLS advertised but TLS handshake to " + mxHost + " failed: " + err.Error(),
			RFCRefs:  refs,
		}
	}
	state := tlsConn.ConnectionState()

	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("STARTTLS advertised, handshake ok (%s)", tlsVersionName(state.Version)),
		RFCRefs:  refs,
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func starttlsRemediation(mx string) string {
	return fmt.Sprintf("Configure %s to advertise the STARTTLS ESMTP keyword (RFC 3207). On Postfix: smtpd_tls_security_level=may. On Exim: tls_advertise_hosts=*.", mx)
}
