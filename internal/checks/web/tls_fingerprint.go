package web

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/probe/tlsfp"
	"github.com/whitworth-org/bedrock/internal/report"
)

// fingerprintPort is the port the ServerHello capture dials; only tests
// change it.
var fingerprintPort = "443"

// runTLSFingerprintJA3S emits a per-host JA3S TLS server fingerprint. JA3S
// (Salesforce, 2017) is the legacy MD5 fingerprint over the cleartext
// ServerHello fields; values are decimal and the order of extensions is
// preserved as observed on the wire. Output is informational — a fingerprint
// alone is not pass/fail; baseline these values externally to detect drift.
func runTLSFingerprintJA3S(ctx context.Context, env *probe.Env) []report.Result {
	return runTLSFingerprint(ctx, env, "ja3s")
}

// runTLSFingerprintJA4S emits a per-host JA4S TLS server fingerprint per the
// FoxIO specification. JA4S is the human-readable successor to JA3S: the
// negotiated TLS version, ALPN, and extension count are surfaced as visible
// fields, and the extension list is hashed with SHA-256 (truncated). Output
// is informational; baseline externally.
func runTLSFingerprintJA4S(ctx context.Context, env *probe.Env) []report.Result {
	return runTLSFingerprint(ctx, env, "ja4s")
}

// runTLSFingerprint is the shared per-host fingerprint walker. It iterates
// the same apex+www host set used by the TLS-profile check (candidateHosts),
// takes each host's ServerHello capture (see captureServerHello), and emits
// one Result per host carrying the requested fingerprint kind. Successful
// captures produce an Info result so they don't pollute the pass/fail
// signal of policy-driven checks; failed ones are graded by
// fingerprintFailed.
func runTLSFingerprint(ctx context.Context, env *probe.Env, kind string) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID:       "web.tls.fingerprint." + kind,
			Category: category,
			Title:    "TLS fingerprint (" + kind + ")",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
		}}
	}
	hosts := candidateHosts(ctx, env)
	if len(hosts) == 0 {
		return []report.Result{{
			ID:       "web.tls.fingerprint." + kind,
			Category: category,
			Title:    "TLS fingerprint (" + kind + ")",
			Status:   report.NotApplicable,
			Evidence: "no A/AAAA records for apex or www",
		}}
	}

	var out []report.Result
	for _, host := range hosts {
		// Mid-flight cancellation gate so a cancelled scan stops dialing
		// further hosts, matching the pattern used by runTLS.
		if err := ctx.Err(); err != nil {
			break
		}
		c := captureServerHello(ctx, env, host)
		if c.err != nil {
			out = append(out, fingerprintFailed(ctx, host, kind, c))
			continue
		}
		out = append(out, fingerprintResult(host, kind, c.res))
	}
	return out
}

// serverHelloCapture is the outcome of capturing one host's ServerHello.
// res is set when err is nil, and also when the handshake completed but the
// captured ServerHello could not be parsed.
type serverHelloCapture struct {
	res *tlsfp.Result
	err error
}

// captureServerHello returns host's ServerHello capture shared by the JA3S
// and JA4S checks, capturing it over the SSRF-safe dialer on first use, so
// each host is handshaken once and both fingerprints describe the same
// ServerHello.
func captureServerHello(ctx context.Context, env *probe.Env, host string) *serverHelloCapture {
	c := probe.Shared(env, probe.CacheKeyTLSFingerprint+":"+host, func() *serverHelloCapture {
		timeout := min(env.Timeout, 30*time.Second)
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return probe.SafeDial(ctx, network, addr, timeout)
		}
		res, err := tlsfp.Capture(ctx, host, fingerprintPort, dial, timeout)
		return &serverHelloCapture{res: res, err: err}
	})
	if c == nil {
		return &serverHelloCapture{err: fmt.Errorf("ServerHello capture from %s %w", host,
			checkutil.ErrSharedProbePanicked)}
	}
	return c
}

// fingerprintFailed grades a capture that ended in an error. It is
// Inconclusive when the capture could not complete or when the handshake
// completed but bedrock could not parse the ServerHello, which says nothing
// about the server; a refused connection or handshake stays a FAIL.
func fingerprintFailed(
	ctx context.Context, host, kind string, c *serverHelloCapture,
) report.Result {
	r := report.Result{
		ID:       "web.tls.fingerprint." + kind + "." + host,
		Category: category,
		Title:    "TLS fingerprint (" + kind + ") — " + host,
	}
	if c.res != nil || checkutil.Incomplete(ctx, c.err) {
		return checkutil.Inconclusive(r, c.err)
	}
	r.Status = report.Fail
	r.Evidence = "capture failed: " + c.err.Error()
	return r
}

func fingerprintResult(host, kind string, r *tlsfp.Result) report.Result {
	id := "web.tls.fingerprint." + kind + "." + host
	title := "TLS fingerprint (" + kind + ") — " + host
	switch kind {
	case "ja3s":
		return report.Result{
			ID:       id,
			Category: category,
			Title:    title,
			Status:   report.Info,
			Evidence: fmt.Sprintf(
				"JA3S=%s raw=%s tls=0x%04x cipher=0x%04x ext_count=%d",
				r.JA3S, r.JA3SString, r.WireVersion, r.Cipher, len(r.Extensions),
			),
		}
	case "ja4s":
		alpn := r.ALPN
		if alpn == "" {
			alpn = "(none)"
		}
		return report.Result{
			ID:       id,
			Category: category,
			Title:    title,
			Status:   report.Info,
			Evidence: fmt.Sprintf(
				"JA4S=%s tls=0x%04x cipher=0x%04x alpn=%s ext_count=%d",
				r.JA4S, r.NegotiatedTLS, r.Cipher, alpn, len(r.Extensions),
			),
		}
	default:
		// Unreachable: the only callers above are runTLSFingerprintJA3S and
		// runTLSFingerprintJA4S. Surface as Fail rather than panic so a stray
		// future caller produces a visible signal.
		return report.Result{
			ID:       id,
			Category: category,
			Title:    title,
			Status:   report.Fail,
			Evidence: "unknown fingerprint kind: " + kind,
		}
	}
}
