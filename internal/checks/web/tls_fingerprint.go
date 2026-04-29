package web

import (
	"context"
	"fmt"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/probe/tlsfp"
	"github.com/whitworth-org/bedrock/internal/report"
)

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
// dials each over the SSRF-safe dialer, captures and parses the cleartext
// ServerHello, and emits one Result per host carrying the requested
// fingerprint kind. Hosts that fail to handshake produce a Fail result;
// successful handshakes produce an Info result so they don't pollute the
// pass/fail signal of policy-driven checks.
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

	timeout := env.Timeout
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	dial := probe.SafeDialContext(timeout, false)

	var out []report.Result
	for _, host := range hosts {
		// Mid-flight cancellation gate so a cancelled scan stops dialing
		// further hosts, matching the pattern used by runTLS.
		if err := ctx.Err(); err != nil {
			break
		}

		// Two checks (ja3s, ja4s) share the same captured ServerHello — but
		// since each Wrap registration calls runTLSFingerprint independently,
		// we cache the per-host result on env to avoid a second handshake.
		// The cache key embeds the host so apex+www don't collide.
		cacheKey := "web.tls.fingerprint.cap:" + host
		var res *tlsfp.Result
		if cached, ok := env.CacheGet(cacheKey); ok {
			if r, ok := cached.(*tlsfp.Result); ok {
				res = r
			}
		}
		if res == nil {
			r, err := tlsfp.Capture(ctx, host, "443", dial, timeout)
			if err != nil {
				out = append(out, report.Result{
					ID:       "web.tls.fingerprint." + kind + "." + host,
					Category: category,
					Title:    "TLS fingerprint (" + kind + ") — " + host,
					Status:   report.Fail,
					Evidence: "capture failed: " + err.Error(),
				})
				continue
			}
			env.CachePut(cacheKey, r)
			res = r
		}

		out = append(out, fingerprintResult(host, kind, res))
	}
	return out
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
