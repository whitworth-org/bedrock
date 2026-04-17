package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/registry"
	"github.com/rwhitworth/bedrock/internal/report"
)

// ecCurveCheck probes which TLS named groups (elliptic curves) the server
// will accept for ECDHE. Go's stdlib crypto/tls does not surface the
// negotiated group from tls.ConnectionState, so we have to detect by
// running a fresh handshake per candidate curve, each constrained via
// tls.Config.CurvePreferences = []tls.CurveID{c}. Curves that succeed are
// the ones the server accepts.
//
// References:
//   - RFC 8446 §4.2.7 (TLS 1.3 supported_groups extension)
//   - RFC 8422       (ECC extensions for TLS 1.2)
//   - RFC 7919       (named groups for FFDH — informational; we do not
//     probe FFDH groups because Go does not expose them via
//     CurvePreferences and FFDHE is rare in practice)
type ecCurveCheck struct{}

func (ecCurveCheck) ID() string       { return "web.tls.curves" }
func (ecCurveCheck) Category() string { return category }

// probeCurves is the candidate set we attempt. `modern` flags whether the
// curve is acceptable in the embedded "modern" TLS profile (X25519, P-256,
// P-384). P-521 is intermediate-only. X448 is intentionally absent — the
// Go stdlib does not expose it as a tls.CurveID, so we cannot probe it.
var probeCurves = []struct {
	id     tls.CurveID
	name   string
	modern bool
}{
	{tls.X25519, "X25519", true},
	{tls.CurveP256, "P-256", true},
	{tls.CurveP384, "P-384", true},
	{tls.CurveP521, "P-521", false},
}

// maxParallelDials caps simultaneous handshakes against the target so we
// don't hammer a single host with one TCP connection per curve at once.
const maxParallelDials = 4

func (ecCurveCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID:       "web.tls.curves",
			Category: category,
			Title:    "TLS elliptic curves accepted",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 8446 §4.2.7", "RFC 8422"},
		}}
	}

	results := probeAllCurves(ctx, env, env.Target)
	return []report.Result{buildCurveResult(env.Target, results)}
}

// probeAllCurves dials each candidate curve in parallel (capped at
// maxParallelDials) and returns a curveID→accepted map. It is split out
// from Run so it can be substituted in tests if needed.
func probeAllCurves(ctx context.Context, env *probe.Env, host string) map[tls.CurveID]bool {
	out := make(map[tls.CurveID]bool, len(probeCurves))
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, maxParallelDials)
	)
	for _, c := range probeCurves {
		wg.Add(1)
		go func(id tls.CurveID) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dctx, cancel := env.WithTimeout(ctx)
			defer cancel()
			ok := dialOneCurve(dctx, host, id, env.Timeout)
			mu.Lock()
			out[id] = ok
			mu.Unlock()
		}(c.id)
	}
	wg.Wait()
	return out
}

// dialOneCurve performs a single TLS handshake constrained to one curve.
// Returns true iff the handshake completed (i.e., the server accepted that
// named group). Any error — including "no supported group", "handshake
// failure", or transport-level errors — is treated as rejection.
func dialOneCurve(ctx context.Context, host string, id tls.CurveID, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, "443")
	d := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		ServerName:       host,
		MinVersion:       tls.VersionTLS12, // curves only matter for ECDHE
		CurvePreferences: []tls.CurveID{id},
	}
	// DialWithDialer does not accept a context directly, so we honor ctx by
	// closing the connection if ctx is already done before/after the dial.
	if err := ctx.Err(); err != nil {
		return false
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// buildCurveResult turns a probe map into a single report.Result.
//
// Status ranking:
//   - PASS  : at least one modern-baseline curve (X25519 or P-256) accepted.
//   - WARN  : only non-modern curves (P-384 / P-521) accepted.
//   - FAIL  : no curves accepted at all (server has ECDHE disabled, which
//     is unusual and breaks PFS for TLS 1.3 entirely).
func buildCurveResult(host string, accepted map[tls.CurveID]bool) report.Result {
	acceptedNames, rejectedNames := partitionCurves(accepted)
	evidence := formatEvidence(acceptedNames, rejectedNames)

	res := report.Result{
		ID:       "web.tls.curves",
		Category: category,
		Title:    "TLS elliptic curves accepted (" + host + ")",
		Evidence: evidence,
		RFCRefs:  []string{"RFC 8446 §4.2.7", "RFC 8422", "RFC 7919"},
	}

	switch {
	case len(acceptedNames) == 0:
		res.Status = report.Fail
		res.Remediation = "enable ECDHE with at least one modern named group (X25519 or secp256r1/P-256); the server currently rejects every probed curve, which disables forward secrecy for TLS 1.3"
	case hasModernBaseline(accepted):
		res.Status = report.Pass
	default:
		res.Status = report.Warn
		res.Remediation = "add a modern named group to the server's supported_groups list — prefer X25519, then secp256r1 (P-256); P-384/P-521 alone are slow and not in the modern TLS profile"
	}
	return res
}

// hasModernBaseline returns true if X25519 or P-256 was accepted. RFC 8446
// §9.1 mandates secp256r1 (P-256) support and recommends X25519; the
// modern Mozilla profile aligns. P-384 may also be in the modern profile
// but is not required for a "modern" baseline pass.
func hasModernBaseline(accepted map[tls.CurveID]bool) bool {
	return accepted[tls.X25519] || accepted[tls.CurveP256]
}

// partitionCurves splits the probe map into accepted and rejected name
// lists, preserving the canonical probeCurves order so output is stable.
func partitionCurves(accepted map[tls.CurveID]bool) (acc, rej []string) {
	for _, c := range probeCurves {
		if accepted[c.id] {
			acc = append(acc, c.name)
		} else {
			rej = append(rej, c.name)
		}
	}
	return acc, rej
}

// formatEvidence renders the accepted/rejected sets into a human-readable
// single-line evidence string. Sort is stable on the canonical ordering so
// tests are deterministic regardless of map iteration order.
func formatEvidence(accepted, rejected []string) string {
	// Defensive copy + sort by canonical position (already in canonical order
	// from partitionCurves; sort.Strings would lose that, so we don't sort).
	var b strings.Builder
	if len(accepted) > 0 {
		fmt.Fprintf(&b, "accepted: %s", strings.Join(accepted, ", "))
	} else {
		b.WriteString("accepted: (none)")
	}
	if len(rejected) > 0 {
		fmt.Fprintf(&b, "; rejected: %s", strings.Join(rejected, ", "))
	}
	return b.String()
}

// curveNameByID is a stable lookup for evidence formatting in tests; not
// used in production code paths but exposed so the test file does not have
// to mirror the probeCurves list.
func curveNameByID(id tls.CurveID) string {
	for _, c := range probeCurves {
		if c.id == id {
			return c.name
		}
	}
	return fmt.Sprintf("curve(0x%04x)", uint16(id))
}

func init() { registry.Register(ecCurveCheck{}) }
