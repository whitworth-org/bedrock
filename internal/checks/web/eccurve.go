package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// ecCurveCheck probes which TLS named groups (elliptic curves) the server
// will accept for ECDHE. A handshake reveals only the one group the server
// picked (tls.ConnectionState.CurveID), not every group it would accept, so
// we run a fresh handshake per candidate curve, each constrained via
// tls.Config.CurvePreferences = []tls.CurveID{c}. Curves that succeed are
// the ones the server accepts.
//
// References:
//   - RFC 8446 §4.2.7 (TLS 1.3 supported_groups extension)
//   - RFC 8422       (ECC extensions for TLS 1.2)
//   - RFC 7919       (named groups for FFDH — informational; we do not
//     probe FFDH groups because Go does not expose them via
//     CurvePreferences and FFDHE is rare in practice)

// probeCurves is the candidate set we attempt. X448 is intentionally
// absent — the Go stdlib does not expose it as a tls.CurveID, so we cannot
// probe it.
var probeCurves = []struct {
	id   tls.CurveID
	name string
}{
	{tls.X25519, "X25519"},
	{tls.CurveP256, "P-256"},
	{tls.CurveP384, "P-384"},
	{tls.CurveP521, "P-521"},
}

// maxParallelDials caps simultaneous handshakes against the target so we
// don't hammer a single host with one TCP connection per curve at once.
const maxParallelDials = 4

// ecCurvePort is the port the curve probes dial; only tests change it.
var ecCurvePort = "443"

func runECCurves(ctx context.Context, env *probe.Env) []report.Result {
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

	verdicts, err := probeAllCurves(ctx, env, env.Target)
	return []report.Result{buildCurveResult(env.Target, verdicts, err)}
}

// probeAllCurves dials each candidate curve in parallel (capped at
// maxParallelDials). The map holds a verdict (true: accepted) for every
// curve whose probe completed. The error, from the first curve in
// probeCurves order whose probe could not complete, is nil when all did.
func probeAllCurves(
	ctx context.Context, env *probe.Env, host string,
) (map[tls.CurveID]bool, error) {
	out := make(map[tls.CurveID]bool, len(probeCurves))
	errs := make([]error, len(probeCurves))
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, maxParallelDials)
	)
	for i, c := range probeCurves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dctx, cancel := env.WithTimeout(ctx)
			defer cancel()
			ok, err := dialOneCurve(dctx, host, c.id, env.Timeout)
			if err != nil {
				errs[i] = fmt.Errorf("%s handshake: %w", c.name, err)
				return
			}
			mu.Lock()
			out[c.id] = ok
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// dialOneCurve reports whether host accepts the curve id: true when a
// handshake offering only that curve completes, false when the server
// refuses the handshake or the connection. It returns an error instead when
// the probe could not complete (see checkutil.Incomplete), since the curve's
// support is then unknown.
func dialOneCurve(
	ctx context.Context, host string, id tls.CurveID, timeout time.Duration,
) (bool, error) {
	err := curveHandshake(ctx, host, id, timeout)
	if err != nil && checkutil.Incomplete(ctx, err) {
		return false, err
	}
	return err == nil, nil
}

// curveHandshake runs one TLS handshake with host, under ctx, offering only
// the curve id.
func curveHandshake(ctx context.Context, host string, id tls.CurveID, timeout time.Duration) error {
	raw, err := probe.SafeDial(ctx, "tcp", net.JoinHostPort(host, ecCurvePort), timeout)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:       host,
		MinVersion:       tls.VersionTLS12, // curves only matter for ECDHE
		CurvePreferences: []tls.CurveID{id},
		// A capability probe: it reports only whether the handshake
		// completes, nothing it receives is trusted, and web.cert.* grades
		// the certificate.
		InsecureSkipVerify: true, //nolint:gosec // G402: capability probe; see above
	})
	defer func() { _ = conn.Close() }()
	return conn.HandshakeContext(ctx)
}

// buildCurveResult turns the curve verdicts into a single report.Result.
// probeErr is the error of a curve probe that could not complete, or nil.
//
// Status ranking:
//   - PASS  : at least one modern-baseline curve (X25519 or P-256) accepted.
//   - checkutil.Inconclusive: otherwise, when a curve probe could not
//     complete, since that curve might be accepted.
//   - WARN  : only non-modern curves (P-384 / P-521) accepted.
//   - FAIL  : no curves accepted at all (server has ECDHE disabled, which
//     is unusual and breaks PFS for TLS 1.3 entirely).
func buildCurveResult(host string, verdicts map[tls.CurveID]bool, probeErr error) report.Result {
	acceptedNames, rejectedNames, unprobedNames := partitionCurves(verdicts)
	res := report.Result{
		ID:       "web.tls.curves",
		Category: category,
		Title:    "TLS elliptic curves accepted (" + host + ")",
		Evidence: formatEvidence(acceptedNames, rejectedNames, unprobedNames),
		RFCRefs:  []string{"RFC 8446 §4.2.7", "RFC 8422", "RFC 7919"},
	}

	switch {
	case hasModernBaseline(verdicts):
		res.Status = report.Pass
	case probeErr != nil:
		return checkutil.Inconclusive(res, probeErr)
	case len(acceptedNames) == 0:
		res.Status = report.Fail
		res.Remediation = "enable ECDHE with at least one modern named group (X25519 or " +
			"secp256r1/P-256); the server currently rejects every probed curve, which " +
			"disables forward secrecy for TLS 1.3"
	default:
		res.Status = report.Warn
		res.Remediation = "add a modern named group to the server's supported_groups list — " +
			"prefer X25519, then secp256r1 (P-256); P-384/P-521 alone are slow and not in " +
			"the modern TLS profile"
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

// partitionCurves splits the probed curves into accepted, rejected and
// unprobed (no verdict in the map: the probe could not complete) name
// lists, preserving the canonical probeCurves order so output is stable.
func partitionCurves(verdicts map[tls.CurveID]bool) (acc, rej, unprobed []string) {
	for _, c := range probeCurves {
		accepted, probed := verdicts[c.id]
		switch {
		case !probed:
			unprobed = append(unprobed, c.name)
		case accepted:
			acc = append(acc, c.name)
		default:
			rej = append(rej, c.name)
		}
	}
	return acc, rej, unprobed
}

// formatEvidence renders the curve name lists, each in probeCurves order
// (see partitionCurves), into a single-line evidence string.
func formatEvidence(accepted, rejected, unprobed []string) string {
	var b strings.Builder
	if len(accepted) > 0 {
		fmt.Fprintf(&b, "accepted: %s", strings.Join(accepted, ", "))
	} else {
		b.WriteString("accepted: (none)")
	}
	if len(rejected) > 0 {
		fmt.Fprintf(&b, "; rejected: %s", strings.Join(rejected, ", "))
	}
	if len(unprobed) > 0 {
		fmt.Fprintf(&b, "; not determined: %s", strings.Join(unprobed, ", "))
	}
	return b.String()
}

func init() { registry.Register(checkutil.Wrap("web.tls.curves", category, runECCurves)) }
