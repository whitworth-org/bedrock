package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// ocspCheck audits the served OCSP staple and (when available) cross-checks
// against the leaf's AIA OCSP responder and CRL distribution point.
//
// Three result IDs are emitted:
//
//   - web.ocsp.staple    — was an OCSP response stapled to the handshake
//     and is it Good + fresh?  (RFC 6066 §8, RFC 6960)
//   - web.ocsp.responder — independent OCSP fetch; warn if its status
//     disagrees with the staple. INFO when the leaf has no AIA OCSP URL
//     or the responder is unreachable (we don't FAIL on responder
//     reachability since the operator can't always control it).
//   - web.crl.status     — fetch the leaf's CRLDistributionPoints[0]
//     and assert the leaf's serial is not present. INFO when missing.
type ocspCheck struct{}

func (ocspCheck) ID() string       { return "web.ocsp" }
func (ocspCheck) Category() string { return category }

// stapleStaleAfter is the max ThisUpdate age before we WARN that the
// staple is stale. 4 days is a common operational guideline (most
// CAs publish 7-day OCSP responses and rotate halfway through).
const stapleStaleAfter = 4 * 24 * time.Hour

// remediationStapling is reused across staple-related FAIL results so the
// operator gets concrete copy-pasteable config no matter which sub-check
// flagged the problem.
const remediationStapling = `enable OCSP stapling on your TLS server.

  nginx:
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/issuer-chain.pem;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

  Apache (httpd 2.4+):
    SSLUseStapling on
    SSLStaplingCache "shmcb:/var/run/ocsp(128000)"
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off`

func (ocspCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{
			{
				ID: "web.ocsp.staple", Category: category,
				Title:    "OCSP stapling",
				Status:   report.NotApplicable,
				Evidence: "active probing disabled (--no-active)",
				RFCRefs:  []string{"RFC 6066 §8", "RFC 6960"},
			},
			{
				ID: "web.ocsp.responder", Category: category,
				Title:    "Independent OCSP responder",
				Status:   report.NotApplicable,
				Evidence: "active probing disabled (--no-active)",
				RFCRefs:  []string{"RFC 6960"},
			},
			{
				ID: "web.crl.status", Category: category,
				Title:    "CRL revocation check",
				Status:   report.NotApplicable,
				Evidence: "active probing disabled (--no-active)",
				RFCRefs:  []string{"RFC 5280 §5"},
			},
		}
	}

	state := getCachedTLSState(env)
	if state == nil || len(state.PeerCertificates) == 0 {
		return []report.Result{
			{
				ID: "web.ocsp.staple", Category: category,
				Title:    "OCSP stapling",
				Status:   report.Info,
				Evidence: "no cached TLS state available (handshake earlier failed)",
				RFCRefs:  []string{"RFC 6066 §8", "RFC 6960"},
			},
			{
				ID: "web.ocsp.responder", Category: category,
				Title:    "Independent OCSP responder",
				Status:   report.Info,
				Evidence: "no cached TLS state available",
				RFCRefs:  []string{"RFC 6960"},
			},
			{
				ID: "web.crl.status", Category: category,
				Title:    "CRL revocation check",
				Status:   report.Info,
				Evidence: "no cached TLS state available",
				RFCRefs:  []string{"RFC 5280 §5"},
			},
		}
	}

	leaf := state.PeerCertificates[0]
	var issuer *x509.Certificate
	if len(state.PeerCertificates) >= 2 {
		issuer = state.PeerCertificates[1]
	}

	stapleRes, stapledResp := checkStaple(state, issuer)

	// Independent responder fetch — uses its own context so we don't share the
	// (possibly already-elapsed) parent timeout with two slow HTTP calls in a row.
	rctx, rcancel := context.WithTimeout(ctx, env.Timeout*2)
	defer rcancel()
	responderRes := checkResponder(rctx, leaf, issuer, stapledResp)

	cctx, ccancel := context.WithTimeout(ctx, env.Timeout*2)
	defer ccancel()
	crlRes := checkCRL(cctx, leaf)

	return []report.Result{stapleRes, responderRes, crlRes}
}

// checkStaple inspects state.OCSPResponse. The returned *ocsp.Response is the
// parsed staple (or nil) so the responder check can compare statuses without
// re-parsing.
func checkStaple(state *tls.ConnectionState, issuer *x509.Certificate) (report.Result, *ocsp.Response) {
	r := report.Result{
		ID: "web.ocsp.staple", Category: category,
		Title:   "OCSP stapling — served and Good",
		RFCRefs: []string{"RFC 6066 §8", "RFC 6960"},
	}
	if len(state.OCSPResponse) == 0 {
		r.Status = report.Fail
		r.Evidence = "no OCSP response stapled to the TLS handshake"
		r.Remediation = remediationStapling
		return r, nil
	}
	if issuer == nil {
		// No intermediate served — we can't verify the staple's signature.
		// Don't double-FAIL (the cert chain check already covers this), but do
		// surface it so the operator sees why we couldn't validate the staple.
		r.Status = report.Warn
		r.Evidence = fmt.Sprintf("OCSP staple present (%d bytes) but no issuer cert in chain to verify it", len(state.OCSPResponse))
		return r, nil
	}
	resp, err := ocsp.ParseResponse(state.OCSPResponse, issuer)
	if err != nil {
		r.Status = report.Fail
		r.Evidence = "OCSP staple present but unparseable: " + err.Error()
		r.Remediation = remediationStapling
		return r, nil
	}

	now := time.Now()
	switch resp.Status {
	case ocsp.Revoked:
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf(
			"OCSP staple says certificate is REVOKED (reason=%d, at %s)",
			resp.RevocationReason,
			resp.RevokedAt.Format(time.RFC3339),
		)
		r.Remediation = "the leaf certificate has been revoked by the issuing CA — reissue and replace immediately, then investigate the cause of revocation"
		return r, resp
	case ocsp.Unknown:
		r.Status = report.Warn
		r.Evidence = "OCSP staple status is Unknown (responder does not recognize this serial)"
		return r, resp
	}

	// Status == Good
	if resp.NextUpdate.IsZero() {
		// Per RFC 6960 §2.4 NextUpdate is optional but in practice every
		// public CA populates it; missing NextUpdate is suspicious.
		r.Status = report.Warn
		r.Evidence = "OCSP staple Good but missing NextUpdate (RFC 6960 §2.4 recommends it)"
		return r, resp
	}
	if now.After(resp.NextUpdate) {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf(
			"OCSP staple Good but expired: NextUpdate=%s (now=%s)",
			resp.NextUpdate.Format(time.RFC3339),
			now.Format(time.RFC3339),
		)
		r.Remediation = remediationStapling
		return r, resp
	}
	if !resp.ThisUpdate.IsZero() && now.Sub(resp.ThisUpdate) > stapleStaleAfter {
		age := now.Sub(resp.ThisUpdate).Round(time.Hour)
		r.Status = report.Warn
		r.Evidence = fmt.Sprintf(
			"OCSP staple Good but stale: ThisUpdate=%s (%s old; threshold %s)",
			resp.ThisUpdate.Format(time.RFC3339), age, stapleStaleAfter,
		)
		return r, resp
	}
	r.Status = report.Pass
	r.Evidence = fmt.Sprintf(
		"staple Good (ThisUpdate=%s, NextUpdate=%s)",
		resp.ThisUpdate.Format(time.RFC3339),
		resp.NextUpdate.Format(time.RFC3339),
	)
	return r, resp
}

// checkResponder POSTs an OCSP request to the leaf's AIA OCSPServer and
// compares the result to the staple. Soft-fail (INFO) on transport errors —
// the responder being temporarily down is not the domain operator's problem.
func checkResponder(ctx context.Context, leaf, issuer *x509.Certificate, stapled *ocsp.Response) report.Result {
	r := report.Result{
		ID: "web.ocsp.responder", Category: category,
		Title:   "Independent OCSP responder agrees with staple",
		RFCRefs: []string{"RFC 6960", "RFC 5280 §4.2.2.1"},
	}
	if len(leaf.OCSPServer) == 0 {
		r.Status = report.Info
		r.Evidence = "leaf has no AIA OCSP URL (Authority Information Access extension absent)"
		return r
	}
	if issuer == nil {
		r.Status = report.Info
		r.Evidence = "no issuer certificate in chain — cannot construct OCSP request"
		return r
	}

	reqBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not construct OCSP request: " + err.Error()
		return r
	}

	url := leaf.OCSPServer[0]
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBytes))
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not build HTTP request to OCSP responder: " + err.Error()
		return r
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	// Dedicated client with a hard timeout — we don't want a stuck responder
	// to wedge the whole web category run.
	client := &http.Client{Timeout: timeoutFromContext(ctx)}
	resp, err := client.Do(req)
	if err != nil {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("could not contact OCSP responder %s: %v", url, err)
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("OCSP responder %s returned HTTP %d", url, resp.StatusCode)
		return r
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not read OCSP responder body: " + err.Error()
		return r
	}
	parsed, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not parse OCSP responder reply: " + err.Error()
		return r
	}

	// If the responder reports Revoked, that's a hard FAIL even if the staple
	// says Good — the operator's server is shipping a stale assertion.
	if parsed.Status == ocsp.Revoked {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf(
			"OCSP responder %s reports REVOKED (reason=%d at %s)",
			url, parsed.RevocationReason, parsed.RevokedAt.Format(time.RFC3339),
		)
		r.Remediation = "the leaf certificate has been revoked by the issuing CA — reissue and replace immediately"
		return r
	}

	if stapled != nil && stapled.Status != parsed.Status {
		r.Status = report.Warn
		r.Evidence = fmt.Sprintf(
			"staple status=%s but responder %s reports status=%s",
			ocspStatusName(stapled.Status), url, ocspStatusName(parsed.Status),
		)
		return r
	}
	r.Status = report.Pass
	r.Evidence = fmt.Sprintf("responder %s reports %s (ThisUpdate=%s)",
		url, ocspStatusName(parsed.Status), parsed.ThisUpdate.Format(time.RFC3339))
	return r
}

// checkCRL fetches the first CRLDistributionPoints URL and walks the
// revocation list looking for the leaf's serial. CRLs may be DER or PEM
// over HTTP — try DER first (the common case), fall back to PEM.
func checkCRL(ctx context.Context, leaf *x509.Certificate) report.Result {
	r := report.Result{
		ID: "web.crl.status", Category: category,
		Title:   "Leaf serial not on CRL",
		RFCRefs: []string{"RFC 5280 §5", "RFC 5280 §4.2.1.13"},
	}
	if len(leaf.CRLDistributionPoints) == 0 {
		r.Status = report.Info
		r.Evidence = "leaf has no CRL distribution point (cRLDistributionPoints extension absent)"
		return r
	}
	url := leaf.CRLDistributionPoints[0]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not build CRL request: " + err.Error()
		return r
	}
	client := &http.Client{Timeout: timeoutFromContext(ctx)}
	resp, err := client.Do(req)
	if err != nil {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("could not fetch CRL %s: %v", url, err)
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("CRL %s returned HTTP %d", url, resp.StatusCode)
		return r
	}
	// CRLs are typically <10 MiB even for large CAs; cap at 32 MiB to be safe.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not read CRL body: " + err.Error()
		return r
	}
	crl, err := parseCRL(body)
	if err != nil {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("could not parse CRL %s: %v", url, err)
		return r
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			r.Status = report.Fail
			r.Evidence = fmt.Sprintf(
				"leaf serial %s is on CRL %s (revoked at %s, reason=%d)",
				leaf.SerialNumber.String(), url,
				entry.RevocationTime.Format(time.RFC3339), entry.ReasonCode,
			)
			r.Remediation = "the leaf certificate has been revoked by the issuing CA — reissue and replace immediately"
			return r
		}
	}
	r.Status = report.Pass
	r.Evidence = fmt.Sprintf("checked %d entries in %s; leaf serial not present",
		len(crl.RevokedCertificateEntries), url)
	return r
}

// parseCRL accepts either DER or PEM-encoded CRL bytes and returns the
// parsed RevocationList.
func parseCRL(body []byte) (*x509.RevocationList, error) {
	// DER first — that is what RFC 5280 §5 mandates on the wire.
	if crl, err := x509.ParseRevocationList(body); err == nil {
		return crl, nil
	}
	// PEM fallback. Some operator-facing endpoints serve "X509 CRL" PEM blocks.
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("body is neither valid DER nor PEM")
	}
	return x509.ParseRevocationList(block.Bytes)
}

// timeoutFromContext returns the time.Duration remaining until the context's
// deadline, or a 10s default when the context has no deadline. We use this
// for the per-call http.Client.Timeout so a buggy server can't block us
// past the parent context's bound either.
func timeoutFromContext(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			return d
		}
	}
	return 10 * time.Second
}

func ocspStatusName(s int) string {
	switch s {
	case ocsp.Good:
		return "Good"
	case ocsp.Revoked:
		return "Revoked"
	case ocsp.Unknown:
		return "Unknown"
	default:
		return fmt.Sprintf("status(%d)", s)
	}
}

func init() { registry.Register(ocspCheck{}) }
