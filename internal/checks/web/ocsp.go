package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
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
//     and is it Good + fresh?  (RFC 6066 §8, RFC 6960) N/A when the leaf
//     names no OCSP responder, because then there is nothing to staple.
//   - web.ocsp.responder — independent OCSP fetch; warn if its status
//     disagrees with the staple. INFO when the leaf has no AIA OCSP URL
//     or the responder is unreachable (we don't FAIL on responder
//     reachability since the operator can't always control it).
//   - web.crl.status     — fetch the leaf's CRLDistributionPoints[0]
//     and assert the leaf's serial is not present. INFO when missing.
//
// OCSP responses and CRLs count only when they are signed for the issuer in
// the verified chain, name the leaf's serial (OCSP), and are current.
type ocspCheck struct{}

func (ocspCheck) ID() string       { return "web.ocsp" }
func (ocspCheck) Category() string { return category }

// ocspStaleAfter is the max ThisUpdate age before an OCSP response counts
// as stale. 4 days is a common operational guideline (most CAs publish
// 7-day OCSP responses and rotate halfway through).
const ocspStaleAfter = 4 * 24 * time.Hour

// revocationSkew is the clock drift allowed between bedrock's host and the
// CA or CT log when comparing the current time with OCSP and CRL
// ThisUpdate/NextUpdate and with SCT timestamps.
const revocationSkew = 5 * time.Minute

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
		const ev = "active probing disabled (--no-active)"
		return ocspPlaceholders(report.NotApplicable, ev, ev)
	}

	h := hostTLS(ctx, env, env.Target)
	if h.err != nil || len(h.chains) == 0 {
		return ocspCannotRun(ctx, h)
	}
	leaf := h.state.PeerCertificates[0]
	issuer := h.verifiedIssuer()

	stapleRes, stapledResp := checkStaple(h.state, leaf, issuer)

	// Independent responder fetch — uses its own context so we don't share the
	// (possibly already-elapsed) parent timeout with two slow HTTP calls in a row.
	rctx, rcancel := context.WithTimeout(ctx, env.Timeout*2)
	defer rcancel()
	responderRes := checkResponder(rctx, env, leaf, issuer, stapledResp)

	cctx, ccancel := context.WithTimeout(ctx, env.Timeout*2)
	defer ccancel()
	crlRes := checkCRL(cctx, env, leaf, issuer)

	return []report.Result{stapleRes, responderRes, crlRes}
}

// ocspPlaceholders returns the three results with one status when the
// revocation checks cannot run; the staple result carries its own evidence.
func ocspPlaceholders(status report.Status, stapleEvidence, evidence string) []report.Result {
	return []report.Result{
		{
			ID: "web.ocsp.staple", Category: category,
			Title:    "OCSP stapling",
			Status:   status,
			Evidence: stapleEvidence,
			RFCRefs:  []string{"RFC 6066 §8", "RFC 6960"},
		},
		{
			ID: "web.ocsp.responder", Category: category,
			Title:    "Independent OCSP responder",
			Status:   status,
			Evidence: evidence,
			RFCRefs:  []string{"RFC 6960"},
		},
		{
			ID: "web.crl.status", Category: category,
			Title:    "CRL revocation check",
			Status:   status,
			Evidence: evidence,
			RFCRefs:  []string{"RFC 5280 §5"},
		},
	}
}

// ocspCannotRun returns the three results when h holds no verified chain:
// graded by handshakeFailed (INFO unless inconclusive; web.tls.profile
// reports the failure) when the handshake failed, otherwise N/A, since
// nothing binds OCSP or CRL data to an issuer and web.cert.chain reports
// the chain.
func ocspCannotRun(ctx context.Context, h *tlsHandshake) []report.Result {
	out := ocspPlaceholders(report.Info, "", "")
	for i, r := range out {
		if h.err != nil {
			out[i] = handshakeFailed(ctx, r, h.err)
		} else {
			out[i] = chainInvalid(r)
		}
	}
	return out
}

// checkStaple validates state.OCSPResponse for leaf against issuer, the
// leaf's issuer in the verified chain. The returned *ocsp.Response is the
// validated staple (or nil) so the responder check can compare statuses
// without re-parsing.
func checkStaple(
	state *tls.ConnectionState, leaf, issuer *x509.Certificate,
) (report.Result, *ocsp.Response) {
	r := report.Result{
		ID: "web.ocsp.staple", Category: category,
		Title:   "OCSP stapling — served and Good",
		RFCRefs: []string{"RFC 6066 §8", "RFC 6960"},
	}
	if len(state.OCSPResponse) == 0 {
		if len(leaf.OCSPServer) == 0 {
			r.Status = report.NotApplicable
			r.Evidence = "no OCSP staple; the leaf names no OCSP responder, " +
				"so there is nothing to staple"
			return r, nil
		}
		r.Status = report.Fail
		r.Evidence = "no OCSP response stapled to the TLS handshake"
		r.Remediation = remediationStapling
		return r, nil
	}
	if issuer == nil {
		// The leaf is itself a trust anchor, so there is no issuer certificate
		// to verify the staple's signature against; surface that instead of
		// grading a staple we cannot validate.
		r.Status = report.Warn
		r.Evidence = fmt.Sprintf(
			"OCSP staple present (%d bytes) but no issuer cert in chain to verify it",
			len(state.OCSPResponse))
		return r, nil
	}
	now := time.Now()
	resp, err := parseOCSPForLeaf(state.OCSPResponse, leaf, issuer, now)
	if err != nil {
		r.Status = report.Fail
		r.Evidence = "OCSP staple present but invalid: " + err.Error()
		r.Remediation = remediationStapling
		return r, nil
	}
	return gradeStaple(r, resp, now), resp
}

// gradeStaple grades a staple that parseOCSPForLeaf accepted.
func gradeStaple(r report.Result, resp *ocsp.Response, now time.Time) report.Result {
	switch resp.Status {
	case ocsp.Revoked:
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf(
			"OCSP staple says certificate is REVOKED (reason=%d, at %s)",
			resp.RevocationReason,
			resp.RevokedAt.Format(time.RFC3339),
		)
		r.Remediation = "the leaf certificate has been revoked by the issuing CA — reissue and " +
			"replace immediately, then investigate the cause of revocation"
		return r
	case ocsp.Unknown:
		r.Status = report.Warn
		r.Evidence = "OCSP staple status is Unknown (responder does not recognize this serial)"
		return r
	}

	// Status == Good
	if problem, invalid := ocspTimeProblem(resp, now); problem != "" {
		r.Status = report.Warn
		r.Evidence = "OCSP staple Good but " + problem
		if invalid {
			r.Status = report.Fail
			r.Remediation = remediationStapling
		}
		return r
	}
	r.Status = report.Pass
	r.Evidence = fmt.Sprintf(
		"staple Good (ThisUpdate=%s, NextUpdate=%s)",
		resp.ThisUpdate.Format(time.RFC3339),
		resp.NextUpdate.Format(time.RFC3339),
	)
	return r
}

// parseOCSPForLeaf parses an OCSP response and checks that it speaks for
// leaf. ParseResponseForCert selects the SingleResponse for leaf's serial
// and verifies the signature against issuer, or against an embedded
// responder certificate that issuer signed. It does not check that such a
// delegated responder carries the OCSP Signing EKU (RFC 6960 §4.2.2.2) or
// is within its validity period; without those checks any certificate from
// the same issuer, such as another subscriber's leaf, could sign a Good
// response for this one.
func parseOCSPForLeaf(
	der []byte, leaf, issuer *x509.Certificate, now time.Time,
) (*ocsp.Response, error) {
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return nil, err
	}
	responder := resp.Certificate
	if responder == nil {
		return resp, nil
	}
	if !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return nil, errors.New("delegated OCSP responder certificate lacks the OCSP Signing EKU")
	}
	if now.Before(responder.NotBefore) || now.After(responder.NotAfter) {
		return nil, fmt.Errorf(
			"delegated OCSP responder certificate is not valid at %s (%s to %s)",
			now.UTC().Format(time.RFC3339), responder.NotBefore.Format(time.RFC3339),
			responder.NotAfter.Format(time.RFC3339))
	}
	return resp, nil
}

// ocspTimeProblem explains why resp cannot be relied on at now, or returns
// "". invalid is true when now falls outside ThisUpdate <= now < NextUpdate,
// allowing revocationSkew at either end; a missing NextUpdate or a
// ThisUpdate older than ocspStaleAfter is a problem but not invalid.
func ocspTimeProblem(resp *ocsp.Response, now time.Time) (problem string, invalid bool) {
	switch {
	case resp.ThisUpdate.After(now.Add(revocationSkew)):
		return fmt.Sprintf("not yet valid: ThisUpdate=%s (now=%s)",
			resp.ThisUpdate.Format(time.RFC3339), now.UTC().Format(time.RFC3339)), true
	case resp.NextUpdate.IsZero():
		// Per RFC 6960 §2.4 NextUpdate is optional but in practice every
		// public CA populates it; missing NextUpdate is suspicious.
		return "missing NextUpdate (RFC 6960 §2.4 recommends it)", false
	case !now.Before(resp.NextUpdate.Add(revocationSkew)):
		return fmt.Sprintf("expired: NextUpdate=%s (now=%s)",
			resp.NextUpdate.Format(time.RFC3339), now.UTC().Format(time.RFC3339)), true
	case now.Sub(resp.ThisUpdate) > ocspStaleAfter:
		age := now.Sub(resp.ThisUpdate).Round(time.Hour)
		return fmt.Sprintf("stale: ThisUpdate=%s (%s old; threshold %s)",
			resp.ThisUpdate.Format(time.RFC3339), age, ocspStaleAfter), false
	}
	return "", false
}

// checkResponder POSTs an OCSP request to the leaf's AIA OCSPServer and
// compares the result to the staple. Soft-fail (INFO) on transport errors —
// the responder being temporarily down is not the domain operator's problem.
func checkResponder(ctx context.Context, env *probe.Env, leaf, issuer *x509.Certificate, stapled *ocsp.Response) report.Result {
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

	resp, err := env.HTTP.Do(req)
	if err != nil {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("could not contact OCSP responder %s: %v", url, err)
		return r
	}
	if resp.Status != http.StatusOK {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("OCSP responder %s returned HTTP %d", url, resp.Status)
		return r
	}
	now := time.Now()
	parsed, err := parseOCSPForLeaf(resp.Body, leaf, issuer, now)
	if err != nil {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("could not validate OCSP responder %s reply: %v", url, err)
		return r
	}
	return gradeResponder(r, url, parsed, stapled, now)
}

// gradeResponder grades a responder reply that parseOCSPForLeaf accepted.
// A reply that is not current is INFO rather than FAIL: the domain operator
// does not run the CA's responder, and the plain-HTTP fetch may have
// returned a cached or replayed reply from before a revocation.
func gradeResponder(
	r report.Result, url string, parsed, stapled *ocsp.Response, now time.Time,
) report.Result {
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
	if problem, _ := ocspTimeProblem(parsed, now); problem != "" {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("OCSP responder %s reply is %s", url, problem)
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
// revocation list looking for the leaf's serial. Distribution points are
// plain http:// URLs, so the CRL counts only when issuer signed it, it is
// current and its scope covers the leaf; otherwise a stale cache or an
// on-path attacker serving another shard could hide a revocation or invent
// one.
func checkCRL(ctx context.Context, env *probe.Env, leaf, issuer *x509.Certificate) report.Result {
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
	if issuer == nil {
		r.Status = report.Info
		r.Evidence = "no issuer certificate in chain — cannot authenticate the CRL"
		return r
	}
	url := leaf.CRLDistributionPoints[0]
	crl, err := fetchCRL(ctx, env, url)
	if err != nil {
		r.Status = report.Info
		r.Evidence = err.Error()
		return r
	}
	if err := authenticateCRL(crl, issuer, url, time.Now()); err != nil {
		r.Status = report.Info
		r.Evidence = fmt.Sprintf("CRL %s rejected: %v", url, err)
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

// fetchCRL downloads the CRL at url and parses it as DER or PEM. Each error
// reads as the evidence of an INFO result.
func fetchCRL(ctx context.Context, env *probe.Env, url string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build CRL request: %w", err)
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch CRL %s: %w", url, err)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("CRL %s returned HTTP %d", url, resp.Status)
	}
	if resp.Truncated {
		return nil, fmt.Errorf("CRL %s exceeds the 1 MiB fetch cap; not checked", url)
	}
	crl, err := parseCRL(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not parse CRL %s: %w", url, err)
	}
	return crl, nil
}

// authenticateCRL checks that issuer signed crl, that crl is current at
// now, allowing revocationSkew, and that its scope covers the leaf whose
// distribution point url served it.
func authenticateCRL(
	crl *x509.RevocationList, issuer *x509.Certificate, url string, now time.Time,
) error {
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("not signed by the leaf's issuer: %w", err)
	}
	if crl.ThisUpdate.After(now.Add(revocationSkew)) {
		return fmt.Errorf("not yet valid: ThisUpdate=%s (now=%s)",
			crl.ThisUpdate.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if !crl.NextUpdate.IsZero() && !now.Before(crl.NextUpdate.Add(revocationSkew)) {
		return fmt.Errorf("expired: NextUpdate=%s (now=%s)",
			crl.NextUpdate.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return checkCRLScope(crl, url)
}

// RFC 5280 §5.2 extensions that limit a CRL's scope.
var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// checkCRLScope rejects a CRL that may leave the leaf's revocation out: a
// delta CRL, one whose Issuing Distribution Point limits it to another
// scope, or one with a critical extension bedrock does not process, which
// RFC 5280 §5.2 says makes the CRL unusable.
func checkCRLScope(crl *x509.RevocationList, url string) error {
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			return errors.New("delta CRL; only complete CRLs are checked")
		case ext.Id.Equal(oidIssuingDistributionPoint):
			if err := checkIDP(ext.Value, url); err != nil {
				return err
			}
		case ext.Critical:
			return fmt.Errorf("unsupported critical extension %s", ext.Id)
		}
	}
	return nil
}

// issuingDistributionPoint is the RFC 5280 §5.2.5 extension value. Its
// distributionPoint is an explicitly tagged CHOICE, which encodes like the
// implicitly tagged struct of alternatives decoded here.
type issuingDistributionPoint struct {
	DistributionPoint          distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.RawValue         `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

// distributionPointName holds a DistributionPointName: fullName, a list of
// GeneralNames, or nameRelativeToCRLIssuer.
type distributionPointName struct {
	FullName     []asn1.RawValue `asn1:"optional,tag:0"`
	RelativeName asn1.RawValue   `asn1:"optional,tag:1"`
}

// generalNameURI is the GeneralName tag of a uniformResourceIdentifier.
const generalNameURI = 6

// checkIDP rejects an Issuing Distribution Point that leaves out some of a
// leaf's revocations or that names distribution points other than url.
func checkIDP(value []byte, url string) error {
	var idp issuingDistributionPoint
	if rest, err := asn1.Unmarshal(value, &idp); err != nil || len(rest) > 0 {
		return errors.New("malformed issuing distribution point extension")
	}
	if reason := idp.narrowing(); reason != "" {
		return errors.New("issuing distribution point " + reason)
	}
	if !idp.DistributionPoint.covers(url) {
		return fmt.Errorf("issuing distribution point does not name %s, "+
			"so the CRL is another distribution point's", url)
	}
	return nil
}

// narrowing names the flag that leaves some of an end-entity certificate's
// revocations out of the CRL, or returns "".
func (idp issuingDistributionPoint) narrowing() string {
	switch {
	case idp.OnlyContainsCACerts, idp.OnlyContainsAttributeCerts:
		return "excludes end-entity certificates"
	case len(idp.OnlySomeReasons.FullBytes) > 0:
		return "covers only some revocation reasons"
	case idp.IndirectCRL:
		return "marks an indirect CRL"
	}
	return ""
}

// covers reports whether the name limits nothing, being absent, or lists url
// as a fullName URI (RFC 5280 §6.3.3 (b)(2)(i)).
func (n distributionPointName) covers(url string) bool {
	if len(n.FullName) == 0 && len(n.RelativeName.FullBytes) == 0 {
		return true
	}
	for _, gn := range n.FullName {
		if gn.Class == asn1.ClassContextSpecific && gn.Tag == generalNameURI &&
			string(gn.Bytes) == url {
			return true
		}
	}
	return false
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
