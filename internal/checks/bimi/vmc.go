package bimi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// logotypeOID is the LogotypeExtension identifier (RFC 3709) that BIMI Group
// reuses to bind the logo bytes to the certificate.
var logotypeOID = []int{1, 3, 6, 1, 5, 5, 7, 1, 12}

// Mark Verifying / Common Mark Certificates carry distinct ExtKeyUsage OIDs.
// Stdlib x509 doesn't recognize either, so they end up as UnknownExtKeyUsage
// entries on the parsed cert.
var (
	vmcEKUOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31} // id-kp-BrandIndicatorforMessageIdentification
	cmcEKUOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32} // id-kp-CommonMarkCertificate
)

// sha256OID is the algorithm identifier the BIMI guidance mandates for the
// LogotypeData hash. Other algorithms decode fine but are flagged so the
// operator knows the cert may not satisfy mailbox-provider gates.
var sha256OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// markCertType describes what flavor of mark certificate we're looking at.
type markCertType string

const (
	markCertVMC   markCertType = "VMC"
	markCertCMC   markCertType = "CMC"
	markCertOther markCertType = "Other"
)

// classifyMarkCert returns VMC / CMC / Other based on the cert's
// ExtKeyUsage / UnknownExtKeyUsage fields. VMC takes precedence when both
// OIDs are unexpectedly present (defensive — shouldn't happen in real
// issuance).
func classifyMarkCert(cert *x509.Certificate) markCertType {
	if cert == nil {
		return markCertOther
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(vmcEKUOID) {
			return markCertVMC
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(cmcEKUOID) {
			return markCertCMC
		}
	}
	return markCertOther
}

type vmcFetchCheck struct{}

func (vmcFetchCheck) ID() string       { return "bimi.vmc.fetch" }
func (vmcFetchCheck) Category() string { return category }

func (vmcFetchCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "bimi.vmc.fetch"
	const title = "BIMI Verified Mark Certificate fetched over HTTPS"
	refs := []string{"BIMI Group draft §4.5", "RFC 3709 (Logotype extension)"}

	rec, ok := getRecord(env)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Info, Evidence: "no parsed BIMI record",
			RFCRefs: refs,
		}}
	}
	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "skipped: --no-active",
			RFCRefs: refs,
		}}
	}
	if rec.A == "" {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no a= URL in BIMI record (Gmail requires a VMC)",
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}

	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	// VMC authenticity is bound to the TLS chain — use GetStrict so a
	// malformed chain is a hard failure, not a degraded success.
	resp, err := env.HTTP.GetStrict(ctx, rec.A)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "GET " + rec.A + " failed: " + err.Error(),
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}
	if resp.Status != 200 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("GET %s returned HTTP %d", rec.A, resp.Status),
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}
	env.CachePut(cacheKeyBIMIVMCBytes, resp.Body)
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("HTTP 200, %d bytes", len(resp.Body)),
		RFCRefs:  refs,
	}}
}

const cacheKeyBIMIVMCBytes = "bimi.vmc.bytes"

type vmcChainCheck struct{}

func (vmcChainCheck) ID() string       { return "bimi.vmc.chain" }
func (vmcChainCheck) Category() string { return category }

func (vmcChainCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "bimi.vmc.chain"
	const title = "BIMI VMC chain validates against system trust store"
	refs := []string{"BIMI Group draft §4.5"}

	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "skipped: --no-active",
			RFCRefs: refs,
		}}
	}
	pemBytes, ok := getVMCBytes(env)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Info, Evidence: "no VMC bytes cached",
			RFCRefs: refs,
		}}
	}
	leaf, intermediates, err := parsePEMChain(pemBytes)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "PEM chain parse failed: " + err.Error(),
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}

	// EKU gate: before any chain validation, refuse leaves that do not carry
	// the BIMI / Common Mark EKU. Without this, any publicly-trusted TLS leaf
	// (e.g. a server certificate from a mainstream CA) would pass the chain
	// check against system roots. Only VMC (id-kp-BrandIndicatorForMessageIdentification)
	// and CMC (id-kp-CommonMarkCertificate) are acceptable for BIMI.
	certType := classifyMarkCert(leaf)
	if certType == markCertOther {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "leaf does not carry BIMI VMC or Common Mark EKU (id-kp-BrandIndicatorForMessageIdentification / id-kp-CommonMarkCertificate)",
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "load system roots: " + err.Error(),
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	// Mark Verifying Certificates use a non-standard EKU (BIMI / id-kp-mark);
	// system roots can still chain-validate trust, but Go's stdlib will reject
	// the EKU. Pass ExtKeyUsage=Any so the chain check focuses on signing trust.
	// The EKU gate above is what prevents arbitrary public TLS leaves from
	// chaining through here.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "chain validation failed: " + err.Error(),
			Remediation: vmcFetchRemediation(),
			RFCRefs:     refs,
		}}
	}
	env.CachePut(cacheKeyBIMIVMCLeaf, leaf)
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status: report.Pass,
		Evidence: fmt.Sprintf(
			"certificate type: %s; subject=%q issuer=%q notBefore=%s notAfter=%s",
			certType, leaf.Subject.String(), leaf.Issuer.String(),
			leaf.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		),
		RFCRefs: refs,
	}}
}

const cacheKeyBIMIVMCLeaf = "bimi.vmc.leaf"

type vmcLogotypeCheck struct{}

func (vmcLogotypeCheck) ID() string       { return "bimi.vmc.logotype" }
func (vmcLogotypeCheck) Category() string { return category }

func (vmcLogotypeCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "bimi.vmc.logotype"
	const title = "BIMI VMC carries the logotype extension binding the SVG"
	refs := []string{"RFC 3709 §4", "BIMI Group draft §4.5"}

	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "skipped: --no-active",
			RFCRefs: refs,
		}}
	}
	leafV, ok := env.CacheGet(cacheKeyBIMIVMCLeaf)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Info, Evidence: "no validated VMC leaf cached",
			RFCRefs: refs,
		}}
	}
	leaf, ok := leafV.(*x509.Certificate)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Info, Evidence: "cached leaf is the wrong type",
			RFCRefs: refs,
		}}
	}

	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(logotypeOID) {
			ext = e.Value
			break
		}
	}
	certType := classifyMarkCert(leaf)
	if ext == nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("certificate type: %s; logotype extension (1.3.6.1.5.5.7.1.12) absent from leaf", certType),
			Remediation: vmcLogotypeRemediation(),
			RFCRefs:     refs,
		}}
	}

	// Decode RFC 3709 LogotypeExtn properly so we surface the bound media
	// type and URI as evidence and so we compare the SVG digest against the
	// signed hash bytes — not just any byte sequence in the extension.
	images, err := DecodeLogotypeExtn(ext)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("certificate type: %s; LogotypeExtn decode failed: %s", certType, err.Error()),
			Remediation: vmcLogotypeRemediation(),
			RFCRefs:     refs,
		}}
	}

	// Recompute the SVG digest from the cached body when possible (we always
	// recompute defensively so a stale or wrong-typed cache entry can't
	// spoof a Pass), and fall back to the cached digest if the SVG bytes
	// aren't around (--no-active was set after the SVG fetch, etc.).
	var svgDigest []byte
	if body, ok := getSVGBytes(env); ok {
		sum := sha256.Sum256(body)
		svgDigest = sum[:]
	} else if d, ok := env.CacheGet(cacheKeyBIMISVGSHA256); ok {
		if b, ok := d.([]byte); ok && len(b) == 32 {
			svgDigest = b
		}
	}
	if svgDigest == nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: fmt.Sprintf("certificate type: %s; logotype extension parsed (%d image entries) but no SVG digest available to compare", certType, len(images)),
			RFCRefs:  refs,
		}}
	}

	// Walk every (image, hash) pair the cert binds. Pass on the first match;
	// remember the URI(s) and media types we saw for evidence either way.
	var uriList []string
	var mediaSet = map[string]struct{}{}
	for _, img := range images {
		if img.URI != "" {
			uriList = append(uriList, img.URI)
		}
		if img.MediaType != "" {
			mediaSet[img.MediaType] = struct{}{}
		}
		if !isSVGMediaType(img.MediaType) {
			continue
		}
		if !img.HashAlg.Equal(sha256OID) {
			// Non-SHA-256 hash; we can't verify without rehashing under the
			// CA's chosen algorithm. Skip — if no SHA-256 entry matches we
			// still surface this in the failure evidence.
			continue
		}
		if bytes.Equal(img.HashValue, svgDigest) {
			return []report.Result{{
				ID: id, Category: category, Title: title,
				Status:   report.Pass,
				Evidence: fmt.Sprintf("certificate type: %s; logotype extension binds %s sha256=%x at %s", certType, img.MediaType, svgDigest[:8], img.URI),
				RFCRefs:  refs,
			}}
		}
	}

	mediaList := make([]string, 0, len(mediaSet))
	for m := range mediaSet {
		mediaList = append(mediaList, m)
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status: report.Fail,
		Evidence: fmt.Sprintf(
			"certificate type: %s; SVG sha256=%x does not match any LogotypeImage hash (images=%d media=%v uris=%v)",
			certType, svgDigest[:8], len(images), mediaList, uriList,
		),
		Remediation: vmcLogotypeRemediation(),
		RFCRefs:     refs,
	}}
}

// isSVGMediaType reports whether the LogotypeDetails mediaType matches one
// of the SVG forms BIMI may bind. Comparison is case-insensitive and
// tolerant of optional parameters (e.g. "image/svg+xml; charset=utf-8").
func isSVGMediaType(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s == "image/svg+xml" || s == "image/svg+xml+gzip"
}

// maxPEMChainCerts is the upper bound on CERTIFICATE blocks parsePEMChain
// will decode from a single PEM blob. A legitimate VMC chain is leaf +
// a small number of intermediates; the cap prevents an adversarial VMC URL
// from serving an arbitrarily large bundle that would slow parsing and the
// O(n^2) leaf-selection loop below.
const maxPEMChainCerts = 16

// parsePEMChain pulls up to maxPEMChainCerts CERTIFICATE blocks out of the
// PEM blob and returns the leaf and the remaining intermediates. The leaf
// is deterministically selected as the cert that is NOT the issuer of any
// other cert in the bundle (i.e. a sink in the issuance DAG). If multiple
// such candidates remain (shouldn't happen for a well-formed chain), the
// first one in document order is returned so the behavior is stable.
func parsePEMChain(b []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if len(certs) >= maxPEMChainCerts {
			return nil, nil, fmt.Errorf("PEM chain has more than %d CERTIFICATE blocks", maxPEMChainCerts)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no CERTIFICATE blocks found")
	}

	leafIdx := selectLeafIndex(certs)
	leaf := certs[leafIdx]
	intermediates := make([]*x509.Certificate, 0, len(certs)-1)
	for i, c := range certs {
		if i == leafIdx {
			continue
		}
		intermediates = append(intermediates, c)
	}
	return leaf, intermediates, nil
}

// selectLeafIndex returns the index of the cert that is NOT the issuer of
// any other cert in the bundle. When multiple candidates remain (e.g. a
// bundle carrying only roots), the first in document order is chosen.
func selectLeafIndex(certs []*x509.Certificate) int {
	// issuesSomeone[i] = true if certs[i]'s Subject matches some other
	// cert's Issuer — meaning certs[i] is an issuer in this bundle and
	// therefore not the leaf.
	issuesSomeone := make([]bool, len(certs))
	for i, ci := range certs {
		for j, cj := range certs {
			if i == j {
				continue
			}
			// Use RawSubject/RawIssuer for exact byte comparison; this
			// avoids pitfalls where pkix.Name string forms differ for
			// the same DN.
			if bytes.Equal(ci.RawSubject, cj.RawIssuer) {
				issuesSomeone[i] = true
				break
			}
		}
	}
	for i, isIssuer := range issuesSomeone {
		if !isIssuer {
			return i
		}
	}
	return 0
}

func getVMCBytes(env *probe.Env) ([]byte, bool) {
	v, ok := env.CacheGet(cacheKeyBIMIVMCBytes)
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

func vmcFetchRemediation() string {
	return `# Host the VMC PEM at the URL referenced by the BIMI a= tag, served over HTTPS,
# with no authentication and Content-Type application/x-pem-file or text/plain.
# Obtain the certificate from a BIMI-authorized CA (DigiCert, Entrust, etc.).`
}

func vmcLogotypeRemediation() string {
	return `# The VMC must embed the SHA-256 digest of the logo bytes via the
# RFC 3709 logotype extension (OID 1.3.6.1.5.5.7.1.12). Re-issue the
# certificate from a BIMI-authorized CA after publishing the final SVG so
# the digest in the cert matches what is served at the l= URL.`
}
