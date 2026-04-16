package bimi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

// logotypeOID is the LogotypeExtension identifier (RFC 3709) that BIMI Group
// reuses to bind the logo bytes to the certificate.
var logotypeOID = []int{1, 3, 6, 1, 5, 5, 7, 1, 12}

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
			Status: report.NotApplicable, Evidence: "no parsed BIMI record",
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

	resp, err := env.HTTP.Get(ctx, rec.A)
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
			Status: report.NotApplicable, Evidence: "no VMC bytes cached",
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
		Status:   report.Pass,
		Evidence: fmt.Sprintf("subject=%q issuer=%q", leaf.Subject.String(), leaf.Issuer.String()),
		RFCRefs:  refs,
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
			Status: report.NotApplicable, Evidence: "no validated VMC leaf cached",
			RFCRefs: refs,
		}}
	}
	leaf, ok := leafV.(*x509.Certificate)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "cached leaf is the wrong type",
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
	if ext == nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "logotype extension (1.3.6.1.5.5.7.1.12) absent from VMC leaf",
			Remediation: vmcLogotypeRemediation(),
			RFCRefs:     refs,
		}}
	}

	// Best-effort hash binding. Full ASN.1 parsing of LogotypeData (RFC 3709
	// §4.1) is non-trivial; we settle for confirming the SVG digest appears
	// somewhere in the extension bytes. False negatives are possible if the
	// CA stored the digest of a transformed SVG (e.g. minified) but the
	// common path — hashing the bytes the publisher serves — is covered.
	digestV, ok := env.CacheGet(cacheKeyBIMISVGSHA256)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "logotype extension present, but no SVG digest cached to compare",
			RFCRefs:  refs,
		}}
	}
	digest, ok := digestV.([]byte)
	if !ok || len(digest) != 32 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "logotype extension present, but cached SVG digest is malformed",
			RFCRefs:  refs,
		}}
	}
	if !bytes.Contains(ext, digest) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("SVG sha256=%x not found in logotype extension (%d bytes)", digest[:8], len(ext)),
			Remediation: vmcLogotypeRemediation(),
			RFCRefs:     refs,
		}}
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("logotype extension contains SVG sha256=%x", digest[:8]),
		RFCRefs:  refs,
	}}
}

// parsePEMChain pulls every CERTIFICATE block out of the PEM blob and
// returns the leaf (first cert) and the remaining intermediates.
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
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no CERTIFICATE blocks found")
	}
	return certs[0], certs[1:], nil
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
