package bimi

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
)

// certWithUnknownEKU builds a stub *x509.Certificate carrying the given
// OIDs in its UnknownExtKeyUsage list. classifyMarkCert reads only that
// field, so we don't need a real signed/parsed cert for these tests.
func certWithUnknownEKU(oids ...asn1.ObjectIdentifier) *x509.Certificate {
	c := &x509.Certificate{}
	c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage, oids...)
	return c
}

// buildLogotypeExtn round-trips the package-private logotypeExtn struct
// through encoding/asn1 to produce a DER blob the decoder will accept.
// Tests assemble the expected structure here so they prove the decoder can
// handle exactly the same shape a CA would emit.
func buildLogotypeExtn(t *testing.T, mediaType, uri string, hashAlg asn1.ObjectIdentifier, hashValue []byte) []byte {
	t.Helper()
	uriSeq, err := encodeIA5StringSeq([]string{uri})
	if err != nil {
		t.Fatalf("encodeIA5StringSeq: %v", err)
	}
	ext := logotypeExtn{
		SubjectLogo: logotypeInfoDirect{
			Data: logotypeData{
				Image: []logotypeImage{
					{
						ImageDetails: logotypeDetails{
							MediaType: mediaType,
							LogotypeHash: []hashAlgAndValue{
								{
									HashAlg:   pkix.AlgorithmIdentifier{Algorithm: hashAlg},
									HashValue: hashValue,
								},
							},
							LogotypeURI: uriSeq,
						},
					},
				},
			},
		},
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return der
}

func TestDecodeLogotypeExtn_Valid(t *testing.T) {
	hash := sha256.Sum256([]byte("<svg/>"))
	der := buildLogotypeExtn(t, "image/svg+xml", "https://example.com/logo.svg", sha256OID, hash[:])

	images, err := DecodeLogotypeExtn(der)
	if err != nil {
		t.Fatalf("DecodeLogotypeExtn: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(images))
	}
	got := images[0]
	if got.MediaType != "image/svg+xml" {
		t.Errorf("MediaType=%q want image/svg+xml", got.MediaType)
	}
	if got.URI != "https://example.com/logo.svg" {
		t.Errorf("URI=%q", got.URI)
	}
	if !got.HashAlg.Equal(sha256OID) {
		t.Errorf("HashAlg=%v want %v", got.HashAlg, sha256OID)
	}
	if string(got.HashValue) != string(hash[:]) {
		t.Errorf("HashValue mismatch: got %x want %x", got.HashValue, hash[:])
	}
}

func TestDecodeLogotypeExtn_Empty(t *testing.T) {
	if _, err := DecodeLogotypeExtn(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, err := DecodeLogotypeExtn([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDecodeLogotypeExtn_Garbage(t *testing.T) {
	_, err := DecodeLogotypeExtn([]byte{0x30, 0x82, 0xff, 0xff, 0xde, 0xad})
	if err == nil {
		t.Fatal("expected error for malformed DER")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "logotype") &&
		!strings.Contains(strings.ToLower(err.Error()), "asn1") &&
		!strings.Contains(strings.ToLower(err.Error()), "parse") {
		t.Errorf("error should mention parse/asn1/logotype, got: %v", err)
	}
}

func TestDecodeLogotypeExtn_NoSubjectLogo(t *testing.T) {
	// Build an extension with every optional field omitted. SubjectLogo's
	// embedded LogotypeData carries no images, so imagesFrom should error.
	der, err := asn1.Marshal(logotypeExtn{})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	if _, err := DecodeLogotypeExtn(der); err == nil {
		t.Fatal("expected error when no images present")
	}
}

func TestIsSVGMediaType(t *testing.T) {
	cases := map[string]bool{
		"image/svg+xml":                true,
		"IMAGE/SVG+XML":                true,
		"image/svg+xml; charset=utf-8": true,
		"image/svg+xml+gzip":           true,
		"image/png":                    false,
		"":                             false,
		"text/plain":                   false,
		"  image/svg+xml  ":            true,
	}
	for in, want := range cases {
		if got := isSVGMediaType(in); got != want {
			t.Errorf("isSVGMediaType(%q)=%v want %v", in, got, want)
		}
	}
}

func TestDecodeLogotypeExtn_ExceedsImageCap(t *testing.T) {
	// Build a LogotypeData with 9 images (exceeds maxLogotypeImages = 8)
	images := make([]logotypeImage, 9)
	for i := range images {
		uriSeq, err := encodeIA5StringSeq([]string{"https://example.com/logo.svg"})
		if err != nil {
			t.Fatalf("encodeIA5StringSeq: %v", err)
		}
		images[i] = logotypeImage{
			ImageDetails: logotypeDetails{
				MediaType: "image/svg+xml",
				LogotypeHash: []hashAlgAndValue{
					{
						HashAlg:   pkix.AlgorithmIdentifier{Algorithm: sha256OID},
						HashValue: make([]byte, 32),
					},
				},
				LogotypeURI: uriSeq,
			},
		}
	}
	ext := logotypeExtn{
		SubjectLogo: logotypeInfoDirect{
			Data: logotypeData{Image: images},
		},
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	_, err = DecodeLogotypeExtn(der)
	if err == nil {
		t.Fatal("expected error for too many images")
	}
	if !strings.Contains(err.Error(), "9 images") || !strings.Contains(err.Error(), "max 8") {
		t.Errorf("error should mention image count limit, got: %v", err)
	}
}

func TestDecodeLogotypeExtn_ContainsAudio(t *testing.T) {
	// Build a LogotypeData with audio entries (BIMI requires 0)
	uriSeq, err := encodeIA5StringSeq([]string{"https://example.com/logo.svg"})
	if err != nil {
		t.Fatalf("encodeIA5StringSeq: %v", err)
	}
	ext := logotypeExtn{
		SubjectLogo: logotypeInfoDirect{
			Data: logotypeData{
				Image: []logotypeImage{
					{
						ImageDetails: logotypeDetails{
							MediaType: "image/svg+xml",
							LogotypeHash: []hashAlgAndValue{
								{
									HashAlg:   pkix.AlgorithmIdentifier{Algorithm: sha256OID},
									HashValue: make([]byte, 32),
								},
							},
							LogotypeURI: uriSeq,
						},
					},
				},
				Audio: []logotypeAudio{{Raw: []byte{0x30, 0x00}}}, // minimal SEQUENCE
			},
		},
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	_, err = DecodeLogotypeExtn(der)
	if err == nil {
		t.Fatal("expected error for audio entries")
	}
	if !strings.Contains(err.Error(), "audio") || !strings.Contains(err.Error(), "BIMI") {
		t.Errorf("error should mention audio/BIMI restriction, got: %v", err)
	}
}

func TestDecodeLogotypeExtn_ExceedsURICap(t *testing.T) {
	// Build a LogotypeImage with 9 URIs (exceeds maxLogotypeURIs = 8)
	uris := make([]string, 9)
	for i := range uris {
		uris[i] = "https://example.com/logo.svg"
	}
	uriSeq, err := encodeIA5StringSeq(uris)
	if err != nil {
		t.Fatalf("encodeIA5StringSeq: %v", err)
	}
	ext := logotypeExtn{
		SubjectLogo: logotypeInfoDirect{
			Data: logotypeData{
				Image: []logotypeImage{
					{
						ImageDetails: logotypeDetails{
							MediaType: "image/svg+xml",
							LogotypeHash: []hashAlgAndValue{
								{
									HashAlg:   pkix.AlgorithmIdentifier{Algorithm: sha256OID},
									HashValue: make([]byte, 32),
								},
							},
							LogotypeURI: uriSeq,
						},
					},
				},
			},
		},
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	_, err = DecodeLogotypeExtn(der)
	if err == nil {
		t.Fatal("expected error for too many URIs")
	}
	if !strings.Contains(err.Error(), "9 URIs") || !strings.Contains(err.Error(), "max 8") {
		t.Errorf("error should mention URI count limit, got: %v", err)
	}
}

func TestDecodeLogotypeExtn_ExceedsHashCap(t *testing.T) {
	// Build a LogotypeImage with 5 hashes (exceeds maxHashesPerImage = 4)
	hashes := make([]hashAlgAndValue, 5)
	for i := range hashes {
		hashes[i] = hashAlgAndValue{
			HashAlg:   pkix.AlgorithmIdentifier{Algorithm: sha256OID},
			HashValue: make([]byte, 32),
		}
	}
	uriSeq, err := encodeIA5StringSeq([]string{"https://example.com/logo.svg"})
	if err != nil {
		t.Fatalf("encodeIA5StringSeq: %v", err)
	}
	ext := logotypeExtn{
		SubjectLogo: logotypeInfoDirect{
			Data: logotypeData{
				Image: []logotypeImage{
					{
						ImageDetails: logotypeDetails{
							MediaType:    "image/svg+xml",
							LogotypeHash: hashes,
							LogotypeURI:  uriSeq,
						},
					},
				},
			},
		},
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	_, err = DecodeLogotypeExtn(der)
	if err == nil {
		t.Fatal("expected error for too many hashes")
	}
	if !strings.Contains(err.Error(), "5 hashes") || !strings.Contains(err.Error(), "max 4") {
		t.Errorf("error should mention hash count limit, got: %v", err)
	}
}

func TestClassifyMarkCert(t *testing.T) {
	if got := classifyMarkCert(nil); got != markCertOther {
		t.Errorf("nil cert: got %s want %s", got, markCertOther)
	}
	// Build minimal *x509.Certificate stand-ins via the public field.
	// classifyMarkCert only reads UnknownExtKeyUsage so we don't need a
	// fully-formed cert here.
	cVMC := certWithUnknownEKU(vmcEKUOID)
	if got := classifyMarkCert(cVMC); got != markCertVMC {
		t.Errorf("VMC cert: got %s want %s", got, markCertVMC)
	}
	cCMC := certWithUnknownEKU(cmcEKUOID)
	if got := classifyMarkCert(cCMC); got != markCertCMC {
		t.Errorf("CMC cert: got %s want %s", got, markCertCMC)
	}
	cBoth := certWithUnknownEKU(vmcEKUOID, cmcEKUOID)
	if got := classifyMarkCert(cBoth); got != markCertVMC {
		t.Errorf("both EKUs: got %s want %s (VMC takes precedence)", got, markCertVMC)
	}
	cOther := certWithUnknownEKU(asn1.ObjectIdentifier{1, 2, 3, 4})
	if got := classifyMarkCert(cOther); got != markCertOther {
		t.Errorf("unrelated EKU: got %s want %s", got, markCertOther)
	}
}
