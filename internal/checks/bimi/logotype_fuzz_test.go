package bimi

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// FuzzDecodeLogotypeExtn fuzzes the ASN.1 logotype extension decoder with
// arbitrary DER-encoded data. This tests the ASN.1 parsing, bounds checking,
// and validation logic for LogotypeExtn structures.
func FuzzDecodeLogotypeExtn(f *testing.F) {
	// Add seed corpus with valid logotype extensions
	hash := sha256.Sum256([]byte("<svg/>"))
	validDER := buildLogotypeExtnForFuzz("image/svg+xml", "https://example.com/logo.svg", sha256OID, hash[:])
	if validDER != nil {
		f.Add(validDER)
	}

	// Add some basic ASN.1 structures
	f.Add([]byte{0x30, 0x00})                               // Empty SEQUENCE
	f.Add([]byte{0x30, 0x02, 0x30, 0x00})                   // SEQUENCE containing empty SEQUENCE
	f.Add([]byte{0x04, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f}) // OCTET STRING "hello"

	// Add malformed DER
	f.Add([]byte{0x30, 0xff})                   // Invalid length
	f.Add([]byte{0x30, 0x05, 0x01, 0x02, 0x03}) // Truncated data

	f.Fuzz(func(t *testing.T, data []byte) {
		// Call the logotype decoder - it should never panic regardless of input
		_, _ = DecodeLogotypeExtn(data)
	})
}

// buildLogotypeExtn is a simplified version that doesn't require *testing.T
// for use in fuzzing. It builds a minimal valid logotype extension.
func buildLogotypeExtnForFuzz(mediaType, uri string, hashAlg asn1.ObjectIdentifier, hashValue []byte) []byte {
	uriSeq, err := encodeIA5StringSeq([]string{uri})
	if err != nil {
		return nil
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
		return nil
	}
	return der
}
