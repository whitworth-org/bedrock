package bimi

import (
	"testing"
)

// FuzzParseVMCChain fuzzes the PEM certificate chain parser with arbitrary
// PEM-encoded data. This tests PEM parsing, certificate validation, and the
// VMC-specific logic for extracting mark certificates.
func FuzzParseVMCChain(f *testing.F) {
	// Add seed corpus with basic PEM structures
	f.Add([]byte(`-----BEGIN CERTIFICATE-----
MIICnjCCAYYCAQAwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAwMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowEzERMA8GA1UEAwwIVGVzdCBDQSAwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890
-----END CERTIFICATE-----`))

	// Empty PEM
	f.Add([]byte(""))

	// Malformed PEM headers
	f.Add([]byte(`-----BEGIN CERTIFICATE-----
invalid-base64-content!@#$%
-----END CERTIFICATE-----`))

	// Multiple PEM blocks
	f.Add([]byte(`-----BEGIN CERTIFICATE-----
MIICnjCCAYYCAQAwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAwMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowEzERMA8GA1UEAwwIVGVzdCBDQSAwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICnjCCAYYCAQAwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAwMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowEzERMA8GA1UEAwwIVGVzdCBDQSAwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890
-----END CERTIFICATE-----`))

	// Wrong PEM type
	f.Add([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXNjc4OTAx
-----END PRIVATE KEY-----`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Call the VMC chain parser - it should never panic regardless of input
		_, _, _ = parsePEMChain(data)
	})
}
