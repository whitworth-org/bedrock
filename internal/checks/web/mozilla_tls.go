package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// mozillaTLSConfig is the embedded Mozilla server-side TLS profile JSON.
// Source: https://github.com/mozilla/server-side-tls/blob/gh-pages/json/server-side-tls-conf-5.0.json
//
// Embedding (rather than fetching at runtime) makes scans reproducible and
// works offline. Refresh the file when Mozilla publishes a new version, then
// bump expectedVersion below.
//
// Mozilla v5.0 ships three profiles: "modern", "intermediate", "old".
// Post-quantum is not yet a published Mozilla profile; when it lands upstream
// we add it here without code changes (just refresh the JSON and add the key
// to the expected profile set).
//
//go:embed mozilla-server-side-tls-5.0.json
var mozillaTLSJSON []byte

const expectedMozillaVersion = 5.0

type mozillaProfile struct {
	OpenSSLCiphers             []string `json:"openssl_ciphers"`
	OpenSSLCipherSuites        []string `json:"openssl_ciphersuites"`
	TLSVersions                []string `json:"tls_versions"`
	TLSCurves                  []string `json:"tls_curves"`
	CertificateTypes           []string `json:"certificate_types"`
	CertificateCurves          []string `json:"certificate_curves"`
	CertificateSignatures      []string `json:"certificate_signatures"`
	RSAKeySize                 int      `json:"rsa_key_size"`
	DHParamSize                *int     `json:"dh_param_size"`
	ECDHParamSize              int      `json:"ecdh_param_size"`
	HSTSMinAge                 int      `json:"hsts_min_age"`
	OldestClients              []string `json:"oldest_clients"`
	OCSPStaple                 bool     `json:"ocsp_staple"`
	ServerPreferredOrder       bool     `json:"server_preferred_order"`
	MaximumCertificateLifespan int      `json:"maximum_certificate_lifespan"`
}

type mozillaConfig struct {
	Href           string                    `json:"href"`
	Configurations map[string]mozillaProfile `json:"configurations"`
	Version        float64                   `json:"version"`
}

// loadMozillaTLS parses the embedded Mozilla TLS profile JSON.
// Errors are wrapped with context for easier debugging when the JSON
// is refreshed and its shape changes.
func loadMozillaTLS() (*mozillaConfig, error) {
	var c mozillaConfig
	if err := json.Unmarshal(mozillaTLSJSON, &c); err != nil {
		return nil, fmt.Errorf("parse mozilla tls json: %w", err)
	}
	if c.Version != expectedMozillaVersion {
		return nil, fmt.Errorf("mozilla tls json version %.1f, expected %.1f — update expectedMozillaVersion", c.Version, expectedMozillaVersion)
	}
	for _, name := range []string{"modern", "intermediate", "old"} {
		if _, ok := c.Configurations[name]; !ok {
			return nil, fmt.Errorf("mozilla tls json missing required profile %q", name)
		}
	}
	return &c, nil
}
