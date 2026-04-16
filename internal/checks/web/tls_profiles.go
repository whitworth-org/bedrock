package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// tlsProfilesJSON is the embedded TLS profile dataset.
//
// Embedding (rather than fetching at runtime) makes scans reproducible and
// works offline. Refresh the file when a new version is published, then bump
// expectedProfilesVersion below.
//
// v5 ships three profiles: "modern", "intermediate", "old". Post-quantum
// is forward-looking; when added, refresh the JSON and add the key to the
// expected profile set in loadTLSProfiles.
//
//go:embed tls-profiles-v5.json
var tlsProfilesJSON []byte

const expectedProfilesVersion = 5.0

type tlsProfile struct {
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

type tlsProfileConfig struct {
	Configurations map[string]tlsProfile `json:"configurations"`
	Version        float64               `json:"version"`
}

// loadTLSProfiles parses the embedded TLS profile JSON.
// Errors are wrapped with context for easier debugging when the JSON is
// refreshed and its shape changes.
func loadTLSProfiles() (*tlsProfileConfig, error) {
	var c tlsProfileConfig
	if err := json.Unmarshal(tlsProfilesJSON, &c); err != nil {
		return nil, fmt.Errorf("parse tls profiles json: %w", err)
	}
	if c.Version != expectedProfilesVersion {
		return nil, fmt.Errorf("tls profiles json version %.1f, expected %.1f — update expectedProfilesVersion", c.Version, expectedProfilesVersion)
	}
	for _, name := range []string{"modern", "intermediate", "old"} {
		if _, ok := c.Configurations[name]; !ok {
			return nil, fmt.Errorf("tls profiles json missing required profile %q", name)
		}
	}
	return &c, nil
}
