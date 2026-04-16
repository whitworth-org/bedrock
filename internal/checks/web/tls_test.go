package web

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLSv1",
		tls.VersionTLS11: "TLSv1.1",
		tls.VersionTLS12: "TLSv1.2",
		tls.VersionTLS13: "TLSv1.3",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(%v) = %q, want %q", v, got, want)
		}
	}
}

func TestOpenSSLCipherName(t *testing.T) {
	cases := map[string]string{
		// Mapped suites
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       "ECDHE-RSA-AES128-GCM-SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":     "ECDHE-ECDSA-AES256-GCM-SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
		// TLS 1.3 — pass through unchanged
		"TLS_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
		"TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
		// Unknown — pass through
		"TLS_FOO_BAR_BAZ": "TLS_FOO_BAR_BAZ",
	}
	for in, want := range cases {
		if got := opensslCipherName(in); got != want {
			t.Errorf("opensslCipherName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileAccepts_Modern(t *testing.T) {
	cfg, err := loadTLSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	modern := cfg.Configurations["modern"]
	// TLS 1.3 + TLS_AES_128_GCM_SHA256 + ECDSA P-256 → matches modern.
	if !profileAccepts(modern, tls.VersionTLS13, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "ecdsa", 256) {
		t.Errorf("modern profile rejected TLS1.3 / AES128-GCM / EC256")
	}
	// TLS 1.2 must NOT match modern.
	if profileAccepts(modern, tls.VersionTLS12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "rsa", 2048) {
		t.Errorf("modern profile accepted TLS 1.2 (should be 1.3 only)")
	}
	// RSA key < 2048 must fail.
	if profileAccepts(modern, tls.VersionTLS13, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "rsa", 1024) {
		t.Errorf("modern profile accepted RSA 1024")
	}
}

func TestProfileAccepts_Intermediate(t *testing.T) {
	cfg, err := loadTLSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	inter := cfg.Configurations["intermediate"]
	// TLS 1.2 + ECDHE-RSA-AES128-GCM-SHA256 + RSA 2048 → matches.
	if !profileAccepts(inter, tls.VersionTLS12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "rsa", 2048) {
		t.Errorf("intermediate rejected TLS1.2/ECDHE-RSA-AES128-GCM/RSA2048")
	}
	// TLS 1.0 must not match.
	if profileAccepts(inter, tls.VersionTLS10, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "rsa", 2048) {
		t.Errorf("intermediate accepted TLS 1.0")
	}
}

func TestProfileAccepts_OldAcceptsLegacy(t *testing.T) {
	cfg, err := loadTLSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	old := cfg.Configurations["old"]
	// TLS 1.0 + AES128-SHA + RSA 2048 → matches old.
	if !profileAccepts(old, tls.VersionTLS10, "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA", "rsa", 2048) {
		t.Errorf("old rejected TLS1.0/AES128-SHA/RSA2048 — should accept")
	}
}
