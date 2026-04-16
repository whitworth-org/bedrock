package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

// tlsCheck scores the negotiated TLS posture of the apex (and www) host
// against the embedded modern → intermediate → old profile cascade. RFC 7525
// (BCP 195) is the floor; the embedded profiles are the target ceiling.
type tlsCheck struct{}

func (tlsCheck) ID() string       { return "web.tls.profile" }
func (tlsCheck) Category() string { return category }

func (tlsCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.tls.profile", Category: category,
			Title:    "TLS profile",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 7525"},
		}}
	}

	cfg, err := loadTLSProfiles()
	if err != nil {
		return []report.Result{{
			ID: "web.tls.profile", Category: category,
			Title:       "TLS profile",
			Status:      report.Fail,
			Evidence:    "failed to load embedded TLS profile JSON: " + err.Error(),
			Remediation: "rebuild bedrock with a refreshed tls-profiles-v5.json",
			RFCRefs:     []string{"RFC 7525"},
		}}
	}

	hosts := candidateHosts(ctx, env)
	if len(hosts) == 0 {
		return []report.Result{{
			ID: "web.tls.profile", Category: category,
			Title:    "TLS profile",
			Status:   report.NotApplicable,
			Evidence: "no A/AAAA records for apex or www",
			RFCRefs:  []string{"RFC 7525"},
		}}
	}

	var out []report.Result
	for i, host := range hosts {
		state, err := dialTLSPriority(ctx, host, env.Timeout)
		if err != nil {
			out = append(out, report.Result{
				ID: "web.tls.profile." + host, Category: category,
				Title:       "TLS handshake (" + host + ")",
				Status:      report.Fail,
				Evidence:    "TLS handshake failed: " + err.Error(),
				Remediation: "ensure HTTPS listener is reachable and presents a valid certificate at " + host,
				RFCRefs:     []string{"RFC 7525 §3.1"},
			})
			continue
		}
		// Cache the first state so other checks (cert hygiene, HSTS context)
		// can reuse it without an extra handshake.
		if i == 0 {
			env.CachePut(probe.CacheKeyTLSCxn, state)
		}
		out = append(out, scoreTLSAgainstProfiles(host, state, cfg)...)
	}
	return out
}

// candidateHosts returns the hostnames to probe — apex always, plus www if
// it has any A/AAAA. We swallow DNS errors here and let downstream checks
// surface them; this routine is just choosing what to dial.
func candidateHosts(ctx context.Context, env *probe.Env) []string {
	hosts := []string{env.Target}
	www := "www." + env.Target
	dctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	a, _ := env.DNS.LookupA(dctx, www)
	aaaa, _ := env.DNS.LookupAAAA(dctx, www)
	if len(a)+len(aaaa) > 0 {
		hosts = append(hosts, www)
	}
	return hosts
}

// dialTLSPriority attempts handshakes in priority order: TLS 1.3 first, then
// TLS 1.2. We negotiate the highest version the server is willing to do so
// the scoring sees the server's preferred posture, not whatever floor we set.
func dialTLSPriority(ctx context.Context, host string, timeout time.Duration) (*tls.ConnectionState, error) {
	addr := net.JoinHostPort(host, "443")
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &net.Dialer{Timeout: timeout}
	// First try with a TLS 1.2 floor — Go will negotiate the highest mutually
	// supported version (typically 1.3). If that handshake fails we retry
	// against a TLS 1.0/1.1 floor so we can still SCORE legacy servers
	// (they get a Fail downstream, but we want evidence rather than a bare
	// dial error).
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err == nil {
		state := conn.ConnectionState()
		_ = conn.Close()
		return &state, nil
	}
	if dctx.Err() != nil {
		return nil, dctx.Err()
	}
	cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10}
	conn, err2 := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err2 == nil {
		state := conn.ConnectionState()
		_ = conn.Close()
		return &state, nil
	}
	return nil, fmt.Errorf("tls dial: %w (legacy retry: %v)", err, err2)
}

// scoreTLSAgainstProfiles picks the highest profile the negotiated state
// satisfies. Returns a primary result for the matched profile plus an
// auxiliary result for the negotiated TLS version.
func scoreTLSAgainstProfiles(host string, state *tls.ConnectionState, cfg *tlsProfileConfig) []report.Result {
	versionName := tlsVersionName(state.Version)
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	openSSLCipher := opensslCipherName(cipherName)

	leafKeySize, leafKeyKind := leafKeyInfo(state)

	matched := ""
	for _, name := range []string{"modern", "intermediate", "old"} {
		p := cfg.Configurations[name]
		if !profileAccepts(p, state.Version, cipherName, openSSLCipher, leafKeyKind, leafKeySize) {
			continue
		}
		matched = name
		break
	}

	versionRes := report.Result{
		ID: "web.tls.version." + host, Category: category,
		Title:    "TLS version (" + host + ")",
		Evidence: fmt.Sprintf("negotiated %s, cipher %s", versionName, cipherName),
		RFCRefs:  []string{"RFC 7525 §3.1.1"},
	}
	switch state.Version {
	case tls.VersionTLS13, tls.VersionTLS12:
		versionRes.Status = report.Pass
	default:
		versionRes.Status = report.Fail
		versionRes.Remediation = "disable TLS 1.0/1.1; enable TLS 1.2 and 1.3 only"
	}

	if matched == "" {
		return []report.Result{
			{
				ID: "web.tls.profile." + host, Category: category,
				Title:  "TLS profile — " + host,
				Status: report.Fail,
				Evidence: fmt.Sprintf(
					"server posture (version=%s cipher=%s key=%s/%d) does not meet the 'old' profile",
					versionName, cipherName, leafKeyKind, leafKeySize,
				),
				Remediation: "raise to at least the 'intermediate' profile: TLS 1.2+, AEAD ciphers (ECDHE-*-AES-GCM, ChaCha20-Poly1305), RSA ≥ 2048 / ECDSA ≥ P-256",
				RFCRefs:     []string{"RFC 7525"},
			},
			versionRes,
		}
	}

	status := report.Pass
	if matched == "old" {
		// "Old" is below recommended baseline — flag as Warn, not Pass.
		status = report.Warn
	}
	return []report.Result{
		{
			ID: "web.tls.profile." + host, Category: category,
			Title:    "TLS profile — " + host,
			Status:   status,
			Evidence: fmt.Sprintf("matched %q profile (%s, %s, key=%s/%d)", matched, versionName, cipherName, leafKeyKind, leafKeySize),
			RFCRefs:  []string{"RFC 7525"},
		},
		versionRes,
	}
}

// profileAccepts is the conjunction of all profile constraints we can verify
// from a Go ConnectionState. Curve and signature-algorithm checks are
// intentionally narrow (see comments) — when a constraint is undecidable
// from stdlib state we skip it rather than fail-closed.
func profileAccepts(p tlsProfile, version uint16, goCipher, opensslCipher, keyKind string, keyBits int) bool {
	// Version must be in the profile's tls_versions.
	wantVersion := tlsVersionName(version)
	if !contains(p.TLSVersions, wantVersion) {
		return false
	}
	// Cipher: profile's openssl_ciphers + openssl_ciphersuites combined must
	// list either the OpenSSL form or, as a last resort, the Go form. Some
	// ciphers (notably TLS 1.3 suites) use the same name in both.
	allowedCiphers := append([]string{}, p.OpenSSLCiphers...)
	allowedCiphers = append(allowedCiphers, p.OpenSSLCipherSuites...)
	if !contains(allowedCiphers, opensslCipher) && !contains(allowedCiphers, goCipher) {
		return false
	}
	// Key strength: RSA must meet rsa_key_size; EC must meet ecdh_param_size.
	switch keyKind {
	case "rsa":
		if keyBits < p.RSAKeySize {
			return false
		}
	case "ecdsa":
		if keyBits < p.ECDHParamSize {
			return false
		}
	}
	return true
}

// tlsVersionName maps Go's tls.VersionTLS* constants to the profile JSON's strings.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// opensslCipherName converts a Go cipher constant name (e.g.
// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") to the OpenSSL form
// ("ECDHE-RSA-AES128-GCM-SHA256"). TLS 1.3 suites already share names, so
// we return them unchanged.
//
// This is a partial mapping — covers the suites the embedded profile JSON
// lists in modern/intermediate/old. Anything else returns the input unchanged;
// callers that don't find a match treat it as "doesn't satisfy the profile"
// rather than crashing. See cipherMap below for the full set.
func opensslCipherName(goName string) string {
	if v, ok := cipherMap[goName]; ok {
		return v
	}
	// TLS 1.3 suite names are identical in OpenSSL and Go.
	if strings.HasPrefix(goName, "TLS_AES_") || strings.HasPrefix(goName, "TLS_CHACHA20_") {
		return goName
	}
	return goName
}

// cipherMap maps Go's TLS cipher-suite constant names to OpenSSL names.
// Only suites referenced by the embedded modern/intermediate/old profiles
// need to be present; anything else is treated as not-in-profile.
var cipherMap = map[string]string{
	// ECDHE-ECDSA / ECDHE-RSA AES-GCM (AEAD)
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   "ECDHE-RSA-AES128-GCM-SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   "ECDHE-RSA-AES256-GCM-SHA384",
	// ChaCha20-Poly1305
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   "ECDHE-RSA-CHACHA20-POLY1305",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":        "ECDHE-ECDSA-CHACHA20-POLY1305",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":          "ECDHE-RSA-CHACHA20-POLY1305",
	// CBC suites (only present in the "old" profile)
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": "ECDHE-ECDSA-AES128-SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   "ECDHE-RSA-AES128-SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    "ECDHE-ECDSA-AES128-SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      "ECDHE-RSA-AES128-SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    "ECDHE-ECDSA-AES256-SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      "ECDHE-RSA-AES256-SHA",
	// Static-RSA (very old; "old" profile only)
	"TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
	"TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
	"TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA":    "AES128-SHA",
	"TLS_RSA_WITH_AES_256_CBC_SHA":    "AES256-SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":   "DES-CBC3-SHA",
}

// leafKeyInfo extracts the leaf certificate's public-key kind and bit length.
// "rsa" returns modulus bit size; "ecdsa" returns curve bit size; unknown
// returns ("unknown", 0). Used by both the profile scoring and the cert
// strength check.
func leafKeyInfo(state *tls.ConnectionState) (bits int, kind string) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return 0, "unknown"
	}
	leaf := state.PeerCertificates[0]
	switch pk := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return pk.N.BitLen(), "rsa"
	case *ecdsa.PublicKey:
		return pk.Curve.Params().BitSize, "ecdsa"
	}
	return 0, certKeyKindFromAlg(leaf.PublicKeyAlgorithm)
}

func certKeyKindFromAlg(a x509.PublicKeyAlgorithm) string {
	switch a {
	case x509.RSA:
		return "rsa"
	case x509.ECDSA:
		return "ecdsa"
	case x509.Ed25519:
		return "ed25519"
	}
	return "unknown"
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// errNoTLSState is returned when a downstream check needs the cached TLS
// state but the upstream tlsCheck didn't capture one (e.g. handshake failed).
// Documented gap: Go's tls.ConnectionState does not expose the negotiated
// curve (RFC 8446 §4.2.7), so tls_curves constraints from the embedded profiles
// are not enforced — they are reported as Info evidence only.
var errNoTLSState = errors.New("no cached TLS state")
