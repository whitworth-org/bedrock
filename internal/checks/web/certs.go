package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runCert inspects the leaf certificate served on the apex's HTTPS port:
// chain validity, hostname match (SAN), expiry, key strength, signature
// algorithm, and lifespan vs the embedded profile's MaximumCertificateLifespan.
func runCert(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.cert.chain", Category: category,
			Title:    "Certificate hygiene",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"RFC 5280"},
		}}
	}
	state := getCachedTLSState(env)
	if state == nil {
		// Cache miss: tlsCheck runs in parallel with us (checks in a category
		// are unordered), so we can lose the race for its cached handshake — or
		// its handshake failed outright. Materialize the state with a direct
		// TLS handshake to the target, NOT env.HTTP.Get: Get follows redirects,
		// so a legitimate cross-host redirect (e.g. apex -> www.other-brand.example)
		// would hand us the redirect target's certificate to validate against
		// env.Target — a bogus SAN/chain failure. The direct dial inspects the
		// cert env.Target actually serves, even if it fails verification
		// (probe.VerifyChain does the real check below).
		s, err := dialCertState(ctx, net.JoinHostPort(env.Target, "443"), env.Target, env.Timeout)
		if err != nil || s == nil {
			ev := "could not retrieve TLS state for cert inspection"
			if err != nil {
				ev += ": " + err.Error()
			}
			return []report.Result{{
				ID: "web.cert.chain", Category: category,
				Title:       "Certificate chain",
				Status:      report.Fail,
				Evidence:    ev,
				Remediation: "ensure HTTPS listener is reachable on " + env.Target,
				RFCRefs:     []string{"RFC 5280"},
			}}
		}
		state = s
	}

	// Verify the chain explicitly with VerifyChain so we can report a clean
	// error string even when net/http accepted the connection (SystemCertPool
	// may include intermediates net/http silently fixed up).
	chainErr := probe.VerifyChain(state, env.Target)
	out := []report.Result{chainResult(chainErr)}
	out = append(out, inspectLeaf(env.Target, state)...)
	return out
}

// dialCertState performs a direct TLS handshake to addr (using serverName for
// SNI) and returns the connection state, so certificate hygiene is judged
// against the certificate the target host itself serves. It deliberately
// speaks no HTTP: a redirect must never divert cert inspection to a different
// host's certificate (the cross-host-redirect false positive). Verification is
// skipped so a broken, expired, or wrong-host certificate is still captured
// for reporting — probe.VerifyChain performs the real chain/hostname check.
// The TLS 1.0 floor mirrors probe.HTTP's degraded-path retry so certs on
// legacy servers stay inspectable; the low version is flagged by the
// TLS-profile check, not here.
func dialCertState(ctx context.Context, addr, serverName string, timeout time.Duration) (*tls.ConnectionState, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS10,
			//nolint:gosec // G402: an auditor must capture the served cert even when it fails verification, so cert hygiene can be reported; probe.VerifyChain does the real chain/hostname check against env.Target.
			InsecureSkipVerify: true,
		},
	}
	conn, err := dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("dial %s: unexpected non-TLS connection", addr)
	}
	state := tlsConn.ConnectionState()
	return &state, nil
}

func chainResult(err error) report.Result {
	r := report.Result{
		ID: "web.cert.chain", Category: category,
		Title:   "Certificate chain validates against system roots",
		RFCRefs: []string{"RFC 5280 §6"},
	}
	if err == nil {
		r.Status = report.Pass
		r.Evidence = "leaf + intermediates chain to a trusted root"
		return r
	}
	r.Status = report.Fail
	r.Evidence = "chain validation failed: " + err.Error()
	r.Remediation = "serve the full intermediate chain from your CA (e.g. 'fullchain.pem' from Let's Encrypt)"
	return r
}

// inspectLeaf produces hygiene results for the served leaf cert independent
// of chain validation. Always returns a stable set of result IDs so callers
// can rely on them appearing in the report.
func inspectLeaf(host string, state *tls.ConnectionState) []report.Result {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()

	out := []report.Result{
		hostnameMatchResult(host, leaf),
		expiryResult(leaf, now),
		keyStrengthResult(leaf),
		signatureResult(leaf),
		lifespanResult(leaf),
	}
	return out
}

func hostnameMatchResult(host string, leaf *x509.Certificate) report.Result {
	r := report.Result{
		ID: "web.cert.san", Category: category,
		Title:   "Leaf SAN matches host",
		RFCRefs: []string{"RFC 6125 §6.4"},
	}
	if err := leaf.VerifyHostname(host); err != nil {
		r.Status = report.Fail
		r.Evidence = err.Error()
		r.Remediation = "issue a certificate whose SAN list includes " + host
		return r
	}
	r.Status = report.Pass
	r.Evidence = "SAN: " + strings.Join(leaf.DNSNames, ", ")
	return r
}

func expiryResult(leaf *x509.Certificate, now time.Time) report.Result {
	r := report.Result{
		ID: "web.cert.expiry", Category: category,
		Title:   "Certificate not expiring within 30 days",
		RFCRefs: []string{"RFC 5280 §4.1.2.5"},
	}
	until := leaf.NotAfter.Sub(now)
	days := int(until.Hours() / 24)
	if until <= 0 {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf("certificate expired %d days ago (%s)", -days, leaf.NotAfter.Format(time.RFC3339))
		r.Remediation = "renew the TLS certificate"
		return r
	}
	if days < 30 {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf("certificate expires in %d days (%s)", days, leaf.NotAfter.Format(time.RFC3339))
		r.Remediation = "renew the TLS certificate now (auto-renew via certbot/acme.sh)"
		return r
	}
	r.Status = report.Pass
	r.Evidence = fmt.Sprintf("expires in %d days (%s)", days, leaf.NotAfter.Format(time.RFC3339))
	return r
}

func keyStrengthResult(leaf *x509.Certificate) report.Result {
	r := report.Result{
		ID: "web.cert.key", Category: category,
		Title:   "Certificate key strength meets baseline",
		RFCRefs: []string{"RFC 7525 §4.3"},
	}
	bits, kind := leafKeyInfo(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
	switch kind {
	case "rsa":
		if bits < 2048 {
			r.Status = report.Fail
			r.Evidence = fmt.Sprintf("RSA %d bits (< 2048)", bits)
			r.Remediation = "reissue with a 2048-bit (or larger) RSA key, or switch to ECDSA P-256"
			return r
		}
		r.Status = report.Pass
		r.Evidence = fmt.Sprintf("RSA %d bits", bits)
	case "ecdsa":
		if bits < 256 {
			r.Status = report.Fail
			r.Evidence = fmt.Sprintf("EC %d bits (< P-256)", bits)
			r.Remediation = "reissue with an ECDSA P-256 (or stronger) key"
			return r
		}
		r.Status = report.Pass
		r.Evidence = fmt.Sprintf("EC %d bits", bits)
	case "ed25519":
		r.Status = report.Pass
		r.Evidence = "Ed25519"
	default:
		r.Status = report.Warn
		r.Evidence = "unrecognized key type: " + kind
	}
	return r
}

func signatureResult(leaf *x509.Certificate) report.Result {
	r := report.Result{
		ID: "web.cert.sig", Category: category,
		Title:   "Certificate signature algorithm is not SHA-1",
		RFCRefs: []string{"RFC 6194"},
	}
	alg := leaf.SignatureAlgorithm.String()
	if strings.Contains(strings.ToLower(alg), "sha1") || leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 || leaf.SignatureAlgorithm == x509.DSAWithSHA1 {
		r.Status = report.Fail
		r.Evidence = "signature algorithm: " + alg
		r.Remediation = "reissue the certificate using SHA-256 or stronger"
		return r
	}
	r.Status = report.Pass
	r.Evidence = "signature algorithm: " + alg
	return r
}

// lifespanResult compares the cert's lifespan against the embedded TLS
// profile's MaximumCertificateLifespan. Anything above the "intermediate"
// max (730 days as of v5) is a Fail.
func lifespanResult(leaf *x509.Certificate) report.Result {
	r := report.Result{
		ID: "web.cert.lifespan", Category: category,
		Title:   "Certificate lifespan within profile recommendation",
		RFCRefs: []string{"RFC 5280 §4.1.2.5"},
	}
	cfg, err := loadTLSProfiles()
	if err != nil {
		r.Status = report.Info
		r.Evidence = "could not load TLS profiles: " + err.Error()
		return r
	}
	maxAllowed := cfg.Configurations["intermediate"].MaximumCertificateLifespan
	lifespanDays := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	if lifespanDays > maxAllowed {
		r.Status = report.Fail
		r.Evidence = fmt.Sprintf("lifespan %d days exceeds intermediate-profile max %d days", lifespanDays, maxAllowed)
		r.Remediation = fmt.Sprintf("issue certificates with a lifespan ≤ %d days", maxAllowed)
		return r
	}
	r.Status = report.Pass
	r.Evidence = fmt.Sprintf("lifespan %d days (≤ %d allowed)", lifespanDays, maxAllowed)
	return r
}

// getCachedTLSState pulls the cached *tls.ConnectionState (set by tlsCheck)
// or returns nil if not present / wrong type.
func getCachedTLSState(env *probe.Env) *tls.ConnectionState {
	v, ok := env.CacheGet(probe.CacheKeyTLSCxn)
	if !ok {
		return nil
	}
	state, ok := v.(*tls.ConnectionState)
	if !ok {
		return nil
	}
	return state
}
