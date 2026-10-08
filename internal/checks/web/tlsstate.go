package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// tlsStatePort is the port hostTLS dials; only tests change it.
var tlsStatePort = "443"

// tlsRoots is the trust store hostTLS verifies served chains against; nil
// means the system roots. Only tests set it.
var tlsRoots *x509.CertPool

// tlsHandshake is the outcome of the one TLS handshake per host that the
// TLS profile, certificate, OCSP, CRL and CT checks share. Exactly one of
// err and state is set.
type tlsHandshake struct {
	err   error
	state *tls.ConnectionState
	// verifyErr is the result of verifying the served chain for the host
	// against tlsRoots, and chains holds the chains that verification
	// built. The handshake itself skips verification, so
	// state.VerifiedChains is always empty: read the issuer from chains.
	verifyErr error
	chains    [][]*x509.Certificate
}

// hostTLS returns the TLS handshake with host shared by every check in the
// scan, performing it on first use. Because the handshake skips
// certificate verification, a server with a broken chain is still profiled
// and its certificate still inspected; only web.cert.* grades the chain.
func hostTLS(ctx context.Context, env *probe.Env, host string) *tlsHandshake {
	h := probe.Shared(env, tlsStateKey(host), func() *tlsHandshake {
		return handshakeTLS(ctx, env, host)
	})
	if h == nil {
		return &tlsHandshake{err: fmt.Errorf("TLS handshake with %s %w", host,
			checkutil.ErrSharedProbePanicked)}
	}
	return h
}

func tlsStateKey(host string) string { return probe.CacheKeyTLSCxn + ":" + host }

// handshakeTLS dials host through the SSRF denylist and completes one TLS
// handshake, allowing TLS 1.0 so that legacy servers are profiled too, then
// verifies the served chain separately.
func handshakeTLS(ctx context.Context, env *probe.Env, host string) *tlsHandshake {
	hctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	addr := net.JoinHostPort(host, tlsStatePort)
	raw, err := probe.SafeDial(hctx, "tcp", addr, env.Timeout)
	if err != nil {
		return &tlsHandshake{err: fmt.Errorf("TLS handshake with %s failed: %w", addr, err)}
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS10,
		// Nothing received is trusted before verifyServedChain below,
		// whose result web.cert.chain grades and which alone supplies
		// the issuer to the revocation and CT checks.
		InsecureSkipVerify: true, //nolint:gosec // G402: verified separately; see above
	})
	defer func() { _ = conn.Close() }()
	if err := conn.HandshakeContext(hctx); err != nil {
		return &tlsHandshake{err: fmt.Errorf("TLS handshake with %s failed: %w", addr, err)}
	}
	state := conn.ConnectionState()
	h := &tlsHandshake{state: &state}
	h.chains, h.verifyErr = verifyServedChain(&state, host)
	return h
}

// verifyServedChain verifies the leaf the server presented for host against
// tlsRoots, with the other certificates it presented as intermediates, and
// returns the chains that verification built.
func verifyServedChain(state *tls.ConnectionState, host string) ([][]*x509.Certificate, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("the server presented no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	return state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         tlsRoots,
		Intermediates: intermediates,
	})
}

// verifiedIssuer returns the certificate that issued the leaf in the first
// verified chain, or nil when the chain did not verify or the leaf is itself
// a trust anchor. The server chooses the order of the certificates it
// presents, so it can put a self-made "issuer" right after the leaf (and the
// real one after that) to vouch for a forged staple or CRL; only
// verification establishes the issuer.
func (h *tlsHandshake) verifiedIssuer() *x509.Certificate {
	if len(h.chains) == 0 || len(h.chains[0]) < 2 {
		return nil
	}
	return h.chains[0][1]
}

// handshakeFailed grades fail, a check's result for a failed handshake with
// its status and any remediation set, after the shared handshake ended in
// err: Inconclusive when the probe could not complete, otherwise fail with
// err as its evidence.
func handshakeFailed(ctx context.Context, fail report.Result, err error) report.Result {
	if checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(fail, err)
	}
	fail.Evidence = err.Error()
	return fail
}
