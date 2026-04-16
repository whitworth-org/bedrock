package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

// maxConcurrentDials caps how many TLS handshakes we run in parallel
// across the discovered host set. Eight is a deliberate compromise: it
// keeps wall-clock latency reasonable for large enumerations while
// avoiding fan-out that could trip rate limits on shared infrastructure.
const maxConcurrentDials = 8

// probeHosts runs a per-host TLS reachability + cert validation check
// against every discovered subdomain. Each host produces exactly one
// "subdomain.tls.<host>" result (Pass / Warn / Fail). Concurrency is
// bounded by maxConcurrentDials.
//
// We deliberately do NOT re-run the full WWW check suite here — that would
// duplicate work and risk diverging from the apex/www results. The caller
// can wire deeper checks later by reading probe.CacheKeySubdomains.
func probeHosts(ctx context.Context, env *probe.Env, hosts []string) []report.Result {
	if len(hosts) == 0 {
		return nil
	}

	sem := make(chan struct{}, maxConcurrentDials)
	var (
		mu  sync.Mutex
		out []report.Result
		wg  sync.WaitGroup
	)

	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			res := tlsReachResult(ctx, host, env.Timeout)
			mu.Lock()
			out = append(out, res)
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	// Stable order so reports are deterministic across runs.
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// tlsReachResult is the per-host TLS check. It does:
//  1. a strict-verify handshake on :443 with ServerName=host;
//  2. if that succeeds, a chain verification against the system root pool;
//  3. a leaf SAN match via x509.Certificate.VerifyHostname.
//
// Each failure mode produces a Fail with a specific evidence string and a
// concrete remediation. A successful handshake whose cert chain validates
// and SAN matches is a Pass.
func tlsReachResult(ctx context.Context, host string, timeout time.Duration) report.Result {
	id := "subdomain.tls." + host
	r := report.Result{
		ID:       id,
		Category: category,
		Title:    "TLS reachability + cert (" + host + ")",
		RFCRefs:  []string{"RFC 5280 §6", "RFC 6125 §6.4"},
	}

	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, "443")
	d := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		// A dial / handshake failure is reported as Warn rather than Fail
		// because not every discovered host is necessarily a live HTTPS
		// origin (an A record may exist for mail or other services). The
		// finding is still actionable evidence for the operator.
		r.Status = report.Warn
		r.Evidence = "TLS dial failed: " + err.Error()
		r.Remediation = "if " + host + " is intended to serve HTTPS, ensure the listener is reachable on :443 and presents a valid certificate"
		return r
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	if dctx.Err() != nil {
		r.Status = report.Warn
		r.Evidence = "context deadline during handshake"
		return r
	}

	if len(state.PeerCertificates) == 0 {
		r.Status = report.Fail
		r.Evidence = "TLS handshake completed but no peer certificate was presented"
		r.Remediation = "configure the HTTPS listener on " + host + " to present a leaf certificate"
		return r
	}

	leaf := state.PeerCertificates[0]

	// Independent chain verification: net/http would have failed during the
	// dial above if the chain was bad (we set MinVersion only, not
	// InsecureSkipVerify), but an explicit check produces a clean error
	// string and decouples us from any future Go default changes.
	if err := verifyChain(&state, host); err != nil {
		r.Status = report.Fail
		r.Evidence = "chain validation failed: " + err.Error()
		r.Remediation = "serve the full intermediate chain from your CA at " + host
		return r
	}

	// SAN / hostname match — use the leaf directly so the error message
	// names the specific DNSNames that did not match.
	if err := leaf.VerifyHostname(host); err != nil {
		r.Status = report.Fail
		r.Evidence = "SAN mismatch: " + err.Error()
		r.Remediation = "issue a certificate whose SAN list includes " + host
		return r
	}

	r.Status = report.Pass
	r.Evidence = fmt.Sprintf("TLS %s, leaf valid through %s", tlsVersionName(state.Version), leaf.NotAfter.Format(time.RFC3339))
	return r
}

// verifyChain mirrors probe.VerifyChain but is duplicated here intentionally
// to keep the discover package self-contained and avoid widening the probe
// package's public surface for a single consumer.
func verifyChain(state *tls.ConnectionState, dnsName string) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificates")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("load system roots: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	leaf := state.PeerCertificates[0]
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       dnsName,
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err
}

// tlsVersionName mirrors web.tlsVersionName so the discover package does not
// import internal/checks/web (which would create a cycle once that package
// grows additional consumers of this one).
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
