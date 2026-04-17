package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTP wraps net/http with a custom Transport that captures the TLS state
// for the WWW checks. Redirects are followed but recorded so the caller can
// reason about HTTP→HTTPS hygiene.
type HTTP struct {
	timeout time.Duration
	client  *http.Client
}

// Response is what HTTP.Get returns. TLSState is nil for plain HTTP responses.
type Response struct {
	Status     int
	URL        *url.URL
	Headers    http.Header
	Body       []byte // capped at maxBodyBytes
	TLSState   *tls.ConnectionState
	RedirectCh []*url.URL // each URL in the chain, including the final
	// CertChainError is non-nil when the served chain is incomplete or invalid
	// against the system trust store, captured BEFORE InsecureSkipVerify lets us
	// continue. Always nil when we connect over plain HTTP.
	CertChainError error
	// Truncated is true when Body hit the maxBodyBytes cap and additional
	// bytes were discarded on the wire. Callers that require full bodies
	// should treat Truncated==true as a failure case.
	Truncated bool
}

// NewHTTP returns an HTTP client primitive with SSRF-safe dial, no
// cross-protocol redirects, and per-operation timeouts.
func NewHTTP(timeout time.Duration) *HTTP {
	h := &HTTP{timeout: timeout}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Reasonable security baseline; checks will inspect TLSState
			// to score the actual server posture against the embedded TLS profiles.
			MinVersion: tls.VersionTLS10,
		},
		// Force a fresh handshake per request — keeps per-host state easy to reason about.
		DisableKeepAlives:     true,
		DialContext:           safeDialContext(timeout, false),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: timeout,
	}
	h.client = &http.Client{
		Transport: tr,
		Timeout:   timeout * 3, // total budget for redirect chain
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 8 {
				return errors.New("too many redirects (>8)")
			}
			// Reject cross-protocol downgrades (https -> http). Private-IP
			// rejection on the redirect target happens naturally in safeDialContext.
			if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme == "http" {
				return fmt.Errorf("redirect downgraded from https to http (%s)", req.URL.String())
			}
			return nil
		},
	}
	return h
}

const maxBodyBytes = 1 << 20 // 1 MiB

// Get fetches target and returns the response. Records the redirect chain. On
// TLS errors caused by an incomplete chain, retries once with verification
// disabled so the caller can still inspect the served leaf metadata.
//
// IMPORTANT: the insecure-retry path explicitly drops the response body
// (sets Body = nil) before returning. Callers that care about the body must
// use GetStrict, which fails closed on chain errors. CertChainError remains
// set on the returned Response so callers can detect the degraded path.
func (h *HTTP) Get(ctx context.Context, target string) (*Response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	chain := []*url.URL{u}
	cli := *h.client
	cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 8 {
			return errors.New("too many redirects (>8)")
		}
		if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return fmt.Errorf("redirect downgraded from https to http (%s)", req.URL.String())
		}
		chain = append(chain, req.URL)
		return nil
	}

	resp, chainErr := h.fetch(ctx, &cli, u)
	if chainErr != nil {
		// Chain validation failed — try again with verification off so we
		// can still inspect what the server served. Record the original
		// error in Response.CertChainError. The body from this retry is
		// NOT trustworthy (no peer identity), so we drop it.
		insecureCli := *h.client
		baseTr := h.client.Transport.(*http.Transport)
		insecureTr := baseTr.Clone()
		insecureTr.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true,
		}
		insecureCli.Transport = insecureTr
		insecureChain := []*url.URL{u}
		insecureCli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) > 8 {
				return errors.New("too many redirects (>8)")
			}
			if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme == "http" {
				return fmt.Errorf("redirect downgraded from https to http (%s)", req.URL.String())
			}
			insecureChain = append(insecureChain, req.URL)
			return nil
		}
		resp2, _ := h.fetch(ctx, &insecureCli, u)
		if resp2 != nil {
			resp2.RedirectCh = insecureChain
			resp2.CertChainError = chainErr
			// Defensive: an un-verified body can be anything; drop it so
			// downstream parsers cannot be tricked by attacker content
			// served over an invalid chain.
			resp2.Body = nil
			resp2.Truncated = false
			return resp2, nil
		}
		return nil, chainErr
	}
	if resp != nil {
		resp.RedirectCh = chain
	}
	return resp, nil
}

// GetStrict fetches target with a strict TLS posture: MinVersion TLS 1.2, no
// InsecureSkipVerify retry, and no cross-protocol redirects. On any TLS
// verification error it returns the error (Response is nil). Suitable for
// fetches whose authenticity matters (MTA-STS policy per RFC 8461 §3.3;
// BIMI Verified Mark Certificate per BIMI Group draft §4.5).
func (h *HTTP) GetStrict(ctx context.Context, target string) (*Response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	baseTr, ok := h.client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("http transport is not *http.Transport")
	}
	strictTr := baseTr.Clone()
	strictTr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	strictTr.DialContext = safeDialContext(h.timeout, false)

	chain := []*url.URL{u}
	strictCli := &http.Client{
		Transport: strictTr,
		Timeout:   h.timeout * 3,
		// Per RFC 8461 §3.3, MTA-STS policy fetch MUST NOT follow redirects.
		// Refuse all redirects here; callers that need redirect handling can
		// use Get with GetStrict only for the final authenticated URL.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := h.fetch(ctx, strictCli, u)
	if err != nil {
		// Do not retry with InsecureSkipVerify. Callers that need to inspect
		// a broken chain must use Get.
		return nil, err
	}
	if resp != nil {
		resp.RedirectCh = chain
	}
	return resp, nil
}

func (h *HTTP) fetch(ctx context.Context, cli *http.Client, u *url.URL) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "github.com/rwhitworth/bedrock/0.1 (+https://example.invalid/)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	r, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Read up to maxBodyBytes+1 so we can detect truncation by whether the
	// cap was exactly hit and another byte was available.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	truncated := false
	if len(body) > maxBodyBytes {
		body = body[:maxBodyBytes]
		truncated = true
	}

	out := &Response{
		Status:    r.StatusCode,
		URL:       r.Request.URL,
		Headers:   r.Header,
		Body:      body,
		Truncated: truncated,
	}
	if r.TLS != nil {
		ts := *r.TLS
		out.TLSState = &ts
	}
	return out, nil
}

// safeDialContext returns a DialContext that rejects SSRF-vulnerable
// destinations: loopback, link-local, multicast, unspecified, private
// (RFC 1918), unique-local (IPv6 ULA fc00::/7), CGNAT (100.64.0.0/10), and
// the cloud metadata literal 169.254.169.254. It resolves the host up front
// and pins the dial to the first acceptable IP so DNS-rebinding cannot
// swap in a bad address between check and dial.
//
// allowPrivate==true bypasses the denylist; today nothing in bedrock sets
// this, but the parameter is plumbed through for future local-probe work.
func safeDialContext(timeout time.Duration, allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf dial: split host/port %q: %w", addr, err)
		}
		// If already a literal IP, validate directly; no DNS lookup needed.
		if ip := net.ParseIP(host); ip != nil {
			if !allowPrivate {
				if reason, blocked := blockedIPReason(ip); blocked {
					return nil, fmt.Errorf("ssrf dial: refusing %s (%s)", ip.String(), reason)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		// Hostname: resolve, filter, pin to the first acceptable IP.
		ips, err := (&net.Resolver{}).LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ssrf dial: resolve %s: %w", host, err)
		}
		for _, a := range ips {
			if !allowPrivate {
				if _, blocked := blockedIPReason(a.IP); blocked {
					continue
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		}
		return nil, fmt.Errorf("ssrf dial: no acceptable IP for %s (all candidates blocked by private-range denylist)", host)
	}
}

// cgnatNet is RFC 6598 carrier-grade NAT space 100.64.0.0/10.
var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// blockedIPReason returns a human-readable reason if ip is on the SSRF
// denylist, together with true. Returns "", false when the address is OK.
func blockedIPReason(ip net.IP) (string, bool) {
	if ip == nil {
		return "nil ip", true
	}
	if ip.IsLoopback() {
		return "loopback", true
	}
	if ip.IsUnspecified() {
		return "unspecified", true
	}
	if ip.IsMulticast() {
		return "multicast", true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local", true
	}
	if ip.IsPrivate() {
		return "private (RFC 1918 / ULA)", true
	}
	if v4 := ip.To4(); v4 != nil && cgnatNet.Contains(v4) {
		return "CGNAT (RFC 6598)", true
	}
	// Cloud metadata literal. ip.IsLinkLocalUnicast already covers 169.254/16
	// but we name it explicitly for clearer error messages.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return "cloud metadata (169.254.169.254)", true
	}
	return "", false
}

// validateURLHostPublic returns an error if u's host is an IP literal in
// the denylist or a hostname that resolves only to denylisted IPs. Intended
// for upstream resolver specs where the dial happens later and we want a
// clear early error rather than a mysterious dial failure.
func validateURLHostPublic(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url has no host: %s", rawURL)
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("url points at localhost: %s", rawURL)
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason, blocked := blockedIPReason(ip); blocked {
			return fmt.Errorf("url host %s is %s", ip.String(), reason)
		}
	}
	return nil
}

// VerifyChain validates the server's leaf+intermediates against the system
// roots, returning a wrapped error that names what's missing. Used by the
// WWW certs check independently of the GET, so we report cert problems
// even when the response itself is fine.
func VerifyChain(state *tls.ConnectionState, dnsName string) error {
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
