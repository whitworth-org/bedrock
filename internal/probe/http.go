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
	"net/http/httptrace"
	"net/url"
	"slices"
	"sync/atomic"
	"time"

	"github.com/whitworth-org/bedrock/internal/version"
)

// HTTP wraps net/http with SSRF-safe transports that capture the TLS state
// for the WWW checks. Redirects are followed but recorded so the caller can
// reason about HTTP→HTTPS hygiene.
type HTTP struct {
	client     *http.Client // verified TLS; redirects per checkRedirect
	noRedirect *http.Client // client's transport; a 3xx is the response
	insecure   *http.Client // Get's diagnostic retry; see NewHTTP
}

// Response is what HTTP.Get returns. TLSState is nil for plain HTTP responses.
type Response struct {
	Status     int
	URL        *url.URL
	Headers    http.Header
	Body       []byte // capped at maxBodyBytes
	TLSState   *tls.ConnectionState
	RedirectCh []*url.URL // each URL in the chain, including the final
	// Truncated is true when Body hit the maxBodyBytes cap and additional
	// bytes were discarded on the wire. Callers that require full bodies
	// should treat Truncated==true as a failure case.
	Truncated bool
	// Verified is false only for a response from Get's diagnostic retry,
	// which skipped certificate verification after a failed TLS handshake:
	// its status, headers and TLSState are unauthenticated and its Body is
	// nil. Plain-HTTP responses are Verified; TLSState tells them apart.
	Verified bool
}

const (
	maxBodyBytes = 1 << 20 // 1 MiB

	// maxRedirects caps every redirect chain the clients follow.
	maxRedirects = 8

	// MaxResponseHeaderBytes caps the response headers every probe transport
	// accepts, far below net/http's 10 MiB default, because checks echo
	// headers into evidence.
	MaxResponseHeaderBytes = 256 << 10
)

// NewHTTP returns an HTTP client primitive with SSRF-safe dials, verified
// TLS 1.2+, bounded response headers and per-operation timeouts.
func NewHTTP(timeout time.Duration) *HTTP {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// TLS 1.2 floor for the verified fetch path: this client's responses
			// may be trusted (bodies are parsed), so it must meet the modern
			// baseline. Legacy servers stay inspectable — the WWW checks
			// handshake with them directly (see checks/web hostTLS), and Get's
			// degraded retry re-attempts with a relaxed, body-dropping config.
			MinVersion: tls.VersionTLS12,
		},
		// Every request gets its own connection, closed once the response is
		// read, so no idle connection outlives the call that opened it.
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return SafeDial(ctx, network, addr, timeout)
		},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
	}
	insecureTr := tr.Clone()
	// SECURITY: diagnostic-only, intentionally relaxed. We permit TLS 1.0 and
	// skip certificate verification on purpose to inspect legacy or
	// misconfigured servers after a verified handshake failed. Get discards
	// every body from this path and marks the response unverified; it must
	// never be used for trusted content retrieval.
	insecureTr.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}
	budget := 3 * timeout // total budget for a redirect chain
	return &HTTP{
		client: &http.Client{Transport: tr, Timeout: budget, CheckRedirect: checkRedirect},
		noRedirect: &http.Client{
			Transport: tr,
			Timeout:   budget,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		insecure: &http.Client{
			Transport:     insecureTr,
			Timeout:       budget,
			CheckRedirect: checkRedirect,
		},
	}
}

// NoRedirectClient returns a client that sends each request through rt and
// returns a redirect as the response instead of following it. rt must dial
// through the SSRF denylist, as an http3.Transport whose Dial is DialQUIC does.
func NoRedirectClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: rt,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkRedirect is the redirect policy of Get, its diagnostic retry, Do and
// DoStrict: at most maxRedirects hops, each compared with the hop before it,
// so an https-to-http downgrade is refused wherever it falls in the chain.
// Private-IP rejection on a redirect target happens in SafeDial.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("too many redirects (>%d)", maxRedirects)
	}
	if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
		return fmt.Errorf("redirect downgraded from https to http (%s)", req.URL.String())
	}
	return nil
}

// Get fetches target over verified TLS, following and recording redirects
// (see checkRedirect). When a TLS handshake fails (an untrusted or
// mismatched certificate, or a server limited to TLS 1.0/1.1) and ctx is
// still live, Get retries once with verification disabled so the caller can
// inspect what the server served. Any other failure is returned as is.
//
// IMPORTANT: a response from that retry has Verified false and a nil Body.
// Callers that care about the body or its authenticity must use GetStrict,
// which fails closed on chain errors.
func (h *HTTP) Get(ctx context.Context, target string) (*Response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	// The transport reports handshakes from its own dial goroutine.
	var handshakeFailed atomic.Bool
	traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				handshakeFailed.Store(true)
			}
		},
	})
	resp, err := h.fetch(traced, h.client, u, true)
	if err == nil || !handshakeFailed.Load() || ctx.Err() != nil {
		return resp, err
	}
	return h.diagnosticRetry(ctx, u, err)
}

// diagnosticRetry refetches u without certificate verification after the
// verified fetch failed a TLS handshake with verifyErr.
func (h *HTTP) diagnosticRetry(
	ctx context.Context, u *url.URL, verifyErr error,
) (*Response, error) {
	// An unverified body can be anything; it is closed unread so downstream
	// parsers cannot be tricked by attacker content served over an invalid
	// chain.
	resp, err := h.fetch(ctx, h.insecure, u, false)
	if err != nil {
		// verifyErr stays the primary (wrapped) error — it names the
		// validation failure callers care about — with the diagnostic
		// retry's failure appended instead of silently dropped.
		return nil, fmt.Errorf("%w (insecure diagnostic retry also failed: %v)", verifyErr, err)
	}
	resp.Verified = false
	return resp, nil
}

// GetStrict fetches target with a strict TLS posture: https only (any other
// scheme is refused before connecting), MinVersion TLS 1.2, no
// InsecureSkipVerify retry, and no redirects (a 3xx is the response). On any
// TLS verification error it returns the error (Response is nil). Suitable
// for fetches whose authenticity matters (MTA-STS policy per RFC 8461 §3.3,
// which forbids following redirects; BIMI Verified Mark Certificate per
// BIMI Group draft §4.5).
func (h *HTTP) GetStrict(ctx context.Context, target string) (*Response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if err := requireHTTPS(u); err != nil {
		return nil, err
	}
	return h.fetch(ctx, h.noRedirect, u, true)
}

// Do performs a custom HTTP request using the safe transport and Get's
// redirect policy, without Get's diagnostic retry. The request must have
// been created with a valid context. The URL must be absolute. For
// mixed-scheme endpoints (HTTP/HTTPS), use Do. For HTTPS-only endpoints, use
// DoStrict.
func (h *HTTP) Do(req *http.Request) (*Response, error) {
	return h.doWithClient(req, h.client, true)
}

// DoStrict is Do for HTTPS-only endpoints: a URL that is not https is
// refused before connecting, and because redirects to http are refused too,
// every hop is verified HTTPS with TLS 1.2+. The request must have been
// created with a valid context.
func (h *HTTP) DoStrict(req *http.Request) (*Response, error) {
	if err := requireHTTPS(req.URL); err != nil {
		return nil, err
	}
	return h.doWithClient(req, h.client, true)
}

// requireHTTPS refuses u unless it is an https URL.
func requireHTTPS(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("strict fetch requires an https URL, got scheme %q", u.Scheme)
	}
	return nil
}

// doWithClient sends req through cli. With readBody it reads the response
// body, up to maxBodyBytes; without, it closes the body unread and Body is
// nil.
func (h *HTTP) doWithClient(
	req *http.Request, cli *http.Client, readBody bool,
) (*Response, error) {
	//nolint:gosec // G704: This is the SSRF-safe HTTP client implementation itself
	r, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Body.Close() }()

	var body []byte
	if readBody {
		// Read up to maxBodyBytes+1 so we can detect truncation by whether the
		// cap was exactly hit and another byte was available.
		body, err = io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
	}
	truncated := false
	if len(body) > maxBodyBytes {
		body = body[:maxBodyBytes]
		truncated = true
	}

	out := &Response{
		Status:     r.StatusCode,
		URL:        r.Request.URL,
		Headers:    r.Header.Clone(),
		Body:       body,
		RedirectCh: redirectChain(r),
		Truncated:  truncated,
		Verified:   true,
	}
	if r.TLS != nil {
		ts := *r.TLS
		out.TLSState = &ts
	}
	return out, nil
}

// fetch GETs u through cli; readBody is as for doWithClient.
func (h *HTTP) fetch(
	ctx context.Context, cli *http.Client, u *url.URL, readBody bool,
) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return h.doWithClient(req, cli, readBody)
}

// redirectChain returns the URL of every request that led to r, oldest
// first. net/http links each redirected request to the response that
// caused it.
func redirectChain(r *http.Response) []*url.URL {
	var chain []*url.URL
	for req := r.Request; req != nil; {
		chain = append(chain, req.URL)
		if req.Response == nil {
			break
		}
		req = req.Response.Request
	}
	slices.Reverse(chain)
	return chain
}

// VerifyChain validates the server's leaf+intermediates against the system
// roots, returning a wrapped error that names what's missing. The discover
// package's HTTPS reachability probe uses it to grade the chain each
// discovered host serves.
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
