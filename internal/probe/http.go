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
	Body       []byte // capped at 1 MiB
	TLSState   *tls.ConnectionState
	RedirectCh []*url.URL // each URL in the chain, including the final
	// CertChainError is non-nil when the served chain is incomplete or invalid
	// against the system trust store, captured BEFORE InsecureSkipVerify lets us
	// continue. Always nil when we connect over plain HTTP.
	CertChainError error
}

func NewHTTP(timeout time.Duration) *HTTP {
	h := &HTTP{timeout: timeout}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Reasonable security baseline; checks will inspect TLSState
			// to score the actual server posture against Mozilla profiles.
			MinVersion: tls.VersionTLS10,
		},
		// Force a fresh handshake per request — keeps per-host state easy to reason about.
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 0,
		}).DialContext,
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
			return nil
		},
	}
	return h
}

const maxBodyBytes = 1 << 20 // 1 MiB

// Get fetches u and returns the response. Records the redirect chain. On
// TLS errors caused by an incomplete chain, retries once with verification
// disabled so the caller can still inspect the served leaf.
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
		chain = append(chain, req.URL)
		return nil
	}

	resp, chainErr := h.fetch(ctx, &cli, u)
	if chainErr != nil {
		// Chain validation failed — try again with verification off so we
		// can still inspect what the server served. Record the original
		// error in Response.CertChainError.
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
			insecureChain = append(insecureChain, req.URL)
			return nil
		}
		resp2, _ := h.fetch(ctx, &insecureCli, u)
		if resp2 != nil {
			resp2.RedirectCh = insecureChain
			resp2.CertChainError = chainErr
			return resp2, nil
		}
		return nil, chainErr
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
	req.Header.Set("User-Agent", "granite-scan/0.1 (+https://example.invalid/)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	r, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))

	out := &Response{
		Status:  r.StatusCode,
		URL:     r.Request.URL,
		Headers: r.Header,
		Body:    body,
	}
	if r.TLS != nil {
		ts := *r.TLS
		out.TLSState = &ts
	}
	return out, nil
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
