package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// dohExchange implements RFC 8484 DNS-over-HTTPS for a single upstream.
// The pattern is: pack the dns.Msg as wire format, POST to the URL with
// Content-Type: application/dns-message, parse the response body as wire.
//
// We use POST rather than GET so we don't have to URL-encode large messages
// (DNSSEC + NSEC3 responses can exceed practical GET length limits).
func dohExchange(ctx context.Context, client *http.Client, url string, m *dns.Msg) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack doh response: %w", err)
	}
	return out, nil
}

// newDoHClient returns a dedicated HTTP client for DoH. We give it the same
// per-operation timeout as DNS so a stalled DoH endpoint doesn't outlive
// the rest of the scan.
func newDoHClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
		},
	}
}
