package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dohMaxResponse is the hard cap on bytes we read from a DoH endpoint. DNS
// messages over UDP/TCP are bounded by 64 KiB, and DoH carries DNS wire
// format inside an HTTP body, so 64 KiB + 1 sentinel byte is enough to
// detect oversized responses without reading unbounded attacker data.
const dohMaxResponse = 1 << 16

// dohExchange implements RFC 8484 DNS-over-HTTPS for a single upstream.
// The pattern is: pack the dns.Msg as wire format, POST to the URL with
// Content-Type: application/dns-message, parse the response body as wire.
//
// We use POST rather than GET so we don't have to URL-encode large messages
// (DNSSEC + NSEC3 responses can exceed practical GET length limits).
//
// Defences:
//   - response Content-Type must begin with application/dns-message (case
//     insensitive); otherwise fail closed so an HTML captive portal or a
//     JSON DoH variant cannot smuggle a parse path.
//   - response body is bounded by dohMaxResponse; oversize is a hard error.
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
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/dns-message") {
		return nil, fmt.Errorf("doh unexpected content-type %q (want application/dns-message)", ct)
	}
	// Read one byte past the cap so we can distinguish "exactly at cap" from
	// "cap hit and more bytes were on the wire".
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}
	if len(body) > dohMaxResponse {
		return nil, fmt.Errorf("doh response exceeds 64 KiB cap")
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack doh response: %w", err)
	}
	return out, nil
}

// newDoHClient returns a dedicated HTTP client for DoH. We give it the same
// per-operation timeout as DNS so a stalled DoH endpoint doesn't outlive
// the rest of the scan. The dialer is the same SSRF-safe dialer used by
// the regular HTTP client; resolver endpoints are public by definition.
func newDoHClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
			DialContext:         safeDialContext(timeout, false),
		},
	}
}
