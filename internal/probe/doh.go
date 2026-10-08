package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
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
//   - redirects are not followed (see newDoHClient), so a 3xx fails with its
//     status instead of moving the query to another server or to plaintext.
//   - response Content-Type must be application/dns-message (parameters are
//     ignored); otherwise fail closed so an HTML captive portal or a JSON
//     DoH variant cannot smuggle a parse path.
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
	// A present but empty Idempotency-Key marks the POST as safe to resend
	// without sending the header, so net/http retries a query that met a
	// kept-alive connection the server had just closed instead of failing
	// with EOF. A DNS query has no side effects.
	req.Header["Idempotency-Key"] = nil

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !isDNSMessage(ct) {
		return nil, fmt.Errorf("doh unexpected content-type %q (want application/dns-message)", ct)
	}
	// Read one byte past the cap so we can distinguish "exactly at cap" from
	// "cap hit and more bytes were on the wire".
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", scrubResolverError(err))
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

// isDNSMessage reports whether the Content-Type value ct names exactly
// application/dns-message. Parameters are ignored, including malformed ones.
func isDNSMessage(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter) {
		return false
	}
	return mediaType == "application/dns-message"
}

// newDoHClient returns a dedicated HTTP client for DoH. We give it the same
// per-operation timeout as DNS so a stalled DoH endpoint doesn't outlive
// the rest of the scan. Connections are kept alive between queries, and
// closed after 30s idle, so a scan's queries share one handshake. Redirects
// are not followed. The dialer is the same SSRF-safe dialer used by the
// regular HTTP client; resolver endpoints are public by definition.
func newDoHClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:      true,
			IdleConnTimeout:        30 * time.Second,
			TLSHandshakeTimeout:    timeout,
			MaxResponseHeaderBytes: MaxResponseHeaderBytes,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return SafeDial(ctx, network, addr, timeout)
			},
		},
	}
}
