// Package tlsfp computes JA3S and JA4S TLS fingerprints from cleartext
// ServerHello bytes captured during a stdlib crypto/tls handshake.
//
// The fingerprints are observational — they describe what the target server
// returned, not whether it is correct or secure. JA3S is the legacy MD5
// fingerprint (Salesforce, 2017); JA4S is the FoxIO replacement that is
// human-readable and namespaces protocol/version/extension-count separately.
//
// All parsing is native: no third-party TLS, fingerprint, or hashing
// dependencies. The parser walks RFC 5246 §7.4.1.3 / RFC 8446 §4.1.3 byte
// layouts directly and is bounds-checked at every step.
//
// Capture is the entry point. Pass any net.Conn-yielding Dialer (typically
// probe.SafeDialContext for SSRF protection) and a host/port; the function
// performs a stdlib TLS handshake, captures the first wire record (always a
// cleartext ServerHello in both TLS 1.2 and 1.3), and returns the parsed
// metadata plus the two computed fingerprints.
package tlsfp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Result is the parsed and computed fingerprint payload for one host:port.
// Extension types are recorded in the order the server emitted them; we do
// not sort. JA4SExt is the SHA-256 hex prefix that JA4S uses internally —
// surfaced so callers can audit the input to the hash.
type Result struct {
	Host          string
	Port          string
	NegotiatedTLS uint16 // tls.VersionTLS{10,11,12,13}, from stdlib state
	WireVersion   uint16 // legacy_version from the ServerHello wire (0x0303 for TLS 1.3)
	Cipher        uint16
	Extensions    []uint16 // ServerHello cleartext extension types, observed order
	ALPN          string   // negotiated ALPN, "" if none
	JA3S          string   // md5 hex (32 chars)
	JA3SString    string   // pre-hash CSV: "<wire_ver>,<cipher>,<ext1>-<ext2>-..."
	JA4S          string   // FoxIO format: t<ver><nn><af>_<cipher>_<ext_hash[:12]>
}

// Dialer is the function signature net.Dialer.DialContext satisfies. Capture
// uses this instead of constructing its own dialer so callers can inject
// SSRF-safe dialers (probe.SafeDialContext) without import cycles.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Capture performs a stdlib TLS handshake against host:port, captures the
// cleartext ServerHello, and returns the JA3S/JA4S fingerprints together
// with the negotiated TLS version, cipher, ALPN, and parsed extension list.
//
// The handshake config is intentionally permissive (TLS 1.0 floor, TLS 1.3
// ceiling, both common ALPNs offered, certificate verification off) because
// the goal is fingerprinting whatever the server is willing to negotiate,
// not authenticating it. Callers that need the connection for other purposes
// after fingerprinting should use a separate handshake.
func Capture(ctx context.Context, host, port string, dial Dialer, timeout time.Duration) (*Result, error) {
	if dial == nil {
		return nil, errors.New("tlsfp: nil dialer")
	}
	addr := net.JoinHostPort(host, port)

	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := dial(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tlsfp: dial %s: %w", addr, err)
	}
	rec := newRecordingConn(raw)

	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // intentional: fingerprinting, not authenticating
		NextProtos:         []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Client(rec, cfg)

	if deadline, ok := dctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tlsfp: handshake %s: %w", addr, err)
	}
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()

	sh, perr := parseServerHello(rec.received())
	out := &Result{
		Host:          host,
		Port:          port,
		NegotiatedTLS: state.Version,
		Cipher:        state.CipherSuite,
		ALPN:          state.NegotiatedProtocol,
	}
	if perr != nil {
		return out, fmt.Errorf("tlsfp: parse %s: %w", addr, perr)
	}
	out.WireVersion = sh.legacyVersion
	out.Extensions = sh.extensions
	// Sanity: the wire cipher must equal what stdlib reports. If it doesn't,
	// we captured the wrong record (e.g. handshake reordering on a custom
	// stack). Surface that as an error and return the partial result.
	if sh.cipher != state.CipherSuite {
		return out, fmt.Errorf(
			"tlsfp: parsed cipher 0x%04x does not match negotiated 0x%04x",
			sh.cipher, state.CipherSuite,
		)
	}

	out.JA3S, out.JA3SString = computeJA3S(out.WireVersion, out.Cipher, out.Extensions)
	out.JA4S = computeJA4S(out.NegotiatedTLS, out.Cipher, out.Extensions, out.ALPN)
	return out, nil
}

// recordingConn is a net.Conn wrapper that tees inbound bytes into an
// internal buffer so callers can recover the raw wire bytes after a stdlib
// TLS handshake completes. Outbound writes are passed through unchanged.
//
// The capture cap (16 KiB) is generous for any real ServerHello — typical
// TLS 1.2 ServerHello is < 1 KiB and TLS 1.3 ServerHello is < 200 bytes —
// while still bounding memory if the peer streams unrelated data.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

const recordingCap = 16 * 1024

func newRecordingConn(c net.Conn) *recordingConn { return &recordingConn{Conn: c} }

func (r *recordingConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		room := recordingCap - len(r.buf)
		if room > 0 {
			take := n
			if take > room {
				take = room
			}
			r.buf = append(r.buf, p[:take]...)
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingConn) received() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out
}
