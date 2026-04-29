package tlsfp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

// computeJA4S follows the FoxIO JA4S specification (BSD-3-Clause):
// https://github.com/FoxIO-LLC/ja4 — `technical_details/JA4S.md`.
//
// Format:
//
//	JA4S = <proto><ver><nn><alpn>_<cipher>_<exthash>
//
//	proto    : "t" for TCP, "q" for QUIC. We only emit "t" — QUIC fingerprinting
//	           would require capturing Initial-packet TLS frames, out of scope here.
//	ver      : 2-char negotiated TLS version code (e.g. "13", "12", "11", "10",
//	           "s3"). Computed from stdlib state.Version, NOT from the wire
//	           legacy_version field — TLS 1.3 ServerHellos lock that to 0x0303
//	           and the real version lives in the supported_versions extension.
//	nn       : 2-digit decimal, zero-padded, count of extensions in the
//	           cleartext ServerHello.
//	alpn     : first + last byte of negotiated ALPN identifier, lowercase.
//	           "00" if no ALPN was selected. ALPN bytes are ASCII per RFC 7301.
//	cipher   : 4-char lowercase hex of the chosen cipher_suite.
//	exthash  : SHA-256 hex digest of the comma-joined 4-char-hex extension
//	           type list (in observed order), truncated to 12 chars. If the
//	           extension list is empty the hash field is the literal "000000000000".
//
// Extensions are NOT sorted. Servers don't shuffle their ServerHello
// extension order, so observed order is itself a stable fingerprint signal.
func computeJA4S(negotiatedVersion, cipher uint16, exts []uint16, alpn string) string {
	const proto = "t"
	ver := ja4VersionCode(negotiatedVersion)
	nn := fmt.Sprintf("%02d", len(exts))
	if len(exts) > 99 {
		// Spec uses a 2-digit field; cap visually rather than overflow it.
		nn = "99"
	}
	af := alpnFirstLast(alpn)
	cipherHex := fmt.Sprintf("%04x", cipher)

	var extHash string
	if len(exts) == 0 {
		extHash = "000000000000"
	} else {
		hexParts := make([]string, len(exts))
		for i, e := range exts {
			hexParts[i] = fmt.Sprintf("%04x", e)
		}
		sum := sha256.Sum256([]byte(strings.Join(hexParts, ",")))
		extHash = hex.EncodeToString(sum[:])[:12]
	}

	return proto + ver + nn + af + "_" + cipherHex + "_" + extHash
}

func ja4VersionCode(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	default:
		// Unknown version — emit hex so the value round-trips losslessly.
		return fmt.Sprintf("%04x", v)
	}
}

// alpnFirstLast returns the JA4S ALPN field. RFC 7301 ALPN identifiers are
// ASCII; we lowercase so fingerprints comparing case-different identifiers
// (extremely rare in practice) still match. Multi-byte names use byte-level
// first/last, which is what the FoxIO spec stipulates.
func alpnFirstLast(alpn string) string {
	if alpn == "" {
		return "00"
	}
	first := alpn[0]
	last := alpn[len(alpn)-1]
	return strings.ToLower(string([]byte{first, last}))
}
