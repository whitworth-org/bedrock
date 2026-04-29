package tlsfp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TLS record layer constants (RFC 5246 §6.2.1, RFC 8446 §5.1).
const (
	recordTypeHandshake  = 22
	handshakeServerHello = 2
	serverHelloRandom    = 32 // bytes
)

// serverHello is the subset of ServerHello fields we care about for
// fingerprinting. The session_id, random, and compression_method bytes are
// consumed by the parser but not retained.
type serverHello struct {
	legacyVersion uint16
	cipher        uint16
	extensions    []uint16
}

// parseServerHello extracts the ServerHello fields needed for JA3S/JA4S
// fingerprinting from raw — the bytes captured off the wire during a TLS
// handshake. raw must begin with a TLS record header whose fragment is a
// ServerHello handshake message; subsequent records are ignored. Both TLS
// 1.2 and TLS 1.3 ServerHellos are cleartext, so no key-derivation state is
// required.
//
// Every length field is bounds-checked before slicing. On any inconsistency
// the function returns a descriptive error instead of panicking.
func parseServerHello(raw []byte) (*serverHello, error) {
	// Record header: type(1) | legacy_record_version(2) | length(2)
	if len(raw) < 5 {
		return nil, errors.New("short record header")
	}
	if raw[0] != recordTypeHandshake {
		return nil, fmt.Errorf("first record type %d, want handshake (22)", raw[0])
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if 5+recLen > len(raw) {
		return nil, fmt.Errorf("record length %d exceeds captured bytes %d", recLen, len(raw)-5)
	}
	body := raw[5 : 5+recLen]

	// Handshake header: msg_type(1) | length(uint24)
	if len(body) < 4 {
		return nil, errors.New("short handshake header")
	}
	if body[0] != handshakeServerHello {
		return nil, fmt.Errorf("first handshake type %d, want ServerHello (2)", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		return nil, fmt.Errorf("handshake length %d exceeds record body %d", hsLen, len(body)-4)
	}
	sh := body[4 : 4+hsLen]

	// ServerHello fields (RFC 5246 §7.4.1.3 / RFC 8446 §4.1.3):
	//   ProtocolVersion legacy_version;       // 2 bytes
	//   Random random;                        // 32 bytes
	//   opaque legacy_session_id<0..32>;      // 1-byte len + data
	//   CipherSuite cipher_suite;             // 2 bytes
	//   uint8 legacy_compression_method;      // 1 byte
	//   Extension extensions<6..2^16-1>;      // 2-byte len + data (TLS 1.3 mandates extensions)
	const minFixed = 2 + serverHelloRandom + 1
	if len(sh) < minFixed {
		return nil, errors.New("short ServerHello fixed fields")
	}
	pos := 0
	legacyVer := binary.BigEndian.Uint16(sh[pos : pos+2])
	pos += 2
	pos += serverHelloRandom // skip random
	sidLen := int(sh[pos])
	pos++
	if sidLen > 32 {
		return nil, fmt.Errorf("session_id length %d exceeds 32", sidLen)
	}
	if pos+sidLen+2+1 > len(sh) {
		return nil, errors.New("short session_id/cipher/compression")
	}
	pos += sidLen
	cipher := binary.BigEndian.Uint16(sh[pos : pos+2])
	pos += 2
	pos++ // legacy_compression_method, always 0 in modern TLS

	// Extensions block. Optional in TLS 1.0/1.1, mandatory and non-empty in
	// TLS 1.3. If absent we return an empty list.
	if pos == len(sh) {
		return &serverHello{legacyVersion: legacyVer, cipher: cipher}, nil
	}
	if pos+2 > len(sh) {
		return nil, errors.New("short extensions length")
	}
	extsLen := int(binary.BigEndian.Uint16(sh[pos : pos+2]))
	pos += 2
	if pos+extsLen > len(sh) {
		return nil, fmt.Errorf("extensions length %d exceeds remainder %d", extsLen, len(sh)-pos)
	}
	exts := sh[pos : pos+extsLen]

	var types []uint16
	p := 0
	for p+4 <= len(exts) {
		t := binary.BigEndian.Uint16(exts[p : p+2])
		l := int(binary.BigEndian.Uint16(exts[p+2 : p+4]))
		if p+4+l > len(exts) {
			return nil, fmt.Errorf("extension 0x%04x data length %d exceeds remainder", t, l)
		}
		types = append(types, t)
		p += 4 + l
	}
	if p != len(exts) {
		return nil, fmt.Errorf("extension parse left %d trailing bytes", len(exts)-p)
	}
	return &serverHello{legacyVersion: legacyVer, cipher: cipher, extensions: types}, nil
}
