package tlsfp

import (
	"encoding/binary"
	"testing"
)

// buildServerHello assembles a synthetic, well-formed ServerHello record
// suitable for parser tests. Random bytes are zeroed for reproducibility.
func buildServerHello(t *testing.T, legacyVer, cipher uint16, sessionID []byte, exts []uint16) []byte {
	t.Helper()
	if len(sessionID) > 32 {
		t.Fatalf("session id too long: %d", len(sessionID))
	}
	// ServerHello body
	body := make([]byte, 0, 64+len(sessionID)+4*len(exts))
	body = binary.BigEndian.AppendUint16(body, legacyVer)
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, byte(len(sessionID)))          // session id length
	body = append(body, sessionID...)                  // session id
	body = binary.BigEndian.AppendUint16(body, cipher) // cipher_suite
	body = append(body, 0)                             // compression null
	extsBuf := make([]byte, 0, 4*len(exts))
	for _, e := range exts {
		extsBuf = binary.BigEndian.AppendUint16(extsBuf, e)
		extsBuf = binary.BigEndian.AppendUint16(extsBuf, 0) // zero-length data
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extsBuf)))
	body = append(body, extsBuf...)
	// Handshake header: type=2, uint24 length
	hsLen := len(body)
	hs := []byte{handshakeServerHello, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	hs = append(hs, body...)
	// Record header: type=22, version=0x0303, uint16 length
	rec := []byte{recordTypeHandshake, 0x03, 0x03}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func TestParseServerHelloHappyPath(t *testing.T) {
	// TLS 1.2 ServerHello with three extensions: extended_master_secret (0x0017),
	// session_ticket (0x0023), ec_point_formats (0x000b).
	raw := buildServerHello(t, 0x0303, 0xc02f, nil, []uint16{0x0017, 0x0023, 0x000b})
	sh, err := parseServerHello(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sh.legacyVersion != 0x0303 {
		t.Errorf("legacyVersion = 0x%04x, want 0x0303", sh.legacyVersion)
	}
	if sh.cipher != 0xc02f {
		t.Errorf("cipher = 0x%04x, want 0xc02f", sh.cipher)
	}
	want := []uint16{0x0017, 0x0023, 0x000b}
	if len(sh.extensions) != len(want) {
		t.Fatalf("extensions len = %d, want %d", len(sh.extensions), len(want))
	}
	for i, e := range want {
		if sh.extensions[i] != e {
			t.Errorf("extensions[%d] = 0x%04x, want 0x%04x", i, sh.extensions[i], e)
		}
	}
}

func TestParseServerHelloNoExtensions(t *testing.T) {
	raw := buildServerHello(t, 0x0303, 0x009c, nil, nil)
	sh, err := parseServerHello(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sh.extensions) != 0 {
		t.Errorf("extensions should be empty, got %v", sh.extensions)
	}
}

func TestParseServerHelloWithSessionID(t *testing.T) {
	sid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	raw := buildServerHello(t, 0x0303, 0x1301, sid, []uint16{0x002b, 0x0033})
	sh, err := parseServerHello(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sh.cipher != 0x1301 {
		t.Errorf("cipher = 0x%04x, want 0x1301", sh.cipher)
	}
	if len(sh.extensions) != 2 {
		t.Errorf("extensions len = %d, want 2", len(sh.extensions))
	}
}

func TestParseServerHelloBoundsErrors(t *testing.T) {
	t.Parallel()
	good := buildServerHello(t, 0x0303, 0xc02f, nil, []uint16{0x0017})

	cases := []struct {
		name string
		mut  func([]byte) []byte
		want string // substring of expected error
	}{
		{
			name: "empty",
			mut:  func(_ []byte) []byte { return nil },
			want: "short record header",
		},
		{
			name: "wrong record type",
			mut:  func(b []byte) []byte { c := append([]byte(nil), b...); c[0] = 23; return c },
			want: "want handshake",
		},
		{
			name: "wrong handshake type",
			mut: func(b []byte) []byte {
				c := append([]byte(nil), b...)
				c[5] = 1 // ClientHello, not ServerHello
				return c
			},
			want: "want ServerHello",
		},
		{
			name: "truncated record body",
			mut:  func(b []byte) []byte { return b[:8] },
			want: "exceeds captured bytes",
		},
		{
			name: "session_id length too large",
			mut: func(b []byte) []byte {
				c := append([]byte(nil), b...)
				// session_id length lives at offset 5+4+2+32 = 43
				c[43] = 33
				return c
			},
			want: "session_id length 33",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := tc.mut(append([]byte(nil), good...))
			_, err := parseServerHello(input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
