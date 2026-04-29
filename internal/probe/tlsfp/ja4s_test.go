package tlsfp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// FoxIO format: t<ver><nn><af>_<cipher>_<exthash>
var ja4sFmt = regexp.MustCompile(`^t([0-9a-z]{2})([0-9]{2})([0-9a-z]{2})_([0-9a-f]{4})_([0-9a-f]{12})$`)

func TestComputeJA4SShape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		version uint16
		cipher  uint16
		exts    []uint16
		alpn    string
	}{
		{"tls13_h2", tls.VersionTLS13, 0x1301, []uint16{0x002b, 0x0033}, "h2"},
		{"tls12_http11_three_exts", tls.VersionTLS12, 0xc02f, []uint16{0x0017, 0x0023, 0x000b}, "http/1.1"},
		{"tls12_no_alpn", tls.VersionTLS12, 0xc02f, []uint16{0x0017}, ""},
		{"tls10_no_exts", tls.VersionTLS10, 0x002f, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := computeJA4S(tc.version, tc.cipher, tc.exts, tc.alpn)
			if !ja4sFmt.MatchString(got) {
				t.Errorf("JA4S %q does not match expected shape", got)
			}
		})
	}
}

func TestComputeJA4SFields(t *testing.T) {
	t.Parallel()
	got := computeJA4S(tls.VersionTLS13, 0x1301, []uint16{0x002b, 0x0033}, "h2")
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 underscore-separated segments, got %d in %q", len(parts), got)
	}
	// Header: proto(t) + version(13) + nn(02) + alpn(h2) = "t1302h2"
	if parts[0] != "t1302h2" {
		t.Errorf("header segment = %q, want %q", parts[0], "t1302h2")
	}
	if parts[1] != "1301" {
		t.Errorf("cipher segment = %q, want %q", parts[1], "1301")
	}
	// Verify the extension hash matches an independent SHA-256 over the
	// canonical CSV ("002b,0033") truncated to 12 hex chars.
	csv := "002b,0033"
	sum := sha256.Sum256([]byte(csv))
	want := hex.EncodeToString(sum[:])[:12]
	if parts[2] != want {
		t.Errorf("ext hash = %q, want %q (csv=%q)", parts[2], want, csv)
	}
}

func TestComputeJA4SNoExtensionsLiteralHash(t *testing.T) {
	t.Parallel()
	got := computeJA4S(tls.VersionTLS12, 0x009c, nil, "")
	want := "t120000_009c_000000000000"
	if got != want {
		t.Errorf("JA4S = %q, want %q", got, want)
	}
}

func TestComputeJA4SAlpnFirstLast(t *testing.T) {
	t.Parallel()
	cases := []struct {
		alpn string
		want string
	}{
		{"", "00"},
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"H2", "h2"}, // lowercase normalisation
		{"acme-tls/1", "a1"},
	}
	for _, tc := range cases {
		got := alpnFirstLast(tc.alpn)
		if got != tc.want {
			t.Errorf("alpnFirstLast(%q) = %q, want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestComputeJA4SVersionCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS13, "13"},
		{tls.VersionTLS12, "12"},
		{tls.VersionTLS11, "11"},
		{tls.VersionTLS10, "10"},
		{0x0300, "s3"},
		{0xfafa, fmt.Sprintf("%04x", uint16(0xfafa))},
	}
	for _, tc := range cases {
		if got := ja4VersionCode(tc.v); got != tc.want {
			t.Errorf("ja4VersionCode(0x%04x) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestComputeJA4SOrderSensitive(t *testing.T) {
	t.Parallel()
	a := computeJA4S(tls.VersionTLS13, 0x1301, []uint16{0x002b, 0x0033}, "h2")
	b := computeJA4S(tls.VersionTLS13, 0x1301, []uint16{0x0033, 0x002b}, "h2")
	if a == b {
		t.Errorf("JA4S should differ for reordered extensions, both = %q", a)
	}
}
