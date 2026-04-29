package tlsfp

import (
	"crypto/md5" //nolint:gosec // verifying the JA3S construction; see ja3s.go.
	"encoding/hex"
	"regexp"
	"testing"
)

var ja3sHex = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestComputeJA3SShape(t *testing.T) {
	t.Parallel()
	hash, raw := computeJA3S(0x0303, 0xc02f, []uint16{0x0017, 0x0023, 0x000b})
	if !ja3sHex.MatchString(hash) {
		t.Errorf("JA3S hash %q is not 32 lowercase hex chars", hash)
	}
	want := "771,49199,23-35-11"
	if raw != want {
		t.Errorf("JA3S raw = %q, want %q", raw, want)
	}
}

func TestComputeJA3SAgainstIndependentMD5(t *testing.T) {
	t.Parallel()
	// Independent MD5 over the documented input must equal computeJA3S.
	// This verifies we are computing what the spec describes — a single MD5
	// over the literal CSV string with no length-prefix or salt.
	cases := []struct {
		ver    uint16
		cipher uint16
		exts   []uint16
		raw    string
	}{
		{0x0303, 0xc02f, []uint16{0x0017, 0x0023, 0x000b}, "771,49199,23-35-11"},
		{0x0303, 0x1301, nil, "771,4865,"},
		{0x0303, 0x009c, []uint16{0x0017}, "771,156,23"},
	}
	for _, tc := range cases {
		gotHash, gotRaw := computeJA3S(tc.ver, tc.cipher, tc.exts)
		if gotRaw != tc.raw {
			t.Errorf("raw = %q, want %q", gotRaw, tc.raw)
		}
		sum := md5.Sum([]byte(tc.raw)) //nolint:gosec
		want := hex.EncodeToString(sum[:])
		if gotHash != want {
			t.Errorf("hash = %q, want %q (raw=%q)", gotHash, want, tc.raw)
		}
	}
}

func TestComputeJA3SDeterministic(t *testing.T) {
	t.Parallel()
	a, _ := computeJA3S(0x0303, 0xc02f, []uint16{0x0017, 0x0023})
	b, _ := computeJA3S(0x0303, 0xc02f, []uint16{0x0017, 0x0023})
	if a != b {
		t.Errorf("JA3S not deterministic: %q != %q", a, b)
	}
}

func TestComputeJA3SOrderSensitive(t *testing.T) {
	t.Parallel()
	a, _ := computeJA3S(0x0303, 0xc02f, []uint16{0x0017, 0x0023})
	b, _ := computeJA3S(0x0303, 0xc02f, []uint16{0x0023, 0x0017})
	if a == b {
		t.Errorf("JA3S should be order-sensitive but produced same hash for different orderings")
	}
}
