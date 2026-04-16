package dnssec

import (
	"testing"

	mdns "github.com/miekg/dns"

	"bedrock/internal/report"
)

// Pin RFC 8624 §3.1 verdicts. Catches accidental loosening of the table.
func TestScoreDNSKEYAlgorithm(t *testing.T) {
	cases := []struct {
		name string
		alg  uint8
		want report.Status
	}{
		{"RSAMD5", mdns.RSAMD5, report.Fail},
		{"DSA", mdns.DSA, report.Fail},
		{"RSASHA1", mdns.RSASHA1, report.Fail},
		{"DSANSEC3SHA1", mdns.DSANSEC3SHA1, report.Fail},
		{"RSASHA1NSEC3SHA1", mdns.RSASHA1NSEC3SHA1, report.Fail},
		{"ECCGOST", mdns.ECCGOST, report.Fail},
		{"RSASHA256", mdns.RSASHA256, report.Pass},
		{"RSASHA512", mdns.RSASHA512, report.Pass},
		{"ECDSAP256SHA256", mdns.ECDSAP256SHA256, report.Pass},
		{"ECDSAP384SHA384", mdns.ECDSAP384SHA384, report.Pass},
		{"ED25519", mdns.ED25519, report.Pass},
		{"ED448", mdns.ED448, report.Pass},
		{"unknown", 99, report.Warn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreDNSKEYAlgorithm(c.alg)
			if got.Status != c.want {
				t.Fatalf("scoreDNSKEYAlgorithm(%s)=%s, want %s; evidence=%q",
					c.name, got.Status, c.want, got.Evidence)
			}
			if got.Evidence == "" {
				t.Fatalf("scoreDNSKEYAlgorithm(%s) returned empty evidence", c.name)
			}
		})
	}
}

// Pin RFC 8624 §3.3 verdicts. SHA-1 must be Fail; SHA-256 must be Pass.
func TestScoreDSDigest(t *testing.T) {
	cases := []struct {
		name string
		dt   uint8
		want report.Status
	}{
		{"SHA1", mdns.SHA1, report.Fail},
		{"GOST94", mdns.GOST94, report.Fail},
		{"SHA256", mdns.SHA256, report.Pass},
		{"SHA384", mdns.SHA384, report.Pass},
		{"unknown", 99, report.Warn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreDSDigest(c.dt)
			if got.Status != c.want {
				t.Fatalf("scoreDSDigest(%s)=%s, want %s; evidence=%q",
					c.name, got.Status, c.want, got.Evidence)
			}
			if got.Evidence == "" {
				t.Fatalf("scoreDSDigest(%s) returned empty evidence", c.name)
			}
		})
	}
}

// dedupeUint8 is straightforward but the rest of the package relies on its
// stable sort for deterministic evidence strings.
func TestDedupeUint8(t *testing.T) {
	in := []uint8{13, 8, 13, 8, 15}
	got := dedupeUint8(in)
	want := []uint8{8, 13, 15}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupeUint8 mismatch at %d: got %v, want %v", i, got, want)
		}
	}
}

// Spot-check the helper used to render evidence for the chain check.
func TestDsKeyTagsAndDnskeyKeyTags(t *testing.T) {
	dss := []*mdns.DS{{KeyTag: 1234, DigestType: mdns.SHA256}}
	if got := dsKeyTags(dss); got != "1234/SHA256" {
		t.Fatalf("dsKeyTags = %q", got)
	}
	keys := []*mdns.DNSKEY{
		{Hdr: mdns.RR_Header{Name: "example.com.", Class: mdns.ClassINET}, Flags: mdns.ZONE | mdns.SEP, Protocol: 3, Algorithm: mdns.ECDSAP256SHA256, PublicKey: ""},
	}
	got := dnskeyKeyTags(keys)
	// KeyTag depends on the key bytes; we mostly want the alg name to render.
	if got == "" || !contains(got, "ECDSAP256SHA256") {
		t.Fatalf("dnskeyKeyTags = %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
