package dnssec

import (
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"granite-scan/internal/report"
)

// newCDS constructs a CDS RR with the given tuple. Digest is stored as-is so
// tests can exercise case-insensitive comparison.
func newCDS(name string, keyTag uint16, algorithm, digestType uint8, digest string) *mdns.CDS {
	return &mdns.CDS{
		DS: mdns.DS{
			Hdr:        mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: mdns.TypeCDS, Class: mdns.ClassINET},
			KeyTag:     keyTag,
			Algorithm:  algorithm,
			DigestType: digestType,
			Digest:     digest,
		},
	}
}

func newDS(name string, keyTag uint16, algorithm, digestType uint8, digest string) *mdns.DS {
	return &mdns.DS{
		Hdr:        mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: mdns.TypeDS, Class: mdns.ClassINET},
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     digest,
	}
}

// TestCDSMatchesDS pins the equality semantics of the CDS-vs-DS comparison.
// Crucial because it drives the Pass/Fail verdict shipped to operators.
func TestCDSMatchesDS(t *testing.T) {
	const apex = "example.com"
	const digestA = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
	const digestB = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

	cases := []struct {
		name string
		cds  []*mdns.CDS
		ds   []*mdns.DS
		want bool
	}{
		{
			name: "identical single-record sets",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, digestA)},
			ds:   []*mdns.DS{newDS(apex, 12345, 13, 2, digestA)},
			want: true,
		},
		{
			name: "case-insensitive digest comparison",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, strings.ToLower(digestA))},
			ds:   []*mdns.DS{newDS(apex, 12345, 13, 2, digestA)},
			want: true,
		},
		{
			name: "multi-record set, order independent",
			cds: []*mdns.CDS{
				newCDS(apex, 12345, 13, 2, digestA),
				newCDS(apex, 65535, 8, 2, digestB),
			},
			ds: []*mdns.DS{
				newDS(apex, 65535, 8, 2, digestB),
				newDS(apex, 12345, 13, 2, digestA),
			},
			want: true,
		},
		{
			name: "different keytag",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, digestA)},
			ds:   []*mdns.DS{newDS(apex, 54321, 13, 2, digestA)},
			want: false,
		},
		{
			name: "different algorithm",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, digestA)},
			ds:   []*mdns.DS{newDS(apex, 12345, 8, 2, digestA)},
			want: false,
		},
		{
			name: "different digest type",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, digestA)},
			ds:   []*mdns.DS{newDS(apex, 12345, 13, 4, digestA)},
			want: false,
		},
		{
			name: "different digest content",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, digestA)},
			ds:   []*mdns.DS{newDS(apex, 12345, 13, 2, digestB)},
			want: false,
		},
		{
			name: "size mismatch — CDS subset of DS",
			cds:  []*mdns.CDS{newCDS(apex, 12345, 13, 2, digestA)},
			ds: []*mdns.DS{
				newDS(apex, 12345, 13, 2, digestA),
				newDS(apex, 65535, 8, 2, digestB),
			},
			want: false,
		},
		{
			name: "size mismatch — DS subset of CDS",
			cds: []*mdns.CDS{
				newCDS(apex, 12345, 13, 2, digestA),
				newCDS(apex, 65535, 8, 2, digestB),
			},
			ds:   []*mdns.DS{newDS(apex, 12345, 13, 2, digestA)},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cdsMatchesDS(c.cds, c.ds)
			if got != c.want {
				t.Fatalf("cdsMatchesDS = %v, want %v", got, c.want)
			}
		})
	}
}

// TestEvaluateCDSvsDS verifies the result envelope (status + remediation
// presence) so the renderer-facing contract holds even as messages evolve.
func TestEvaluateCDSvsDS(t *testing.T) {
	const apex = "example.com"
	const digest = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"

	cases := []struct {
		name           string
		cds            []*mdns.CDS
		ds             []*mdns.DS
		wantStatus     report.Status
		wantHasRemFix  bool
		wantIDContains string
	}{
		{
			name:           "match → Pass",
			cds:            []*mdns.CDS{newCDS(apex, 12345, 13, 2, digest)},
			ds:             []*mdns.DS{newDS(apex, 12345, 13, 2, digest)},
			wantStatus:     report.Pass,
			wantHasRemFix:  false,
			wantIDContains: "matches_ds",
		},
		{
			name:           "divergent → Fail with remediation",
			cds:            []*mdns.CDS{newCDS(apex, 12345, 13, 2, digest)},
			ds:             []*mdns.DS{newDS(apex, 54321, 13, 2, digest)},
			wantStatus:     report.Fail,
			wantHasRemFix:  true,
			wantIDContains: "matches_ds",
		},
		{
			name:           "no DS at parent → Info (bootstrap)",
			cds:            []*mdns.CDS{newCDS(apex, 12345, 13, 2, digest)},
			ds:             nil,
			wantStatus:     report.Info,
			wantHasRemFix:  false,
			wantIDContains: "matches_ds",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evaluateCDSvsDS(c.cds, c.ds)
			if got.Status != c.wantStatus {
				t.Fatalf("status = %s, want %s (evidence=%q)", got.Status, c.wantStatus, got.Evidence)
			}
			if c.wantHasRemFix && got.Remediation == "" {
				t.Fatalf("Fail result missing remediation; evidence=%q", got.Evidence)
			}
			// Remediation must include the literal DS line so operators can
			// paste it into their registrar.
			if c.wantStatus == report.Fail && !strings.Contains(got.Remediation, "IN DS") {
				t.Fatalf("Fail remediation missing 'IN DS' line: %q", got.Remediation)
			}
			if !strings.Contains(got.ID, c.wantIDContains) {
				t.Fatalf("id = %q, want it to contain %q", got.ID, c.wantIDContains)
			}
			if len(got.RFCRefs) == 0 {
				t.Fatalf("result missing RFC refs")
			}
		})
	}
}

// TestIsDeleteSentinel covers RFC 8078 §4 — the all-zero "remove DS" signal.
func TestIsDeleteSentinel(t *testing.T) {
	const apex = "example.com"

	deleteCDS := newCDS(apex, 0, 0, 0, "00")
	deleteCDS2 := newCDS(apex, 0, 0, 0, "")
	normalCDS := newCDS(apex, 12345, 13, 2, "ABCDEF")

	deleteCDNSKEY := &mdns.CDNSKEY{
		DNSKEY: mdns.DNSKEY{
			Hdr:       mdns.RR_Header{Name: mdns.Fqdn(apex), Rrtype: mdns.TypeCDNSKEY, Class: mdns.ClassINET},
			Flags:     257,
			Protocol:  3,
			Algorithm: 0,
			PublicKey: "AA==",
		},
	}
	normalCDNSKEY := &mdns.CDNSKEY{
		DNSKEY: mdns.DNSKEY{
			Hdr:       mdns.RR_Header{Name: mdns.Fqdn(apex), Rrtype: mdns.TypeCDNSKEY, Class: mdns.ClassINET},
			Flags:     257,
			Protocol:  3,
			Algorithm: 13,
			PublicKey: "abcd",
		},
	}

	cases := []struct {
		name string
		cds  []*mdns.CDS
		ck   []*mdns.CDNSKEY
		want bool
	}{
		{"both delete sentinels", []*mdns.CDS{deleteCDS}, []*mdns.CDNSKEY{deleteCDNSKEY}, true},
		{"CDS-only delete sentinel", []*mdns.CDS{deleteCDS}, nil, true},
		{"CDS-only delete with empty digest", []*mdns.CDS{deleteCDS2}, nil, true},
		{"CDNSKEY-only delete sentinel", nil, []*mdns.CDNSKEY{deleteCDNSKEY}, true},
		{"normal CDS + CDNSKEY", []*mdns.CDS{normalCDS}, []*mdns.CDNSKEY{normalCDNSKEY}, false},
		{"empty sets", nil, nil, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDeleteSentinel(c.cds, c.ck); got != c.want {
				t.Fatalf("isDeleteSentinel = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDsTuple confirms the canonical key collapses case differences in
// digest hex without losing the rest of the tuple.
func TestDsTuple(t *testing.T) {
	a := newDS("example.com", 12345, 13, 2, "abcdef")
	b := newDS("example.com", 12345, 13, 2, "ABCDEF")
	if dsTuple(a) != dsTuple(b) {
		t.Fatalf("dsTuple should be case-insensitive on digest: %q vs %q", dsTuple(a), dsTuple(b))
	}
	c := newDS("example.com", 12346, 13, 2, "abcdef")
	if dsTuple(a) == dsTuple(c) {
		t.Fatalf("dsTuple should differ on KeyTag: %q", dsTuple(a))
	}
}
