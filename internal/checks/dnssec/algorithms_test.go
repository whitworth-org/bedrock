package dnssec

import (
	"context"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
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

// algorithmResults runs the algorithms check on a signed zone whose DNSKEYs
// use algs and whose DS records use digests.
func algorithmResults(t *testing.T, algs, digests []uint8) map[string]report.Result {
	t.Helper()
	cd := &chainData{signed: true}
	for _, a := range algs {
		cd.keySet = append(cd.keySet, &mdns.DNSKEY{Algorithm: a})
	}
	for _, d := range digests {
		cd.dsSet = append(cd.dsSet, &mdns.DS{DigestType: d})
	}
	env := &probe.Env{Target: "example.test"}
	env.CachePut(cacheKeyChain, cd)
	got := byID(t, runAlgorithms(context.Background(), env))
	if len(got) != 2 {
		t.Fatalf("got %d results, want one per table: %+v", len(got), got)
	}
	return got
}

// TestRunAlgorithms pins one result per RFC 8624 table, graded by its worst
// value, with every value in the evidence, worst first.
func TestRunAlgorithms(t *testing.T) {
	cases := []struct {
		name          string
		algs, digests []uint8
		id            string
		status        report.Status
		evidence      string
	}{
		{
			name: "DS digest types 1 and 2", algs: []uint8{13}, digests: []uint8{1, 2},
			id: "dnssec.algorithm.ds", status: report.Fail,
			evidence: "SHA-1 — MUST NOT (RFC 8624 §3.3); SHA-256 — MUST (RFC 4509, RFC 8624 §3.3)",
		},
		{
			name: "algorithms 8 and 13", algs: []uint8{8, 13}, digests: []uint8{2},
			id: "dnssec.algorithm.dnskey", status: report.Pass,
			evidence: "RSASHA256 — MUST per RFC 8624 §3.1; " +
				"ECDSAP256SHA256 — MUST / RECOMMENDED (RFC 8624 §3.1)",
		},
		{
			name: "MUST NOT algorithm listed first", algs: []uint8{8, 12}, digests: []uint8{2},
			id: "dnssec.algorithm.dnskey", status: report.Fail,
			evidence: "ECC-GOST — MUST NOT (RFC 8624 §3.1); RSASHA256 — MUST per RFC 8624 §3.1",
		},
		{
			name: "unclassified algorithm", algs: []uint8{13, 99}, digests: []uint8{2},
			id: "dnssec.algorithm.dnskey", status: report.Warn,
			evidence: "algorithm 99 not classified by RFC 8624; ECDSAP256SHA256",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := algorithmResults(t, c.algs, c.digests)[c.id]
			if r.Status != c.status || !strings.HasPrefix(r.Evidence, c.evidence) {
				t.Errorf("%s = %s %q, want %s with evidence starting %q",
					c.id, r.Status, r.Evidence, c.status, c.evidence)
			}
			if (r.Status == report.Fail) != (r.Remediation != "") {
				t.Errorf("%s = %s with remediation %q; only a FAIL has one",
					c.id, r.Status, r.Remediation)
			}
		})
	}
}

// TestRunAlgorithmsBoundsEvidence pins that the evidence names at most ten
// values and counts the rest, since a zone can publish hundreds of keys.
func TestRunAlgorithmsBoundsEvidence(t *testing.T) {
	var algs []uint8
	for a := uint8(100); a < 113; a++ {
		algs = append(algs, a)
	}

	r := algorithmResults(t, algs, []uint8{2})["dnssec.algorithm.dnskey"]

	if n := strings.Count(r.Evidence, "not classified"); n != 10 ||
		!strings.HasSuffix(r.Evidence, "; and 3 more") {
		t.Errorf("evidence %q names %d of 13 algorithms, want 10 and \"; and 3 more\"",
			r.Evidence, n)
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
