package email

import (
	"strings"
	"testing"
)

// FuzzParseDMARC drives the strict DMARC record parser with arbitrary
// tag-list input. The parser must never panic, and any record it accepts
// must satisfy the RFC 9989 value constraints the checks rely on.
func FuzzParseDMARC(f *testing.F) {
	seeds := []string{
		"v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com",
		"v=DMARC1; p=reject; sp=quarantine; np=reject; adkim=s; aspf=s",
		"v=DMARC1; p=reject; t=y; psd=y; fo=1:d:s",
		"v=DMARC1; p=none; pct=50; rf=afrf; ri=86400",
		"v=DMARC1; p=quarantine; rua=mailto:a@x.com,mailto:b@x.com!10m; ruf=mailto:c@x.com",
		"v=DMARC1",
		"p=reject",
		"v=DMARC1;;;p=none;",
		"v=DMARC1; p=none; p=reject",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	valid := map[string]bool{"none": true, "quarantine": true, "reject": true}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := ParseDMARC(raw)
		if err != nil {
			return
		}
		if !valid[p.Policy] || !valid[p.SubdomainPolicy] || !valid[p.NPPolicy] {
			t.Errorf("accepted out-of-range policy: p=%q sp=%q np=%q (raw=%q)",
				p.Policy, p.SubdomainPolicy, p.NPPolicy, raw)
		}
		if p.Pct < 0 || p.Pct > 100 {
			t.Errorf("accepted out-of-range pct=%d (raw=%q)", p.Pct, raw)
		}
	})
}

// FuzzDMARCWalkNames locks in the structural invariants of the RFC 9989
// tree-walk query plan: at most eight names, the author domain queried
// first, and each subsequent name strictly shorter than the last.
func FuzzDMARCWalkNames(f *testing.F) {
	for _, s := range []string{
		"", "com", "example.com", "a.b.example.com",
		"a.b.c.d.e.f.g.h.i.j.mail.example.com",
		".", "..", "a..b", "example.com.",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		names := dmarcWalkNames(domain)
		if len(names) > maxWalkQueries {
			t.Fatalf("dmarcWalkNames(%q) returned %d names, cap is %d", domain, len(names), maxWalkQueries)
		}
		if domain == "" {
			if names != nil {
				t.Fatalf("dmarcWalkNames(\"\") = %v, want nil", names)
			}
			return
		}
		if names[0] != "_dmarc."+domain {
			t.Fatalf("first name = %q, want %q", names[0], "_dmarc."+domain)
		}
		prev := len(strings.Split(names[0], "."))
		for _, n := range names[1:] {
			cur := len(strings.Split(n, "."))
			if cur >= prev {
				t.Fatalf("label counts must strictly decrease: %v", names)
			}
			prev = cur
		}
	})
}
