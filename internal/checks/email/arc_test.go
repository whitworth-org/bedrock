package email

import (
	"context"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// arcOwnWalk is a seeded tree walk whose effective record, with the given p=
// and sp=, is the author's own.
func arcOwnWalk(p, sp string) *DMARCWalk {
	return &DMARCWalk{Author: "example.test", PolicyDomain: "example.test",
		Policy: &DMARC{Policy: p, SubdomainPolicy: sp}}
}

// arcInheritedWalk is a seeded tree walk for news.example.test whose effective
// record, with the given p= and sp=, is inherited from example.test.
func arcInheritedWalk(p, sp string) *DMARCWalk {
	return &DMARCWalk{Author: "news.example.test", PolicyDomain: "example.test",
		Policy: &DMARC{Policy: p, SubdomainPolicy: sp}}
}

// TestARCDMARCResultFromCache exercises arcDMARCResult against a seeded tree
// walk, so no DNS query runs. The check must NEVER return Fail (ARC is an
// enhancement, not a baseline requirement): it is Info, or inconclusive when
// the walk may have missed the record.
func TestARCDMARCResultFromCache(t *testing.T) {
	cases := []struct {
		name       string
		seed       any // stored under probe.CacheKeyDMARCWalk
		wantStatus report.Status
		// wantEvidenceContains is a substring the evidence must include so we
		// know the right code path fired.
		wantEvidenceContains string
	}{
		{
			name: "walk found no record",
			seed: &DMARCWalk{Author: "example.test", Steps: []DMARCWalkStep{
				{QueryName: "_dmarc.example.test", Outcome: walkNXDomain},
			}},
			wantStatus:           report.Info,
			wantEvidenceContains: "no DMARC record cached",
		},
		{
			name: "walk lookup failed",
			seed: &DMARCWalk{Author: "example.test", Steps: []DMARCWalkStep{
				{QueryName: "_dmarc.example.test", Outcome: walkError, Detail: "timeout"},
			}},
			wantStatus: report.Warn,
			wantEvidenceContains: "could not determine: " +
				"TXT lookup for _dmarc.example.test: timeout",
		},
		{
			name:                 "cache holds wrong type",
			seed:                 "not a *DMARCWalk",
			wantStatus:           report.Warn,
			wantEvidenceContains: "could not determine: " + errWalkPanicked.Error(),
		},
		{
			name:                 "DMARC p=none",
			seed:                 arcOwnWalk("none", "reject"),
			wantStatus:           report.Info,
			wantEvidenceContains: "current policy=none",
		},
		{
			name:                 "DMARC policy missing string",
			seed:                 arcOwnWalk("", ""),
			wantStatus:           report.Info,
			wantEvidenceContains: "current policy=none",
		},
		{
			name:                 "DMARC p=quarantine",
			seed:                 arcOwnWalk("quarantine", "none"),
			wantStatus:           report.Info,
			wantEvidenceContains: "DMARC enforced (p=quarantine)",
		},
		{
			name:                 "DMARC p=reject",
			seed:                 arcOwnWalk("reject", "none"),
			wantStatus:           report.Info,
			wantEvidenceContains: "DMARC enforced (p=reject)",
		},
		{
			name:                 "inherited sp=quarantine",
			seed:                 arcInheritedWalk("reject", "quarantine"),
			wantStatus:           report.Info,
			wantEvidenceContains: "enforced (sp=quarantine inherited from _dmarc.example.test)",
		},
		{
			name:                 "inherited sp=none under p=reject",
			seed:                 arcInheritedWalk("reject", "none"),
			wantStatus:           report.Info,
			wantEvidenceContains: "policy=none (sp=none inherited from _dmarc.example.test)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := probe.NewEnv("example.test", time.Second, false, "")
			env.CachePut(probe.CacheKeyDMARCWalk, tc.seed)

			got := arcDMARCResult(context.Background(), env)

			if got.Status == report.Fail {
				t.Fatalf("arcDMARCResult returned Fail; ARC check must never Fail. Got: %+v", got)
			}
			if got.Status != tc.wantStatus {
				t.Errorf("Status = %v, want %v", got.Status, tc.wantStatus)
			}
			if tc.wantEvidenceContains != "" && !contains(got.Evidence, tc.wantEvidenceContains) {
				t.Errorf("Evidence = %q, want substring %q", got.Evidence, tc.wantEvidenceContains)
			}
			if got.Category != category {
				t.Errorf("Category = %q, want %q", got.Category, category)
			}
			if got.ID != "email.arc.dmarc" {
				t.Errorf("ID = %q, want %q", got.ID, "email.arc.dmarc")
			}
			if len(got.RFCRefs) == 0 {
				t.Errorf("RFCRefs is empty; ARC check must cite RFC 8617")
			}
		})
	}
}

// arcDMARCEvidence runs the whole ARC check and returns the email.arc.dmarc
// evidence.
func arcDMARCEvidence(t *testing.T, env *probe.Env) string {
	t.Helper()
	for _, r := range runARC(context.Background(), env) {
		if r.ID == "email.arc.dmarc" {
			return r.Evidence
		}
	}
	t.Fatal("runARC returned no email.arc.dmarc result")
	return ""
}

// TestARCDMARCRunsWalkWhenUnprimed runs ARC on a fresh Env, before any other
// check has walked the DMARC tree: the verdict must not depend on which
// check the registry schedules first.
func TestARCDMARCRunsWalkWhenUnprimed(t *testing.T) {
	env := newCannedEnv(t, "example.com", cannedZone{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}})
	if ev := arcDMARCEvidence(t, env); !contains(ev, "DMARC enforced (p=reject)") {
		t.Errorf("evidence = %q, want the published p=reject", ev)
	}
}

// TestARCDMARCGradesInheritedSubdomainPolicy covers a subdomain with no record
// of its own: the organizational domain's sp=none applies (RFC 9989), not its
// p=reject.
func TestARCDMARCGradesInheritedSubdomainPolicy(t *testing.T) {
	env := newCannedEnv(t, "news.example.com", cannedZone{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; sp=none; adkim=s; aspf=s"},
	}})
	runDMARC(context.Background(), env)

	ev := arcDMARCEvidence(t, env)
	if !contains(ev, "current policy=none (sp=none inherited from _dmarc.example.com)") {
		t.Errorf("evidence = %q, want the inherited sp=none", ev)
	}
}

// TestARCGuidanceIsInfo locks in the policy-level invariant: the guidance
// row is always Info and always cites RFC 8617.
func TestARCGuidanceIsInfo(t *testing.T) {
	r := arcGuidanceResult()
	if r.Status != report.Info {
		t.Errorf("guidance Status = %v, want Info", r.Status)
	}
	if r.Remediation == "" {
		t.Errorf("guidance Remediation is empty; want deployment guidance text")
	}
	hasRFC := false
	for _, ref := range r.RFCRefs {
		if contains(ref, "RFC 8617") {
			hasRFC = true
			break
		}
	}
	if !hasRFC {
		t.Errorf("guidance RFCRefs = %v, want at least one RFC 8617 citation", r.RFCRefs)
	}
}

// contains is a tiny strings.Contains shim kept inline so the test file's
// imports stay narrow.
func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
