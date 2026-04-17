package email

import (
	"testing"
	"time"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

// TestARCDMARCResultFromCache exercises arcDMARCResult's DMARC-cache reading
// path. The check must NEVER return Fail (ARC is an enhancement, not a
// baseline requirement) — every case here must be Info.
func TestARCDMARCResultFromCache(t *testing.T) {
	cases := []struct {
		name       string
		seed       *DMARC // when nil, leave cache empty
		notDMARC   bool   // when true, cache an unrelated value at the DMARC key
		wantStatus report.Status
		// wantEvidenceContains is a substring the evidence must include so we
		// know the right code path fired.
		wantEvidenceContains string
	}{
		{
			name:                 "cache empty",
			seed:                 nil,
			wantStatus:           report.Info,
			wantEvidenceContains: "no DMARC record cached",
		},
		{
			name:                 "cache holds wrong type",
			notDMARC:             true,
			wantStatus:           report.Info,
			wantEvidenceContains: "unrecognized shape",
		},
		{
			name:                 "DMARC p=none",
			seed:                 &DMARC{Raw: "v=DMARC1; p=none", Policy: "none", Pct: 100, Adkim: "r", Aspf: "r"},
			wantStatus:           report.Info,
			wantEvidenceContains: "current policy=none",
		},
		{
			name:                 "DMARC policy missing string",
			seed:                 &DMARC{Raw: "v=DMARC1", Policy: "", Pct: 100},
			wantStatus:           report.Info,
			wantEvidenceContains: "current policy=none",
		},
		{
			name:                 "DMARC p=quarantine",
			seed:                 &DMARC{Raw: "v=DMARC1; p=quarantine", Policy: "quarantine", Pct: 100, Adkim: "r", Aspf: "r"},
			wantStatus:           report.Info,
			wantEvidenceContains: "DMARC enforced (p=quarantine)",
		},
		{
			name:                 "DMARC p=reject",
			seed:                 &DMARC{Raw: "v=DMARC1; p=reject", Policy: "reject", Pct: 100, Adkim: "s", Aspf: "s"},
			wantStatus:           report.Info,
			wantEvidenceContains: "DMARC enforced (p=reject)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := probe.NewEnv("example.test", time.Second, false, "")
			if tc.seed != nil {
				env.CachePut(probe.CacheKeyDMARC, tc.seed)
			} else if tc.notDMARC {
				env.CachePut(probe.CacheKeyDMARC, "not a *DMARC")
			}

			got := arcDMARCResult(env)

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
