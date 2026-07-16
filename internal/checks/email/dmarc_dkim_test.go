package email

import (
	"context"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// injectWalk builds a hermetic Env with a pre-seeded tree walk and DKIM
// sweep so runDMARCRejectDKIM never probes the network.
func injectWalk(t *testing.T, walk *DMARCWalk, sweep *DKIMSweep) *probe.Env {
	t.Helper()
	env := probe.NewEnv("example.com", time.Second, false, "")
	env.CachePut(probe.CacheKeyDMARCWalk, walk)
	env.CachePut(probe.CacheKeyDKIM, sweep)
	return env
}

func rejectWalk(author, policyDomain string, p *DMARC) *DMARCWalk {
	return &DMARCWalk{
		Author:       author,
		OrgDomain:    policyDomain,
		PolicyDomain: policyDomain,
		Policy:       p,
		Steps:        []DMARCWalkStep{{Domain: author, QueryName: "_dmarc." + author, Outcome: walkNXDomain}},
		Queries:      1,
	}
}

func TestRunDMARCRejectDKIM(t *testing.T) {
	liveSweep := &DKIMSweep{Probes: []DKIMProbe{
		foundProbe("s1", &DKIMKey{Version: "DKIM1", KeyType: "rsa", P: "AAAA"}),
	}}
	emptySweep := &DKIMSweep{Selectors: []string{"default", "google"}}
	revokedSweep := &DKIMSweep{
		Selectors: []string{"default"},
		Probes:    []DKIMProbe{foundProbe("default", &DKIMKey{Version: "DKIM1", KeyType: "rsa", P: ""})},
	}

	cases := []struct {
		name       string
		walk       *DMARCWalk
		sweep      *DKIMSweep
		wantStatus report.Status
		wantSub    string
	}{
		{
			name:       "no DMARC policy",
			walk:       rejectWalk("example.com", "", nil),
			sweep:      emptySweep,
			wantStatus: report.NotApplicable,
			wantSub:    "no DMARC record",
		},
		{
			name:       "effective policy below reject",
			walk:       rejectWalk("example.com", "example.com", &DMARC{Policy: "quarantine", SubdomainPolicy: "quarantine"}),
			sweep:      emptySweep,
			wantStatus: report.NotApplicable,
			wantSub:    "effective policy is quarantine",
		},
		{
			name: "inherited sp=none is not reject",
			walk: rejectWalk("mail.example.com", "example.com",
				&DMARC{Policy: "reject", SubdomainPolicy: "none"}),
			sweep:      emptySweep,
			wantStatus: report.NotApplicable,
			wantSub:    "effective policy is none",
		},
		{
			name:       "reject with live key",
			walk:       rejectWalk("example.com", "example.com", &DMARC{Policy: "reject", SubdomainPolicy: "reject"}),
			sweep:      liveSweep,
			wantStatus: report.Pass,
			wantSub:    "discoverable DKIM key(s) at: s1",
		},
		{
			name:       "reject with no discoverable key",
			walk:       rejectWalk("example.com", "example.com", &DMARC{Policy: "reject", SubdomainPolicy: "reject"}),
			sweep:      emptySweep,
			wantStatus: report.Warn,
			wantSub:    "MUST apply DKIM",
		},
		{
			name:       "reject with only a revoked key",
			walk:       rejectWalk("example.com", "example.com", &DMARC{Policy: "reject", SubdomainPolicy: "reject"}),
			sweep:      revokedSweep,
			wantStatus: report.Warn,
			wantSub:    "MUST apply DKIM",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := injectWalk(t, tc.walk, tc.sweep)
			res := runDMARCRejectDKIM(context.Background(), env)
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(res), res)
			}
			r := res[0]
			if r.ID != "email.dmarc.reject_dkim" {
				t.Errorf("ID = %q", r.ID)
			}
			if r.Status != tc.wantStatus {
				t.Errorf("Status = %s, want %s (evidence=%q)", r.Status, tc.wantStatus, r.Evidence)
			}
			if !contains(r.Evidence, tc.wantSub) {
				t.Errorf("evidence = %q, want substring %q", r.Evidence, tc.wantSub)
			}
			if r.Status == report.Fail {
				t.Error("reject_dkim must never Fail (heuristic probe)")
			}
		})
	}
}
