package email

import (
	"context"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// ed25519TestKey is the RFC 8463 example public key (32 bytes base64).
const ed25519TestKey = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

// newEnvWithSweep returns a hermetic Env whose DKIM sweep cache is
// pre-seeded, so sweep consumers never touch the network.
func newEnvWithSweep(t *testing.T, sweep *DKIMSweep) *probe.Env {
	t.Helper()
	env := probe.NewEnv("example.com", time.Second, false, "")
	env.CachePut(probe.CacheKeyDKIM, sweep)
	return env
}

func foundProbe(selector string, key *DKIMKey) DKIMProbe {
	return DKIMProbe{
		Selector: selector,
		Name:     selector + "._domainkey.example.com",
		Outcome:  dkimFound,
		Key:      key,
	}
}

func TestRunDKIM2Readiness(t *testing.T) {
	cases := []struct {
		name       string
		sweep      *DKIMSweep
		wantStatus report.Status
		wantSub    string
	}{
		{
			name:       "no keys discoverable",
			sweep:      &DKIMSweep{Selectors: []string{"default"}},
			wantStatus: report.NotApplicable,
			wantSub:    "no DKIM keys discoverable",
		},
		{
			name: "v=DKIM2 record published",
			sweep: &DKIMSweep{Probes: []DKIMProbe{
				foundProbe("s1", &DKIMKey{Version: "DKIM2", KeyType: "ed25519", P: ed25519TestKey}),
			}},
			wantStatus: report.Pass,
			wantSub:    "v=DKIM2 key record(s) published at: s1",
		},
		{
			name: "ed25519 only, still DKIM1",
			sweep: &DKIMSweep{Probes: []DKIMProbe{
				foundProbe("s1", &DKIMKey{Version: "DKIM1", KeyType: "ed25519", P: ed25519TestKey}),
			}},
			wantStatus: report.Info,
			wantSub:    "ed25519 key(s) at: s1",
		},
		{
			name: "rsa DKIM1 only",
			sweep: &DKIMSweep{Probes: []DKIMProbe{
				foundProbe("s1", &DKIMKey{Version: "DKIM1", KeyType: "rsa", P: "AAAA"}),
			}},
			wantStatus: report.Info,
			wantSub:    "no DKIM2 readiness signals",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnvWithSweep(t, tc.sweep)
			res := runDKIM2Readiness(context.Background(), env)
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(res), res)
			}
			r := res[0]
			if r.ID != "email.dkim2.readiness" {
				t.Errorf("ID = %q", r.ID)
			}
			if r.Status != tc.wantStatus {
				t.Errorf("Status = %s, want %s (evidence=%q)", r.Status, tc.wantStatus, r.Evidence)
			}
			if !contains(r.Evidence, tc.wantSub) {
				t.Errorf("evidence = %q, want substring %q", r.Evidence, tc.wantSub)
			}
		})
	}
}
