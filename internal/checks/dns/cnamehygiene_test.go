package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestMaxCNAMEChain_IsConservative(t *testing.T) {
	// Tripwire: don't let someone bump the limit silently. Major recursors
	// (Unbound, BIND) cap at 8-16; we keep the lower end intentionally.
	if maxCNAMEChain > 8 {
		t.Fatalf("maxCNAMEChain=%d exceeds the documented ceiling of 8 (RFC 1912 §2.4 spirit)", maxCNAMEChain)
	}
}

// TestCNAMEApex_Forbidden: a CNAME at the zone apex is a FAIL that names the
// record and carries the zone-file fix.
func TestCNAMEApex_Forbidden(t *testing.T) {
	fake := newFakeDNS(t)
	fake.add(t, "example.test. 300 IN CNAME other.test.")
	env := fake.env(t, "example.test", time.Second)

	results := runCNAMEApex(context.Background(), env)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	r := results[0]
	if r.Status != report.Fail || r.Title != "CNAME present at zone apex (forbidden)" ||
		!strings.HasPrefix(r.Evidence, "example.test IN CNAME other.test") ||
		!strings.Contains(r.Remediation, "example.test. IN CNAME other.test") {
		t.Errorf("got %+v, want FAIL naming example.test IN CNAME other.test", r)
	}
}

// TestCNAMEChecks_Inconclusive: a CNAME walk that cannot finish, because a
// lookup failed or the scan was cancelled, is inconclusive rather than a
// finding about the zone.
func TestCNAMEChecks_Inconclusive(t *testing.T) {
	const servfail = "resolver answered SERVFAIL"
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name     string
		ctx      context.Context
		failing  string
		run      func(context.Context, *probe.Env) []report.Result
		evidence string
	}{
		{"apex lookup failed", context.Background(), "example.test.", runCNAMEApex,
			"could not determine: CNAME lookup for example.test: " + servfail},
		{"chain lookup failed", context.Background(), "edge.cdn.test.", runCNAMEChain,
			"could not determine: CNAME lookup for edge.cdn.test: " + servfail},
		{"chain walk cancelled", cancelled, "", runCNAMEChain,
			"could not determine: CNAME lookup for www.example.test: context canceled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.add(t, "www.example.test. 300 IN CNAME edge.cdn.test.")
			if tc.failing != "" {
				fake.setTypeRcode(tc.failing, miekg.TypeCNAME, miekg.RcodeServerFailure)
			}
			env := fake.env(t, "example.test", time.Second)

			results := tc.run(tc.ctx, env)

			if len(results) != 1 || results[0].Status != wantInconclusive ||
				results[0].Evidence != tc.evidence || results[0].Remediation != "" {
				t.Errorf("got %+v, want one inconclusive result %q", results, tc.evidence)
			}
		})
	}
}
