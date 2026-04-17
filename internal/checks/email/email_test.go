package email

import (
	"context"
	"testing"
	"time"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/registry"
	"github.com/rwhitworth/bedrock/internal/report"
)

// TestFailResultsCarryRemediation enforces the project-wide invariant that
// any Status=Fail result includes a non-empty Remediation. We exercise each
// registered Email check against a deliberately invalid target so most
// records fail to resolve.
func TestFailResultsCarryRemediation(t *testing.T) {
	env := probe.NewEnv(
		"invalid-domain-that-cannot-exist.example.invalid",
		2*time.Second,
		false, // Active=false to skip outbound TCP
		"",
	)
	ctx := context.Background()

	for _, c := range registry.All() {
		if c.Category() != category {
			continue
		}
		for _, r := range c.Run(ctx, env) {
			if r.Status == report.Fail && r.Remediation == "" {
				t.Errorf("check %s returned Fail with empty Remediation: %+v", c.ID(), r)
			}
			if r.Category != category {
				t.Errorf("check %s returned Result with Category %q, want %q", c.ID(), r.Category, category)
			}
		}
	}
}
