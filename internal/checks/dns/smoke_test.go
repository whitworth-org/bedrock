//go:build smoke

package dns

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestSmokeDomain is a network-dependent smoke check, hidden behind the
// `smoke` build tag so it doesn't run in CI by default. The target domain
// defaults to a neutral example but can be overridden with
// BEDROCK_SMOKE_DOMAIN. Invoke with:
//
//	go test -tags=smoke -run TestSmokeDomain ./internal/checks/dns
//	BEDROCK_SMOKE_DOMAIN=example.org go test -tags=smoke ./internal/checks/dns
func TestSmokeDomain(t *testing.T) {
	domain := os.Getenv("BEDROCK_SMOKE_DOMAIN")
	if domain == "" {
		domain = "example.com"
	}
	env := probe.NewEnv(domain, 5*time.Second, true, "")
	results := registry.Run(context.Background(), env)
	rep := report.Report{Target: domain, Results: results}
	if err := report.Render(os.Stdout, rep, report.FormatText, false); err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatalf("expected at least one DNS result for %s", domain)
	}
	t.Logf("got %d results for %s", len(results), domain)
}
