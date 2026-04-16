//go:build smoke

package dns

import (
	"context"
	"os"
	"testing"
	"time"

	"bedrock/internal/probe"
	"bedrock/internal/registry"
	"bedrock/internal/report"
)

// TestSmokeWhitworth is a network-dependent smoke check, hidden behind the
// `smoke` build tag so it doesn't run in CI by default. Invoke with:
//
//	go test -tags=smoke -run TestSmokeWhitworth ./internal/checks/dns
func TestSmokeWhitworth(t *testing.T) {
	env := probe.NewEnv("whitworth.org", 5*time.Second, true, "")
	results := registry.Run(context.Background(), env)
	rep := report.Report{Target: "whitworth.org", Results: results}
	if err := report.Render(os.Stdout, rep, report.FormatText, false); err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one DNS result")
	}
	t.Logf("got %d results", len(results))
}
