package bimi

import (
	"context"
	"testing"
	"time"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

// fakeDMARC mirrors the field shape of email.DMARC so the reflection-based
// reader in gmail.go can pull values without an import on the email package.
type fakeDMARC struct {
	Policy string
	Pct    int
	Adkim  string
	Aspf   string
	Raw    string
}

func newEnvWithDMARC(t *testing.T, d any) *probe.Env {
	t.Helper()
	env := probe.NewEnv("example.com", time.Second, true, "")
	if d != nil {
		env.CachePut(probe.CacheKeyDMARC, d)
	}
	return env
}

func runGmail(t *testing.T, env *probe.Env) []report.Result {
	t.Helper()
	return gmailGateCheck{}.Run(context.Background(), env)
}

func TestGmailGate_NoCacheEntry(t *testing.T) {
	env := newEnvWithDMARC(t, nil) // do not put anything
	results := runGmail(t, env)
	if len(results) != 1 || results[0].Status != report.Info {
		t.Fatalf("want single Info; got %+v", results)
	}
}

func TestGmailGate_NilCacheValue(t *testing.T) {
	env := probe.NewEnv("example.com", time.Second, true, "")
	env.CachePut(probe.CacheKeyDMARC, (*fakeDMARC)(nil))
	results := runGmail(t, env)
	// Reflection unwrap of typed-nil pointer surfaces "nil DMARC value"
	// from readDMARC and we report Info for that path.
	if len(results) != 1 {
		t.Fatalf("want 1 result; got %d: %+v", len(results), results)
	}
	if results[0].Status != report.Info {
		t.Errorf("want Info; got %s", results[0].Status)
	}
}

func TestGmailGate_PolicyNone(t *testing.T) {
	env := newEnvWithDMARC(t, &fakeDMARC{Policy: "none", Pct: 100, Adkim: "s", Aspf: "s"})
	results := runGmail(t, env)
	if len(results) != 1 {
		t.Fatalf("want 1 result; got %d: %+v", len(results), results)
	}
	if results[0].Status != report.Fail {
		t.Errorf("want Fail; got %s", results[0].Status)
	}
	if results[0].Remediation == "" {
		t.Error("Fail must carry a remediation")
	}
}

func TestGmailGate_PctNot100(t *testing.T) {
	env := newEnvWithDMARC(t, &fakeDMARC{Policy: "quarantine", Pct: 50, Adkim: "s", Aspf: "s"})
	results := runGmail(t, env)
	failCount := 0
	for _, r := range results {
		if r.Status == report.Fail {
			failCount++
		}
	}
	if failCount != 1 {
		t.Errorf("want 1 fail (pct), got %d (%+v)", failCount, results)
	}
}

func TestGmailGate_RelaxedAlignment(t *testing.T) {
	env := newEnvWithDMARC(t, &fakeDMARC{Policy: "reject", Pct: 100, Adkim: "r", Aspf: "r"})
	results := runGmail(t, env)
	if len(results) != 2 {
		t.Errorf("want 2 fails (adkim+aspf); got %d (%+v)", len(results), results)
	}
	for _, r := range results {
		if r.Status != report.Fail {
			t.Errorf("each result should be Fail; got %s", r.Status)
		}
	}
}

func TestGmailGate_Pass(t *testing.T) {
	env := newEnvWithDMARC(t, &fakeDMARC{Policy: "quarantine", Pct: 100, Adkim: "s", Aspf: "s"})
	results := runGmail(t, env)
	if len(results) != 1 || results[0].Status != report.Pass {
		t.Fatalf("want single Pass; got %+v", results)
	}
}

func TestReadDMARC_PtrAndValue(t *testing.T) {
	d := fakeDMARC{Policy: "reject", Pct: 100, Adkim: "s", Aspf: "s"}
	for _, v := range []any{d, &d} {
		out, err := readDMARC(v)
		if err != nil {
			t.Errorf("readDMARC(%T) err: %v", v, err)
			continue
		}
		if out.Policy != "reject" || out.Pct != 100 || out.Adkim != "s" || out.Aspf != "s" {
			t.Errorf("got %+v", out)
		}
	}
}
