package registry

import (
	"context"
	"testing"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

type stubCheck struct {
	id  string
	cat string
	run func(ctx context.Context, env *probe.Env) []report.Result
}

func (s stubCheck) ID() string       { return s.id }
func (s stubCheck) Category() string { return s.cat }
func (s stubCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	return s.run(ctx, env)
}

// withEmptyRegistry swaps the global checks slice out for a test and
// restores it afterwards so parallel tests and package init() registrations
// are not disturbed.
func withEmptyRegistry(t *testing.T) func() {
	t.Helper()
	checksMu.Lock()
	saved := checks
	checks = nil
	checksMu.Unlock()
	return func() {
		checksMu.Lock()
		checks = saved
		checksMu.Unlock()
	}
}

func TestRegisterAndAll(t *testing.T) {
	defer withEmptyRegistry(t)()

	a := stubCheck{id: "a", cat: "x", run: func(context.Context, *probe.Env) []report.Result { return nil }}
	b := stubCheck{id: "b", cat: "y", run: func(context.Context, *probe.Env) []report.Result { return nil }}
	Register(a)
	Register(b)

	got := All()
	if len(got) != 2 {
		t.Fatalf("want 2 checks, got %d", len(got))
	}
	if got[0].ID() != "a" || got[1].ID() != "b" {
		t.Fatalf("ordering unexpected: %v %v", got[0].ID(), got[1].ID())
	}
	// All must return a copy — mutating the slice must not affect the registry.
	got[0] = nil
	again := All()
	if again[0] == nil {
		t.Fatal("All returned a live reference, not a copy")
	}
}

func TestRunOrdersByCategoryThenID(t *testing.T) {
	defer withEmptyRegistry(t)()

	mk := func(cat, id string) stubCheck {
		return stubCheck{id: id, cat: cat, run: func(ctx context.Context, env *probe.Env) []report.Result {
			return []report.Result{{ID: id, Category: cat, Status: report.Pass}}
		}}
	}
	Register(mk("dns", "dns.b"))
	Register(mk("email", "email.a"))
	Register(mk("dns", "dns.a"))

	out := Run(context.Background(), nil)
	if len(out) != 3 {
		t.Fatalf("want 3 results, got %d (%+v)", len(out), out)
	}
	want := []string{"dns.a", "dns.b", "email.a"}
	for i, w := range want {
		if out[i].ID != w {
			t.Fatalf("result[%d].ID = %q, want %q (full: %+v)", i, out[i].ID, w, out)
		}
	}
}

func TestRunRecoversFromPanic(t *testing.T) {
	defer withEmptyRegistry(t)()

	good := stubCheck{id: "good", cat: "cat1", run: func(context.Context, *probe.Env) []report.Result {
		return []report.Result{{ID: "good", Category: "cat1", Status: report.Pass}}
	}}
	boom := stubCheck{id: "boom", cat: "cat2", run: func(context.Context, *probe.Env) []report.Result {
		panic("kaboom")
	}}
	Register(good)
	Register(boom)

	out := Run(context.Background(), nil)
	// good must survive; boom must be converted to a registry.panic Fail.
	var foundGood, foundPanic bool
	for _, r := range out {
		if r.ID == "good" && r.Status == report.Pass {
			foundGood = true
		}
		if r.ID == "registry.panic" && r.Category == "cat2" && r.Status == report.Fail {
			foundPanic = true
		}
	}
	if !foundGood {
		t.Fatalf("expected 'good' result to survive panic in other category: %+v", out)
	}
	if !foundPanic {
		t.Fatalf("panic should be converted to registry.panic Fail: %+v", out)
	}
}

func TestRunEmptyRegistry(t *testing.T) {
	defer withEmptyRegistry(t)()
	out := Run(context.Background(), nil)
	if out != nil && len(out) != 0 {
		t.Fatalf("empty registry should produce no results, got %+v", out)
	}
}
