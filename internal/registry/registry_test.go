package registry

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
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
	if len(out) != 0 {
		t.Fatalf("empty registry should produce no results, got %+v", out)
	}
}

// TestRunParallelManyChecks registers 100 checks across 5 categories, runs
// them concurrently, and asserts result count plus stable (category, id)
// ordering. Run with `go test -race -count=10 ./internal/registry/...` to
// stress the per-check fan-out introduced for A1.
//
// This test mutates the package-level checks slice, so it cannot use
// t.Parallel(); the race detector still gets full coverage of the
// fan-out within a single Run call.
func TestRunParallelManyChecks(t *testing.T) {
	defer withEmptyRegistry(t)()

	const cats = 5
	const perCat = 20
	var ran atomic.Int32
	var registered []Check
	for ci := 0; ci < cats; ci++ {
		for ki := 0; ki < perCat; ki++ {
			cat := fmt.Sprintf("cat%02d", ci)
			id := fmt.Sprintf("%s.%03d", cat, ki)
			registered = append(registered, stubCheck{id: id, cat: cat, run: func(context.Context, *probe.Env) []report.Result {
				ran.Add(1)
				return []report.Result{{ID: id, Category: cat, Status: report.Pass}}
			}})
		}
	}
	for _, c := range registered {
		Register(c)
	}

	out := Run(context.Background(), nil)
	if got, want := len(out), cats*perCat; got != want {
		t.Fatalf("result count = %d, want %d", got, want)
	}
	if got := ran.Load(); got != int32(cats*perCat) {
		t.Fatalf("ran count = %d, want %d", got, cats*perCat)
	}
	if !sort.SliceIsSorted(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	}) {
		t.Fatalf("results not sorted by (category, id)")
	}
}

// TestRunPanicIsolatedToOneCheck confirms a single panicking check no longer
// terminates its siblings inside the same category. After A1 the recover is
// per check, not per category.
func TestRunPanicIsolatedToOneCheck(t *testing.T) {
	defer withEmptyRegistry(t)()

	good := stubCheck{id: "ok", cat: "shared", run: func(context.Context, *probe.Env) []report.Result {
		return []report.Result{{ID: "ok", Category: "shared", Status: report.Pass}}
	}}
	boom := stubCheck{id: "boom", cat: "shared", run: func(context.Context, *probe.Env) []report.Result {
		panic("kaboom")
	}}
	Register(good)
	Register(boom)

	out := Run(context.Background(), nil)
	var foundGood, foundPanic bool
	for _, r := range out {
		if r.ID == "ok" && r.Status == report.Pass {
			foundGood = true
		}
		if r.ID == "registry.panic" && r.Category == "shared" && r.Status == report.Fail {
			foundPanic = true
		}
	}
	if !foundGood {
		t.Fatalf("sibling check 'ok' must survive panic in same category: %+v", out)
	}
	if !foundPanic {
		t.Fatalf("panic must surface as registry.panic Fail: %+v", out)
	}
}
