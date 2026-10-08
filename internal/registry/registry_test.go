package registry

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	return swapEmptyRegistry()
}

// swapEmptyRegistry is the helper-free variant used by benchmarks (which
// take *testing.B, not *testing.T). It returns the same restore closure.
func swapEmptyRegistry() func() {
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

	out := Run(context.Background(), nil, nil)
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

	out := Run(context.Background(), nil, nil)
	// good must survive; boom must be converted to a registry.panic Fail.
	if !hasResult(out, "good", "cat1", report.Pass) {
		t.Fatalf("expected 'good' result to survive panic in other category: %+v", out)
	}
	if !hasResult(out, "registry.panic", "cat2", report.Fail) {
		t.Fatalf("panic should be converted to registry.panic Fail: %+v", out)
	}
}

// hasResult reports whether out holds a result with this ID, category and
// status.
func hasResult(out []report.Result, id, cat string, status report.Status) bool {
	return slices.ContainsFunc(out, func(r report.Result) bool {
		return r.ID == id && r.Category == cat && r.Status == status
	})
}

func TestRunEmptyRegistry(t *testing.T) {
	defer withEmptyRegistry(t)()
	out := Run(context.Background(), nil, nil)
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

	out := Run(context.Background(), nil, nil)
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

	out := Run(context.Background(), nil, nil)
	if !hasResult(out, "ok", "shared", report.Pass) {
		t.Fatalf("sibling check 'ok' must survive panic in same category: %+v", out)
	}
	if !hasResult(out, "registry.panic", "shared", report.Fail) {
		t.Fatalf("panic must surface as registry.panic Fail: %+v", out)
	}
}

// registerTrackedChecks registers three categories of four checks, the first
// in each category panicking. Each check calls finish just before it returns
// or panics. It returns the check IDs.
func registerTrackedChecks(finish func(id string)) []string {
	var ids []string
	for ci := 0; ci < 3; ci++ {
		for ki := 0; ki < 4; ki++ {
			cat := fmt.Sprintf("cat%d", ci)
			id := fmt.Sprintf("%s.%d", cat, ki)
			ids = append(ids, id)
			run := func(context.Context, *probe.Env) []report.Result {
				finish(id)
				if ki == 0 {
					panic("kaboom")
				}
				return []report.Result{{ID: id, Category: cat, Status: report.Pass}}
			}
			Register(stubCheck{id: id, cat: cat, run: run})
		}
	}
	return ids
}

// TestRunCallsOnDoneOncePerCheck checks that onDone sees every check exactly
// once, panicking ones included, only after the check has finished and any
// panic has been recorded, and that even a slow callback has returned by the
// time Run does.
func TestRunCallsOnDoneOncePerCheck(t *testing.T) {
	defer withEmptyRegistry(t)()

	var (
		mu       sync.Mutex
		finished = map[string]bool{}
		calls    = map[string]int{}
		problems []string
	)
	ids := registerTrackedChecks(func(id string) {
		mu.Lock()
		defer mu.Unlock()
		finished[id] = true
	})

	out := Run(context.Background(), nil, func(c Check) {
		// recover is non-nil only if onDone runs while the check's panic is
		// still unwinding, that is, before Run has recorded it.
		unwinding := recover() != nil
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		if unwinding {
			problems = append(problems, c.ID()+" before its panic was recorded")
		}
		if !finished[c.ID()] {
			problems = append(problems, c.ID()+" before it finished")
		}
		calls[c.ID()]++
	})

	mu.Lock()
	defer mu.Unlock()
	if len(problems) > 0 {
		t.Errorf("onDone ran too early: %v", problems)
	}
	want := map[string]int{}
	for _, id := range ids {
		want[id] = 1
	}
	if !maps.Equal(calls, want) {
		t.Errorf("onDone calls per check when Run returned = %v, want one each", calls)
	}
	if !hasResult(out, "registry.panic", "cat0", report.Fail) || len(out) != len(ids) {
		t.Errorf("want one result per check, panics included: %+v", out)
	}
}

// TestRunCallsOnDoneAsEachCheckFinishes checks that onDone reports a check
// while others are still running, not after the whole run: the slow check
// waits for onDone to report the fast one.
func TestRunCallsOnDoneAsEachCheckFinishes(t *testing.T) {
	defer withEmptyRegistry(t)()

	fastDone := make(chan struct{})
	var sawFast atomic.Bool
	runFast := func(context.Context, *probe.Env) []report.Result {
		return []report.Result{{ID: "fast", Category: "a", Status: report.Pass}}
	}
	runSlow := func(context.Context, *probe.Env) []report.Result {
		select {
		case <-fastDone:
			sawFast.Store(true)
		case <-time.After(5 * time.Second):
		}
		return []report.Result{{ID: "slow", Category: "b", Status: report.Pass}}
	}
	Register(stubCheck{id: "fast", cat: "a", run: runFast})
	Register(stubCheck{id: "slow", cat: "b", run: runSlow})

	Run(context.Background(), nil, func(c Check) {
		if c.ID() == "fast" {
			close(fastDone)
		}
	})
	if !sawFast.Load() {
		t.Fatal("onDone(fast) did not run while the slow check was still running")
	}
}

// BenchmarkRunCategoryParallel measures wall-clock time for a single Run
// over a category with checks that each sleep 50ms — modelling I/O-bound
// checks waiting on DNS or HTTP. With maxChecksPerCategory=8 the wall-clock
// should be ~ ceil(N/8) * 50ms; the pre-A1 sequential loop would have been
// N * 50ms.
func BenchmarkRunCategoryParallel(b *testing.B) {
	defer swapEmptyRegistry()()

	const sleep = 50 * time.Millisecond
	const checks = 16
	for i := 0; i < checks; i++ {
		id := fmt.Sprintf("bench.%02d", i)
		Register(stubCheck{id: id, cat: "B", run: func(ctx context.Context, _ *probe.Env) []report.Result {
			select {
			case <-ctx.Done():
			case <-time.After(sleep):
			}
			return []report.Result{{ID: id, Category: "B", Status: report.Pass}}
		}})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Run(context.Background(), nil, nil)
	}
}
