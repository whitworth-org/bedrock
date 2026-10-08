package registry

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

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

	out := Run(context.Background(), nil, Options{})
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

	out := Run(context.Background(), nil, Options{})
	// good must survive; boom must be converted to a registry.panic.boom Fail.
	var foundGood, foundPanic bool
	for _, r := range out {
		if r.ID == "good" && r.Status == report.Pass {
			foundGood = true
		}
		if r.ID == "registry.panic.boom" && r.Category == "cat2" && r.Status == report.Fail {
			foundPanic = true
		}
	}
	if !foundGood {
		t.Fatalf("expected 'good' result to survive panic in other category: %+v", out)
	}
	if !foundPanic {
		t.Fatalf("panic should be converted to registry.panic.boom Fail: %+v", out)
	}
}

func TestRunEmptyRegistry(t *testing.T) {
	defer withEmptyRegistry(t)()
	out := Run(context.Background(), nil, Options{})
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

	out := Run(context.Background(), nil, Options{})
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

	out := Run(context.Background(), nil, Options{})
	var foundGood, foundPanic bool
	for _, r := range out {
		if r.ID == "ok" && r.Status == report.Pass {
			foundGood = true
		}
		if r.ID == "registry.panic.boom" && r.Category == "shared" && r.Status == report.Fail {
			foundPanic = true
		}
	}
	if !foundGood {
		t.Fatalf("sibling check 'ok' must survive panic in same category: %+v", out)
	}
	if !foundPanic {
		t.Fatalf("panic must surface as registry.panic.boom Fail: %+v", out)
	}
}

func noResults(context.Context, *probe.Env) []report.Result { return nil }

// TestRegisterRejectsDuplicateID pins that registering a second check under
// an ID already registered panics, naming the ID, and leaves the registry
// as it was.
func TestRegisterRejectsDuplicateID(t *testing.T) {
	defer withEmptyRegistry(t)()

	Register(stubCheck{id: "dup", cat: "x", run: noResults})
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("registering a duplicate check ID did not panic")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, `"dup"`) {
			t.Errorf("panic %q does not name the duplicate ID", msg)
		}
		if n := len(All()); n != 1 {
			t.Errorf("registry holds %d checks after the rejected duplicate, want 1", n)
		}
	}()
	Register(stubCheck{id: "dup", cat: "y", run: noResults})
}

// TestRunGivesEachPanicItsOwnID pins that two checks panicking in one
// category yield one FAIL each, under an ID that names the check, so a
// baseline holding one panic cannot hide the other.
func TestRunGivesEachPanicItsOwnID(t *testing.T) {
	defer withEmptyRegistry(t)()

	boom := func(context.Context, *probe.Env) []report.Result { panic("kaboom") }
	for _, id := range []string{"web.b", "web.a"} {
		Register(stubCheck{id: id, cat: "WWW", run: boom})
	}
	out := Run(context.Background(), nil, Options{})
	var ids []string
	for _, r := range out {
		if r.Status != report.Fail || r.Category != "WWW" {
			t.Errorf("panic result %+v: want a WWW FAIL", r)
		}
		ids = append(ids, r.ID)
	}
	if want := []string{"registry.panic.web.a", "registry.panic.web.b"}; !slices.Equal(ids, want) {
		t.Fatalf("result IDs = %v, want %v", ids, want)
	}
}

// TestRunSkipsCategoriesKeepRejects pins that Run never calls the checks of
// a category Keep rejects, and runs every check of the others.
func TestRunSkipsCategoriesKeepRejects(t *testing.T) {
	defer withEmptyRegistry(t)()

	var mu sync.Mutex
	ran := map[string]int{}
	for _, cat := range []string{"DNS", "WWW", "Email"} {
		for i := range 3 {
			id := fmt.Sprintf("%s.%d", strings.ToLower(cat), i)
			run := func(context.Context, *probe.Env) []report.Result {
				mu.Lock()
				ran[cat]++
				mu.Unlock()
				return []report.Result{{ID: id, Category: cat, Status: report.Pass}}
			}
			Register(stubCheck{id: id, cat: cat, run: run})
		}
	}

	notWWW := func(cat string) bool { return cat != "WWW" }
	out := Run(context.Background(), nil, Options{Keep: notWWW})
	if want := map[string]int{"DNS": 3, "Email": 3}; !reflect.DeepEqual(ran, want) {
		t.Errorf("checks run per category = %v, want %v", ran, want)
	}
	for _, r := range out {
		if r.Category == "WWW" {
			t.Errorf("result %q from a category Keep rejected", r.ID)
		}
	}
	if len(out) != 6 {
		t.Errorf("got %d results, want 6: %+v", len(out), out)
	}
}

// TestRunBreaksIDTiesByTitleThenEvidence pins the order of results sharing
// a category and ID: by title, then evidence, whatever order the checks
// returned them in.
func TestRunBreaksIDTiesByTitleThenEvidence(t *testing.T) {
	defer withEmptyRegistry(t)()

	tie := func(title, evidence string) report.Result {
		return report.Result{ID: "dns.x", Category: "DNS", Title: title, Evidence: evidence}
	}
	run := func(context.Context, *probe.Env) []report.Result {
		return []report.Result{tie("b", "1"), tie("a", "2"), tie("a", "1")}
	}
	Register(stubCheck{id: "dns.x", cat: "DNS", run: run})
	out := Run(context.Background(), nil, Options{})
	want := []report.Result{tie("a", "1"), tie("a", "2"), tie("b", "1")}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("results = %+v\nwant %+v", out, want)
	}
}

// blackHoleResolver returns the address of a loopback UDP socket that never
// reads, so every query sent to it times out unanswered.
func blackHoleResolver(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// nxdomainResolver starts a loopback UDP resolver that answers every query
// with NXDOMAIN and returns its address.
func nxdomainResolver(t *testing.T) string {
	t.Helper()
	return rcodeResolver(t, mdns.RcodeNameError)
}

// rcodeResolver starts a loopback UDP resolver that replies to every query
// with rcode and returns its address.
func rcodeResolver(t *testing.T, rcode int) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetRcode(req, rcode)
		_ = w.WriteMsg(resp)
	})
	srv := &mdns.Server{PacketConn: pc, Handler: handler}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fake DNS server did not start within 2s")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// lookupCheck is a WWW check that sends one A query through env.DNS.
var lookupCheck = stubCheck{id: "web.lookup", cat: "WWW",
	run: func(ctx context.Context, env *probe.Env) []report.Result {
		_, _ = env.DNS.LookupA(ctx, "www.example.test")
		return nil
	}}

func findID(results []report.Result, id string) (report.Result, bool) {
	i := slices.IndexFunc(results, func(r report.Result) bool { return r.ID == id })
	if i < 0 {
		return report.Result{}, false
	}
	return results[i], true
}

// TestRunReportsUnreachableResolver pins the run-level FAIL for a scan whose
// DNS queries all went unanswered. It is reported in DNS even though Keep
// rejects DNS, so --only and --exclude cannot hide a dead resolver.
func TestRunReportsUnreachableResolver(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	defer withEmptyRegistry(t)()
	Register(lookupCheck)

	env := probe.NewEnv("example.test", 100*time.Millisecond, false, blackHoleResolver(t))
	notDNS := func(cat string) bool { return cat != "DNS" }
	out := Run(context.Background(), env, Options{Keep: notDNS})
	r, ok := findID(out, "dns.resolver.unreachable")
	if !ok {
		t.Fatalf("no dns.resolver.unreachable result: %+v", out)
	}
	if r.Category != "DNS" || r.Status != report.Fail || r.Remediation == "" {
		t.Errorf("result = %+v, want a DNS FAIL with a remediation", r)
	}
	if want := "none of the 1 DNS queries"; !strings.Contains(r.Evidence, want) {
		t.Errorf("evidence %q does not contain %q", r.Evidence, want)
	}
	if err := report.CheckRemediation(r.Remediation); err != nil {
		t.Error(err)
	}
}

// TestRunReportsResolverAnsweringOnlyErrors pins the run-level FAIL for a
// resolver that replies to every query, but only with SERVFAIL or REFUSED,
// as one that refuses this host does: it answers nothing either.
func TestRunReportsResolverAnsweringOnlyErrors(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	for _, rcode := range []int{mdns.RcodeServerFailure, mdns.RcodeRefused} {
		t.Run(mdns.RcodeToString[rcode], func(t *testing.T) {
			defer withEmptyRegistry(t)()
			Register(lookupCheck)

			env := probe.NewEnv("example.test", time.Second, false, rcodeResolver(t, rcode))
			r, ok := findID(Run(context.Background(), env, Options{}), "dns.resolver.unreachable")
			if !ok || r.Status != report.Fail {
				t.Fatalf("dns.resolver.unreachable = %+v (found %v), want a FAIL", r, ok)
			}
			if want := "replied to 1 of the 1 DNS queries"; !strings.Contains(r.Evidence, want) {
				t.Errorf("evidence %q does not contain %q", r.Evidence, want)
			}
		})
	}
}

// TestRunOmitsUnreachableResolver pins that the run-level FAIL needs a scan
// that sent DNS queries, had none answered and was not cancelled.
func TestRunOmitsUnreachableResolver(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	blackHole := blackHoleResolver(t)
	cases := []struct {
		name     string
		ctx      context.Context
		resolver string // "" leaves the Env without a DNS client
		check    stubCheck
	}{
		{"query answered", context.Background(), nxdomainResolver(t), lookupCheck},
		{"no query sent", context.Background(), blackHole,
			stubCheck{id: "web.quiet", cat: "WWW", run: noResults}},
		{"scan cancelled", cancelled, blackHole, lookupCheck},
		{"no DNS client", context.Background(), "",
			stubCheck{id: "web.quiet", cat: "WWW", run: noResults}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer withEmptyRegistry(t)()
			Register(c.check)
			env := &probe.Env{Target: "example.test"}
			if c.resolver != "" {
				env = probe.NewEnv("example.test", 100*time.Millisecond, false, c.resolver)
			}
			if r, ok := findID(Run(c.ctx, env, Options{}), "dns.resolver.unreachable"); ok {
				t.Errorf("unexpected %+v", r)
			}
		})
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
		_ = Run(context.Background(), nil, Options{})
	}
}
