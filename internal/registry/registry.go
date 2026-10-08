// Package registry holds the registered checks and runs them.
//
// Categories run in parallel; checks within a category also run in parallel,
// bounded by maxChecksPerCategory. Checks run in no fixed order: only the
// order of the results Run returns is deterministic.
package registry

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// maxChecksPerCategory caps simultaneous in-flight checks within one
// category. Eight is enough to overlap I/O for the slowest categories (web,
// email). It does not cap the connections one host sees: categories run in
// parallel, and one check can open several connections.
const maxChecksPerCategory = 8

// Check is one registered audit. Checks run concurrently and in no fixed
// order, and Run can skip whole categories, so a check must never wait for
// another check to run. A check that needs data another check also uses
// calls the shared producer itself (one built on probe.Shared, such as
// email.EnsureDMARCWalk), which does the work once per scan for whichever
// check asks first. Reading a cache entry that only another check fills
// would see it only when that check happened to run first.
type Check interface {
	// ID names the check; Register rejects an ID that is already registered.
	ID() string
	// Category groups the check's results; Options.Keep selects by it.
	Category() string
	Run(ctx context.Context, env *probe.Env) []report.Result
}

// Options tune one Run.
type Options struct {
	// Keep reports whether to run the checks in category; nil runs every
	// category.
	Keep func(category string) bool
	// OnDone, when not nil, is called exactly once per check Run runs, from
	// that check's goroutine, after the check's results (or its
	// registry.panic.<check ID> result) have been recorded. Calls therefore
	// arrive concurrently, and every call returns before Run does. The check
	// keeps its worker slot until OnDone returns, so a slow OnDone delays the
	// next check in its category.
	OnDone func(Check)
}

// checksMu guards the global checks slice. Register is called from init()
// (single-threaded at program start) and All / Run may be called from test
// code concurrently, so the lock is cheap insurance against a race.
var (
	checksMu sync.RWMutex
	checks   []Check
)

// Register adds a check to the global registry. Called from package init().
// It panics when a check with the same ID is already registered: two checks
// under one ID give results that a baseline cannot tell apart.
func Register(c Check) {
	checksMu.Lock()
	defer checksMu.Unlock()
	for _, have := range checks {
		if have.ID() == c.ID() {
			panic(fmt.Sprintf("registry: register check %q: the ID is already registered; "+
				"give each check its own ID", c.ID()))
		}
	}
	checks = append(checks, c)
}

// All returns the registered checks (defensive copy under read lock).
func All() []Check {
	checksMu.RLock()
	defer checksMu.RUnlock()
	out := make([]Check, len(checks))
	copy(out, checks)
	return out
}

// Categories returns the sorted, deduplicated categories of the registered
// checks.
func Categories() []string {
	checksMu.RLock()
	defer checksMu.RUnlock()
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		out = append(out, c.Category())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Run executes the registered checks of every category opts.Keep accepts.
// Each category gets its own goroutine, and within a category checks fan
// out across a bounded worker pool sized by maxChecksPerCategory.
// Panic-recover is per check so a single buggy check cannot tank its
// siblings; the panic is recorded as a registry.panic.<check ID> Fail
// result. After the scan, Run adds a dns.resolver.unreachable Fail when no
// DNS query got an answer, whatever opts.Keep accepts. The final result slice
// is sorted by category, id, title and evidence for stable output.
func Run(ctx context.Context, env *probe.Env, opts Options) []report.Result {
	byCat := checksByCategory(opts.Keep)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		out     []report.Result
		appendR = func(rs ...report.Result) {
			if len(rs) == 0 {
				return
			}
			mu.Lock()
			out = append(out, rs...)
			mu.Unlock()
		}
	)
	for cat, list := range byCat {
		wg.Add(1)
		go func(cat string, list []Check) {
			defer wg.Done()
			// Bounded worker pool: every check holds one semaphore slot for
			// the duration of its Run, capping in-flight checks per category.
			sem := make(chan struct{}, maxChecksPerCategory)
			var inner sync.WaitGroup
			for _, c := range list {
				inner.Add(1)
				go func(c Check) {
					defer inner.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					// Deferred before the recovery below, so it runs after the
					// check's results or its panic result are recorded.
					if opts.OnDone != nil {
						defer opts.OnDone(c)
					}
					// Per-check panic recovery so one bad check cannot abort
					// its siblings. The recovered value becomes a Fail result
					// tagged with the check's own category and id.
					defer func() {
						if r := recover(); r != nil {
							appendR(panicResult(c, r))
						}
					}()
					appendR(c.Run(ctx, env)...)
				}(c)
			}
			inner.Wait()
		}(cat, list)
	}
	wg.Wait()

	appendR(resolverUnreachable(ctx, env)...)
	slices.SortStableFunc(out, compareResults)
	return out
}

// checksByCategory groups the registered checks by category, leaving out
// the categories keep rejects. A nil keep keeps every category. The
// registry is snapshotted under the read lock (through All), so a late
// Register cannot change the checks a Run iterates.
func checksByCategory(keep func(category string) bool) map[string][]Check {
	byCat := map[string][]Check{}
	for _, c := range All() {
		if keep == nil || keep(c.Category()) {
			byCat[c.Category()] = append(byCat[c.Category()], c)
		}
	}
	return byCat
}

// IDs of the results Run adds about the run as a whole rather than about
// one check's verdict on the target.
const (
	resolverUnreachableID = "dns.resolver.unreachable"
	panicIDPrefix         = "registry.panic."
)

// RunLevel reports whether r is a result Run adds about the run as a whole:
// the dns.resolver.unreachable Fail or a registry.panic.<check ID> Fail.
// Either one alone decides the exit code, so a filter of the report by
// check ID must keep them.
func RunLevel(r report.Result) bool {
	return r.ID == resolverUnreachableID || strings.HasPrefix(r.ID, panicIDPrefix)
}

// panicResult is the Fail that replaces the results of check c, which
// panicked with v. Its ID names the check, so two panics never share an ID
// and a baseline attributes each one to its own check.
func panicResult(c Check, v any) report.Result {
	return report.Result{
		ID:       panicIDPrefix + c.ID(),
		Category: c.Category(),
		Title:    "check panic recovered: " + c.ID(),
		Status:   report.Fail,
		Evidence: fmt.Sprintf("panic: %v", v),
	}
}

// resolverUnreachable returns the dns.resolver.unreachable Fail when the
// scan sent DNS queries and none of them was answered, because the resolver
// sent no reply or replied only with errors such as SERVFAIL and REFUSED.
// Every result that needed DNS is then inconclusive, and without this Fail
// such a run would exit 0. A scan that ctx cut short gets none: its queries
// failed because it was cancelled.
func resolverUnreachable(ctx context.Context, env *probe.Env) []report.Result {
	if env == nil || env.DNS == nil || ctx.Err() != nil {
		return nil
	}
	sent, replied, answered := env.DNS.Health()
	if sent == 0 || answered > 0 {
		return nil
	}
	evidence := fmt.Sprintf("none of the %d DNS queries the scan sent was answered", sent)
	if replied > 0 {
		evidence = fmt.Sprintf("the resolver replied to %d of the %d DNS queries the scan "+
			"sent, each time with an error rcode such as SERVFAIL or REFUSED", replied, sent)
	}
	return []report.Result{{
		ID:       resolverUnreachableID,
		Category: "DNS",
		Title:    "DNS resolver answered the scan's queries",
		Status:   report.Fail,
		Evidence: evidence + ", so every result that needed DNS is inconclusive",
		Remediation: "Check that this host can reach the resolver and that the resolver " +
			"serves this host, or pass one that does (e.g. --resolver cloudflare-dot), " +
			"then run bedrock again.",
	}}
}

// compareResults orders results by category, then id. Title and evidence
// break ties, so the order never depends on which check finished first.
func compareResults(a, b report.Result) int {
	return cmp.Or(
		cmp.Compare(a.Category, b.Category),
		cmp.Compare(a.ID, b.ID),
		cmp.Compare(a.Title, b.Title),
		cmp.Compare(a.Evidence, b.Evidence),
	)
}
