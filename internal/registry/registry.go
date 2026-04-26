// Package registry holds the ordered set of checks and runs them.
//
// Categories run in parallel; checks within a category also run in parallel,
// bounded by maxChecksPerCategory. This keeps per-host load predictable and
// output deterministic.
package registry

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// maxChecksPerCategory caps simultaneous in-flight checks within one
// category. Eight is enough to overlap I/O for the slowest categories (web,
// email) without flooding a single target with more sockets than a normal
// browser would open.
const maxChecksPerCategory = 8

type Check interface {
	ID() string
	Category() string
	Run(ctx context.Context, env *probe.Env) []report.Result
}

// checksMu guards the global checks slice. Register is called from init()
// (single-threaded at program start) and All / Run may be called from test
// code concurrently, so the lock is cheap insurance against a race.
var (
	checksMu sync.RWMutex
	checks   []Check
)

// Register adds a check to the global registry. Called from package init().
func Register(c Check) {
	checksMu.Lock()
	defer checksMu.Unlock()
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

// Run executes every registered check. Each category gets its own goroutine,
// and within a category checks fan out across a bounded worker pool sized by
// maxChecksPerCategory. Panic-recover is per check so a single buggy check
// cannot tank its siblings; the panic is recorded as a registry.panic Fail
// result. The final result slice is sorted by (category, id) for stable
// output.
func Run(ctx context.Context, env *probe.Env) []report.Result {
	// Snapshot the registry under the read lock so later Register calls
	// (shouldn't happen — init() runs before Run — but cheap to guard
	// against) cannot mutate the slice we iterate.
	checksMu.RLock()
	snapshot := make([]Check, len(checks))
	copy(snapshot, checks)
	checksMu.RUnlock()

	byCat := map[string][]Check{}
	for _, c := range snapshot {
		byCat[c.Category()] = append(byCat[c.Category()], c)
	}

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
					// Per-check panic recovery so one bad check cannot abort
					// its siblings. The recovered value becomes a Fail result
					// tagged with the check's own category and id.
					defer func() {
						if r := recover(); r != nil {
							appendR(report.Result{
								ID:       "registry.panic",
								Category: c.Category(),
								Title:    "check panic recovered: " + c.ID(),
								Status:   report.Fail,
								Evidence: fmt.Sprintf("panic: %v", r),
							})
						}
					}()
					appendR(c.Run(ctx, env)...)
				}(c)
			}
			inner.Wait()
		}(cat, list)
	}
	wg.Wait()

	// Stable order: by category, then ID.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}
