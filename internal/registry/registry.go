// Package registry holds the ordered set of checks and runs them.
//
// Categories run in parallel; checks within a category run sequentially.
// This keeps per-host load low and output deterministic.
package registry

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

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

// Run executes every registered check, grouping by category for parallelism.
// A per-category goroutine recovers from panics so a single buggy check
// cannot abort the whole scan — the panicking check is reported as a Fail
// result with evidence naming the recovered value.
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
		mu  sync.Mutex
		wg  sync.WaitGroup
		out []report.Result
	)
	for cat, list := range byCat {
		wg.Add(1)
		go func(cat string, list []Check) {
			defer wg.Done()
			var local []report.Result
			defer func() {
				if r := recover(); r != nil {
					local = append(local, report.Result{
						ID:       "registry.panic",
						Category: cat,
						Title:    "check panic recovered",
						Status:   report.Fail,
						Evidence: fmt.Sprintf("panic: %v", r),
					})
				}
				mu.Lock()
				out = append(out, local...)
				mu.Unlock()
			}()
			for _, c := range list {
				local = append(local, c.Run(ctx, env)...)
			}
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
