// Package registry holds the ordered set of checks and runs them.
//
// Categories run in parallel; checks within a category run sequentially.
// This keeps per-host load low and output deterministic.
package registry

import (
	"context"
	"sort"
	"sync"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

type Check interface {
	ID() string
	Category() string
	Run(ctx context.Context, env *probe.Env) []report.Result
}

var checks []Check

// Register adds a check to the global registry. Called from package init().
func Register(c Check) { checks = append(checks, c) }

// All returns the registered checks (defensive copy).
func All() []Check {
	out := make([]Check, len(checks))
	copy(out, checks)
	return out
}

// Run executes every registered check, grouping by category for parallelism.
func Run(ctx context.Context, env *probe.Env) []report.Result {
	byCat := map[string][]Check{}
	for _, c := range checks {
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
			for _, c := range list {
				local = append(local, c.Run(ctx, env)...)
			}
			mu.Lock()
			out = append(out, local...)
			mu.Unlock()
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
