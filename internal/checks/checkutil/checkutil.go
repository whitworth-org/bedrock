// Package checkutil collapses the boilerplate that almost every check in
// internal/checks/* repeats: declaring an empty struct that exposes ID() /
// Category() / Run(); opting out when --no-active is set; reporting a probe
// that could not complete; probing several hosts at once without losing a
// panic to a worker goroutine; and bounding the lists that evidence names.
//
// Existing checks remain free to implement registry.Check directly. The
// migration target is to replace the two-method-and-a-struct shape with a
// call to Wrap that returns a value satisfying the same interface.
package checkutil

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// RunFn is the per-check work function. It receives the registry's context
// and the shared probe.Env, and returns one or more report.Result values.
// Checks that return zero results are valid — the registry will simply
// contribute nothing for that check.
type RunFn func(ctx context.Context, env *probe.Env) []report.Result

// Option mutates the wrapped check at construction time. Options compose
// left-to-right; later options override earlier ones for the same field.
type Option func(*wrapped)

// RequireActive makes the wrapped check return a single NotApplicable
// Result when env.Active is false (i.e. the operator passed --no-active).
// Title and rfcRefs are used to build that Result so the output is
// indistinguishable from a hand-rolled gate.
func RequireActive(title string, rfcRefs ...string) Option {
	return func(w *wrapped) {
		w.requireActive = true
		w.inactiveTitle = title
		w.inactiveRefs = append(w.inactiveRefs[:0:0], rfcRefs...)
	}
}

// Wrap constructs a registry.Check-shaped value (returned as the unexported
// `wrapped` type) from an id, category, run function, and options. The
// returned value implements ID() / Category() / Run() so it can be passed
// straight to registry.Register.
func Wrap(id, cat string, fn RunFn, opts ...Option) Check {
	w := &wrapped{id: id, cat: cat, fn: fn}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Check is the minimal interface registry.Register accepts. Defined here
// (instead of importing the registry interface) to avoid an import cycle —
// registry imports the report package, and the per-check packages import
// registry; checkutil sits below all of them.
type Check interface {
	ID() string
	Category() string
	Run(ctx context.Context, env *probe.Env) []report.Result
}

type wrapped struct {
	id  string
	cat string
	fn  RunFn

	requireActive bool
	inactiveTitle string
	inactiveRefs  []string
}

func (w *wrapped) ID() string       { return w.id }
func (w *wrapped) Category() string { return w.cat }

func (w *wrapped) Run(ctx context.Context, env *probe.Env) []report.Result {
	if w.requireActive && env != nil && !env.Active {
		return []report.Result{{
			ID:       w.id,
			Category: w.cat,
			Title:    w.inactiveTitle,
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  append([]string(nil), w.inactiveRefs...),
		}}
	}
	return w.fn(ctx, env)
}

// inconclusiveStatus is the status of a result whose probe could not
// complete. It is not FAIL: the target's posture is unknown, not wrong.
// Change it here and nowhere else.
const inconclusiveStatus = report.Warn

// Inconclusive returns base reworked into the result of a probe that could
// not complete, such as a timeout, an SSRF denylist refusal, a reset
// connection or an unreachable network (see probe.IsProbeFailure): status
// inconclusiveStatus, evidence "could not determine: <err>" and no
// remediation, since there is nothing for the operator to fix. base
// supplies the ID, category, title and RFC references; err must be non-nil.
func Inconclusive(base report.Result, err error) report.Result {
	base.Status = inconclusiveStatus
	base.Evidence = "could not determine: " + err.Error()
	base.Remediation = ""
	return base
}

// ErrSharedProbePanicked is wrapped by the error a check gets for a probe
// it shares with other checks through probe.Shared when the check that ran
// the probe panicked.
var ErrSharedProbePanicked = errors.New(
	"did not complete in another check; see its registry.panic result")

// Incomplete reports whether err, returned by a probe that ran under ctx,
// means the probe could not complete, so the target's posture is unknown: a
// probe failure (probe.IsProbeFailure), a shared probe lost to a panic
// (ErrSharedProbePanicked), or ctx ending first, as when the operator
// interrupts the scan. Grade such an error with Inconclusive, never as a
// verdict on the target.
func Incomplete(ctx context.Context, err error) bool {
	return probe.IsProbeFailure(err) || errors.Is(err, ErrSharedProbePanicked) ||
		ctx.Err() != nil
}

// MaxListed bounds how many items an evidence string names: a hostile zone,
// site or logo can supply thousands.
const MaxListed = 10

// ListBounded joins the first MaxListed items with sep and counts the rest,
// as in "a, b, and 3 more".
func ListBounded(items []string, sep string) string {
	if len(items) <= MaxListed {
		return strings.Join(items, sep)
	}
	return fmt.Sprintf("%s%sand %d more", strings.Join(items[:MaxListed], sep), sep,
		len(items)-MaxListed)
}

// ForEach calls fn(i) for each i in [0, n), at most limit calls at a time,
// and returns once every call has returned. A panic in fn is re-raised on
// the calling goroutine after the other calls finish: the registry recovers
// a check's panics only on the check's own goroutine, and a panic left on a
// worker goroutine would end the whole scan.
func ForEach(n, limit int, fn func(i int)) {
	sem := make(chan struct{}, limit)
	var (
		wg       sync.WaitGroup
		once     sync.Once
		panicked any
	)
	for i := range n {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					once.Do(func() { panicked = r })
				}
			}()
			fn(i)
		})
	}
	wg.Wait()
	if panicked != nil {
		panic(panicked)
	}
}
