// Package checkutil collapses the boilerplate that almost every check in
// internal/checks/* repeats: declaring an empty struct that exposes ID() /
// Category() / Run(); applying env.WithTimeout; opting out when --no-active
// is set; and turning a context-cancellation into a single Fail Result.
//
// Existing checks remain free to implement registry.Check directly. The
// migration target is to replace the two-method-and-a-struct shape with a
// call to Wrap that returns a value satisfying the same interface.
package checkutil

import (
	"context"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// RunFn is the per-check work function. It receives a (possibly already
// timeout-bounded) context and the shared probe.Env, and returns one or more
// report.Result values. Checks that return zero results are valid — the
// registry will simply contribute nothing for that check.
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

// Timeout makes Wrap call env.WithTimeout(parent) and pass the bounded
// context to fn (with cancel deferred). Without this option the parent
// context is passed through unchanged and the check is responsible for its
// own deadline management.
func Timeout() Option {
	return func(w *wrapped) { w.timeout = true }
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

	timeout bool
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
	if w.timeout && env != nil {
		var cancel context.CancelFunc
		ctx, cancel = env.WithTimeout(ctx)
		defer cancel()
	}
	return w.fn(ctx, env)
}

// FailErr converts a lookup error into a single Fail Result with the
// canonical "lookup error: <err>" evidence string. RFC refs are optional.
func FailErr(id, cat, title string, err error, rfcRefs ...string) report.Result {
	ev := "lookup error"
	if err != nil {
		ev = "lookup error: " + err.Error()
	}
	return report.Result{
		ID:       id,
		Category: cat,
		Title:    title,
		Status:   report.Fail,
		Evidence: ev,
		RFCRefs:  append([]string(nil), rfcRefs...),
	}
}

// FailCtx converts a ctx.Err() (typically context.Canceled or
// context.DeadlineExceeded) into a single Fail Result. Used by mid-flight
// cancellation gates: between two independent network round-trips inside a
// check, a `if err := ctx.Err(); err != nil { return checkutil.FailCtx(...) }`
// returns immediately with a clear evidence string instead of issuing a
// second, doomed lookup.
func FailCtx(id, cat, title string, err error, rfcRefs ...string) []report.Result {
	ev := "context cancelled"
	if err != nil {
		ev = "context: " + err.Error()
	}
	return []report.Result{{
		ID:       id,
		Category: cat,
		Title:    title,
		Status:   report.Fail,
		Evidence: ev,
		RFCRefs:  append([]string(nil), rfcRefs...),
	}}
}
