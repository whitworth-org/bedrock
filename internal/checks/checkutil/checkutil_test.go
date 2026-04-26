package checkutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestWrapBasic(t *testing.T) {
	t.Parallel()
	called := false
	c := Wrap("x.id", "x", func(ctx context.Context, env *probe.Env) []report.Result {
		called = true
		return []report.Result{{ID: "x.id", Category: "x", Status: report.Pass}}
	})
	if c.ID() != "x.id" || c.Category() != "x" {
		t.Fatalf("ID/Category: got %q/%q", c.ID(), c.Category())
	}
	got := c.Run(context.Background(), nil)
	if !called {
		t.Fatal("fn should have been invoked")
	}
	if len(got) != 1 || got[0].Status != report.Pass {
		t.Fatalf("unexpected results: %+v", got)
	}
}

func TestRequireActiveTriggersNotApplicable(t *testing.T) {
	t.Parallel()
	called := false
	c := Wrap("x.id", "x",
		func(ctx context.Context, env *probe.Env) []report.Result {
			called = true
			return nil
		},
		RequireActive("ActiveTitle", "RFC X"),
	)
	env := probe.NewEnv("example.org", time.Second, false /* active */, "")
	got := c.Run(context.Background(), env)
	if called {
		t.Fatal("fn must not run when env.Active=false")
	}
	if len(got) != 1 || got[0].Status != report.NotApplicable {
		t.Fatalf("expected single N/A result, got %+v", got)
	}
	if got[0].Title != "ActiveTitle" {
		t.Fatalf("title = %q, want ActiveTitle", got[0].Title)
	}
	if len(got[0].RFCRefs) != 1 || got[0].RFCRefs[0] != "RFC X" {
		t.Fatalf("rfc refs = %+v", got[0].RFCRefs)
	}
}

func TestRequireActivePassThroughWhenActive(t *testing.T) {
	t.Parallel()
	called := false
	c := Wrap("x.id", "x",
		func(ctx context.Context, env *probe.Env) []report.Result {
			called = true
			return []report.Result{{ID: "x.id", Category: "x", Status: report.Pass}}
		},
		RequireActive("ActiveTitle"),
	)
	env := probe.NewEnv("example.org", time.Second, true /* active */, "")
	got := c.Run(context.Background(), env)
	if !called {
		t.Fatal("fn must run when env.Active=true")
	}
	if len(got) != 1 || got[0].Status != report.Pass {
		t.Fatalf("expected single Pass result, got %+v", got)
	}
}

func TestTimeoutBoundsContext(t *testing.T) {
	t.Parallel()
	var sawDeadline bool
	c := Wrap("x.id", "x",
		func(ctx context.Context, env *probe.Env) []report.Result {
			_, ok := ctx.Deadline()
			sawDeadline = ok
			return nil
		},
		Timeout(),
	)
	env := probe.NewEnv("example.org", 10*time.Millisecond, true, "")
	c.Run(context.Background(), env)
	if !sawDeadline {
		t.Fatal("Timeout option should have attached a deadline to ctx")
	}
}

func TestFailErrSetsEvidence(t *testing.T) {
	t.Parallel()
	r := FailErr("id", "cat", "Title", errors.New("nope"), "RFC 1")
	if r.Status != report.Fail {
		t.Fatalf("status = %v, want Fail", r.Status)
	}
	if r.Evidence != "lookup error: nope" {
		t.Fatalf("evidence = %q", r.Evidence)
	}
	if len(r.RFCRefs) != 1 || r.RFCRefs[0] != "RFC 1" {
		t.Fatalf("rfc refs = %+v", r.RFCRefs)
	}
}

func TestFailErrNilError(t *testing.T) {
	t.Parallel()
	r := FailErr("id", "cat", "Title", nil)
	if r.Evidence != "lookup error" {
		t.Fatalf("evidence = %q", r.Evidence)
	}
}

func TestFailCtx(t *testing.T) {
	t.Parallel()
	rs := FailCtx("id", "cat", "Title", context.Canceled, "RFC 1")
	if len(rs) != 1 || rs[0].Status != report.Fail {
		t.Fatalf("expected single Fail result, got %+v", rs)
	}
	if rs[0].Evidence != "context: context canceled" {
		t.Fatalf("evidence = %q", rs[0].Evidence)
	}
}
