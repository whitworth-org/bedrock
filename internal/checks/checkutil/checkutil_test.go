package checkutil

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
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

// TestInconclusive: a probe that could not complete is a WARN, never a
// FAIL, keeps its identity, quotes the error and offers no remediation,
// because there is nothing for the operator to fix.
func TestInconclusive(t *testing.T) {
	t.Parallel()
	base := report.Result{
		ID: "x.id", Category: "x", Title: "Title",
		Status:      report.Fail,
		Evidence:    "stale evidence",
		Remediation: "stale remediation",
		RFCRefs:     []string{"RFC 1"},
	}
	got := Inconclusive(base, errors.New("dial tcp 192.0.2.1:443: i/o timeout"))

	want := report.Result{
		ID: "x.id", Category: "x", Title: "Title",
		Status:   report.Warn,
		Evidence: "could not determine: dial tcp 192.0.2.1:443: i/o timeout",
		RFCRefs:  []string{"RFC 1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Inconclusive = %+v, want %+v", got, want)
	}
	if err := report.CheckRemediation(got.Remediation); err != nil {
		t.Error(err)
	}
}

// TestIncomplete: a probe failure, a shared probe lost to a panic and an
// ended context each mean the probe could not complete; the target's own
// answer does not.
func TestIncomplete(t *testing.T) {
	t.Parallel()
	live := context.Background()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	blocked := &probe.BlockedAddrError{Addr: netip.MustParseAddr("10.0.0.1"), Reason: "private"}
	answer := errors.New("HTTP 404")
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"answer", live, answer, false},
		{"probe failure", live, fmt.Errorf("dial: %w", blocked), true},
		{"shared probe panicked", live, fmt.Errorf("fetch %w", ErrSharedProbePanicked), true},
		{"context ended", ended, answer, true},
	}
	for _, tc := range cases {
		if got := Incomplete(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: Incomplete(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// TestListBounded: evidence names at most MaxListed items and counts the
// rest after the same separator.
func TestListBounded(t *testing.T) {
	t.Parallel()
	items := make([]string, 12)
	for i := range items {
		items[i] = fmt.Sprintf("i%02d", i)
	}
	cases := []struct {
		n    int
		sep  string
		want string
	}{
		{0, ", ", ""},
		{1, ", ", "i00"},
		{10, ", ", "i00, i01, i02, i03, i04, i05, i06, i07, i08, i09"},
		{11, ", ", "i00, i01, i02, i03, i04, i05, i06, i07, i08, i09, and 1 more"},
		{12, "; ", "i00; i01; i02; i03; i04; i05; i06; i07; i08; i09; and 2 more"},
	}
	for _, tc := range cases {
		if got := ListBounded(items[:tc.n], tc.sep); got != tc.want {
			t.Errorf("ListBounded(%d items, %q) = %q, want %q", tc.n, tc.sep, got, tc.want)
		}
	}
}

// TestForEachRunsLimitAtOnce: ForEach calls fn once per index, keeps limit
// calls in flight together and never more.
func TestForEachRunsLimitAtOnce(t *testing.T) {
	t.Parallel()
	const n, limit = 12, 3
	var calls [n]atomic.Int32
	started := make(chan struct{}, n)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForEach(n, limit, func(i int) {
			calls[i].Add(1)
			started <- struct{}{}
			<-release
		})
	}()
	for range limit {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("fewer than %d calls started together", limit)
		}
	}
	select {
	case <-started:
		t.Fatalf("more than %d calls in flight", limit)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
	for i := range calls {
		if got := calls[i].Load(); got != 1 {
			t.Errorf("fn(%d) called %d times, want once", i, got)
		}
	}
}

// TestForEachRepanicsOnCaller: a panic in one call reaches the goroutine
// that called ForEach, where the registry's recover sees it, once the other
// calls have finished.
func TestForEachRepanicsOnCaller(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	finished := 0
	got := func() (r any) {
		defer func() { r = recover() }()
		ForEach(5, 2, func(i int) {
			if i == 2 {
				panic("boom")
			}
			mu.Lock()
			finished++
			mu.Unlock()
		})
		return nil
	}()
	if got != "boom" {
		t.Fatalf("recovered %v, want boom", got)
	}
	if finished != 4 {
		t.Errorf("%d other calls finished before the panic reached the caller, want 4", finished)
	}
}
