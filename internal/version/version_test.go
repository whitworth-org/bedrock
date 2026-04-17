package version

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func withVars(t *testing.T, v, c, d string) func() {
	t.Helper()
	ov, oc, od := Version, Commit, Date
	Version, Commit, Date = v, c, d
	return func() {
		Version, Commit, Date = ov, oc, od
	}
}

func TestStringDefaultHasVersionAndArch(t *testing.T) {
	out := String()
	if !strings.HasPrefix(out, "bedrock ") {
		t.Fatalf("String() should start with 'bedrock ': %q", out)
	}
	plat := fmt.Sprintf(" %s/%s", runtime.GOOS, runtime.GOARCH)
	if !strings.HasSuffix(out, plat) {
		t.Fatalf("String() should end with %q, got %q", plat, out)
	}
}

func TestStringWithCommitAndDate(t *testing.T) {
	defer withVars(t, "1.2.3", "deadbeefcafe", "2026-04-17T00:00:00Z")()
	out := String()
	if !strings.Contains(out, "bedrock 1.2.3") {
		t.Fatalf("missing version: %q", out)
	}
	if !strings.Contains(out, "deadbeefcafe") {
		t.Fatalf("missing commit: %q", out)
	}
	if !strings.Contains(out, "2026-04-17T00:00:00Z") {
		t.Fatalf("missing date: %q", out)
	}
}

func TestStringWithCommitOnly(t *testing.T) {
	defer withVars(t, "9.9.9", "short", "")()
	out := String()
	if !strings.Contains(out, "(short)") {
		// The BuildInfo fallback may populate Date when Commit is a
		// recognisable vcs.revision. If it didn't, the commit should
		// appear bare without a trailing date.
		t.Logf("commit-only render (may include BuildInfo date): %q", out)
	}
	if !strings.Contains(out, "short") {
		t.Fatalf("commit 'short' missing from %q", out)
	}
}

func TestShortRev(t *testing.T) {
	if got := shortRev(""); got != "" {
		t.Fatalf("empty -> %q", got)
	}
	if got := shortRev("abc"); got != "abc" {
		t.Fatalf("short passthrough -> %q", got)
	}
	long := "0123456789abcdef0123"
	if got := shortRev(long); got != "0123456789ab" {
		t.Fatalf("long truncate -> %q", got)
	}
}
