package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
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

// withReadBuildInfo swaps the debug.ReadBuildInfo seam so a test can force the
// fallback branch deterministically, then restores it.
func withReadBuildInfo(t *testing.T, f func() (*debug.BuildInfo, bool)) func() {
	t.Helper()
	orig := readBuildInfo
	readBuildInfo = f
	return func() { readBuildInfo = orig }
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
	defer withVars(t, "1.2.3", "deadbeefcafe", "1970-01-01T00:00:00Z")()
	out := String()
	if !strings.Contains(out, "bedrock 1.2.3") {
		t.Fatalf("missing version: %q", out)
	}
	if !strings.Contains(out, "deadbeefcafe") {
		t.Fatalf("missing commit: %q", out)
	}
	if !strings.Contains(out, "1970-01-01T00:00:00Z") {
		t.Fatalf("missing date: %q", out)
	}
}

func TestStringWithCommitOnly(t *testing.T) {
	defer withVars(t, "9.9.9", "short", "")()
	// Force the fallback to report nothing, so with an empty Date the commit
	// renders bare — no trailing date — regardless of the test binary's stamp.
	defer withReadBuildInfo(t, func() (*debug.BuildInfo, bool) { return nil, false })()
	out := String()
	if !strings.HasPrefix(out, "bedrock 9.9.9 (short) ") {
		t.Fatalf("commit-only render should be 'bedrock 9.9.9 (short) <platform>': %q", out)
	}
}

func TestStringCommitWithBuildInfoDate(t *testing.T) {
	defer withVars(t, "9.9.9", "short", "")()
	// Empty Date falls back to vcs.time from BuildInfo; the resolved date is
	// appended to the already-set commit.
	defer withReadBuildInfo(t, func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.time", Value: "1970-01-01T00:00:00Z"},
		}}, true
	})()
	out := String()
	if !strings.Contains(out, "bedrock 9.9.9 (short 1970-01-01T00:00:00Z)") {
		t.Fatalf("commit+BuildInfo-date render wrong: %q", out)
	}
}

func TestUserAgentCarriesResolvedVersion(t *testing.T) {
	defer withVars(t, "1.2.3", "", "")()
	ua := UserAgent()
	if !strings.HasPrefix(ua, "github.com/whitworth-org/bedrock/") {
		t.Fatalf("UserAgent should start with the module product token: %q", ua)
	}
	if !strings.Contains(ua, "1.2.3") {
		t.Fatalf("UserAgent should carry the build version: %q", ua)
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
