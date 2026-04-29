package email

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// newEnvWithMX builds a minimal *probe.Env whose MX cache entry is
// pre-populated. The check reads from cache before falling back to DNS, so
// this keeps the test hermetic without starting a resolver.
func newEnvWithMX(t *testing.T, mxs []probe.MX) *probe.Env {
	t.Helper()
	env := probe.NewEnv("example.com", time.Second, false, "")
	env.CachePut(probe.CacheKeyMX, mxs)
	return env
}

func findResult(rs []report.Result, id string) (report.Result, bool) {
	for _, r := range rs {
		if r.ID == id {
			return r, true
		}
	}
	return report.Result{}, false
}

func TestGoogleWorkspaceMX_LegacyFullSet(t *testing.T) {
	env := newEnvWithMX(t, []probe.MX{
		{Preference: 1, Host: "ASPMX.L.GOOGLE.COM"},
		{Preference: 5, Host: "ALT1.ASPMX.L.GOOGLE.COM"},
		{Preference: 5, Host: "ALT2.ASPMX.L.GOOGLE.COM"},
		{Preference: 10, Host: "ALT3.ASPMX.L.GOOGLE.COM"},
		{Preference: 10, Host: "ALT4.ASPMX.L.GOOGLE.COM"},
	})
	got := runGoogleWorkspaceMX(context.Background(), env)
	r, ok := findResult(got, "email.google_workspace_mx")
	if !ok {
		t.Fatalf("expected result, got none: %+v", got)
	}
	if r.Status != report.Info {
		t.Fatalf("status: got %v want Info", r.Status)
	}
	for _, want := range []string{
		"aspmx.l.google.com",
		"alt1.aspmx.l.google.com",
		"alt4.aspmx.l.google.com",
		googleWorkspaceMigrationURL,
	} {
		if !strings.Contains(r.Evidence, want) {
			t.Fatalf("evidence missing %q:\n%s", want, r.Evidence)
		}
	}
}

func TestGoogleWorkspaceMX_LegacyPrimaryOnly(t *testing.T) {
	// A domain using only ASPMX.L.GOOGLE.COM without ALTs is still on the
	// legacy layout and should be nudged.
	env := newEnvWithMX(t, []probe.MX{{Preference: 1, Host: "aspmx.l.google.com"}})
	got := runGoogleWorkspaceMX(context.Background(), env)
	if _, ok := findResult(got, "email.google_workspace_mx"); !ok {
		t.Fatalf("legacy-primary-only should emit INFO, got %+v", got)
	}
}

func TestGoogleWorkspaceMX_MixedMigrationInProgress(t *testing.T) {
	env := newEnvWithMX(t, []probe.MX{
		{Preference: 1, Host: "smtp.google.com"},
		{Preference: 5, Host: "alt1.aspmx.l.google.com"},
	})
	got := runGoogleWorkspaceMX(context.Background(), env)
	r, ok := findResult(got, "email.google_workspace_mx")
	if !ok {
		t.Fatalf("mixed setup should still emit INFO: %+v", got)
	}
	if !strings.Contains(r.Evidence, "mixed") {
		t.Fatalf("expected evidence to note mixed state, got: %s", r.Evidence)
	}
}

func TestGoogleWorkspaceMX_NewSingleOnlySuppresses(t *testing.T) {
	env := newEnvWithMX(t, []probe.MX{{Preference: 1, Host: "smtp.google.com"}})
	got := runGoogleWorkspaceMX(context.Background(), env)
	if len(got) != 0 {
		t.Fatalf("new single-MX form should emit nothing, got %+v", got)
	}
}

func TestGoogleWorkspaceMX_NonGoogleSuppresses(t *testing.T) {
	env := newEnvWithMX(t, []probe.MX{
		{Preference: 10, Host: "mx1.fastmail.com"},
		{Preference: 20, Host: "mx2.fastmail.com"},
	})
	got := runGoogleWorkspaceMX(context.Background(), env)
	if len(got) != 0 {
		t.Fatalf("non-Google MX should emit nothing, got %+v", got)
	}
}

func TestGoogleWorkspaceMX_NoMXSuppresses(t *testing.T) {
	env := newEnvWithMX(t, nil)
	got := runGoogleWorkspaceMX(context.Background(), env)
	if len(got) != 0 {
		t.Fatalf("empty MX set should emit nothing, got %+v", got)
	}
}

func TestGoogleWorkspaceMX_TrailingDotAndDuplicate(t *testing.T) {
	// DNS answer hosts can carry a trailing dot; we also guard against
	// duplicate MX entries (some zones publish the primary twice). Neither
	// should affect detection.
	env := newEnvWithMX(t, []probe.MX{
		{Preference: 1, Host: "ASPMX.L.GOOGLE.COM."},
		{Preference: 1, Host: "aspmx.l.google.com"},
	})
	got := runGoogleWorkspaceMX(context.Background(), env)
	r, ok := findResult(got, "email.google_workspace_mx")
	if !ok {
		t.Fatalf("expected INFO result: %+v", got)
	}
	// Duplicate suppression: the host should appear exactly once in evidence.
	if strings.Count(r.Evidence, "aspmx.l.google.com") != 1 {
		t.Fatalf("duplicate host should appear once in evidence, got: %s", r.Evidence)
	}
}
