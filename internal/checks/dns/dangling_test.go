package dns

import (
	"strings"
	"testing"
)

// TestTakeoverPatterns_Coverage is a tripwire: if someone deletes a pattern
// or accidentally removes the marker, the test fails. The patterns are
// load-bearing — operators rely on the literal markers to confirm a takeover.
func TestTakeoverPatterns_Coverage(t *testing.T) {
	wantSuffixes := []string{
		".s3.amazonaws.com",
		".s3-website.amazonaws.com",
		".herokudns.com",
		".herokuapp.com",
		".github.io",
		".azurewebsites.net",
	}
	got := map[string]bool{}
	for _, p := range takeoverPatterns {
		got[p.suffix] = true
	}
	for _, s := range wantSuffixes {
		if !got[s] {
			t.Errorf("missing takeover pattern for suffix %q", s)
		}
	}
}

// TestTakeoverPatterns_HaveMarkersOrAreInfoOnly: every pattern is either
// active (has a marker we Fail on) or explicitly marker-empty (we treat as
// Info). The test prevents a future edit from silently downgrading a known
// fail-only pattern to "no marker, never fail."
func TestTakeoverPatterns_HaveMarkersOrAreInfoOnly(t *testing.T) {
	mustHaveMarker := map[string]bool{
		".s3.amazonaws.com":         true,
		".s3-website.amazonaws.com": true,
		".herokudns.com":            true,
		".herokuapp.com":            true,
		".github.io":                true,
		".azurewebsites.net":        true,
	}
	for _, p := range takeoverPatterns {
		if mustHaveMarker[p.suffix] && p.marker == "" {
			t.Errorf("pattern %s should have a marker — empty marker means we cannot fail on it", p.suffix)
		}
	}
}

func TestDanglingHosts_IncludesApexAndCommonLabels(t *testing.T) {
	want := []string{"", "www", "api"}
	got := strings.Join(danglingHosts, ",")
	for _, w := range want {
		// "" matches the comma-joined start; check positionally
		found := false
		for _, h := range danglingHosts {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("danglingHosts missing %q (have %s)", w, got)
		}
	}
}
