package web

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

// TestBuildCurveResult_Pass verifies that any modern-baseline curve being
// accepted yields a PASS regardless of which non-modern curves succeed.
func TestBuildCurveResult_Pass(t *testing.T) {
	cases := []map[tls.CurveID]bool{
		// X25519 alone is sufficient for modern baseline.
		{tls.X25519: true, tls.CurveP256: false, tls.CurveP384: false, tls.CurveP521: false},
		// P-256 alone is sufficient.
		{tls.X25519: false, tls.CurveP256: true, tls.CurveP384: false, tls.CurveP521: false},
		// Modern + non-modern still PASS.
		{tls.X25519: true, tls.CurveP256: true, tls.CurveP384: true, tls.CurveP521: true},
	}
	for i, m := range cases {
		got := buildCurveResult("example.com", m)
		if got.Status != report.Pass {
			t.Errorf("case %d: status = %s, want PASS (evidence=%q)", i, got.Status, got.Evidence)
		}
		if got.Remediation != "" {
			t.Errorf("case %d: remediation set on PASS: %q", i, got.Remediation)
		}
	}
}

// TestBuildCurveResult_Warn verifies that only-non-modern curves yields WARN
// with a remediation hint pointing at modern groups.
func TestBuildCurveResult_Warn(t *testing.T) {
	cases := []map[tls.CurveID]bool{
		{tls.X25519: false, tls.CurveP256: false, tls.CurveP384: true, tls.CurveP521: false},
		{tls.X25519: false, tls.CurveP256: false, tls.CurveP384: false, tls.CurveP521: true},
		{tls.X25519: false, tls.CurveP256: false, tls.CurveP384: true, tls.CurveP521: true},
	}
	for i, m := range cases {
		got := buildCurveResult("example.com", m)
		if got.Status != report.Warn {
			t.Errorf("case %d: status = %s, want WARN (evidence=%q)", i, got.Status, got.Evidence)
		}
		if got.Remediation == "" {
			t.Errorf("case %d: remediation empty on WARN", i)
		}
		if !strings.Contains(strings.ToLower(got.Remediation), "x25519") {
			t.Errorf("case %d: remediation should mention X25519, got %q", i, got.Remediation)
		}
	}
}

// TestBuildCurveResult_Fail verifies that no curves accepted yields FAIL
// with a remediation explaining ECDHE is required.
func TestBuildCurveResult_Fail(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.X25519:    false,
		tls.CurveP256: false,
		tls.CurveP384: false,
		tls.CurveP521: false,
	}
	got := buildCurveResult("example.com", m)
	if got.Status != report.Fail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}
	if got.Remediation == "" {
		t.Fatal("remediation empty on FAIL")
	}
	if !strings.Contains(strings.ToLower(got.Remediation), "ecdhe") {
		t.Errorf("remediation should mention ECDHE, got %q", got.Remediation)
	}
}

// TestBuildCurveResult_Evidence checks the human-readable evidence string
// reflects accepted and rejected curves in canonical probe order.
func TestBuildCurveResult_Evidence(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.X25519:    true,
		tls.CurveP256: true,
		tls.CurveP384: false,
		tls.CurveP521: false,
	}
	got := buildCurveResult("example.com", m)
	// Canonical order: X25519, P-256, P-384, P-521.
	wantSubstrings := []string{
		"accepted: X25519, P-256",
		"rejected: P-384, P-521",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(got.Evidence, s) {
			t.Errorf("evidence %q missing %q", got.Evidence, s)
		}
	}
}

// TestBuildCurveResult_EvidenceNoneAccepted verifies the (none) sentinel
// is used when no curves are accepted.
func TestBuildCurveResult_EvidenceNoneAccepted(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.X25519:    false,
		tls.CurveP256: false,
		tls.CurveP384: false,
		tls.CurveP521: false,
	}
	got := buildCurveResult("example.com", m)
	if !strings.Contains(got.Evidence, "accepted: (none)") {
		t.Errorf("evidence should report (none), got %q", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "rejected: X25519, P-256, P-384, P-521") {
		t.Errorf("evidence should list every probed curve as rejected, got %q", got.Evidence)
	}
}

// TestHasModernBaseline covers each candidate independently. The baseline
// is X25519 OR P-256 — P-384 and P-521 alone do not satisfy modern.
func TestHasModernBaseline(t *testing.T) {
	cases := []struct {
		name   string
		in     map[tls.CurveID]bool
		expect bool
	}{
		{"x25519 only", map[tls.CurveID]bool{tls.X25519: true}, true},
		{"p256 only", map[tls.CurveID]bool{tls.CurveP256: true}, true},
		{"p384 only", map[tls.CurveID]bool{tls.CurveP384: true}, false},
		{"p521 only", map[tls.CurveID]bool{tls.CurveP521: true}, false},
		{"none", map[tls.CurveID]bool{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasModernBaseline(tc.in); got != tc.expect {
				t.Errorf("hasModernBaseline(%v) = %v, want %v", tc.in, got, tc.expect)
			}
		})
	}
}

// TestPartitionCurves verifies canonical ordering of the partitioned slices
// regardless of map iteration order (Go randomizes map iteration).
func TestPartitionCurves(t *testing.T) {
	m := map[tls.CurveID]bool{
		tls.CurveP521: true,
		tls.X25519:    false,
		tls.CurveP384: true,
		tls.CurveP256: false,
	}
	acc, rej := partitionCurves(m)
	wantAcc := []string{"P-384", "P-521"} // canonical order: X25519, P-256, P-384, P-521
	wantRej := []string{"X25519", "P-256"}
	if !equalStrings(acc, wantAcc) {
		t.Errorf("accepted = %v, want %v", acc, wantAcc)
	}
	if !equalStrings(rej, wantRej) {
		t.Errorf("rejected = %v, want %v", rej, wantRej)
	}
}

func TestCurveNameByID(t *testing.T) {
	cases := map[tls.CurveID]string{
		tls.X25519:    "X25519",
		tls.CurveP256: "P-256",
		tls.CurveP384: "P-384",
		tls.CurveP521: "P-521",
	}
	for id, want := range cases {
		if got := curveNameByID(id); got != want {
			t.Errorf("curveNameByID(%v) = %q, want %q", id, got, want)
		}
	}
	// Unknown curve falls through to the hex sentinel.
	if got := curveNameByID(tls.CurveID(0xBEEF)); !strings.Contains(got, "0xbeef") {
		t.Errorf("unknown curve fallback = %q, want contains 0xbeef", got)
	}
}

// TestECCurveCheck_NoActive ensures the --no-active short-circuit fires
// without any network I/O.
func TestECCurveCheck_NoActive(t *testing.T) {
	env := probe.NewEnv("example.com", time.Second, false /* active */, "")
	results := ecCurveCheck{}.Run(context.Background(), env)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != report.NotApplicable {
		t.Errorf("status = %s, want N/A", r.Status)
	}
	if !strings.Contains(r.Evidence, "no-active") {
		t.Errorf("evidence should mention no-active, got %q", r.Evidence)
	}
}

// equalStrings is a tiny helper to keep test diagnostics readable.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
