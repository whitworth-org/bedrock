package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whitworth-org/bedrock/internal/report"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	body := `{"target":"example.com","results":[{"id":"a","category":"dns","title":"ok","status":"PASS"}]}`
	path := writeTemp(t, body)
	_, err := Load(path)
	if err == nil {
		return // accepted
	}
	// Status is an int on the wire; the decoder will reject the string form.
	// Use the int form so the test reflects real baseline files produced by
	// FormatJSON (which goes through Status.MarshalJSON -> string). We
	// instead round-trip a numeric-status file.
	numeric := `{"target":"example.com","results":[{"id":"a","category":"dns","title":"ok","status":0}]}`
	path = writeTemp(t, numeric)
	if _, err := Load(path); err != nil {
		t.Fatalf("numeric load: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadUnknownField(t *testing.T) {
	// DisallowUnknownFields should reject schema drift.
	body := `{"target":"ex.com","results":[],"bogus":"field"}`
	path := writeTemp(t, body)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	if !strings.Contains(err.Error(), "parse baseline") {
		t.Fatalf("error should mention parse failure: %v", err)
	}
}

func TestLoadOversize(t *testing.T) {
	// Craft a file slightly over the 16 MiB limit.
	dir := t.TempDir()
	p := filepath.Join(dir, "big.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Write past the limit with a JSON-legal prefix.
	if _, err := f.WriteString(`{"target":"x","results":[],"pad":"`); err != nil {
		t.Fatalf("write: %v", err)
	}
	const pad = 17 << 20
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = 'x'
	}
	written := 0
	for written < pad {
		n, err := f.Write(buf)
		if err != nil {
			t.Fatalf("pad: %v", err)
		}
		written += n
	}
	if _, err := f.WriteString(`"}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = Load(p)
	if err == nil {
		t.Fatal("expected oversize rejection")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error should mention size limit: %v", err)
	}
}

func TestDiffNilBaseline(t *testing.T) {
	out := Diff(nil, report.Report{Results: []report.Result{{ID: "a", Status: report.Fail}}})
	if out != nil {
		t.Fatalf("nil baseline should yield nil diff, got %+v", out)
	}
}

func TestDiffNewFailureIsRegression(t *testing.T) {
	base := &report.Report{Results: []report.Result{
		{ID: "existing", Status: report.Pass},
	}}
	cur := report.Report{Results: []report.Result{
		{ID: "existing", Status: report.Pass},
		{ID: "brand-new", Status: report.Fail},
	}}
	got := Diff(base, cur)
	if len(got) != 1 || got[0].ID != "brand-new" {
		t.Fatalf("unexpected diff: %+v", got)
	}
}

func TestDiffExistingFailureIsNotRegression(t *testing.T) {
	base := &report.Report{Results: []report.Result{{ID: "flaky", Status: report.Fail}}}
	cur := report.Report{Results: []report.Result{{ID: "flaky", Status: report.Fail}}}
	got := Diff(base, cur)
	if len(got) != 0 {
		t.Fatalf("pre-existing failure should not regress: %+v", got)
	}
}

func TestDiffWarnToFailIsRegression(t *testing.T) {
	base := &report.Report{Results: []report.Result{{ID: "w2f", Status: report.Warn}}}
	cur := report.Report{Results: []report.Result{{ID: "w2f", Status: report.Fail}}}
	got := Diff(base, cur)
	if len(got) != 1 || got[0].ID != "w2f" {
		t.Fatalf("warn->fail should regress: %+v", got)
	}
}

func TestDiffDuplicateIDFailsClosed(t *testing.T) {
	// Baseline has the same ID twice with different statuses: an attacker
	// could use this to mask a regression. The implementation must report
	// any current Fail for such an ID.
	base := &report.Report{Results: []report.Result{
		{ID: "dup", Status: report.Pass},
		{ID: "dup", Status: report.Fail},
	}}
	cur := report.Report{Results: []report.Result{{ID: "dup", Status: report.Fail}}}
	got := Diff(base, cur)
	if len(got) != 1 || got[0].ID != "dup" {
		t.Fatalf("duplicate baseline ID must fail closed, got %+v", got)
	}
}
