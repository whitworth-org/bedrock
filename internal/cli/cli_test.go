package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/report"
)

func TestLoadConfigEmptyPath(t *testing.T) {
	c, err := LoadConfig("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if c == nil || !reflect.DeepEqual(*c, Config{}) {
		t.Fatalf("empty path should yield zero config, got %+v", c)
	}
}

func TestLoadConfigValid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	body := `{"no_color":true,"timeout":"10s","only":["dns","email"]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.NoColor || c.Timeout != "10s" || !reflect.DeepEqual(c.Only, []string{"dns", "email"}) {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestLoadConfigMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(p, []byte(`{"no_color":`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestConfigDuration(t *testing.T) {
	def := 5 * time.Second
	c := &Config{}
	d, err := c.Duration(def)
	if err != nil || d != def {
		t.Fatalf("empty timeout: got %v %v", d, err)
	}
	c.Timeout = "2m30s"
	d, err = c.Duration(def)
	if err != nil {
		t.Fatalf("valid timeout: %v", err)
	}
	if d != 2*time.Minute+30*time.Second {
		t.Fatalf("unexpected duration: %v", d)
	}
	c.Timeout = "nope"
	if _, err := c.Duration(def); err == nil {
		t.Fatal("expected parse error for bad duration")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    report.Status
		set     bool
		wantErr bool
	}{
		{"", report.Info, false, false},
		{"info", report.Info, true, false},
		{"pass", report.Pass, true, false},
		{"WARN", report.Warn, true, false},
		{"failure", report.Fail, true, false},
		{"oops", report.Info, false, true},
	}
	for _, c := range cases {
		got, set, err := ParseSeverity(c.in)
		if (err != nil) != c.wantErr {
			t.Fatalf("ParseSeverity(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
		}
		if got != c.want || set != c.set {
			t.Fatalf("ParseSeverity(%q) = (%v,%v), want (%v,%v)", c.in, got, set, c.want, c.set)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	if SplitCSV("") != nil {
		t.Fatal("empty should be nil")
	}
	if SplitCSV("  , , ") != nil {
		t.Fatal("whitespace-only entries should be nil")
	}
	got := SplitCSV(" a , b,c ,  ")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitCSV got %v want %v", got, want)
	}
}

func TestFilterApplyPassthrough(t *testing.T) {
	input := []report.Result{
		{ID: "a", Category: "DNS", Status: report.Pass},
		{ID: "b", Category: "Email", Status: report.Fail},
	}
	f := Filter{}
	got := f.Apply(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("no filters should passthrough, got %+v", got)
	}
}

func TestFilterApplyOnly(t *testing.T) {
	input := []report.Result{
		{ID: "a", Category: "dns", Status: report.Pass},
		{ID: "b", Category: "email", Status: report.Fail},
	}
	got := Filter{Only: []string{"DNS"}}.Apply(input)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("Only filter case-insensitive failed: %+v", got)
	}
}

func TestFilterApplyExclude(t *testing.T) {
	input := []report.Result{
		{ID: "a", Category: "dns", Status: report.Pass},
		{ID: "b", Category: "email", Status: report.Fail},
	}
	got := Filter{Exclude: []string{"email"}}.Apply(input)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("Exclude filter failed: %+v", got)
	}
}

func TestFilterApplyIDs(t *testing.T) {
	input := []report.Result{
		{ID: "keep", Status: report.Pass},
		{ID: "drop", Status: report.Fail},
	}
	got := Filter{IDs: []string{"keep"}}.Apply(input)
	if len(got) != 1 || got[0].ID != "keep" {
		t.Fatalf("ID filter failed: %+v", got)
	}
}

func TestFilterApplyMinSeverity(t *testing.T) {
	input := []report.Result{
		{ID: "info", Status: report.Info},
		{ID: "pass", Status: report.Pass},
		{ID: "warn", Status: report.Warn},
		{ID: "fail", Status: report.Fail},
		{ID: "na", Status: report.NotApplicable},
	}
	f := Filter{MinSeverity: report.Warn, SeveritySet: true}
	got := f.Apply(input)
	// N/A is structurally preserved; warn and fail survive min=Warn.
	ids := make(map[string]struct{}, len(got))
	for _, r := range got {
		ids[r.ID] = struct{}{}
	}
	for _, want := range []string{"warn", "fail", "na"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("expected %q in filtered set, got %+v", want, got)
		}
	}
	for _, bad := range []string{"info", "pass"} {
		if _, ok := ids[bad]; ok {
			t.Fatalf("unexpected %q survived min=Warn: %+v", bad, got)
		}
	}
}
