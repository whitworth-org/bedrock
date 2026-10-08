package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestLoadConfigTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	// Create a file larger than 1 MiB (1<<20 bytes)
	largeContent := `{"no_color":true,"large_field":"` + strings.Repeat("x", 1<<20) + `"}`
	if err := os.WriteFile(p, []byte(largeContent), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadConfig(p)
	if err == nil {
		t.Fatal("expected error for file too large")
	}
	// The error should indicate it's a parse error due to truncation
	if !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("unexpected error type: %v", err)
	}
}

func TestLoadConfigUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	// Include a field that doesn't exist in the Config struct
	body := `{"no_color":true,"unknown_field":"value"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadConfig(p)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error should mention unknown field, got: %v", err)
	}
}

func TestLoadConfigMultipleValues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	// Two separate JSON objects in one file
	body := `{"no_color":true}{"timeout":"10s"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadConfig(p)
	if err == nil {
		t.Fatal("expected error for multiple JSON values")
	}
	if !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("error should mention multiple JSON values, got: %v", err)
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

func TestFilterKeepCategory(t *testing.T) {
	cases := []struct {
		name     string
		f        Filter
		category string
		want     bool
	}{
		{"no filter", Filter{}, "WWW", true},
		{"only matches ignoring case and space",
			Filter{Only: []string{" dns ", "email"}}, "DNS", true},
		{"only leaves out the rest", Filter{Only: []string{"DNS"}}, "Email", false},
		{"exclude matches ignoring case", Filter{Exclude: []string{"www"}}, "WWW", false},
		{"exclude keeps the rest", Filter{Exclude: []string{"WWW"}}, "DNSSEC", true},
		{"exclude beats only",
			Filter{Only: []string{"Email"}, Exclude: []string{"EMAIL"}}, "Email", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.KeepCategory(c.category); got != c.want {
				t.Errorf("%+v.KeepCategory(%q) = %v, want %v", c.f, c.category, got, c.want)
			}
		})
	}
}

// TestFilterApplyLeavesCategoriesToTheScan pins that Apply keeps a result
// whatever its category: Only and Exclude choose the categories the scan
// runs, and a run-level result such as dns.resolver.unreachable must reach
// the report under --only and --exclude.
func TestFilterApplyLeavesCategoriesToTheScan(t *testing.T) {
	input := []report.Result{
		{ID: "dns.resolver.unreachable", Category: "DNS", Status: report.Fail},
		{ID: "email.spf.record", Category: "Email", Status: report.Pass},
	}
	f := Filter{
		Only: []string{"Email"}, Exclude: []string{"DNS"},
		MinSeverity: report.Pass, SeveritySet: true,
	}
	if got := f.Apply(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("Apply dropped results by category: got %+v, want %+v", got, input)
	}
}

// TestFilterApplyIDsKeepsRunLevelResults pins that --ids cannot hide a dead
// resolver or a panicked check: either alone decides the exit code.
func TestFilterApplyIDsKeepsRunLevelResults(t *testing.T) {
	input := []report.Result{
		{ID: "dns.resolver.unreachable", Category: "DNS", Status: report.Fail},
		{ID: "email.spf.record", Category: "Email", Status: report.Warn},
		{ID: "registry.panic.web.hsts", Category: "WWW", Status: report.Fail},
		{ID: "web.hsts", Category: "WWW", Status: report.Pass},
	}
	got := Filter{IDs: []string{"email.spf.record"}}.Apply(input)
	want := []report.Result{input[0], input[1], input[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Apply = %+v, want %+v", got, want)
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
