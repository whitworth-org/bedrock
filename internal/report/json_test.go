package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// stripANSI removes ANSI CSI sequences. The colored renderer should
// produce the same bytes as the plain renderer once these are stripped.
var stripANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func sampleReport() Report {
	return Report{
		Target: "example.com",
		Results: []Result{
			{
				ID:          "demo.fail",
				Category:    "demo",
				Title:       "fail with multi-line fix",
				Status:      Fail,
				Evidence:    "evidence body",
				Remediation: "line-one\nline-two\nline-three",
				RFCRefs:     []string{"RFC 1234 §1"},
			},
			{
				ID:       "demo.pass",
				Category: "demo",
				Title:    "pass",
				Status:   Pass,
			},
			{
				ID:       "demo.warn",
				Category: "demo",
				Title:    "warn",
				Status:   Warn,
			},
			{
				ID:       "demo.info",
				Category: "demo",
				Title:    "info",
				Status:   Info,
			},
			{
				ID:       "demo.na",
				Category: "demo",
				Title:    "n/a",
				Status:   NotApplicable,
			},
		},
	}
}

func TestRenderJSON_PlainRoundTrip(t *testing.T) {
	orig := sampleReport()
	var buf bytes.Buffer
	if err := RenderJSON(&buf, orig, false); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Compare key fields (Results slice order should be preserved)
	if decoded.Target != orig.Target {
		t.Errorf("Target: got %q, want %q", decoded.Target, orig.Target)
	}
	if len(decoded.Results) != len(orig.Results) {
		t.Fatalf("Results length: got %d, want %d", len(decoded.Results), len(orig.Results))
	}
	for i, r := range decoded.Results {
		o := orig.Results[i]
		if r.ID != o.ID || r.Category != o.Category || r.Title != o.Title || r.Status != o.Status {
			t.Errorf("Result[%d]: got {%s %s %s %s}, want {%s %s %s %s}",
				i, r.ID, r.Category, r.Title, r.Status, o.ID, o.Category, o.Title, o.Status)
		}
	}
}

func TestRenderJSON_ColoredMatchesPlain(t *testing.T) {
	report := sampleReport()

	var plain bytes.Buffer
	if err := RenderJSON(&plain, report, false); err != nil {
		t.Fatalf("plain RenderJSON: %v", err)
	}

	var colored bytes.Buffer
	if err := RenderJSON(&colored, report, true); err != nil {
		t.Fatalf("colored RenderJSON: %v", err)
	}

	stripped := stripANSI.ReplaceAll(colored.Bytes(), []byte{})
	if !bytes.Equal(stripped, plain.Bytes()) {
		t.Errorf("colored output (stripped) != plain output")
		t.Logf("plain:\n%s", plain.String())
		t.Logf("colored (stripped):\n%s", stripped)
	}
}

func TestRenderJSON_StatusColors(t *testing.T) {
	report := Report{
		Target: "test.com",
		Results: []Result{
			{ID: "p", Status: Pass, Category: "test", Title: "pass"},
			{ID: "w", Status: Warn, Category: "test", Title: "warn"},
			{ID: "f", Status: Fail, Category: "test", Title: "fail"},
			{ID: "i", Status: Info, Category: "test", Title: "info"},
			{ID: "n", Status: NotApplicable, Category: "test", Title: "na"},
		},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, report, true); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	output := buf.String()

	// Verify status colors are applied
	if !strings.Contains(output, ansiGreen+`"PASS"`+ansiReset) {
		t.Error("PASS status not colored green")
	}
	if !strings.Contains(output, ansiYellow+`"WARN"`+ansiReset) {
		t.Error("WARN status not colored yellow")
	}
	if !strings.Contains(output, ansiRed+`"FAIL"`+ansiReset) {
		t.Error("FAIL status not colored red")
	}
	if !strings.Contains(output, ansiCyan+`"INFO"`+ansiReset) {
		t.Error("INFO status not colored cyan")
	}
	if !strings.Contains(output, ansiGrey+`"N/A"`+ansiReset) {
		t.Error("N/A status not colored grey")
	}
}

func TestRenderJSON_EmptyReport(t *testing.T) {
	empty := Report{Target: "empty.com", Results: []Result{}}

	var plain bytes.Buffer
	if err := RenderJSON(&plain, empty, false); err != nil {
		t.Fatalf("plain RenderJSON: %v", err)
	}

	var colored bytes.Buffer
	if err := RenderJSON(&colored, empty, true); err != nil {
		t.Fatalf("colored RenderJSON: %v", err)
	}

	// Should still produce valid JSON
	var decoded Report
	if err := json.Unmarshal(plain.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Target != "empty.com" {
		t.Errorf("Target: got %q, want %q", decoded.Target, "empty.com")
	}
	if len(decoded.Results) != 0 {
		t.Errorf("Results should be empty, got %d items", len(decoded.Results))
	}
}

func TestRenderJSON_WithRegressions(t *testing.T) {
	report := Report{
		Target:  "regress.com",
		Results: []Result{{ID: "test", Category: "demo", Title: "test", Status: Pass}},
		Regressions: []ResultRef{
			{ID: "reg1", Title: "regression one"},
			{ID: "reg2", Title: "regression two"},
		},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, report, false); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if len(decoded.Regressions) != 2 {
		t.Fatalf("Regressions length: got %d, want 2", len(decoded.Regressions))
	}
	if decoded.Regressions[0].ID != "reg1" {
		t.Errorf("Regression[0].ID: got %q, want %q", decoded.Regressions[0].ID, "reg1")
	}
}

func TestSanitizeReport_CleanupStringFields(t *testing.T) {
	// Test that sanitization occurs on all string fields
	dirty := Report{
		Target: "example\x00.com",
		Results: []Result{
			{
				ID:          "test\x07id",
				Category:    "test\x1bcat",
				Title:       "test\ntitle",
				Evidence:    "evidence\x7f",
				Remediation: "line1\nline2\rline3\r\n",
				RFCRefs:     []string{"rfc\x08ref"},
			},
		},
		Regressions: []ResultRef{
			{ID: "reg\x90id", Title: "reg\x1ftitle"},
		},
	}

	clean := sanitizeReport(dirty)

	// Target should be cleaned
	if strings.Contains(clean.Target, "\x00") {
		t.Error("Target not sanitized")
	}

	// Result fields should be cleaned
	r := clean.Results[0]
	if strings.Contains(r.ID, "\x07") {
		t.Error("Result.ID not sanitized")
	}
	if strings.Contains(r.Category, "\x1b") {
		t.Error("Result.Category not sanitized")
	}
	if strings.Contains(r.Title, "\n") {
		t.Error("Result.Title not sanitized")
	}
	if strings.Contains(r.Evidence, "\x7f") {
		t.Error("Result.Evidence not sanitized")
	}
	if strings.Contains(r.RFCRefs[0], "\x08") {
		t.Error("Result.RFCRefs not sanitized")
	}

	// Remediation should preserve newlines but clean other control chars
	if !strings.Contains(r.Remediation, "\n") {
		t.Error("Remediation should preserve newlines")
	}
	if strings.Contains(r.Remediation, "\r") {
		t.Error("Remediation should normalize CR/CRLF to LF")
	}

	// Regressions should be cleaned - control chars should become replacement char
	reg := clean.Regressions[0]
	if !strings.Contains(reg.ID, "�") {
		t.Error("ResultRef.ID should contain replacement character after sanitization")
	}
	if strings.Contains(reg.Title, "\x1f") {
		t.Error("ResultRef.Title not sanitized")
	}
}

func TestSanitizeRemediation_PreservesNewlines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"single line", "simple", "simple"},
		{"lf preserved", "line1\nline2", "line1\nline2"},
		{"crlf normalized", "line1\r\nline2", "line1\nline2"},
		{"cr normalized", "line1\rline2", "line1\nline2"},
		{"mixed normalized", "line1\r\nline2\rline3\nline4", "line1\nline2\nline3\nline4"},
		{"controls cleaned per line", "line1\x07\nline2\x1b", "line1�\nline2�"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeRemediation(tt.in)
			if got != tt.want {
				t.Fatalf("sanitizeRemediation(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestJsonQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"simple", `"simple"`},
		{"with\"quote", `"with\"quote"`},
		{"with\\backslash", `"with\\backslash"`},
		{"with\nnewline", `"with\nnewline"`},
	}

	for _, tt := range tests {
		got := jsonQuote(tt.in)
		if got != tt.want {
			t.Errorf("jsonQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStatusColorFor(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{Pass, ansiGreen},
		{Warn, ansiYellow},
		{Fail, ansiRed},
		{Info, ansiCyan},
		{NotApplicable, ansiGrey},
		{Status(999), ansiGrey}, // Unknown status defaults to grey
	}

	for _, tt := range tests {
		got := statusColorFor(tt.status)
		if got != tt.want {
			t.Errorf("statusColorFor(%v) = %q, want %q", tt.status, got, tt.want)
		}
	}
}
