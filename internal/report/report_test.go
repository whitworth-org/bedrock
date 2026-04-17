package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeForTerminal(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain ASCII", "hello world", "hello world"},
		{"tab preserved", "a\tb", "a\tb"},
		{"newline replaced", "a\nb", "a\uFFFDb"},
		{"cr replaced", "a\rb", "a\uFFFDb"},
		{"bel replaced", "a\x07b", "a\uFFFDb"},
		{"backspace replaced", "a\x08b", "a\uFFFDb"},
		{"esc replaced", "\x1b[31mred\x1b[0m", "\uFFFD[31mred\uFFFD[0m"},
		{"del replaced", "a\x7fb", "a\uFFFDb"},
		{"c1 control replaced", "a\u0090b", "a\uFFFDb"},
		{"multibyte utf8 preserved", "héllo→★", "héllo→★"},
		{"nul replaced", "a\x00b", "a\uFFFDb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForTerminal(tt.in)
			if got != tt.want {
				t.Fatalf("SanitizeForTerminal(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStatusMarshalJSON(t *testing.T) {
	cases := []struct {
		s    Status
		want string
	}{
		{Pass, `"PASS"`},
		{Warn, `"WARN"`},
		{Fail, `"FAIL"`},
		{Info, `"INFO"`},
		{NotApplicable, `"N/A"`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.s)
		if err != nil {
			t.Fatalf("marshal %v: %v", c.s, err)
		}
		if string(b) != c.want {
			t.Fatalf("marshal %v: got %s want %s", c.s, b, c.want)
		}
	}
}

func TestHasFailures(t *testing.T) {
	if (Report{}).HasFailures() {
		t.Fatal("empty report should not have failures")
	}
	passOnly := Report{Results: []Result{{Status: Pass}, {Status: Warn}, {Status: Info}}}
	if passOnly.HasFailures() {
		t.Fatal("no Fail results should report HasFailures=false")
	}
	withFail := Report{Results: []Result{{Status: Pass}, {Status: Fail}}}
	if !withFail.HasFailures() {
		t.Fatal("Fail result should report HasFailures=true")
	}
}

// TestRenderTextPreservesMultilineRemediation guards against the regression
// that sanitising the whole Result (including Remediation) collapsed its \n
// into U+FFFD before strings.Split got to see the newlines.
func TestRenderTextPreservesMultilineRemediation(t *testing.T) {
	r := Report{
		Target: "example.com",
		Results: []Result{{
			ID:          "demo.fail",
			Category:    "demo",
			Title:       "multi-line fix",
			Status:      Fail,
			Remediation: "line-one\nline-two\nline-three",
		}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, FormatText, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"line-one", "line-two", "line-three"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\uFFFD") {
		t.Fatalf("remediation should survive intact, got replacement rune:\n%s", out)
	}
}

func TestRenderTextSanitizesTitleAndEvidence(t *testing.T) {
	r := Report{
		Target: "example.com",
		Results: []Result{{
			ID:       "ansi.inject",
			Category: "demo",
			Title:    "title\x1b[31mred",
			Status:   Fail,
			Evidence: "evidence\x07bell",
		}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, FormatText, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[31m") {
		t.Fatalf("ESC sequence leaked into output:\n%s", out)
	}
	if strings.Contains(out, "\x07") {
		t.Fatalf("BEL leaked into output:\n%s", out)
	}
}

func TestRenderMarkdownEscapesMetaChars(t *testing.T) {
	r := Report{
		Target: "ex|ample.com",
		Results: []Result{{
			ID:       "md.esc",
			Category: "demo",
			Title:    "pipe|inject*[link](x)",
			Status:   Fail,
			Evidence: "<script>alert(1)</script>",
		}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, FormatMarkdown, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, bad := range []string{"<script>", "</script>"} {
		if strings.Contains(out, bad) {
			t.Fatalf("raw HTML leaked into markdown: %q in:\n%s", bad, out)
		}
	}
	// Pipe inside a cell must be backslash-escaped so it doesn't split the
	// table column.
	if !strings.Contains(out, `pipe\|inject`) {
		t.Fatalf("pipe not escaped in title cell:\n%s", out)
	}
}

func TestMdRemediationFence(t *testing.T) {
	single := mdRemediation("restart service")
	if !strings.HasPrefix(single, "`") || !strings.HasSuffix(single, "`") {
		t.Fatalf("single-line remediation should be inline code, got %q", single)
	}
	multi := mdRemediation("cmd1\ncmd2\ncmd3")
	if !strings.Contains(multi, "```bash") {
		t.Fatalf("multi-line remediation should use fenced bash block, got %q", multi)
	}
	// triple-backtick injection attempts must not close our fence.
	hostile := mdRemediation("evil\n```\nrm -rf /")
	if strings.Count(hostile, "```") != 2 {
		t.Fatalf("hostile triple-backtick should be neutralised, got %q", hostile)
	}
}

func TestRenderJSONShape(t *testing.T) {
	r := Report{
		Target: "example.com",
		Results: []Result{{
			ID:       "json.shape",
			Category: "demo",
			Title:    "ok",
			Status:   Pass,
		}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, FormatJSON, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	var back struct {
		Target  string `json:"target"`
		Results []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("round-trip: %v\n%s", err, buf.String())
	}
	if back.Target != r.Target || len(back.Results) != 1 ||
		back.Results[0].ID != "json.shape" || back.Results[0].Status != "PASS" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestColorizeOffAndOn(t *testing.T) {
	if got := colorize("PASS", Pass, false); got != "PASS" {
		t.Fatalf("color=false should be passthrough, got %q", got)
	}
	if got := colorize("FAIL", Fail, true); !strings.Contains(got, "\x1b[31m") || !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("color=true should wrap ANSI, got %q", got)
	}
}
