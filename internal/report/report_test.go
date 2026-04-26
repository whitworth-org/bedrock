package report

import (
	"encoding/json"
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
		{"newline replaced", "a\nb", "a�b"},
		{"cr replaced", "a\rb", "a�b"},
		{"bel replaced", "a\x07b", "a�b"},
		{"backspace replaced", "a\x08b", "a�b"},
		{"esc replaced", "\x1b[31mred\x1b[0m", "�[31mred�[0m"},
		{"del replaced", "a\x7fb", "a�b"},
		{"c1 control replaced", "a\u0090b", "a�b"},
		{"multibyte utf8 preserved", "héllo→★", "héllo→★"},
		{"nul replaced", "a\x00b", "a�b"},
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
