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

func TestSummarize(t *testing.T) {
	t.Run("empty results", func(t *testing.T) {
		s := Summarize(nil)
		if s == nil || s.Categories == nil {
			t.Fatal("Summarize(nil) must return a non-nil Summary with a non-nil Categories slice")
		}
		if len(s.Categories) != 0 || s.Totals != (StatusCounts{}) {
			t.Errorf("empty summary = %+v, want zero totals and no categories", s)
		}
	})

	t.Run("multi-category tallies and sort order", func(t *testing.T) {
		s := Summarize([]Result{
			{Category: "WWW", Status: Pass},
			{Category: "DNS", Status: Fail},
			{Category: "WWW", Status: Warn},
			{Category: "DNS", Status: Pass},
			{Category: "Email", Status: Info},
			{Category: "Email", Status: NotApplicable},
			{Category: "WWW", Status: Pass},
		})
		if got := len(s.Categories); got != 3 {
			t.Fatalf("category rows = %d, want 3", got)
		}
		for i, want := range []string{"DNS", "Email", "WWW"} {
			if s.Categories[i].Category != want {
				t.Errorf("category[%d] = %q, want %q (sorted)", i, s.Categories[i].Category, want)
			}
		}
		www := s.Categories[2].Counts
		if www.Pass != 2 || www.Warn != 1 || www.Total != 3 {
			t.Errorf("WWW counts = %+v, want pass=2 warn=1 total=3", www)
		}
		if s.Totals.Total != 7 || s.Totals.Pass != 3 || s.Totals.Fail != 1 ||
			s.Totals.Info != 1 || s.Totals.NotApplicable != 1 || s.Totals.Warn != 1 {
			t.Errorf("totals = %+v, want pass=3 warn=1 fail=1 info=1 na=1 total=7", s.Totals)
		}
	})
}
