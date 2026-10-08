package report

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzRenderHuman feeds hostile strings into every field the terminal
// report prints, across all five statuses, regressions and the View, and
// checks that the view stays inert: valid UTF-8, no rune but LF that is not
// graphic or that renders as nothing, no ESC without colour, and colour
// that strips back to exactly the plain view.
func FuzzRenderHuman(f *testing.F) {
	f.Add("email.spf.record", "SPF \u202eflaw\u3164", "p=\u2066reject\u2069\tok\ufe0f",
		"a\tb\nc\u2028d\r\n\u2029\u034f")
	f.Add("x\x1b[2J\u00ad", "t\x07\x08\U000e0100", "\u0085\u009b31m\u2065\ue000",
		"\n\n\x1b]0;title\x07\n\xff\xfe")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, id, title, evidence, rem string) {
		r := Report{Target: id, Results: []Result{
			{ID: title, Category: "DNS", Title: id, Status: NotApplicable, Evidence: evidence},
			{ID: id, Category: "DNS", Title: title, Status: Pass, Evidence: evidence},
			{ID: id, Category: "DNS", Title: title, Status: Info, Evidence: evidence},
			{ID: id, Category: evidence, Title: title, Status: Warn, Evidence: evidence,
				Remediation: rem},
			{ID: id, Category: title, Title: title, Status: Fail, Evidence: evidence,
				Remediation: rem, RFCRefs: []string{title, evidence}},
			{ID: id, Category: title, Title: title, Status: Fail, Evidence: rem,
				Remediation: rem, RFCRefs: []string{title, evidence}},
		}, Regressions: []ResultRef{{ID: id, Title: title}}}
		v := View{Scanned: 9, Resolvers: []string{evidence, id}, Baseline: title,
			Interrupted: true, Unfinished: []string{id, title}, Exit: 1}

		plain := renderHumanString(t, r, v)
		requireInert(t, "report", plain)
		v.Color = true
		colored := renderHumanString(t, r, v)
		if stripped := humanSGR.ReplaceAllString(colored, ""); stripped != plain {
			t.Fatalf("coloured view stripped of bedrock's SGR differs from the plain view\n"+
				"stripped: %q\nplain:    %q", stripped, plain)
		}
		v.RegressionOnly = true
		lines := []string{Verdict(r, v), Verdict(r, View{Baseline: title}), DisplaySafe(rem)}
		lines = append(lines, FailingIDs(r, v)...)
		lines = append(lines, FailingIDs(r, View{})...)
		for _, line := range lines {
			requireInert(t, "one-line output", line)
			if strings.Contains(line, "\n") {
				t.Fatalf("one-line output contains LF: %q", line)
			}
		}
	})
}

func requireInert(t *testing.T, what, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%s is not valid UTF-8: %q", what, s)
	}
	for _, c := range s {
		if c == '\n' {
			continue
		}
		if !unicode.IsGraphic(c) ||
			unicode.In(c, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector) {
			t.Fatalf("unsafe rune %U reached the %s: %q", c, what, s)
		}
	}
}
