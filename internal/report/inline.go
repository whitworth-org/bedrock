package report

import (
	"fmt"
	"strings"
	"unicode"
)

// clipRunes is how much of a value ClipValue keeps: enough to recognise it,
// too little for a hostile value to flood a report.
const clipRunes = 64

// InlineValue makes s safe to interpolate into one line of a remediation
// template. Every control character, TAB included, becomes U+FFFD, so the
// value can neither start a line nor indent one with a TAB. It never
// shortens s: a 253-octet DNS name must stay whole in a fix the user pastes.
func InlineValue(s string) string {
	return strings.ReplaceAll(SanitizeForTerminal(s), "\t", "�")
}

// ClipValue is InlineValue keeping only the first 64 runes, followed by an
// ellipsis when anything was cut. It is for evidence and titles; a
// remediation needs the whole value, so it uses InlineValue.
func ClipValue(s string) string {
	runes := 0
	for i := range s {
		if runes == clipRunes {
			return InlineValue(s[:i]) + "…"
		}
		runes++
	}
	return InlineValue(s)
}

// CheckRemediation returns an error when s holds a control character other
// than LF, TAB included. Operators paste a remediation as written, so its
// line breaks and indentation must come only from bedrock's own templates.
func CheckRemediation(s string) error {
	for i, r := range s {
		if r != '\n' && unicode.IsControl(r) {
			return fmt.Errorf("check remediation %q: control character %U at byte %d; "+
				"pass values interpolated into the template through report.InlineValue",
				ClipValue(s), r, i)
		}
	}
	return nil
}

// CheckUniqueIDs returns an error naming every result ID that appears more
// than once. Baseline diffs match results by ID, so a FAIL under an ID the
// baseline repeats is ambiguous and counts as a regression on every run.
func CheckUniqueIDs(results []Result) error {
	seen := make(map[string]int, len(results))
	var repeated []string
	for _, r := range results {
		seen[r.ID]++
		if seen[r.ID] == 2 {
			repeated = append(repeated, r.ID)
		}
	}
	if len(repeated) == 0 {
		return nil
	}
	counts := make([]string, len(repeated))
	for i, id := range repeated {
		counts[i] = fmt.Sprintf("%q (%d results)", id, seen[id])
	}
	return fmt.Errorf("check result IDs: %s repeated; give each result its own ID or merge "+
		"the results into one", strings.Join(counts, ", "))
}
