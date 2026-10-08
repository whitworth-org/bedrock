// json.go is the machine-readable renderer, which pipes, files and --json
// receive: stock encoding/json with a two-space indent. Every string field
// passes through SanitizeForTerminal first, so attacker-controlled bytes (DNS
// TXT, certificate subjects, HTTP headers) cannot carry escape sequences into
// a terminal or a log. Remediation is sanitised line by line so multi-line
// snippets keep their newlines.

package report

import (
	"encoding/json"
	"io"
	"strings"
)

// RenderJSON writes r to w as one indented JSON document with every string
// sanitised. These bytes are bedrock's stable machine output.
func RenderJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sanitizeReport(r))
}

// sanitizeReport returns a deep-ish copy of r with every user-visible
// string field passed through SanitizeForTerminal. Remediation is
// processed per-line so multi-line snippets keep their newlines.
func sanitizeReport(r Report) Report {
	out := Report{
		Target:  SanitizeForTerminal(r.Target),
		Results: make([]Result, len(r.Results)),
	}
	for i, res := range r.Results {
		out.Results[i] = sanitizeResultJSON(res)
	}
	if r.Summary != nil {
		s := Summary{
			Categories: make([]CategoryCounts, len(r.Summary.Categories)),
			Totals:     r.Summary.Totals,
		}
		for i, c := range r.Summary.Categories {
			s.Categories[i] = CategoryCounts{
				Category: SanitizeForTerminal(c.Category),
				Counts:   c.Counts,
			}
		}
		out.Summary = &s
	}
	out.Regressions = make([]ResultRef, len(r.Regressions))
	for i, ref := range r.Regressions {
		out.Regressions[i] = ResultRef{
			ID:    SanitizeForTerminal(ref.ID),
			Title: SanitizeForTerminal(ref.Title),
		}
	}
	if len(out.Regressions) == 0 {
		out.Regressions = nil
	}
	return out
}

func sanitizeResultJSON(res Result) Result {
	res.ID = SanitizeForTerminal(res.ID)
	res.Category = SanitizeForTerminal(res.Category)
	res.Title = SanitizeForTerminal(res.Title)
	res.Evidence = SanitizeForTerminal(res.Evidence)
	res.Remediation = sanitizeRemediation(res.Remediation)
	if len(res.RFCRefs) > 0 {
		refs := make([]string, len(res.RFCRefs))
		for i, ref := range res.RFCRefs {
			refs[i] = SanitizeForTerminal(ref)
		}
		res.RFCRefs = refs
	}
	return res
}

// sanitizeRemediation sanitises each line independently so newlines
// survive while every other control byte is scrubbed.
func sanitizeRemediation(s string) string {
	if s == "" {
		return s
	}
	// Normalise CRLF/CR to LF so the renderer doesn't have to.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = SanitizeForTerminal(line)
	}
	return strings.Join(lines, "\n")
}
