// Package report defines the cross-cutting Result type and renderers.
//
// All checks return []Result. Renderers (text/JSON/markdown) are pure
// projections of the same []Result so output is consistent across formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Status int

const (
	Pass Status = iota
	Warn
	Fail
	Info
	NotApplicable
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	case Info:
		return "INFO"
	case NotApplicable:
		return "N/A"
	default:
		return "?"
	}
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Result is the output of a single check. Remediation is required when
// Status == Fail; the renderer will surface a missing remediation as a bug.
type Result struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Status      Status   `json:"status"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	RFCRefs     []string `json:"rfc_refs,omitempty"`
}

// Report is the top-level rendered structure.
type Report struct {
	Target  string   `json:"target"`
	Results []Result `json:"results"`
}

// HasFailures returns true if any result is Fail. Drives exit code.
func (r Report) HasFailures() bool {
	for _, res := range r.Results {
		if res.Status == Fail {
			return true
		}
	}
	return false
}

// Format selects an output renderer.
type Format int

const (
	FormatText Format = iota
	FormatJSON
	FormatMarkdown
)

// Render writes the report in the requested format. The text renderer
// honors color only when caller passes color=true (caller decides via TTY check).
func Render(w io.Writer, r Report, f Format, color bool) error {
	switch f {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case FormatMarkdown:
		return renderMarkdown(w, r)
	default:
		return renderText(w, r, color)
	}
}

func groupByCategory(results []Result) ([]string, map[string][]Result) {
	g := map[string][]Result{}
	for _, res := range results {
		g[res.Category] = append(g[res.Category], res)
	}
	cats := make([]string, 0, len(g))
	for c := range g {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return cats, g
}

func renderText(w io.Writer, r Report, color bool) error {
	fmt.Fprintf(w, "bedrock report for %s\n\n", r.Target)
	cats, g := groupByCategory(r.Results)
	for _, c := range cats {
		fmt.Fprintf(w, "== %s ==\n", c)
		for _, res := range g[c] {
			fmt.Fprintf(w, "  [%s] %s\n", colorize(res.Status.String(), res.Status, color), res.Title)
			if res.Evidence != "" {
				fmt.Fprintf(w, "        evidence: %s\n", res.Evidence)
			}
			if res.Status == Fail && res.Remediation != "" {
				for _, line := range strings.Split(res.Remediation, "\n") {
					fmt.Fprintf(w, "        fix:      %s\n", line)
				}
			}
			if len(res.RFCRefs) > 0 {
				fmt.Fprintf(w, "        ref:      %s\n", strings.Join(res.RFCRefs, ", "))
			}
		}
		fmt.Fprintln(w)
	}
	return nil
}

func renderMarkdown(w io.Writer, r Report) error {
	fmt.Fprintf(w, "# bedrock report — `%s`\n\n", r.Target)
	cats, g := groupByCategory(r.Results)
	for _, c := range cats {
		fmt.Fprintf(w, "## %s\n\n", c)
		fmt.Fprintln(w, "| Status | Check | Evidence | Remediation | Refs |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, res := range g[c] {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
				res.Status.String(),
				mdEscape(res.Title),
				mdEscape(res.Evidence),
				mdCode(res.Remediation),
				mdEscape(strings.Join(res.RFCRefs, ", ")),
			)
		}
		fmt.Fprintln(w)
	}
	return nil
}

func mdEscape(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func mdCode(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return "`" + s + "`"
}

// colorize wraps s with an ANSI sequence when color is enabled.
// Kept dependency-free; we only need 4 colors.
func colorize(s string, st Status, color bool) string {
	if !color {
		return s
	}
	const reset = "\x1b[0m"
	var code string
	switch st {
	case Pass:
		code = "\x1b[32m" // green
	case Warn:
		code = "\x1b[33m" // yellow
	case Fail:
		code = "\x1b[31m" // red
	case Info:
		code = "\x1b[36m" // cyan
	default:
		code = "\x1b[90m" // grey
	}
	return code + s + reset
}
