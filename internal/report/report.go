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

// SanitizeForTerminal scrubs characters that can corrupt or weaponise terminal
// output: all C0 controls (0x00–0x1F) except TAB, the DEL byte (0x7F), and all
// C1 controls (0x80–0x9F). This explicitly drops newline/carriage-return, BEL,
// backspace and ESC so that evidence strings carrying attacker-controlled data
// (DNS TXT content, certificate subjects, HTTP headers) cannot inject ANSI
// escape sequences, clear the screen, or smuggle hidden text. Each removed
// byte is replaced with the Unicode replacement rune U+FFFD. Multi-byte UTF-8
// is preserved because iteration is rune-wise.
func SanitizeForTerminal(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteRune(r)
		case r >= 0x00 && r <= 0x1F:
			// All C0 controls other than TAB — including \n, \r, BEL (0x07),
			// backspace (0x08) and ESC (0x1B) — are replaced.
			b.WriteRune('\uFFFD')
		case r == 0x7F:
			b.WriteRune('\uFFFD')
		case r >= 0x80 && r <= 0x9F:
			// C1 controls, some of which begin ANSI CSI sequences.
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeResult returns a copy of res with every user-visible string field
// passed through SanitizeForTerminal. Remediation is deliberately NOT
// sanitised here: it is intentionally multi-line and is sanitised per-line
// by renderText after the newline split so its formatting survives.
func sanitizeResult(res Result) Result {
	res.Title = SanitizeForTerminal(res.Title)
	res.Evidence = SanitizeForTerminal(res.Evidence)
	for i, ref := range res.RFCRefs {
		res.RFCRefs[i] = SanitizeForTerminal(ref)
	}
	return res
}

func renderText(w io.Writer, r Report, color bool) error {
	target := SanitizeForTerminal(r.Target)
	fmt.Fprintf(w, "bedrock report for %s\n\n", target)
	cats, g := groupByCategory(r.Results)
	for _, c := range cats {
		fmt.Fprintf(w, "== %s ==\n", SanitizeForTerminal(c))
		for _, res := range g[c] {
			res = sanitizeResult(res)
			fmt.Fprintf(w, "  [%s] %s\n", colorize(res.Status.String(), res.Status, color), res.Title)
			if res.Evidence != "" {
				fmt.Fprintf(w, "        evidence: %s\n", res.Evidence)
			}
			if res.Status == Fail && res.Remediation != "" {
				for _, line := range strings.Split(res.Remediation, "\n") {
					fmt.Fprintf(w, "        fix:      %s\n", SanitizeForTerminal(line))
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
	fmt.Fprintf(w, "# bedrock report — `%s`\n\n", mdEscape(r.Target))
	cats, g := groupByCategory(r.Results)
	for _, c := range cats {
		fmt.Fprintf(w, "## %s\n\n", mdEscape(c))
		fmt.Fprintln(w, "| Status | Check | Evidence | Remediation | Refs |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, res := range g[c] {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
				res.Status.String(),
				mdEscape(res.Title),
				mdEscape(res.Evidence),
				mdRemediation(res.Remediation),
				mdEscape(strings.Join(res.RFCRefs, ", ")),
			)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// mdMetaChars lists Markdown punctuation we must escape inside table cells.
// We treat the full CommonMark meta-set (minus whitespace) conservatively:
// better a noisy cell than an injected link, emphasis span, or HTML element
// rendered from attacker-controlled content.
var mdMetaChars = []string{
	"\\", "`", "<", ">", "[", "]", "(", ")", "!", "*", "_",
	"{", "}", "#", "+", "-", ".", "|",
}

// mdEscape prepares a plain string for safe embedding in a Markdown table
// cell. It strips terminal control bytes via SanitizeForTerminal, folds
// CR/LF to spaces so the row stays on one line, and backslash-escapes every
// Markdown meta character including the table-cell delimiter.
func mdEscape(s string) string {
	if s == "" {
		return ""
	}
	s = SanitizeForTerminal(s)
	// SanitizeForTerminal already turned \n and \r into U+FFFD; collapse any
	// leftover literal newlines callers may have inserted post-sanitise.
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	for _, m := range mdMetaChars {
		s = strings.ReplaceAll(s, m, "\\"+m)
	}
	return s
}

// mdRemediation renders a Remediation field for the Markdown renderer.
// Single-line remediations use inline `backticks`; multi-line remediations
// use a fenced ```bash block so shell snippets retain their shape. The text
// is sanitised of terminal controls first but is NOT Markdown-escaped inside
// the code literal (code spans are already inert for Markdown). Pipes are
// still escaped so they do not break the enclosing table row.
func mdRemediation(s string) string {
	if s == "" {
		return ""
	}
	s = SanitizeForTerminal(s)
	s = strings.ReplaceAll(s, "\r", "")
	if strings.Contains(s, "\n") {
		// Fenced code block form. Strip any internal triple-backticks so the
		// attacker cannot close our fence early, then escape pipes so the
		// block stays within a single table cell.
		s = strings.ReplaceAll(s, "```", "'''")
		s = strings.ReplaceAll(s, "|", "\\|")
		return "\n```bash\n" + s + "\n```\n"
	}
	// Single-line form: inline code. Swap backticks for single quotes so the
	// code span itself closes cleanly, then escape table-breaking pipes.
	s = strings.ReplaceAll(s, "`", "'")
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
