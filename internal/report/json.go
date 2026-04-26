// Package report — JSON-only output for bedrock. Two paths share one
// document shape:
//
//   - color == false: a stock encoding/json stream with two-space indent.
//     This is the canonical machine output and round-trips through
//     json.Unmarshal byte-for-byte equivalent to today's --json output.
//   - color == true:  a hand-rolled walker that emits the same JSON
//     document but wraps each token with ANSI escapes so a TTY user
//     gets syntax highlighting.
//
// Both paths apply SanitizeForTerminal to every string field so attacker-
// controlled bytes (DNS TXT, cert subjects, HTTP headers) cannot smuggle
// ANSI escapes or terminal-corrupting control chars through the report.
// remediation is sanitised per-line so multi-line shell snippets stay
// readable.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ANSI color codes. Kept inline so the renderer has zero third-party deps.
// Numbers / booleans / null tokens never appear in the current Report
// shape (Status is rendered as a string), so only the string-applicable
// colors are wired in. Keep magenta/yellow constants ready for a future
// schema extension without re-surveying the codebase.
const (
	ansiReset  = "\x1b[0m"
	ansiCyan   = "\x1b[36m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiGrey   = "\x1b[90m"
)

// RenderJSON writes r as JSON to w. When color is false the output is
// canonical encoding/json with two-space indent. When color is true the
// same document is emitted with ANSI syntax highlighting.
func RenderJSON(w io.Writer, r Report, color bool) error {
	clean := sanitizeReport(r)
	if !color {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(clean)
	}
	return renderColoredJSON(w, clean)
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

// renderColoredJSON walks the Report and emits an ANSI-highlighted JSON
// document with the same indentation and field ordering as the plain
// encoder path. No reflection: we know the Report shape statically.
func renderColoredJSON(w io.Writer, r Report) error {
	cw := &colorWriter{w: w}
	cw.openObj(0)
	cw.field("target", 1)
	cw.writeString(r.Target, "")
	cw.comma()

	cw.field("results", 1)
	cw.writeResults(r.Results, 1)

	if len(r.Regressions) > 0 {
		cw.comma()
		cw.field("regressions", 1)
		cw.writeRegressions(r.Regressions, 1)
	}

	cw.newline()
	cw.closeObj(0)
	cw.newline()
	return cw.err
}

// colorWriter is a tiny stateful helper for hand-rolling the indented
// JSON document. Errors are sticky: we record the first one and skip
// subsequent writes so the caller still sees a clean error.
type colorWriter struct {
	w   io.Writer
	err error
}

func (c *colorWriter) write(s string) {
	if c.err != nil {
		return
	}
	_, c.err = io.WriteString(c.w, s)
}

func (c *colorWriter) indent(level int) {
	c.write(strings.Repeat("  ", level))
}

func (c *colorWriter) newline()      { c.write("\n") }
func (c *colorWriter) comma()        { c.write(",\n") }
func (c *colorWriter) openObj(_ int) { c.write("{\n") }
func (c *colorWriter) closeObj(level int) {
	c.indent(level)
	c.write("}")
}
func (c *colorWriter) openArr() { c.write("[\n") }
func (c *colorWriter) closeArr(level int) {
	c.indent(level)
	c.write("]")
}

// field writes "key":<space> at the requested indent level.
func (c *colorWriter) field(name string, level int) {
	c.indent(level)
	c.write(ansiCyan)
	c.write(jsonQuote(name))
	c.write(ansiReset)
	c.write(": ")
}

// writeString writes a JSON string token. statusColor, if non-empty,
// colors the value (used for the "status" field).
func (c *colorWriter) writeString(s, statusColor string) {
	if statusColor != "" {
		c.write(statusColor)
		c.write(jsonQuote(s))
		c.write(ansiReset)
		return
	}
	// Default: no color. encoding/json default is bare quoted string.
	c.write(jsonQuote(s))
}

func (c *colorWriter) writeResults(results []Result, level int) {
	if len(results) == 0 {
		c.write("[]")
		return
	}
	c.openArr()
	for i, res := range results {
		c.indent(level + 1)
		c.writeResult(res, level+1)
		if i < len(results)-1 {
			c.comma()
		} else {
			c.newline()
		}
	}
	c.closeArr(level)
}

func (c *colorWriter) writeResult(res Result, level int) {
	c.write("{\n")
	// Field order matches the struct tags (encoding/json default).
	c.field("id", level+1)
	c.writeString(res.ID, "")
	c.comma()

	c.field("category", level+1)
	c.writeString(res.Category, "")
	c.comma()

	c.field("title", level+1)
	c.writeString(res.Title, "")
	c.comma()

	c.field("status", level+1)
	c.writeString(res.Status.String(), statusColorFor(res.Status))

	if res.Evidence != "" {
		c.comma()
		c.field("evidence", level+1)
		c.writeString(res.Evidence, "")
	}
	if res.Remediation != "" {
		c.comma()
		c.field("remediation", level+1)
		c.writeString(res.Remediation, "")
	}
	if len(res.RFCRefs) > 0 {
		c.comma()
		c.field("rfc_refs", level+1)
		c.writeStringArray(res.RFCRefs, level+1)
	}
	c.newline()
	c.closeObj(level)
}

func (c *colorWriter) writeStringArray(xs []string, level int) {
	if len(xs) == 0 {
		c.write("[]")
		return
	}
	c.openArr()
	for i, s := range xs {
		c.indent(level + 1)
		c.writeString(s, "")
		if i < len(xs)-1 {
			c.comma()
		} else {
			c.newline()
		}
	}
	c.closeArr(level)
}

func (c *colorWriter) writeRegressions(refs []ResultRef, level int) {
	if len(refs) == 0 {
		c.write("[]")
		return
	}
	c.openArr()
	for i, ref := range refs {
		c.indent(level + 1)
		c.write("{\n")
		c.field("id", level+2)
		c.writeString(ref.ID, "")
		c.comma()
		c.field("title", level+2)
		c.writeString(ref.Title, "")
		c.newline()
		c.closeObj(level + 1)
		if i < len(refs)-1 {
			c.comma()
		} else {
			c.newline()
		}
	}
	c.closeArr(level)
}

// statusColorFor returns the ANSI escape that should wrap a status string.
func statusColorFor(s Status) string {
	switch s {
	case Pass:
		return ansiGreen
	case Warn:
		return ansiYellow
	case Fail:
		return ansiRed
	case Info:
		return ansiCyan
	case NotApplicable:
		return ansiGrey
	default:
		return ansiGrey
	}
}

// jsonQuote returns s wrapped in JSON-style double quotes, with the
// minimal escape set encoding/json itself emits. We delegate to the
// stdlib so escaping rules stay bug-for-bug compatible with the plain
// path.
func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// Marshalling a string never fails in practice; fall back to a
		// safely-escaped placeholder rather than panicking.
		return fmt.Sprintf("%q", s)
	}
	return string(b)
}
