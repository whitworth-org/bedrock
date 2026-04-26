// Package report defines the cross-cutting Result type and the JSON
// renderer.
//
// All checks return []Result. Output is JSON only; the actual emission
// (plain or ANSI-colorized) lives in json.go.
package report

import (
	"encoding/json"
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

func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "PASS":
		*s = Pass
	case "WARN":
		*s = Warn
	case "FAIL":
		*s = Fail
	case "INFO":
		*s = Info
	case "N/A":
		*s = NotApplicable
	default:
		*s = NotApplicable // Default to N/A for unknown values
	}
	return nil
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

// ResultRef is a compact reference to a Result, used to surface
// regressions without duplicating the full Result body. Populated by
// main.go after a baseline diff and then folded into Report.Regressions
// before rendering.
type ResultRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Report is the top-level rendered structure. Regressions, when set, is
// a non-empty list of (id, title) for every check that regressed against
// the supplied --baseline.
type Report struct {
	Target      string      `json:"target"`
	Results     []Result    `json:"results"`
	Regressions []ResultRef `json:"regressions,omitempty"`
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
			b.WriteRune('�')
		case r == 0x7F:
			b.WriteRune('�')
		case r >= 0x80 && r <= 0x9F:
			// C1 controls, some of which begin ANSI CSI sequences.
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
