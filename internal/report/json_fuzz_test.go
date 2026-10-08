package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"unicode/utf8"
)

// FuzzSanitizeReport locks the JSON output contract: for any Report, however
// hostile its strings or malformed its statuses, every string in the
// sanitised report is valid UTF-8 with no C0 control except TAB (and LF
// inside a remediation), no DEL and no C1 control, and RenderJSON writes one
// valid JSON document that decodes back to exactly those strings.
func FuzzSanitizeReport(f *testing.F) {
	f.Add([]byte("seed"))
	f.Add([]byte("\x1b[31mred\x1b[0m\x00\x9bevil\xff\xfe"))
	f.Add(bytes.Repeat([]byte{0x02, 'A', 0x1b, '['}, 40))
	f.Add([]byte("\x08\x04\x00\x02\x00a\tb\r\nc\rd\u0085e\u009bf\x7f\n\n\x00"))
	// A C1 control in every string field, and ESC and DEL in two, laid out
	// as reportFromBytes reads it: the target's length and the target, one
	// result (fixed-width ID, category and title, then FAIL, evidence,
	// remediation and two refs), a computed summary, and one regression.
	f.Add([]byte("\x0a" + "a\u009b[2Jb\u0085c" + "\x01" +
		"id\u009bx\u0090y" + "ca\x1b\u0080!" + "title\u009f\x7fbc" + "\x02" +
		"\x00" + "ev\u0085idence\u009c" + "\x00" + "fix\nline\u009b2\r\n\u0085z" +
		"\x03" + "RFC\u00991" + "r\u0091\u0092x" + "\x01" +
		"\x00" + "r\u0093gg" + "t\u0094tle!"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := reportFromBytes(data)
		clean := sanitizeReport(r)
		for _, fl := range reportFields(clean) {
			requireScrubbed(t, fl)
		}

		var out bytes.Buffer
		if err := RenderJSON(&out, r); err != nil {
			t.Fatalf("render: %v", err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("output is not valid JSON: %.300q", out.String())
		}
		var back Report
		if err := json.Unmarshal(out.Bytes(), &back); err != nil {
			t.Fatalf("decode output: %v", err)
		}
		if got, want := reportFields(back), reportFields(clean); !slices.Equal(got, want) {
			t.Fatalf("decoded strings differ from the sanitised report\ngot:  %+v\nwant: %+v",
				got, want)
		}
	})
}

// field is one string of a Report, named for failure messages.
type field struct {
	name, value string
	multiline   bool // a remediation, whose template line breaks survive
}

// reportFields lists every string in r, in document order.
func reportFields(r Report) []field {
	fs := []field{{name: "target", value: r.Target}}
	for _, res := range r.Results {
		fs = append(fs, field{name: "id", value: res.ID},
			field{name: "category", value: res.Category},
			field{name: "title", value: res.Title},
			field{name: "evidence", value: res.Evidence},
			field{name: "remediation", value: res.Remediation, multiline: true})
		for _, ref := range res.RFCRefs {
			fs = append(fs, field{name: "rfc_refs", value: ref})
		}
	}
	if r.Summary != nil {
		for _, c := range r.Summary.Categories {
			fs = append(fs, field{name: "summary category", value: c.Category})
		}
	}
	for _, ref := range r.Regressions {
		fs = append(fs, field{name: "regression id", value: ref.ID},
			field{name: "regression title", value: ref.Title})
	}
	return fs
}

func requireScrubbed(t *testing.T, fl field) {
	t.Helper()
	if !utf8.ValidString(fl.value) {
		t.Fatalf("%s is not valid UTF-8: %q", fl.name, fl.value)
	}
	for _, c := range fl.value {
		if mustScrub(c, fl.multiline) {
			t.Fatalf("control %U survived in %s: %q", c, fl.name, fl.value)
		}
	}
}

// mustScrub reports whether SanitizeForTerminal must have replaced c: every
// C0 control but TAB (and LF in a remediation), DEL, and every C1 control.
func mustScrub(c rune, multiline bool) bool {
	switch {
	case c == '\t', c == '\n' && multiline:
		return false
	case c < 0x20, c == 0x7f:
		return true
	}
	return c >= 0x80 && c <= 0x9f
}

// reportFromBytes deterministically derives an arbitrary Report from raw
// fuzz bytes: adversarial strings (ANSI, control bytes, invalid UTF-8),
// all Status values including out-of-range, nil / computed / handcrafted
// summaries, and optional regressions.
func reportFromBytes(data []byte) Report {
	next := func(n int) []byte {
		if len(data) < n {
			n = len(data)
		}
		b := data[:n]
		data = data[n:]
		return b
	}
	nextStr := func(n int) string { return string(next(n)) }
	nb := func() byte {
		x := next(1)
		if len(x) == 0 {
			return 0
		}
		return x[0]
	}

	r := Report{Target: nextStr(int(nb()) % 24)}
	nres := int(nb()) % 5
	for i := 0; i < nres; i++ {
		res := Result{
			ID:       nextStr(8),
			Category: nextStr(6),
			Title:    nextStr(10),
			Status:   Status(int(nb()) % 7), // includes out-of-range values
		}
		if nb()%2 == 0 {
			res.Evidence = nextStr(12)
		}
		if nb()%2 == 0 {
			res.Remediation = nextStr(16)
		}
		if nb()%3 == 0 {
			res.RFCRefs = []string{nextStr(6), nextStr(6)}
		}
		r.Results = append(r.Results, res)
	}
	switch nb() % 3 {
	case 0: // nil summary (old-report shape)
	case 1:
		r.Summary = Summarize(r.Results)
	case 2:
		r.Summary = &Summary{
			Categories: []CategoryCounts{{
				Category: nextStr(9),
				Counts:   StatusCounts{Pass: int(nb()), Fail: int(nb()), Total: int(nb())},
			}},
			Totals: StatusCounts{Warn: int(nb()), Total: int(nb())},
		}
	}
	if nb()%3 == 0 {
		r.Regressions = []ResultRef{{ID: nextStr(5), Title: nextStr(7)}}
	}
	return r
}
