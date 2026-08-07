package report

// FuzzRenderParity locks the renderer contract: for any Report — however
// hostile its strings or malformed its statuses — the plain renderer must
// emit valid JSON, the colored renderer stripped of ANSI must match it
// byte-for-byte, and the output must round-trip back through Unmarshal.

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzRenderParity(f *testing.F) {
	f.Add([]byte("seed"))
	f.Add([]byte("\x1b[31mred\x1b[0m\x00\x9bevil\xff\xfe"))
	f.Add(bytes.Repeat([]byte{0x02, 'A', 0x1b, '['}, 40))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := reportFromBytes(data)

		var plain bytes.Buffer
		if err := RenderJSON(&plain, r, false); err != nil {
			t.Fatalf("plain render: %v", err)
		}
		if !json.Valid(plain.Bytes()) {
			t.Fatalf("plain output is not valid JSON: %.200q", plain.String())
		}

		var colored bytes.Buffer
		if err := RenderJSON(&colored, r, true); err != nil {
			t.Fatalf("colored render: %v", err)
		}
		stripped := stripANSI.ReplaceAll(colored.Bytes(), nil)
		if !bytes.Equal(plain.Bytes(), stripped) {
			t.Fatalf("parity mismatch\nplain:    %.300q\nstripped: %.300q",
				plain.String(), string(stripped))
		}

		var back Report
		if err := json.Unmarshal(plain.Bytes(), &back); err != nil {
			t.Fatalf("round-trip unmarshal: %v", err)
		}
	})
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
