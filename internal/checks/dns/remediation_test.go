package dns

import (
	"strings"
	"testing"
	"unicode"

	"github.com/whitworth-org/bedrock/internal/report"
)

// columnZeroValues carry the bytes that could forge a remediation line or
// push one off column 0: LF, CR, ESC, a C1 control and a leading TAB.
var columnZeroValues = []string{
	"evil.example\nforged.example. IN A 192.0.2.1",
	"evil.example\rforged.example. IN A 192.0.2.1",
	"evil.example\x1b[2J",
	"evil.example\u0085forged",
	"\tevil.example",
}

func TestRemediationBuilders_KeepColumnZero(t *testing.T) {
	builders := []struct {
		name  string
		build func(v string) string
	}{
		{"dangling orphan", func(v string) string { return orphanCNAMERemediation(v, v) }},
		{"dangling takeover", func(v string) string { return takeoverRemediation(v, v, v) }},
		{"ns count", nsCountRemediation},
		{"cname apex", func(v string) string { return apexCNAMERemediation(v, v) }},
		{"zone soa", soaRemediationExample},
	}
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			plain := b.build("example.com")
			assertZoneColumnZero(t, plain)
			for _, v := range columnZeroValues {
				got := b.build(v)
				if err := report.CheckRemediation(got); err != nil {
					t.Errorf("value %q: %v", v, err)
				}
				if strings.Count(got, "\n") != strings.Count(plain, "\n") {
					t.Errorf("value %q changed the line count:\n%s", v, got)
				}
				assertZoneColumnZero(t, got)
			}
		})
	}
}

// assertZoneColumnZero fails when a line of a zone-file snippet starts with
// whitespace, which makes the record inherit the previous owner name
// (RFC 1035 §5.1), or holds a '#', which zone files do not treat as a
// comment: a '#' line is a syntax error and a trailing one adds RDATA.
func assertZoneColumnZero(t *testing.T, snippet string) {
	t.Helper()
	for _, line := range strings.Split(snippet, "\n") {
		if strings.Contains(line, "#") || strings.TrimLeftFunc(line, unicode.IsSpace) != line {
			t.Errorf("zone snippet line %q must start at column 0 and comment with ';'", line)
		}
	}
}
