package web

import (
	"strings"
	"testing"

	"github.com/whitworth-org/bedrock/internal/report"
)

// columnZeroValues carry the bytes that could forge a remediation line or
// push one off column 0: LF, CR, ESC, a C1 control and a leading TAB.
var columnZeroValues = []string{
	"evil.example\nforged: instruction",
	"evil.example\rforged: instruction",
	"evil.example\x1b[2J",
	"evil.example\u0085forged",
	"\tevil.example",
}

func TestRemediationBuilders_KeepColumnZero(t *testing.T) {
	leaf := selfSignedLeaf(t, "target.example")
	builders := []struct {
		name  string
		build func(v string) string
	}{
		{"http2 dial", http2DialRemediation},
		{"http2 handshake", http2HandshakeRemediation},
		{"cert fetch", certFetchRemediation},
		{"cert SAN", func(v string) string { return hostnameMatchResult(v, leaf).Remediation }},
		{"tls handshake", tlsHandshakeRemediation},
	}
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			plain := b.build("example.com")
			if plain == "" {
				t.Fatal("no remediation for a plain value")
			}
			for _, v := range columnZeroValues {
				got := b.build(v)
				if err := report.CheckRemediation(got); err != nil {
					t.Errorf("value %q: %v", v, err)
				}
				if strings.Count(got, "\n") != strings.Count(plain, "\n") {
					t.Errorf("value %q changed the line count:\n%s", v, got)
				}
			}
		})
	}
}
