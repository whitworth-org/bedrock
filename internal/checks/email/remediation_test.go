package email

import (
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/report"
)

// columnZeroValues carry the bytes that could forge a remediation line or
// push one off column 0: LF, CR, ESC, a C1 control and a leading TAB.
var columnZeroValues = []string{
	"evil.example\nforged.example. IN TXT \"v=DMARC1\"",
	"evil.example\rforged.example. IN TXT \"v=DMARC1\"",
	"evil.example\x1b[2J",
	"evil.example\u0085forged",
	"\tevil.example",
}

func TestRemediationBuilders_KeepColumnZero(t *testing.T) {
	builders := []struct {
		name  string
		build func(v string) string
	}{
		{"dkim key", dkimKeyRemediation},
		{"dmarc external destination", func(v string) string { return extDestRemediation(v, v) }},
		{"mta-sts txt", mtastsTXTRemediation},
		{"mta-sts policy", mtastsPolicyRemediation},
		{"starttls", starttlsRemediation},
	}
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			plain := b.build("example.com")
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

func TestExtDestRemediation_ParsesAsOneTXTString(t *testing.T) {
	snippet := extDestRemediation("example.com", "reports.example.net")
	rr, err := mdns.NewRR(snippet)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", snippet, err)
	}
	if txt, ok := rr.(*mdns.TXT); !ok || !slices.Equal(txt.Txt, []string{"v=DMARC1"}) {
		t.Errorf("NewRR(%q) = %v, want one TXT string \"v=DMARC1\"", snippet, rr)
	}
}
