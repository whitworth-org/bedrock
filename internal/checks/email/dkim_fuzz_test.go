package email

import (
	"strings"
	"testing"
)

// FuzzParseDKIM drives the DKIM key-record parser with arbitrary tag-list
// input. The parser must never panic, and any record it accepts must have a
// normalized version tag the DKIM2-readiness check can key on, a p= tag with
// no folding whitespace left in its value, a key the grader can grade, and be
// a record the selector sweep examines rather than skips.
func FuzzParseDKIM(f *testing.F) {
	seeds := []string{
		"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ",
		"v=DKIM2; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		"v=dkim2; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		"v=DKIM1; h=sha256; k=rsa; p=ABC",
		"k=rsa; p=ABC",
		"p=",
		"v=DKIM3; p=ABC",
		"v=DKIM1;;p=ABC;",
		"v=DKIM1; p=ABC; p=DEF",
		"v=DKIM1; k=rsa",
		"v=DKIM1; p=MIGf MA0G\tCSqG\r\n SIb3",
		"v=DKIM1; h=sha1 : sha256; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		"v=spf1 -all",
		"p=QUJD; v=DKIM1",
		"p=\xc2 \x85", // removing the space leaves U+0085, a Unicode space
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		k, err := ParseDKIM(raw)
		if err != nil {
			return
		}
		if k.Version != "DKIM1" && k.Version != "DKIM2" {
			t.Errorf("accepted unnormalized version %q (raw=%q)", k.Version, raw)
		}
		if _, ok := k.Tags["p"]; !ok || strings.ContainsAny(k.P, " \t\r\n") {
			t.Errorf("accepted p=%q without a p= tag or with whitespace (raw=%q)", k.P, raw)
		}
		if !isDKIMRecord(raw) {
			t.Errorf("the sweep skips a record ParseDKIM accepts (raw=%q)", raw)
		}
		gradeDKIMKey(k)
	})
}
