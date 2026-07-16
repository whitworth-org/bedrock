package email

import "testing"

// FuzzParseDKIM drives the DKIM key-record parser with arbitrary tag-list
// input. The parser must never panic, and any record it accepts must have a
// normalized version tag the DKIM2-readiness check can key on.
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
	})
}
