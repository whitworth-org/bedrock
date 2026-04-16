package web

import "testing"

// TestMozillaTLSEmbedded asserts the embedded Mozilla profile JSON parses
// and contains the three required profiles. Acts as a tripwire when the
// JSON is refreshed in testdata/.
func TestMozillaTLSEmbedded(t *testing.T) {
	c, err := loadMozillaTLS()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"modern", "intermediate", "old"} {
		p, ok := c.Configurations[name]
		if !ok {
			t.Fatalf("missing profile %q", name)
		}
		if len(p.TLSVersions) == 0 {
			t.Errorf("profile %q has no tls_versions", name)
		}
	}
	// Modern profile must require TLS 1.3 only — sanity check on parse.
	if v := c.Configurations["modern"].TLSVersions; len(v) != 1 || v[0] != "TLSv1.3" {
		t.Errorf("modern.tls_versions = %v, want [TLSv1.3]", v)
	}
}
