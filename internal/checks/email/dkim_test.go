package email

import (
	"testing"

	"granite-scan/internal/probe"
)

func TestParseDKIM(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		wantP   string
		wantK   string
	}{
		{
			name:  "minimal RFC 6376 §3.6.1 example",
			raw:   "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
			wantP: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ", wantK: "rsa",
		},
		{
			name:  "with k tag",
			raw:   "v=DKIM1; k=rsa; p=ABC==",
			wantP: "ABC==", wantK: "rsa",
		},
		{
			name:  "revoked key (empty p)",
			raw:   "v=DKIM1; p=",
			wantP: "", wantK: "rsa",
		},
		{
			name:  "extra spaces",
			raw:   "v=DKIM1 ; k = rsa ; p = ABC ",
			wantP: "ABC", wantK: "rsa",
		},
		{
			name:    "wrong version",
			raw:     "v=DKIM2; p=ABC",
			wantErr: true,
		},
		{
			name:    "malformed tag",
			raw:     "v=DKIM1; foo",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDKIM(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDKIM: %v", err)
			}
			if got.P != tc.wantP {
				t.Errorf("P = %q, want %q", got.P, tc.wantP)
			}
			if got.KeyType != tc.wantK {
				t.Errorf("KeyType = %q, want %q", got.KeyType, tc.wantK)
			}
		})
	}
}

// containsString is a tiny helper to keep selector assertions readable.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func TestCommonSelectorsDeduped(t *testing.T) {
	seen := map[string]int{}
	for _, s := range commonSelectors {
		seen[s]++
		if s == "" {
			t.Errorf("empty selector in commonSelectors")
		}
	}
	for s, n := range seen {
		if n > 1 {
			t.Errorf("selector %q appears %d times in commonSelectors", s, n)
		}
	}
	// Sanity: the historical baseline must remain probed.
	for _, must := range []string{"default", "google", "selector1", "selector2", "mail", "dkim"} {
		if _, ok := seen[must]; !ok {
			t.Errorf("baseline selector %q missing from commonSelectors", must)
		}
	}
}

func TestSelectorListNoSPFCache(t *testing.T) {
	env := probe.NewEnv("example.com", 0, false, "")
	got := selectorList(env)
	if len(got) != len(commonSelectors) {
		t.Fatalf("selectorList without SPF: got %d selectors, want %d (no extras expected)",
			len(got), len(commonSelectors))
	}
	if got[0] != commonSelectors[0] {
		t.Errorf("selectorList must preserve commonSelectors order; first=%q want %q",
			got[0], commonSelectors[0])
	}
}

func TestSelectorListNilEnv(t *testing.T) {
	got := selectorList(nil)
	if len(got) != len(commonSelectors) {
		t.Fatalf("selectorList(nil): got %d, want %d", len(got), len(commonSelectors))
	}
}

func TestEspSelectorsSalesforce(t *testing.T) {
	env := probe.NewEnv("example.com", 0, false, "")
	env.CachePut(probe.CacheKeySPF, &SPF{
		Raw: "v=spf1 include:_spf.salesforce.com -all",
	})
	got := espSelectors(env)
	for _, want := range []string{"mfsv01", "mfsv02", "mfsv03", "et"} {
		if !containsString(got, want) {
			t.Errorf("espSelectors missing %q for salesforce include; got %v", want, got)
		}
	}
}

func TestEspSelectorsMultiProvider(t *testing.T) {
	env := probe.NewEnv("example.com", 0, false, "")
	env.CachePut(probe.CacheKeySPF, &SPF{
		Raw: "v=spf1 include:_spf.google.com include:sendgrid.net include:amazonses.com -all",
	})
	got := espSelectors(env)
	for _, want := range []string{"google", "google2", "s1", "s2", "smtpapi", "amazonses"} {
		if !containsString(got, want) {
			t.Errorf("espSelectors missing %q for multi-provider include; got %v", want, got)
		}
	}
}

func TestEspSelectorsNoSPF(t *testing.T) {
	env := probe.NewEnv("example.com", 0, false, "")
	if got := espSelectors(env); got != nil {
		t.Errorf("espSelectors with empty cache: want nil, got %v", got)
	}
}

func TestEspSelectorsWrongCacheType(t *testing.T) {
	env := probe.NewEnv("example.com", 0, false, "")
	env.CachePut(probe.CacheKeySPF, "not an SPF struct")
	if got := espSelectors(env); got != nil {
		t.Errorf("espSelectors with wrong type: want nil, got %v", got)
	}
}

func TestSelectorListMergesAndDedups(t *testing.T) {
	env := probe.NewEnv("example.com", 0, false, "")
	// Use a provider whose selectors overlap commonSelectors (google,
	// google2 are already in the common list) plus one that only the SPF
	// branch adds for sendgrid (smtpapi is in common; s1/s2 are too).
	env.CachePut(probe.CacheKeySPF, &SPF{
		Raw: "v=spf1 include:_spf.google.com -all",
	})
	got := selectorList(env)
	// Dedup: each selector appears at most once.
	seen := map[string]int{}
	for _, s := range got {
		seen[s]++
	}
	for s, n := range seen {
		if n > 1 {
			t.Errorf("selector %q appears %d times after merge", s, n)
		}
	}
	// google and google2 must be present and only once each.
	for _, want := range []string{"google", "google2"} {
		if seen[want] != 1 {
			t.Errorf("selector %q count = %d, want 1", want, seen[want])
		}
	}
}
