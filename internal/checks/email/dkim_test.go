package email

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestParseDKIM(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		wantP   string
		wantK   string
		wantV   string
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
			name:  "DKIM2 key record (draft-ietf-dkim-dkim2-spec)",
			raw:   "v=DKIM2; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
			wantP: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
			wantK: "ed25519", wantV: "DKIM2",
		},
		{
			name:  "DKIM2 version folds case",
			raw:   "v=dkim2; k=ed25519; p=ABC",
			wantP: "ABC", wantK: "ed25519", wantV: "DKIM2",
		},
		{
			name:    "wrong version",
			raw:     "v=DKIM3; p=ABC",
			wantErr: true,
		},
		{
			name:  "h tag stored",
			raw:   "v=DKIM1; h=sha256; p=ABC",
			wantP: "ABC", wantK: "rsa",
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
			if tc.wantV != "" && got.Version != tc.wantV {
				t.Errorf("Version = %q, want %q", got.Version, tc.wantV)
			}
		})
	}
}

// TestParseDKIMPTag: p= is required (RFC 6376 §3.6.1), and the folding
// whitespace a base64 value may contain is removed from it, but no other
// character is.
func TestParseDKIMPTag(t *testing.T) {
	cases := []struct {
		raw     string
		wantP   string
		wantErr string // a substring of the error, "" when the record parses
	}{
		{"v=DKIM1; p=abc def=", "abcdef=", ""},
		{"v=DKIM1; p=ab\tcd\r\n ef", "abcdef", ""},
		{"v=DKIM1; p=ab\u00a0cd", "ab\u00a0cd", ""},
		{"v=DKIM1; k=rsa", "", "missing required p= tag"},
		{"foo=bar", "", "missing required p= tag"},
	}
	for _, tc := range cases {
		got, err := ParseDKIM(tc.raw)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParseDKIM(%q) = %+v, %v; want an error naming %q",
					tc.raw, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got.P != tc.wantP {
			t.Errorf("ParseDKIM(%q) = %+v, %v; want P %q", tc.raw, got, err, tc.wantP)
		}
	}
}

// TestParseDKIMDomainTag: a d= tag must be a DNS-safe name, so a record
// cannot carry other content in it.
func TestParseDKIMDomainTag(t *testing.T) {
	if _, err := ParseDKIM("v=DKIM1; d=mail.example.com; p=ABC"); err != nil {
		t.Errorf("ParseDKIM with a DNS-safe d=: %v", err)
	}
	for _, d := range []string{"evil@example.com", "exa$mple.com"} {
		raw := "v=DKIM1; d=" + d + "; p=ABC"
		want := fmt.Sprintf("invalid d=%q", d)
		if got, err := ParseDKIM(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseDKIM(%q) = %+v, %v; want an error naming %s", raw, got, err, want)
		}
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

// TestRunDKIMSelectorRecords: only DKIM key records at a selector count, a
// key record without p= is malformed rather than revoked, and a selector
// with more than one TXT record draws a WARN (RFC 6376 §3.6.2.2).
func TestRunDKIMSelectorRecords(t *testing.T) {
	cases := []struct {
		name       string
		txt        []string
		wantID     string
		wantStatus report.Status
		wantSub    string
	}{
		{
			name:       "TXT records that are not DKIM keys",
			txt:        []string{"v=spf1 -all exp=x.example.com", "google-site-verification=abc"},
			wantID:     "email.dkim.selector.none",
			wantStatus: report.Fail,
			wantSub:    "no DKIM key found at any of",
		},
		{
			name:       "SPF record beside a key",
			txt:        []string{"v=spf1 -all", ed25519Record},
			wantID:     "email.dkim.selector.google",
			wantStatus: report.Warn,
			wantSub:    "v=DKIM1 k=ed25519, 32-byte key; 2 TXT records at the selector",
		},
		{
			name:       "key record without p=",
			txt:        []string{"v=DKIM1; k=rsa"},
			wantID:     "email.dkim.selector.google",
			wantStatus: report.Fail,
			wantSub:    "parse error at google._domainkey.example.com: missing required p= tag",
		},
		{
			name:       "key record with an empty p=",
			txt:        []string{"v=DKIM1; p="},
			wantID:     "email.dkim.selector.google",
			wantStatus: report.Fail,
			wantSub:    "revoked key (p= empty) at google._domainkey.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newCannedEnv(t, "example.com", cannedZone{
				txt: map[string][]string{"google._domainkey.example.com": tc.txt},
			})
			res := runDKIM(context.Background(), env)
			if len(res) != 1 || res[0].ID != tc.wantID {
				t.Fatalf("results = %v, want only %s", resultIDs(res), tc.wantID)
			}
			if res[0].Status != tc.wantStatus || !strings.Contains(res[0].Evidence, tc.wantSub) {
				t.Errorf("%s = %s %q, want %s naming %q", res[0].ID, res[0].Status,
					res[0].Evidence, tc.wantStatus, tc.wantSub)
			}
		})
	}
}

// TestRunDKIMSeveralKeyRecords: of several key records at one selector, the
// check grades the same one whatever order the resolver returns them in.
func TestRunDKIMSeveralKeyRecords(t *testing.T) {
	orders := [][]string{
		{"v=DKIM1; p=", ed25519Record},
		{ed25519Record, "v=DKIM1; p="},
	}
	var got []report.Result
	for _, txt := range orders {
		env := newCannedEnv(t, "example.com", cannedZone{
			txt: map[string][]string{"google._domainkey.example.com": txt},
		})
		res := runDKIM(context.Background(), env)
		if len(res) != 1 {
			t.Fatalf("TXT %q: results = %v, want one", txt, resultIDs(res))
		}
		got = append(got, res[0])
	}
	if got[0].Status != got[1].Status || got[0].Evidence != got[1].Evidence {
		t.Errorf("the record order changes the result: %s %q, then %s %q",
			got[0].Status, got[0].Evidence, got[1].Status, got[1].Evidence)
	}
}

// TestDKIMKeyGrades: a key record PASSes only with a key verifiers accept:
// an RSA key of at least 2048 bits (WARN from 1024, FAIL below, RFC 8301
// §3.2) or a 32-byte ed25519 key, usable with sha256 (RFC 8301 §3.1).
func TestDKIMKeyGrades(t *testing.T) {
	rsa2048 := rsaKeyBase64(t, 2048, false)
	edRaw, err := base64.StdEncoding.DecodeString(ed25519TestKey)
	if err != nil {
		t.Fatal(err)
	}
	edSPKI, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(edRaw))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		record     string
		wantStatus report.Status
		wantSub    string
	}{
		{"512-bit SPKI", "v=DKIM1; k=rsa; p=" + rsaKeyBase64(t, 512, false),
			report.Fail, "512-bit RSA key, which verifiers reject"},
		{"512-bit PKCS#1", "v=DKIM1; p=" + rsaKeyBase64(t, 512, true),
			report.Fail, "512-bit RSA key, which verifiers reject"},
		{"1023-bit", "v=DKIM1; p=" + rsaKeyBase64(t, 1023, false),
			report.Fail, "1023-bit RSA key, which verifiers reject"},
		{"1024-bit", "v=DKIM1; p=" + rsaKeyBase64(t, 1024, false),
			report.Warn, "1024-bit RSA key (RFC 8301 §3.2: signers SHOULD use at least 2048"},
		{"2047-bit", "v=DKIM1; p=" + rsaKeyBase64(t, 2047, true),
			report.Warn, "2047-bit RSA key"},
		{"2048-bit SPKI", "v=DKIM1; k=rsa; p=" + rsa2048,
			report.Pass, "v=DKIM1 k=rsa, 2048-bit key"},
		{"2048-bit PKCS#1", "v=DKIM1; p=" + rsaKeyBase64(t, 2048, true),
			report.Pass, "2048-bit key"},
		{"2048-bit split by whitespace", "v=DKIM1; p=" + rsa2048[:100] + " \t" + rsa2048[100:],
			report.Pass, "2048-bit key"},
		{"invalid base64", "v=DKIM1; p=!!not-base64!!",
			report.Fail, "k=rsa but p= is not valid base64"},
		{"base64 that is not a key", "v=DKIM1; p=QUJD", report.Fail, "p= is not an RSA public key"},
		{"ed25519 SPKI as k=rsa", "v=DKIM1; p=" + base64.StdEncoding.EncodeToString(edSPKI),
			report.Fail, "p= is not an RSA public key"},
		{"h=sha1", "v=DKIM1; h=sha1; p=" + rsa2048, report.Fail, "h=sha1 leaves out sha256"},
		{"h=sha1:sha256", "v=DKIM1; h=sha1:sha256; p=" + rsa2048, report.Pass, "2048-bit key"},
		{"h= with whitespace", "v=DKIM1; h=sha1 : sha256; p=" + rsa2048,
			report.Pass, "2048-bit key"},
		{"ed25519", ed25519Record, report.Pass, "v=DKIM1 k=ed25519, 32-byte key"},
		{"ed25519 without padding", "k=ed25519; p=" + strings.TrimRight(ed25519TestKey, "="),
			report.Pass, "32-byte key"},
		{"ed25519 of 31 bytes", "k=ed25519; p=" + base64.StdEncoding.EncodeToString(edRaw[:31]),
			report.Fail, "k=ed25519 but p= decodes to 31 bytes (want 32)"},
		{"ed25519 invalid base64", "k=ed25519; p=%%%",
			report.Fail, "k=ed25519 but p= is not valid base64"},
		{"unregistered k=", "v=DKIM1; k=foo; p=QUJD", report.Warn, `k="foo" is not a registered`},
		{"revoked", "v=DKIM1; p=", report.Fail, "revoked key (p= empty)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := DKIMProbe{Selector: "s1", Name: "s1._domainkey.example.com"}
			classifyDKIM(&p, []string{tc.record})
			r := dkimSelectorResult(p)
			if r.Status != tc.wantStatus || !strings.Contains(r.Evidence, tc.wantSub) {
				t.Errorf("%s %q, want %s naming %q",
					r.Status, r.Evidence, tc.wantStatus, tc.wantSub)
			}
			if (r.Status == report.Fail) != (r.Remediation != "") {
				t.Errorf("%s with remediation %q: only a FAIL says what to publish",
					r.Status, r.Remediation)
			}
		})
	}
}

// rsaKeyBase64 returns a base64 RSA public key whose modulus is bits long,
// as a SubjectPublicKeyInfo or, with pkcs1, as a PKCS#1 RSAPublicKey. The
// modulus is 2^(bits-1)+1: only its length matters to the grading.
func rsaKeyBase64(t *testing.T, bits int, pkcs1 bool) string {
	t.Helper()
	pub := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), bits-1, 1), E: 65537}
	if pkcs1 {
		return base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal %d-bit RSA key: %v", bits, err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
