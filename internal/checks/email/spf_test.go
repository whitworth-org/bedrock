package email

import (
	"testing"
)

func TestParseSPF(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantAll     string
		wantLookups int
		wantRedir   string
		wantErr     bool
	}{
		{name: "minus all", raw: "v=spf1 -all", wantAll: "-"},
		{name: "soft fail", raw: "v=spf1 ip4:192.0.2.0/24 ~all", wantAll: "~"},
		{name: "neutral", raw: "v=spf1 ?all", wantAll: "?"},
		{name: "plus all", raw: "v=spf1 +all", wantAll: "+"},
		{name: "implicit all", raw: "v=spf1 ip4:192.0.2.1"},
		{name: "include", raw: "v=spf1 include:_spf.google.com -all", wantAll: "-", wantLookups: 1},
		{name: "many lookups", raw: "v=spf1 a mx include:a include:b include:c include:d include:e include:f include:g include:h -all", wantAll: "-", wantLookups: 10},
		{name: "redirect modifier", raw: "v=spf1 redirect=_spf.example.com", wantRedir: "_spf.example.com", wantLookups: 1},
		{name: "case-insensitive prefix", raw: "V=SPF1 -ALL", wantAll: "-"},
		{name: "not spf", raw: "v=spf2 -all", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSPF(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil; parsed=%+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSPF: %v", err)
			}
			if got.AllQualifier != tc.wantAll {
				t.Errorf("AllQualifier = %q, want %q", got.AllQualifier, tc.wantAll)
			}
			if got.CountDNSLookups() != tc.wantLookups {
				t.Errorf("CountDNSLookups = %d, want %d", got.CountDNSLookups(), tc.wantLookups)
			}
			if got.Redirect != tc.wantRedir {
				t.Errorf("Redirect = %q, want %q", got.Redirect, tc.wantRedir)
			}
		})
	}
}

func TestParseSPFTermClassification(t *testing.T) {
	// RFC 7208 §4.6.1 ABNF: modifier has "=" before any ":" or "/".
	cases := []struct {
		raw       string
		isMod     bool
		name      string
		qualifier string
	}{
		{raw: "include:_spf.example.com", name: "include", qualifier: ""},
		{raw: "-all", name: "all", qualifier: "-"},
		{raw: "ip4:192.0.2.0/24", name: "ip4", qualifier: ""},
		{raw: "redirect=_spf.example.com", name: "redirect", isMod: true},
		{raw: "exp=explain.example.com", name: "exp", isMod: true},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseSPFTerm(tc.raw)
			if err != nil {
				t.Fatalf("parseSPFTerm: %v", err)
			}
			if got.IsModifier != tc.isMod {
				t.Errorf("IsModifier = %v, want %v", got.IsModifier, tc.isMod)
			}
			if got.Name != tc.name {
				t.Errorf("Name = %q, want %q", got.Name, tc.name)
			}
			if got.Qualifier != tc.qualifier {
				t.Errorf("Qualifier = %q, want %q", got.Qualifier, tc.qualifier)
			}
		})
	}
}
