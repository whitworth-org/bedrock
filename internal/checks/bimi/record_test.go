package bimi

import (
	"strings"
	"testing"
)

func TestParseRecord_Valid(t *testing.T) {
	r, err := ParseRecord("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Version != "BIMI1" {
		t.Errorf("Version=%q want BIMI1", r.Version)
	}
	if r.L != "https://example.com/logo.svg" {
		t.Errorf("L=%q", r.L)
	}
	if r.A != "https://example.com/vmc.pem" {
		t.Errorf("A=%q", r.A)
	}
}

func TestParseRecord_TolerateWhitespace(t *testing.T) {
	r, err := ParseRecord("  v=BIMI1 ;  l = https://example.com/logo.svg ;  a=https://example.com/vmc.pem  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.L != "https://example.com/logo.svg" || r.A != "https://example.com/vmc.pem" {
		t.Errorf("got L=%q A=%q", r.L, r.A)
	}
}

func TestParseRecord_MissingVersion(t *testing.T) {
	_, err := ParseRecord("l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
	if err == nil {
		t.Fatal("expected error for missing v= tag")
	}
	if !strings.Contains(err.Error(), "v=") {
		t.Errorf("error should mention v=: %v", err)
	}
}

func TestParseRecord_WrongVersion(t *testing.T) {
	_, err := ParseRecord("v=BIMI2; l=https://example.com/logo.svg")
	if err == nil {
		t.Fatal("expected error for v=BIMI2")
	}
}

func TestParseRecord_MalformedTag(t *testing.T) {
	_, err := ParseRecord("v=BIMI1; lhttps://example.com/logo.svg")
	if err == nil {
		t.Fatal("expected error for tag missing '='")
	}
}

func TestParseRecord_EmptyL(t *testing.T) {
	r, err := ParseRecord("v=BIMI1; l=; a=https://example.com/vmc.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.L != "" {
		t.Errorf("L=%q want empty", r.L)
	}
}

func TestHTTPSURL(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"https://example.com/logo.svg", false},
		{"http://example.com/logo.svg", true},
		{"ftp://example.com/logo.svg", true},
		{"", true},
		{"https:///nohost", true},
		{"::not a url", true},
	}
	for _, c := range cases {
		err := httpsURL(c.in)
		gotErr := err != nil
		if gotErr != c.wantErr {
			t.Errorf("httpsURL(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestHasBIMIPrefix(t *testing.T) {
	if !hasBIMIPrefix("v=BIMI1; l=...") {
		t.Error("should match")
	}
	if !hasBIMIPrefix("V=bimi1; l=...") {
		t.Error("case insensitive")
	}
	if hasBIMIPrefix("v=spf1") {
		t.Error("should not match SPF")
	}
}
