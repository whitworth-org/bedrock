package bimi

import (
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/report"
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

func TestRecordCheckGrades(t *testing.T) {
	const name = "default._bimi.example.test"
	cases := []struct {
		name         string
		zone         testZone
		wantStatus   report.Status
		wantEvidence string
	}{
		{
			name:       "both URLs empty",
			zone:       testZone{txt: map[string][]string{name: {"v=BIMI1; l=; a="}}},
			wantStatus: report.Fail,
			wantEvidence: "l= tag invalid: empty URL; " +
				"a= tag invalid (Gmail requires VMC): empty URL",
		},
		{
			name: "both URLs plain http",
			zone: testZone{txt: map[string][]string{
				name: {"v=BIMI1; l=http://example.test/l.svg; a=http://example.test/a.pem"},
			}},
			wantStatus: report.Fail,
			wantEvidence: `l= tag invalid: scheme "http" is not https; ` +
				`a= tag invalid (Gmail requires VMC): scheme "http" is not https`,
		},
		{
			name:         "no BIMI record",
			zone:         testZone{txt: map[string][]string{name: {"v=spf1 -all"}}},
			wantStatus:   report.Fail,
			wantEvidence: "no v=BIMI1 record at " + name,
		},
		{
			name: "two BIMI records",
			zone: testZone{txt: map[string][]string{name: {
				"v=BIMI1; l=https://example.test/a.svg; a=https://example.test/a.pem",
				"v=BIMI1; l=https://example.test/b.svg; a=https://example.test/b.pem",
			}}},
			wantStatus:   report.Fail,
			wantEvidence: "multiple v=BIMI1 records (2) at " + name,
		},
		{
			name:         "malformed record",
			zone:         testZone{txt: map[string][]string{name: {"v=BIMI1; l"}}},
			wantStatus:   report.Fail,
			wantEvidence: "parse error: ",
		},
		{
			name:         "no record",
			zone:         testZone{},
			wantStatus:   report.Fail,
			wantEvidence: "no TXT record at " + name,
		},
		{
			name:         "resolver failure",
			zone:         testZone{servfail: map[string]bool{name: true}},
			wantStatus:   report.Warn,
			wantEvidence: "could not determine: ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newZoneEnv(t, "example.test", tc.zone, 2*time.Second)
			r := runOne(t, recordCheck{}, env)
			if r.Status != tc.wantStatus || !strings.HasPrefix(r.Evidence, tc.wantEvidence) {
				t.Errorf("got %s %q, want %s %q",
					r.Status, r.Evidence, tc.wantStatus, tc.wantEvidence)
			}
			if (r.Status == report.Fail) != (r.Remediation != "") {
				t.Errorf("status %s with remediation %q", r.Status, r.Remediation)
			}
		})
	}
}
