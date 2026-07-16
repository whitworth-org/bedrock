package email

import (
	"reflect"
	"testing"

	"github.com/whitworth-org/bedrock/internal/report"
)

func TestDMARCWalkNames(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		want   []string
	}{
		{name: "empty", domain: "", want: nil},
		{name: "single label", domain: "com", want: []string{"_dmarc.com"}},
		{
			name:   "two labels",
			domain: "example.com",
			want:   []string{"_dmarc.example.com", "_dmarc.com"},
		},
		{
			name:   "four labels shed one per step",
			domain: "a.b.example.com",
			want: []string{
				"_dmarc.a.b.example.com",
				"_dmarc.b.example.com",
				"_dmarc.example.com",
				"_dmarc.com",
			},
		},
		{
			name:   "eight labels use all eight queries",
			domain: "a.b.c.d.e.f.example.com",
			want: []string{
				"_dmarc.a.b.c.d.e.f.example.com",
				"_dmarc.b.c.d.e.f.example.com",
				"_dmarc.c.d.e.f.example.com",
				"_dmarc.d.e.f.example.com",
				"_dmarc.e.f.example.com",
				"_dmarc.f.example.com",
				"_dmarc.example.com",
				"_dmarc.com",
			},
		},
		{
			name:   "nine labels jump to the last seven after the author query",
			domain: "x.a.b.c.d.e.f.example.com",
			want: []string{
				"_dmarc.x.a.b.c.d.e.f.example.com",
				"_dmarc.b.c.d.e.f.example.com",
				"_dmarc.c.d.e.f.example.com",
				"_dmarc.d.e.f.example.com",
				"_dmarc.e.f.example.com",
				"_dmarc.f.example.com",
				"_dmarc.example.com",
				"_dmarc.com",
			},
		},
		{
			// The RFC 9989 §4.8 deep-name shape: 13 labels still cost exactly
			// eight queries, ending at the TLD.
			name:   "thirteen labels capped at eight queries",
			domain: "a.b.c.d.e.f.g.h.i.j.mail.example.com",
			want: []string{
				"_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
				"_dmarc.g.h.i.j.mail.example.com",
				"_dmarc.h.i.j.mail.example.com",
				"_dmarc.i.j.mail.example.com",
				"_dmarc.j.mail.example.com",
				"_dmarc.mail.example.com",
				"_dmarc.example.com",
				"_dmarc.com",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dmarcWalkNames(tc.domain)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("dmarcWalkNames(%q) = %v, want %v", tc.domain, got, tc.want)
			}
			if len(got) > maxWalkQueries {
				t.Errorf("dmarcWalkNames(%q) returned %d names, cap is %d", tc.domain, len(got), maxWalkQueries)
			}
		})
	}
}

// foundStep builds a walkFound step for org-domain selection tests.
func foundStep(domain, psd string) DMARCWalkStep {
	return DMARCWalkStep{
		Domain:    domain,
		QueryName: "_dmarc." + domain,
		Outcome:   walkFound,
		Record:    &DMARC{Policy: "none", SubdomainPolicy: "none", PSD: psd},
	}
}

func nxStep(domain string) DMARCWalkStep {
	return DMARCWalkStep{Domain: domain, QueryName: "_dmarc." + domain, Outcome: walkNXDomain}
}

func TestSelectOrgDomain(t *testing.T) {
	cases := []struct {
		name     string
		author   string
		steps    []DMARCWalkStep
		wantOrg  string
		wantRule string
	}{
		{
			name:   "no records found",
			author: "mail.example.com",
			steps:  []DMARCWalkStep{nxStep("mail.example.com"), nxStep("example.com"), nxStep("com")},
		},
		{
			name:     "single record wins by fewest labels",
			author:   "mail.example.com",
			steps:    []DMARCWalkStep{nxStep("mail.example.com"), foundStep("example.com", "u"), nxStep("com")},
			wantOrg:  "example.com",
			wantRule: "fewest-labels",
		},
		{
			name:   "psd=n stops at the longest declaring domain",
			author: "mail.example.com",
			steps: []DMARCWalkStep{
				foundStep("mail.example.com", "n"),
				foundStep("example.com", "u"),
				nxStep("com"),
			},
			wantOrg:  "mail.example.com",
			wantRule: "psd=n",
		},
		{
			name:     "psd=y marks one label below along the author path",
			author:   "foo.bar.co.uk",
			steps:    []DMARCWalkStep{nxStep("foo.bar.co.uk"), nxStep("bar.co.uk"), foundStep("co.uk", "y"), nxStep("uk")},
			wantOrg:  "bar.co.uk",
			wantRule: "psd=y-one-below",
		},
		{
			name:     "psd=y on the author domain itself is ignored",
			author:   "example.com",
			steps:    []DMARCWalkStep{foundStep("example.com", "y"), nxStep("com")},
			wantOrg:  "example.com",
			wantRule: "fewest-labels",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			org, rule := selectOrgDomain(tc.author, tc.steps)
			if org != tc.wantOrg || rule != tc.wantRule {
				t.Errorf("selectOrgDomain(%q) = (%q, %q), want (%q, %q)",
					tc.author, org, rule, tc.wantOrg, tc.wantRule)
			}
		})
	}
}

func TestChildTowards(t *testing.T) {
	cases := []struct {
		author, parent, want string
	}{
		{"a.b.c.com", "com", "c.com"},
		{"a.b.c.com", "c.com", "b.c.com"},
		{"com", "com", "com"},
		{"example.com", "example.com", "example.com"},
	}
	for _, tc := range cases {
		if got := childTowards(tc.author, tc.parent); got != tc.want {
			t.Errorf("childTowards(%q, %q) = %q, want %q", tc.author, tc.parent, got, tc.want)
		}
	}
}

func TestSelectPolicyRecord(t *testing.T) {
	authorRec := foundStep("mail.example.com", "u")
	orgRec := foundStep("example.com", "u")
	psdRec := foundStep("com", "y")

	cases := []struct {
		name       string
		author     string
		org        string
		steps      []DMARCWalkStep
		wantDomain string
		wantNil    bool
	}{
		{
			name:   "author record preferred",
			author: "mail.example.com", org: "example.com",
			steps:      []DMARCWalkStep{authorRec, orgRec},
			wantDomain: "mail.example.com",
		},
		{
			name:   "org record when author has none",
			author: "mail.example.com", org: "example.com",
			steps:      []DMARCWalkStep{nxStep("mail.example.com"), orgRec},
			wantDomain: "example.com",
		},
		{
			name:   "fewest-labels fallback when only a PSD record exists",
			author: "mail.example.com", org: "bar.com",
			steps:      []DMARCWalkStep{nxStep("mail.example.com"), nxStep("example.com"), psdRec},
			wantDomain: "com",
		},
		{
			name:   "nothing found",
			author: "mail.example.com", org: "",
			steps:   []DMARCWalkStep{nxStep("mail.example.com"), nxStep("example.com"), nxStep("com")},
			wantNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			domain, rec := selectPolicyRecord(tc.author, tc.org, tc.steps)
			if tc.wantNil {
				if rec != nil || domain != "" {
					t.Errorf("want no policy, got (%q, %+v)", domain, rec)
				}
				return
			}
			if domain != tc.wantDomain || rec == nil {
				t.Errorf("selectPolicyRecord = (%q, %v), want domain %q with record", domain, rec, tc.wantDomain)
			}
		})
	}
}

func TestDMARCPolicyStatus(t *testing.T) {
	cases := []struct {
		policy, testMode string
		wantStatus       report.Status
		wantNoteSub      string
	}{
		{"reject", "n", report.Pass, ""},
		{"reject", "y", report.Warn, "effective policy quarantine"},
		{"quarantine", "n", report.Warn, ""},
		{"quarantine", "y", report.Warn, "effective policy none"},
		{"none", "n", report.Warn, ""},
		{"none", "y", report.Warn, "effective policy none"},
	}
	for _, tc := range cases {
		status, note := dmarcPolicyStatus(tc.policy, tc.testMode)
		if status != tc.wantStatus {
			t.Errorf("dmarcPolicyStatus(%q, %q) status = %s, want %s",
				tc.policy, tc.testMode, status, tc.wantStatus)
		}
		if tc.wantNoteSub != "" && !contains(note, tc.wantNoteSub) {
			t.Errorf("dmarcPolicyStatus(%q, %q) note = %q, want substring %q",
				tc.policy, tc.testMode, note, tc.wantNoteSub)
		}
	}
}
