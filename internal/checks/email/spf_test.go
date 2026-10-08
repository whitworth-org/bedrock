package email

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
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
		// RFC 7208 §5.1: evaluation ends at the first all.
		{name: "first all wins over a later -all", raw: "v=spf1 +all -all", wantAll: "+"},
		{name: "first all wins over a later +all", raw: "v=spf1 -all +all", wantAll: "-"},
		{name: "bare all passes", raw: "v=spf1 all", wantAll: "+"},
		{name: "terms after all are never looked up", raw: "v=spf1 -all include:a mx",
			wantAll: "-"},
		{name: "malformed term after all", raw: "v=spf1 -all +", wantErr: true},
		// RFC 7208 §6.1: redirect is ignored beside an all.
		{name: "redirect beside all", raw: "v=spf1 include:a redirect=b ~all", wantAll: "~",
			wantLookups: 1, wantRedir: "b"},
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

// TestRunSPF grades the apex SPF record the way receivers evaluate it: the
// first "all" ends evaluation (RFC 7208 §5.1), a bare "all" passes everyone
// (§4.6.2), and an ip4 or ip6 range of prefix length 0 passes everyone, as
// +all does.
func TestRunSPF(t *testing.T) {
	elevenLookups := strings.Repeat(" include:x.example", 11)
	cases := []struct {
		name   string
		txt    []string // apex TXT strings; nil means the name does not exist
		want   report.Status
		detail string // in the evidence
		ref    string // the RFC reference the result adds, if any
	}{
		{"NXDOMAIN", nil, report.Fail, "no v=spf1 TXT record at apex", ""},
		{"no SPF among TXT", []string{"site-verification=x"}, report.Fail, "no v=spf1 TXT", ""},
		{"two records", []string{"v=spf1 -all", "v=spf1 ~all"}, report.Fail,
			"multiple v=spf1 records (2)", "RFC 7208 §3.2"},
		{"malformed term", []string{"v=spf1 -all +"}, report.Fail, "parse error", ""},
		{"11 lookups", []string{"v=spf1" + elevenLookups + " -all"}, report.Fail,
			"DNS-lookup terms = 11", ""},
		{"lookups after all", []string{"v=spf1 -all" + elevenLookups}, report.Pass,
			"v=spf1 -all include:x.example", ""},
		{"-all", []string{"v=spf1 ip4:192.0.2.0/24 -all"}, report.Pass, "/24 -all", ""},
		{"~all", []string{"v=spf1 ~all"}, report.Warn, "softfail (~all)", ""},
		{"?all", []string{"v=spf1 ?all"}, report.Warn, "neutral (?all)", ""},
		{"+all", []string{"v=spf1 +all"}, report.Fail, "+all permits anyone", "RFC 7208 §11.4"},
		{"+all before -all", []string{"v=spf1 +all -all"}, report.Fail, "+all permits anyone",
			"RFC 7208 §11.4"},
		{"-all before +all", []string{"v=spf1 -all +all"}, report.Pass, "v=spf1 -all +all", ""},
		{"bare all", []string{"v=spf1 all"}, report.Fail, "+all permits anyone", "RFC 7208 §11.4"},
		{"bare all beside redirect", []string{"v=spf1 redirect=_spf.example.net all"}, report.Fail,
			"+all permits anyone", "RFC 7208 §11.4"},
		{"redirect", []string{"v=spf1 redirect=_spf.example.net"}, report.Pass,
			"redirect=_spf.example.net", ""},
		{"no all", []string{"v=spf1 ip4:192.0.2.1"}, report.Warn, "implicit ?all", ""},
		{"ip4 /0", []string{"v=spf1 ip4:0.0.0.0/0 -all"}, report.Fail,
			"ip4:0.0.0.0/0 permits anyone to send", "RFC 7208 §5.6"},
		{"ip6 /0", []string{"v=spf1 +ip6:::/0 -all"}, report.Fail,
			"+ip6:::/0 permits anyone to send", "RFC 7208 §5.6"},
		{"/0 with host bits", []string{"v=spf1 ip4:192.0.2.1/0 ~all"}, report.Fail,
			"ip4:192.0.2.1/0 permits", "RFC 7208 §5.6"},
		{"/0 after all", []string{"v=spf1 -all ip4:0.0.0.0/0"}, report.Pass,
			"-all ip4:0.0.0.0/0", ""},
		{"/0 that fails", []string{"v=spf1 -ip4:0.0.0.0/0 ~all"}, report.Warn, "softfail", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := cannedZone{}
			if tc.txt != nil {
				zone.txt = map[string][]string{"example.com": tc.txt}
			}
			res := runSPF(context.Background(), newCannedEnv(t, "example.com", zone))
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(res), res)
			}
			refs := []string{"RFC 7208 §3", "RFC 7208 §4.6.4", "RFC 7208 §11"}
			if tc.ref != "" {
				refs = append(refs, tc.ref)
			}
			assertSPFResult(t, res[0], tc.want, tc.detail, refs)
		})
	}
}

// assertSPFResult wants r to be an email.spf.record result with status
// want, evidence naming detail, a remediation only on FAIL, and the RFC
// references refs.
func assertSPFResult(t *testing.T, r report.Result, want report.Status, detail string,
	refs []string,
) {
	t.Helper()
	if r.ID != "email.spf.record" || r.Status != want || !strings.Contains(r.Evidence, detail) {
		t.Errorf("got %s %s %q, want email.spf.record %s naming %q",
			r.ID, r.Status, r.Evidence, want, detail)
	}
	if (r.Remediation != "") != (r.Status == report.Fail) {
		t.Errorf("%s result has remediation %q; want one only on FAIL", r.Status, r.Remediation)
	}
	if !slices.Equal(r.RFCRefs, refs) {
		t.Errorf("RFC refs = %q, want %q", r.RFCRefs, refs)
	}
}

// TestRunSPF_LookupFailures: a failed apex TXT lookup leaves the SPF record
// unknown, so the check is inconclusive rather than FAIL.
func TestRunSPF_LookupFailures(t *testing.T) {
	assertTXTLookupFailuresInconclusive(t, runSPF, "example.com", "example.com", cannedZone{})
}

// txtLookupFailures are resolver answers that leave a TXT record's
// existence unknown; RFC 7208 §4.4 calls them a temperror.
var txtLookupFailures = []struct {
	name   string
	rcode  int
	detail string // in the evidence
}{
	{"SERVFAIL", mdns.RcodeServerFailure, "resolver answered SERVFAIL"},
	{"REFUSED", mdns.RcodeRefused, "resolver answered REFUSED"},
	{"no answer", noReply, "timeout"},
}

// assertTXTLookupFailuresInconclusive runs check against target once for
// each of txtLookupFailures, with the TXT lookup at name failing that way
// and zone answering every other query, and wants a single inconclusive
// result naming the lookup.
func assertTXTLookupFailuresInconclusive(
	t *testing.T, check func(context.Context, *probe.Env) []report.Result,
	target, name string, zone cannedZone,
) {
	t.Helper()
	for _, tc := range txtLookupFailures {
		t.Run(tc.name, func(t *testing.T) {
			zone.rcode = map[string]int{name: tc.rcode}
			env := probe.NewEnv(target, 300*time.Millisecond, false, startCannedDNS(t, zone))
			res := check(context.Background(), env)
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(res), res)
			}
			assertInconclusive(t, res[0], "TXT lookup for "+name, tc.detail)
		})
	}
}
