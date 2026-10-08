package bimi

import (
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/report"
)

// gateZone returns a zone publishing a BIMI record for target, whose URLs
// the gate never fetches, plus the given DMARC records by name.
func gateZone(target string, dmarc map[string]string) testZone {
	zone := testZone{txt: map[string][]string{
		"default._bimi." + target: {"v=BIMI1; l=https://" + target + "/logo.svg; a=https://" +
			target + "/vmc.pem"},
	}}
	for name, record := range dmarc {
		zone.txt[name] = []string{record}
	}
	return zone
}

func runGate(t *testing.T, target string, zone testZone) report.Result {
	t.Helper()
	return runOne(t, gmailGateCheck{}, newZoneEnv(t, target, zone, 2*time.Second))
}

func TestGmailGateWithoutBIMIRecord(t *testing.T) {
	zone := testZone{txt: map[string][]string{"_dmarc.example.test": {"v=DMARC1; p=none"}}}
	r := runGate(t, "example.test", zone)
	if r.Status != report.NotApplicable || r.Remediation != "" {
		t.Errorf("got %s %q (remediation %q), want N/A without remediation",
			r.Status, r.Evidence, r.Remediation)
	}
}

func TestGmailGateWithoutDMARC(t *testing.T) {
	r := runGate(t, "example.test", gateZone("example.test", nil))
	const want = "no DMARC record at _dmarc.example.test or any tree-walk ancestor"
	if r.Status != report.Fail || r.Evidence != want {
		t.Errorf("got %s %q, want FAIL %q", r.Status, r.Evidence, want)
	}
	if !strings.Contains(r.Remediation, "_dmarc.example.test. IN TXT") {
		t.Errorf("remediation %q does not publish _dmarc.example.test", r.Remediation)
	}
}

func TestGmailGateDMARCLookupFailure(t *testing.T) {
	zone := gateZone("example.test", map[string]string{"_dmarc.test": "v=DMARC1; p=reject"})
	zone.servfail = map[string]bool{"_dmarc.example.test": true}
	r := runGate(t, "example.test", zone)
	const want = "could not determine: TXT lookup for _dmarc.example.test: " +
		"resolver answered SERVFAIL"
	if r.Status != report.Warn || r.Evidence != want || r.Remediation != "" {
		t.Errorf("got %s %q (remediation %q), want Inconclusive %q",
			r.Status, r.Evidence, r.Remediation, want)
	}
}

func TestGmailGateGrades(t *testing.T) {
	cases := []struct {
		name       string
		target     string
		dmarc      map[string]string
		wantStatus report.Status
		wantIn     []string // evidence substrings
		wantOut    []string // evidence substrings that must be absent
		wantFix    string   // remediation substring
	}{
		{
			name: "none and pct below 100", target: "example.test",
			dmarc:      map[string]string{"_dmarc.example.test": "v=DMARC1; p=none; pct=50"},
			wantStatus: report.Fail,
			wantIn:     []string{"p=none at _dmarc.example.test", "pct=50 at _dmarc.example.test"},
			wantOut:    []string{"sp=none"},
			wantFix:    `_dmarc.example.test. IN TXT "v=DMARC1; p=quarantine;`,
		},
		{
			name: "relaxed alignment", target: "example.test",
			dmarc:      map[string]string{"_dmarc.example.test": "v=DMARC1; p=reject"},
			wantStatus: report.Pass,
			wantIn: []string{
				"effective policy reject", "recommended, not required: strict alignment",
			},
		},
		{
			name: "strict alignment", target: "example.test",
			dmarc: map[string]string{
				"_dmarc.example.test": "v=DMARC1; p=quarantine; adkim=s; aspf=s",
			},
			wantStatus: report.Pass,
			wantOut:    []string{"recommended"},
		},
		{
			name: "subdomain policy none", target: "example.test",
			dmarc:      map[string]string{"_dmarc.example.test": "v=DMARC1; p=reject; sp=none"},
			wantStatus: report.Fail,
			wantIn:     []string{"sp=none at _dmarc.example.test"},
			wantOut:    []string{"p=reject at"},
			wantFix:    `_dmarc.example.test. IN TXT "v=DMARC1; p=reject;`,
		},
		{
			name: "subdomain inherits sp=none", target: "mail.example.test",
			dmarc:      map[string]string{"_dmarc.example.test": "v=DMARC1; p=reject; sp=none"},
			wantStatus: report.Fail,
			wantIn:     []string{"sp=none at _dmarc.example.test"},
		},
		{
			name: "subdomain inherits enforcement", target: "mail.example.test",
			dmarc:      map[string]string{"_dmarc.example.test": "v=DMARC1; p=reject"},
			wantStatus: report.Pass,
			wantIn:     []string{"effective policy reject for mail.example.test"},
		},
		{
			name: "organizational domain at none", target: "mail.example.test",
			dmarc: map[string]string{
				"_dmarc.mail.example.test": "v=DMARC1; p=reject",
				"_dmarc.example.test":      "v=DMARC1; p=none",
			},
			wantStatus: report.Fail,
			wantIn:     []string{"p=none at _dmarc.example.test"},
			wantOut:    []string{"_dmarc.mail.example.test"},
		},
		{
			name: "test mode", target: "example.test",
			dmarc:      map[string]string{"_dmarc.example.test": "v=DMARC1; p=reject; t=y"},
			wantStatus: report.Fail,
			wantIn:     []string{"t=y at _dmarc.example.test"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runGate(t, tc.target, gateZone(tc.target, tc.dmarc))
			if r.Status != tc.wantStatus {
				t.Errorf("status = %s (%q), want %s", r.Status, r.Evidence, tc.wantStatus)
			}
			checkEvidence(t, r.Evidence, tc.wantIn, tc.wantOut)
			if (r.Status == report.Fail) != (r.Remediation != "") {
				t.Errorf("status %s with remediation %q", r.Status, r.Remediation)
			}
			if !strings.Contains(r.Remediation, tc.wantFix) {
				t.Errorf("remediation %q lacks %q", r.Remediation, tc.wantFix)
			}
		})
	}
}

// checkEvidence reports each of want that evidence lacks and each of absent
// that it contains.
func checkEvidence(t *testing.T, evidence string, want, absent []string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(evidence, s) {
			t.Errorf("evidence %q lacks %q", evidence, s)
		}
	}
	for _, s := range absent {
		if strings.Contains(evidence, s) {
			t.Errorf("evidence %q contains %q", evidence, s)
		}
	}
}

// TestGmailGateRemediatesFailingRecord checks that the fix names the record
// that fails, here the Organizational Domain's rather than the target's.
func TestGmailGateRemediatesFailingRecord(t *testing.T) {
	r := runGate(t, "mail.example.test", gateZone("mail.example.test", map[string]string{
		"_dmarc.mail.example.test": "v=DMARC1; p=reject",
		"_dmarc.example.test":      "v=DMARC1; p=none",
	}))
	const want = `_dmarc.example.test. IN TXT ` +
		`"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.test"`
	if r.Remediation != want {
		t.Errorf("remediation = %q, want %q", r.Remediation, want)
	}
}
