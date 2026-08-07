package web

import (
	"strings"
	"testing"
	"time"
)

var secTxtNow = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

const secTxtURL = "https://example.com/.well-known/security.txt"

const secTxtClearsigned = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

- # dash-escaped comment
Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00Z
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEE
-----END PGP SIGNATURE-----
`

func TestParseSecurityTxt(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string // substring; "" means parse must succeed
		contact int
		expires int
		signed  bool
	}{
		{
			name:    "minimal LF",
			body:    "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
			contact: 1, expires: 1,
		},
		{
			name:    "CRLF with comment and blank line",
			body:    "# policy\r\nContact: https://example.com/report\r\n\r\nExpires: 2027-01-01T00:00:00Z\r\n",
			contact: 1, expires: 1,
		},
		{
			name:    "UTF-8 BOM stripped",
			body:    "\uFEFFContact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z",
			contact: 1, expires: 1,
		},
		{
			name:    "field names are case-insensitive",
			body:    "CONTACT: mailto:s@example.com\nexpires: 2027-01-01T00:00:00Z",
			contact: 1, expires: 1,
		},
		{
			name:    "clearsigned with dash escape",
			body:    secTxtClearsigned,
			contact: 1, expires: 1, signed: true,
		},
		{
			name:    "line without colon",
			body:    "Contact: mailto:s@example.com\nnot a field line\n",
			wantErr: "not a \"Field: value\" pair",
		},
		{
			name:    "empty value",
			body:    "Contact:\n",
			wantErr: "empty value",
		},
		{
			name:    "oversized field value",
			body:    "Contact: mailto:" + strings.Repeat("a", maxSecTxtFieldLen) + "@example.com\n",
			wantErr: "cap is 2048",
		},
		{
			name:    "too many lines",
			body:    strings.Repeat("# c\n", maxSecTxtLines+1),
			wantErr: "line cap",
		},
		{
			name:    "oversized body",
			body:    "# " + strings.Repeat("a", maxSecTxtBytes) + "\n",
			wantErr: "byte cap",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := parseSecurityTxt(tc.body)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := len(st.values("contact")); got != tc.contact {
				t.Errorf("contact count = %d, want %d", got, tc.contact)
			}
			if got := len(st.values("expires")); got != tc.expires {
				t.Errorf("expires count = %d, want %d", got, tc.expires)
			}
			if st.signed != tc.signed {
				t.Errorf("signed = %v, want %v", st.signed, tc.signed)
			}
		})
	}
}

func TestEvaluateSecTxt(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		finalURL      string
		wantViolation string // substring of a violation; "" = none expected
		wantWarning   string // substring of a warning; "" = none expected
		wantSummary   string // substring of the summary; "" = don't check
	}{
		{
			name:        "valid minimal passes",
			body:        "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
			wantSummary: "contact: mailto:security@example.com",
		},
		{
			name:          "missing Contact",
			body:          "Expires: 2027-01-01T00:00:00Z\n",
			wantViolation: "missing required Contact",
		},
		{
			name:          "bare email is not a URI",
			body:          "Contact: security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
			wantViolation: "not an absolute URI",
		},
		{
			name:          "http contact URI",
			body:          "Contact: http://example.com/report\nExpires: 2027-01-01T00:00:00Z\n",
			wantViolation: "web URIs must be https",
		},
		{
			name:          "missing Expires",
			body:          "Contact: mailto:security@example.com\n",
			wantViolation: "missing required Expires",
		},
		{
			name:          "duplicate Expires",
			body:          "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n",
			wantViolation: "appears 2 times",
		},
		{
			// RFC 3339 §5.6: 't' and 'z' may be lower case (github.com does this).
			name:        "lowercase z in Expires is valid RFC 3339",
			body:        "Contact: mailto:s@example.com\nExpires: 2027-01-01t00:00:00z\n",
			wantSummary: "expires: 2027-01-01t00:00:00z",
		},
		{
			name:          "malformed Expires",
			body:          "Contact: mailto:s@example.com\nExpires: January 1st 2027\n",
			wantViolation: "not an RFC 3339 timestamp",
		},
		{
			name:          "expired file",
			body:          "Contact: mailto:s@example.com\nExpires: 2026-01-01T00:00:00Z\n",
			wantViolation: "expired",
		},
		{
			name:        "expiry beyond a year warns",
			body:        "Contact: mailto:s@example.com\nExpires: 2030-01-01T00:00:00Z\n",
			wantWarning: "more than a year out",
		},
		{
			name:          "duplicate Preferred-Languages",
			body:          "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en\nPreferred-Languages: de\n",
			wantViolation: "Preferred-Languages appears 2 times",
		},
		{
			name:          "http Policy URI",
			body:          "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nPolicy: http://example.com/policy\n",
			wantViolation: "must begin with https://",
		},
		{
			name:        "Canonical mismatch warns",
			body:        "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://other.example/.well-known/security.txt\n",
			wantWarning: "not listed in Canonical",
		},
		{
			name: "Canonical match is clean",
			body: "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: " + secTxtURL + "\n",
		},
		{
			name: "Encryption dns scheme is allowed",
			body: "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nEncryption: dns:key.example.com?type=OPENPGPKEY\n",
		},
		{
			name:        "clearsigned noted in summary",
			body:        secTxtClearsigned,
			wantSummary: "OpenPGP clearsigned",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := parseSecurityTxt(tc.body)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			finalURL := tc.finalURL
			if finalURL == "" {
				finalURL = secTxtURL
			}
			violations, warnings, summary := evaluateSecTxt(st, finalURL, secTxtNow)
			checkIssueList(t, "violations", violations, tc.wantViolation)
			checkIssueList(t, "warnings", warnings, tc.wantWarning)
			if tc.wantSummary != "" && !strings.Contains(strings.Join(summary, "; "), tc.wantSummary) {
				t.Errorf("summary %q missing %q", strings.Join(summary, "; "), tc.wantSummary)
			}
		})
	}
}

// checkIssueList asserts that want appears in got when non-empty, and that
// got is empty when want is empty.
func checkIssueList(t *testing.T, kind string, got []string, want string) {
	t.Helper()
	joined := strings.Join(got, "; ")
	if want == "" {
		if len(got) > 0 {
			t.Errorf("unexpected %s: %q", kind, joined)
		}
		return
	}
	if !strings.Contains(joined, want) {
		t.Errorf("%s %q missing %q", kind, joined, want)
	}
}

func TestSecTxtContentTypeIssue(t *testing.T) {
	cases := []struct {
		header string
		wantOK bool
	}{
		{"text/plain", true},
		{"text/plain; charset=utf-8", true},
		{"TEXT/PLAIN; charset=UTF-8", true},
		{"", false},
		{"text/html", false},
		{"text/plain; charset=iso-8859-1", false},
	}
	for _, tc := range cases {
		if issue := secTxtContentTypeIssue(tc.header); (issue == "") != tc.wantOK {
			t.Errorf("secTxtContentTypeIssue(%q) = %q, wantOK=%v", tc.header, issue, tc.wantOK)
		}
	}
}

func TestSecTxtVerdictStatuses(t *testing.T) {
	fail := secTxtVerdict("example.com", []string{"missing required Contact field (§2.5.3)"}, nil, nil)
	if fail.Status.String() != "FAIL" || fail.Remediation == "" {
		t.Errorf("violation verdict = %v (remediation %q), want FAIL with remediation",
			fail.Status, fail.Remediation)
	}
	warn := secTxtVerdict("example.com", nil, []string{"Expires is far out"}, []string{"contact: x"})
	if warn.Status.String() != "WARN" {
		t.Errorf("warning verdict = %v, want WARN", warn.Status)
	}
	pass := secTxtVerdict("example.com", nil, nil, []string{"contact: x", "expires: y"})
	if pass.Status.String() != "PASS" || pass.Evidence != "contact: x; expires: y" {
		t.Errorf("clean verdict = %v evidence=%q, want PASS", pass.Status, pass.Evidence)
	}
}

// TestRemediationExpiresInsideHorizon pins the remediation template against
// the check's own Expires rules: the example it tells operators to publish
// must never trip a violation or the under-a-year warning. now is fixed
// just before a leap day, the case where a one-year AddDate spans 366 days.
func TestRemediationExpiresInsideHorizon(t *testing.T) {
	now := time.Date(2024, 2, 28, 12, 0, 0, 0, time.UTC)
	rem := securityTxtRemediation("example.com", now)
	var exp string
	for _, line := range strings.Split(rem, "\n") {
		if v, ok := strings.CutPrefix(line, "Expires: "); ok {
			exp = v
		}
	}
	if exp == "" {
		t.Fatalf("remediation has no Expires line:\n%s", rem)
	}
	st := &securityTxt{fields: map[string][]string{"expires": {exp}}}
	viol, warn, _ := secTxtExpiresIssues(st, now)
	if len(viol) > 0 || len(warn) > 0 {
		t.Errorf("remediation Expires %q trips the check itself: violations=%v warnings=%v",
			exp, viol, warn)
	}
}
