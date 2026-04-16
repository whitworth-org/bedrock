package web

import (
	"crypto/tls"
	"testing"
	"time"

	"bedrock/internal/probe"
)

func TestParseCrtShJSON_Array(t *testing.T) {
	body := []byte(`[
        {
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com",
            "not_before": "2024-01-01T00:00:00",
            "not_after":  "2024-04-01T00:00:00",
            "entry_timestamp": "2024-01-01T00:05:00.123"
        },
        {
            "issuer_ca_id": 99,
            "issuer_name": "C=US, O=Other CA, CN=X1",
            "common_name": "api.example.com",
            "name_value": "api.example.com",
            "not_before": "2023-06-01T00:00:00",
            "not_after":  "2023-09-01T00:00:00",
            "entry_timestamp": "2023-06-01T00:05:00"
        }
    ]`)
	entries, err := parseCrtShJSON(body)
	if err != nil {
		t.Fatalf("parseCrtShJSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].IssuerCAID != 16418 {
		t.Errorf("issuer_ca_id[0] = %d, want 16418", entries[0].IssuerCAID)
	}
	if entries[0].CommonName != "example.com" {
		t.Errorf("common_name[0] = %q, want example.com", entries[0].CommonName)
	}
}

func TestParseCrtShJSON_NDJSONFallback(t *testing.T) {
	body := []byte(`{"issuer_ca_id":1,"issuer_name":"O=A","common_name":"a.test","name_value":"a.test","not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00","entry_timestamp":"2024-01-01T00:05:00"}
{"issuer_ca_id":2,"issuer_name":"O=B","common_name":"b.test","name_value":"b.test","not_before":"2024-01-02T00:00:00","not_after":"2024-04-02T00:00:00","entry_timestamp":"2024-01-02T00:05:00"}`)
	entries, err := parseCrtShJSON(body)
	if err != nil {
		t.Fatalf("parseCrtShJSON NDJSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
}

func TestParseCrtShJSON_Empty(t *testing.T) {
	entries, err := parseCrtShJSON([]byte(""))
	if err != nil {
		t.Fatalf("parseCrtShJSON empty: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

func TestParseCrtShTime(t *testing.T) {
	cases := map[string]bool{
		"2024-01-02T03:04:05Z":       true,
		"2024-01-02T03:04:05.123Z":   true,
		"2024-01-02T03:04:05":        true,
		"2024-01-02T03:04:05.123456": true,
		"2024-01-02 03:04:05":        true,
		"":                           false,
		"not-a-date":                 false,
	}
	for in, wantOK := range cases {
		_, ok := parseCrtShTime(in)
		if ok != wantOK {
			t.Errorf("parseCrtShTime(%q) ok=%v, want %v", in, ok, wantOK)
		}
	}
}

func TestSummarizeCrtShEntries(t *testing.T) {
	now := time.Date(2024, 4, 16, 12, 0, 0, 0, time.UTC)
	entries := []crtShEntry{
		{
			IssuerName: "C=US, O=Let's Encrypt, CN=R3",
			NotBefore:  "2024-04-15T00:00:00", // 1 day ago → recent
			NotAfter:   "2024-07-15T00:00:00", // future → valid
		},
		{
			IssuerName: "C=US, O=Let's Encrypt, CN=R3",
			NotBefore:  "2024-04-10T00:00:00", // 6 days ago → recent
			NotAfter:   "2024-07-10T00:00:00", // valid
		},
		{
			IssuerName: "C=US, O=Other CA, CN=X1",
			NotBefore:  "2023-01-01T00:00:00", // ancient → not recent
			NotAfter:   "2023-04-01T00:00:00", // expired → not valid
		},
		{
			IssuerName: "C=US, O=Other CA, CN=X1",
			NotBefore:  "2024-01-01T00:00:00", // 3+ months ago → not recent
			NotAfter:   "2024-12-31T00:00:00", // valid
		},
	}
	s := summarizeCrtShEntries(entries, now)
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
	if s.UniqueIssuers != 2 {
		t.Errorf("UniqueIssuers = %d, want 2", s.UniqueIssuers)
	}
	if s.TopIssuer != "C=US, O=Let's Encrypt, CN=R3" {
		t.Errorf("TopIssuer = %q, want Let's Encrypt", s.TopIssuer)
	}
	if s.TopIssuerCount != 2 {
		t.Errorf("TopIssuerCount = %d, want 2", s.TopIssuerCount)
	}
	if s.ValidCount != 3 {
		t.Errorf("ValidCount = %d, want 3", s.ValidCount)
	}
	if s.RecentCount != 2 {
		t.Errorf("RecentCount = %d, want 2", s.RecentCount)
	}
}

func TestCountSCTs(t *testing.T) {
	cases := []struct {
		name  string
		state *tls.ConnectionState
		want  int
	}{
		{"nil state", nil, 0},
		{"zero SCTs", &tls.ConnectionState{}, 0},
		{
			"one SCT",
			&tls.ConnectionState{SignedCertificateTimestamps: [][]byte{{0x01}}},
			1,
		},
		{
			"two SCTs",
			&tls.ConnectionState{SignedCertificateTimestamps: [][]byte{{0x01}, {0x02}}},
			2,
		},
		{
			"three SCTs",
			&tls.ConnectionState{SignedCertificateTimestamps: [][]byte{{0x01}, {0x02}, {0x03}}},
			3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countSCTs(tc.state); got != tc.want {
				t.Errorf("countSCTs = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestNormalizeIssuerForCAA(t *testing.T) {
	cases := map[string]string{
		`C=US, O="Let's Encrypt", CN=R3`:        "let's encrypt",
		`C=US, O=Let's Encrypt, CN=R3`:          "let's encrypt",
		`CN=Some CA`:                            "",
		`O=DigiCert Inc, CN=DigiCert Global G2`: "digicert inc",
	}
	for in, want := range cases {
		if got := normalizeIssuerForCAA(in); got != want {
			t.Errorf("normalizeIssuerForCAA(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIssuerMatchesCAA(t *testing.T) {
	allowed := []string{"letsencrypt.org", "digicert.com"}
	cases := map[string]bool{
		"let's encrypt":   true,  // O=Let's Encrypt → letsencrypt
		"digicert inc":    true,  // contains "digicert"
		"sectigo limited": false, // not on allowlist
		"some other ca":   false,
	}
	for issuer, want := range cases {
		if got := issuerMatchesCAA(issuer, allowed); got != want {
			t.Errorf("issuerMatchesCAA(%q) = %v, want %v", issuer, got, want)
		}
	}
}

func TestCAAIssueAllowlist(t *testing.T) {
	records := []probe.CAA{
		{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
		{Flag: 0, Tag: "issuewild", Value: ";"}, // deny-all wildcard → skipped
		{Flag: 0, Tag: "iodef", Value: "mailto:sec@example.com"},
		{Flag: 0, Tag: "issue", Value: "digicert.com; account=12345"},
		{Flag: 0, Tag: "ISSUE", Value: "letsencrypt.org"}, // dedupe (case-insensitive tag)
	}
	got := caaIssueAllowlist(records)
	want := []string{"digicert.com", "letsencrypt.org"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCTCheck_DisabledReturnsNotApplicable(t *testing.T) {
	env := &probe.Env{Target: "example.com", EnableCT: false}
	results := ctCheck{}.Run(t.Context(), env)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].ID != "web.ct.lookup" {
		t.Errorf("ID = %q, want web.ct.lookup", results[0].ID)
	}
	if results[0].Status.String() != "N/A" {
		t.Errorf("Status = %s, want N/A", results[0].Status)
	}
}
