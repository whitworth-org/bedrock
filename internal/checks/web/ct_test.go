package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ocsp"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
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

// tlsSCT serializes an RFC 6962 §3.2 v1 SignedCertificateTimestamp
// timestamped at ts, with a placeholder signature.
func tlsSCT(t *testing.T, ts time.Time) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(0)                // v1
	b.AddBytes(make([]byte, 32)) // log ID
	b.AddUint64(uint64(ts.UnixMilli()))
	b.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {}) // no extensions
	b.AddUint16(0x0403)                                     // SHA-256 with ECDSA
	b.AddUint16LengthPrefixed(func(sig *cryptobyte.Builder) { sig.AddBytes([]byte{0x30, 0x00}) })
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("build SCT: %v", err)
	}
	return raw
}

// TestCountSCTs: the TLS extension's SCTs count only when each is a
// well-formed v1 SCT timestamped while the leaf has been valid.
func TestCountSCTs(t *testing.T) {
	pki := newTestPKI(t)
	sct := tlsSCT(t, time.Now().Add(-time.Minute))
	cases := []struct {
		name string
		scts [][]byte
		want int
	}{
		{"none", nil, 0},
		{"two well-formed", [][]byte{sct, sct}, 2},
		{"junk", [][]byte{{0x01}, {0x02}}, 0},
		{"the replaced certificate's", [][]byte{tlsSCT(t, time.Now().Add(-30*24*time.Hour))}, 0},
		{"timestamped in the future", [][]byte{tlsSCT(t, time.Now().Add(time.Hour))}, 0},
		{"version 2", [][]byte{append([]byte{1}, sct[1:]...)}, 0},
		{"trailing byte", [][]byte{append(append([]byte{}, sct...), 0)}, 0},
		{"empty signature", [][]byte{append(sct[:len(sct)-4:len(sct)-4], 0, 0)}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := countSCTs(&tls.ConnectionState{
				PeerCertificates:            []*x509.Certificate{pki.leafCert},
				SignedCertificateTimestamps: tc.scts,
			}, nil)
			if err != nil || got.tls != tc.want {
				t.Errorf("countSCTs = %+v, %v; want %d TLS-extension SCTs", got, err, tc.want)
			}
		})
	}
	if got, err := countSCTs(nil, nil); err != nil || got.total() != 0 {
		t.Errorf("countSCTs(nil) = %+v, %v; want none", got, err)
	}
}

// sctListValue encodes scts as the extension value RFC 6962 §3.3 defines: a
// DER OCTET STRING holding a u16-length-prefixed list of u16-length-prefixed
// SCTs.
func sctListValue(t *testing.T, scts ...[]byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, sct := range scts {
			list.AddUint16LengthPrefixed(func(entry *cryptobyte.Builder) {
				entry.AddBytes(sct)
			})
		}
	})
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("build SCT list: %v", err)
	}
	return octetString(t, raw)
}

func octetString(t *testing.T, b []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(b)
	if err != nil {
		t.Fatalf("marshal OCTET STRING: %v", err)
	}
	return der
}

// leafWithSCTExtension issues a leaf from pki whose certificate SCT
// extension holds value.
func leafWithSCTExtension(t *testing.T, pki *testPKI, value []byte) *x509.Certificate {
	t.Helper()
	leaf, _ := pki.issue(t, &x509.Certificate{
		SerialNumber:    big.NewInt(5150),
		Subject:         pkix.Name{CommonName: "leaf.test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidCertSCTList, Value: value}},
	})
	return leaf
}

// runCTSCTsWith runs the SCT check against a shared handshake with
// leaf.test that recorded state and the verified chains.
func runCTSCTsWith(
	t *testing.T, state *tls.ConnectionState, chains ...[]*x509.Certificate,
) report.Result {
	t.Helper()
	env := probe.NewEnv("leaf.test", time.Second, true, "")
	env.CachePut(tlsStateKey("leaf.test"), &tlsHandshake{state: state, chains: chains})
	return runCTSCTs(context.Background(), env)
}

// TestRunCTSCTs_CountsEveryChannel: RFC 6962 §3.3 lets a server deliver SCTs
// in the certificate, the TLS extension or the OCSP staple. Nearly every
// public CA embeds them, so a check that ignored embedded SCTs FAILed
// compliant sites. Stapled SCTs count only when the staple validates.
func TestRunCTSCTs_CountsEveryChannel(t *testing.T) {
	pki := newTestPKI(t)
	twoSCTs := sctListValue(t, []byte{0x00, 0x01}, []byte{0x00, 0x02})
	embedded := leafWithSCTExtension(t, pki, twoSCTs)
	now := time.Now()
	stapleFrom := func(signer *testPKI) []byte {
		return signer.signOCSP(t, ocsp.Response{
			Status: ocsp.Good, SerialNumber: pki.leafCert.SerialNumber,
			ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: oidOCSPSCTList, Value: twoSCTs}},
		})
	}
	cases := []struct {
		name     string
		state    *tls.ConnectionState
		want     report.Status
		evidence string
	}{
		{
			name: "embedded in the certificate",
			state: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{embedded, pki.issuerCert},
			},
			want:     report.Pass,
			evidence: "2 SCT(s) (embedded 2, TLS extension 0, OCSP staple 0)",
		},
		{
			name: "TLS extension",
			state: &tls.ConnectionState{
				PeerCertificates:            []*x509.Certificate{pki.leafCert, pki.issuerCert},
				SignedCertificateTimestamps: [][]byte{tlsSCT(t, now), tlsSCT(t, now)},
			},
			want: report.Warn,
			evidence: "2 SCT(s) (embedded 0, TLS extension 2, OCSP staple 0); " +
				"the TLS extension's SCT signatures are not verified",
		},
		{
			name: "TLS extension beside embedded",
			state: &tls.ConnectionState{
				PeerCertificates:            []*x509.Certificate{embedded, pki.issuerCert},
				SignedCertificateTimestamps: [][]byte{tlsSCT(t, now)},
			},
			want:     report.Pass,
			evidence: "3 SCT(s) (embedded 2, TLS extension 1, OCSP staple 0)",
		},
		{
			name: "junk in the TLS extension",
			state: &tls.ConnectionState{
				PeerCertificates:            []*x509.Certificate{pki.leafCert, pki.issuerCert},
				SignedCertificateTimestamps: [][]byte{{0x01}, {0x02}},
			},
			want:     report.Fail,
			evidence: "0 SCT(s) (embedded 0, TLS extension 0, OCSP staple 0)",
		},
		{
			name: "staple signed by the verified issuer",
			state: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
				OCSPResponse:     stapleFrom(pki),
			},
			want:     report.Pass,
			evidence: "2 SCT(s) (embedded 0, TLS extension 0, OCSP staple 2)",
		},
		{
			name: "staple signed by another CA",
			state: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
				OCSPResponse:     stapleFrom(newTestPKI(t)),
			},
			want:     report.Fail,
			evidence: "0 SCT(s) (embedded 0, TLS extension 0, OCSP staple 0)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := []*x509.Certificate{tc.state.PeerCertificates[0], pki.issuerCert}
			r := runCTSCTsWith(t, tc.state, chain)
			if r.Status != tc.want || r.Evidence != tc.evidence {
				t.Errorf("got %s %q, want %s %q", r.Status, r.Evidence, tc.want, tc.evidence)
			}
		})
	}
}

// TestRunCTSCTs_MalformedSCTListIsInfo: when the SCT list cannot be parsed
// the count is unknown, which is INFO rather than a missing-SCT FAIL.
func TestRunCTSCTs_MalformedSCTListIsInfo(t *testing.T) {
	pki := newTestPKI(t)
	cases := []struct {
		name  string
		value []byte
	}{
		{"not an OCTET STRING", []byte{0x02, 0x01, 0x00}},
		{"bytes after the OCTET STRING", append(sctListValue(t, []byte{0x01}), 0x00)},
		{"list length past the end", octetString(t, []byte{0x00, 0x05, 0x00, 0x01, 0xaa})},
		{"bytes after the list", octetString(t, []byte{0x00, 0x03, 0x00, 0x01, 0xaa, 0xff})},
		{"truncated entry", octetString(t, []byte{0x00, 0x03, 0x00, 0x05, 0xaa})},
		{"empty entry", octetString(t, []byte{0x00, 0x02, 0x00, 0x00})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := leafWithSCTExtension(t, pki, tc.value)
			r := runCTSCTsWith(t, &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf, pki.issuerCert},
			}, []*x509.Certificate{leaf, pki.issuerCert})
			if r.Status != report.Info {
				t.Errorf("want Info, got %s (evidence=%q)", r.Status, r.Evidence)
			}
		})
	}
}

// TestRunCTSCTs_IssuerFromRecordedChain: stapled SCTs count against the
// issuer hostTLS's own verification found, even though the handshake skipped
// verification and so left ConnectionState.VerifiedChains empty; a server
// can put a self-made "issuer" right after the leaf, which must not count.
func TestRunCTSCTs_IssuerFromRecordedChain(t *testing.T) {
	pki := newTestPKI(t)
	attacker := newTestPKI(t)
	now := time.Now()
	staple := pki.signOCSP(t, ocsp.Response{
		Status: ocsp.Good, SerialNumber: pki.leafCert.SerialNumber,
		ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidOCSPSCTList,
			Value: sctListValue(t, []byte{0x00, 0x01}, []byte{0x00, 0x02})}},
	})
	r := runCTSCTsWith(t, &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			pki.leafCert, attacker.issuerCert, pki.issuerCert,
		},
		OCSPResponse: staple,
	}, []*x509.Certificate{pki.leafCert, pki.issuerCert})
	want := "2 SCT(s) (embedded 0, TLS extension 0, OCSP staple 2)"
	if r.Status != report.Pass || r.Evidence != want {
		t.Errorf("got %s %q, want PASS %q", r.Status, r.Evidence, want)
	}
}

// TestRunCTSCTs_UnverifiedChainIsNotApplicable: SCTs on a chain that did
// not verify are not graded; web.cert.chain reports the chain.
func TestRunCTSCTs_UnverifiedChainIsNotApplicable(t *testing.T) {
	pki := newTestPKI(t)
	r := runCTSCTsWith(t, &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.leafCert, pki.issuerCert},
	})
	if r.Status != report.NotApplicable || r.Evidence != "TLS chain invalid; see web.cert.*" {
		t.Errorf("got %s %q, want N/A pointing at web.cert.*", r.Status, r.Evidence)
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

// TestRunCTLookup grades the run's one crt.sh query: a failed query is a
// WARN naming the error, and an answer is summarized as INFO.
func TestRunCTLookup(t *testing.T) {
	entry := crtShEntry{
		IssuerName: "C=US, O=Let's Encrypt, CN=R3",
		NotBefore:  "2024-04-15T00:00:00", NotAfter: "2024-07-15T00:00:00",
	}
	cases := []struct {
		name     string
		entries  []crtShEntry
		err      error
		status   report.Status
		evidence string
	}{
		{"query failed", nil, errors.New("crt.sh returned HTTP 502"), report.Warn,
			"could not query crt.sh: crt.sh returned HTTP 502"},
		{"no certificates", nil, nil, report.Info, "crt.sh returned 0 entries for %.example.com"},
		{"one certificate", []crtShEntry{entry}, nil, report.Info, "1 total certs; "},
	}
	for _, tc := range cases {
		r := runCTLookup("example.com", tc.entries, tc.err)
		if r.ID != "web.ct.lookup" || r.Status != tc.status ||
			!strings.HasPrefix(r.Evidence, tc.evidence) {
			t.Errorf("%s: got %s %q, want %s %q", tc.name, r.Status, r.Evidence, tc.status,
				tc.evidence)
		}
	}
}

// TestRunCTCAADiverge_NoEntries: without certificates from crt.sh there is
// nothing to compare, so the CAA records are not even looked up.
func TestRunCTCAADiverge_NoEntries(t *testing.T) {
	env := &probe.Env{Target: "example.com", Timeout: time.Second} // nil DNS: a lookup panics
	if r := runCTCAADiverge(context.Background(), env, nil); r != nil {
		t.Errorf("got %+v, want no result", r)
	}
}

func TestCTCheck_DisabledReturnsInfo(t *testing.T) {
	env := &probe.Env{Target: "example.com", EnableCT: false}
	results := ctCheck{}.Run(t.Context(), env)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].ID != "web.ct.lookup" {
		t.Errorf("ID = %q, want web.ct.lookup", results[0].ID)
	}
	if results[0].Status != report.Info {
		t.Errorf("Status = %s, want INFO", results[0].Status)
	}
}
