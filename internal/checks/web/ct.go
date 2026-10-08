package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// ctCheck queries Certificate Transparency log aggregators (crt.sh) for
// certificates issued for the apex (and subdomains) and inspects the SCTs
// served alongside the leaf certificate. CT is defined by RFC 6962 (CT v1)
// and RFC 9162 (CT v2). Chrome's CT enforcement requires >= 2 SCTs from
// independent logs for publicly trusted certs.
//
// Gated behind env.EnableCT because it issues a third-party HTTPS request
// to crt.sh — operators may want to keep the scan off-network or avoid
// leaking the target to a remote service.
//
// v1 of this check uses the crt.sh JSON API as a first-pass anomaly detector.
// A future v2 (parked) would read CT log tiles directly via the sunlight
// reader for live monitoring; that is intentionally out of scope here.
type ctCheck struct{}

func (ctCheck) ID() string       { return "web.ct" }
func (ctCheck) Category() string { return category }

// crtShEntry mirrors the subset of fields crt.sh's JSON output returns.
// Times come back in a non-strict ISO-8601 form (e.g. "2024-01-02T03:04:05"
// without a timezone) so we parse permissively.
type crtShEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// ctSummary is what we surface as Evidence for the lookup result.
type ctSummary struct {
	Total          int
	UniqueIssuers  int
	TopIssuer      string
	TopIssuerCount int
	RecentCount    int // issued within last 7 days
	ValidCount     int // not_after > now
	Issuers        []string
}

const (
	ctRecentWindow  = 7 * 24 * time.Hour
	ctRFCCore       = "RFC 6962"
	ctRFCv2         = "RFC 9162"
	ctRFCSCTSection = "RFC 6962 §3.3"
)

func (ctCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.EnableCT {
		return []report.Result{{
			ID: "web.ct.lookup", Category: category,
			Title:    "Certificate Transparency log lookup",
			Status:   report.Info,
			Evidence: "disabled (--enable-ct off)",
			RFCRefs:  []string{ctRFCCore, ctRFCv2},
		}}
	}

	entries, err := fetchCrtShEntries(ctx, env, env.Target)
	out := []report.Result{runCTLookup(env.Target, entries, err), runCTSCTs(ctx, env)}
	if extra := runCTCAADiverge(ctx, env, entries); extra != nil {
		out = append(out, *extra)
	}
	return out
}

// runCTLookup summarizes entries, the certificates crt.sh returned for
// target, or reports err, the query's failure, as a Warn: crt.sh is a
// third-party service known to be flaky, so it should not gate the run.
func runCTLookup(target string, entries []crtShEntry, err error) report.Result {
	res := report.Result{
		ID: "web.ct.lookup", Category: category,
		Title:   "Certificate Transparency log lookup",
		RFCRefs: []string{ctRFCCore, ctRFCv2},
	}
	if err != nil {
		res.Status = report.Warn
		res.Evidence = "could not query crt.sh: " + err.Error()
		return res
	}

	summary := summarizeCrtShEntries(entries, time.Now())
	res.Status = report.Info
	if summary.Total == 0 {
		res.Evidence = "crt.sh returned 0 entries for %." + target
		return res
	}
	parts := []string{
		fmt.Sprintf("%d total certs", summary.Total),
		fmt.Sprintf("%d currently valid", summary.ValidCount),
		fmt.Sprintf("%d issued in last 7d", summary.RecentCount),
		fmt.Sprintf("%d unique issuer(s)", summary.UniqueIssuers),
	}
	if summary.TopIssuer != "" {
		parts = append(parts, fmt.Sprintf("top issuer: %q (%d)", summary.TopIssuer, summary.TopIssuerCount))
	}
	res.Evidence = strings.Join(parts, "; ")
	return res
}

// runCTSCTs counts the SCTs delivered for the leaf on the shared TLS
// handshake with the apex. RFC 6962 §3.3 lets a server deliver SCTs in an
// X.509 v3 extension on the cert itself, the TLS extension, or an
// OCSP-stapled response, and all three count. Warn/Fail are reported only
// for a chain that verified. Only the TLS extension's SCTs are not signed
// by the CA, and bedrock cannot check their log signatures, so they alone
// do not make a PASS.
func runCTSCTs(ctx context.Context, env *probe.Env) report.Result {
	res := report.Result{
		ID: "web.ct.scts", Category: category,
		Title:   "Signed Certificate Timestamps (SCTs)",
		RFCRefs: []string{ctRFCSCTSection, ctRFCv2},
	}
	if !env.Active {
		res.Status = report.NotApplicable
		res.Evidence = "active probing disabled (--no-active)"
		return res
	}
	h := hostTLS(ctx, env, env.Target)
	switch {
	case h.err != nil:
		res.Status = report.Info // web.tls.profile reports the failure
		return handshakeFailed(ctx, res, h.err)
	case len(h.chains) == 0:
		return chainInvalid(res)
	}
	counts, err := countSCTs(h.state, h.verifiedIssuer())
	if err != nil {
		res.Status = report.Info
		res.Evidence = "could not count SCTs: " + err.Error()
		return res
	}
	count := counts.total()
	res.Evidence = fmt.Sprintf("%d SCT(s) (embedded %d, TLS extension %d, OCSP staple %d)",
		count, counts.embedded, counts.tls, counts.ocsp)
	switch {
	case count == 0:
		res.Status = report.Fail
		res.Remediation = sctRemediation
	case count == 1:
		res.Status = report.Warn
		res.Remediation = sctRemediation
	case count-counts.tls < 2:
		res.Status = report.Warn
		res.Evidence += "; the TLS extension's SCT signatures are not verified"
		res.Remediation = sctRemediation
	default:
		res.Status = report.Pass
	}
	return res
}

const sctRemediation = "reissue the certificate from a CA that includes >= 2 SCTs " +
	"from independent CT logs (Let's Encrypt does this by default)"

// runCTCAADiverge cross-references the apex's CAA allowlist with the issuers
// crt.sh reports. If certs exist from CAs not on the allowlist, that is a
// strong signal of either an unauthorized issuance or a stale CAA record;
// either way the operator should investigate.
//
// entries are the certificates crt.sh returned. Returns nil when there is
// nothing notable to report (no CAA, no CT data, no divergence) so the
// caller can omit the result entirely.
func runCTCAADiverge(ctx context.Context, env *probe.Env, entries []crtShEntry) *report.Result {
	if len(entries) == 0 {
		return nil
	}
	cctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	caaRecords, err := env.DNS.LookupCAA(cctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return nil
	}
	allowed := caaIssueAllowlist(caaRecords)
	if len(allowed) == 0 {
		// No "issue" tags = either no CAA at all (any CA permitted) or a
		// "deny all" config. Either way the CAA check itself surfaces it;
		// we don't double-report here.
		return nil
	}

	now := time.Now()
	unauthorized := map[string]int{}
	for _, e := range entries {
		// Only consider currently valid certs — historical issuances from a
		// no-longer-allowed CA are noise, not an actionable finding.
		if !isCurrentlyValid(e, now) {
			continue
		}
		issuer := normalizeIssuerForCAA(e.IssuerName)
		if issuer == "" {
			continue
		}
		if !issuerMatchesCAA(issuer, allowed) {
			unauthorized[e.IssuerName]++
		}
	}
	if len(unauthorized) == 0 {
		return nil
	}

	names := make([]string, 0, len(unauthorized))
	for n := range unauthorized {
		names = append(names, fmt.Sprintf("%q (%d)", n, unauthorized[n]))
	}
	sort.Strings(names)

	return &report.Result{
		ID: "web.ct.caa_diverge", Category: category,
		Title:       "CT issuers diverge from CAA allowlist",
		Status:      report.Warn,
		Evidence:    "certs from issuers not in CAA allowlist " + strings.Join(allowed, ",") + ": " + strings.Join(names, ", "),
		Remediation: "either add the unauthorized issuer to your CAA allowlist or revoke any certs from that issuer",
		RFCRefs:     []string{"RFC 8659", ctRFCCore},
	}
}

// caaIssueAllowlist returns the set of CA identifiers from "issue" / "issuewild"
// CAA tags. RFC 8659 §4.2: an empty value (";") is a deny-all and yields nothing
// here — callers treat that the same as "no allowlist to enforce".
func caaIssueAllowlist(records []probe.CAA) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range records {
		tag := strings.ToLower(r.Tag)
		if tag != "issue" && tag != "issuewild" {
			continue
		}
		// CAA value syntax: "<domain>" or "<domain>; key=value; ..." — we
		// only care about the leading domain. ";" alone (deny-all) yields "".
		val := strings.TrimSpace(r.Value)
		if i := strings.IndexByte(val, ';'); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		if val == "" {
			continue
		}
		val = strings.ToLower(val)
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		out = append(out, val)
	}
	sort.Strings(out)
	return out
}

// normalizeIssuerForCAA pulls a comparable token out of crt.sh's free-form
// issuer DN. crt.sh returns issuer_name like
//
//	`C=US, O="Let's Encrypt", CN=R3`
//
// We fold the O attribute to lowercase and strip punctuation so it can be
// fuzzy-matched against the CAA value (e.g. "letsencrypt.org"). Returns the
// empty string when no O attribute is present.
func normalizeIssuerForCAA(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(kv[0]), "O") {
			v := strings.TrimSpace(kv[1])
			v = strings.Trim(v, `"`)
			return strings.ToLower(v)
		}
	}
	return ""
}

// issuerMatchesCAA returns true if the issuer's normalized O matches any
// allowlist entry. The match is intentionally loose (substring, both
// directions) because CAA values are domains while issuer Os are org names —
// e.g. "letsencrypt.org" vs "let's encrypt". Spaces, apostrophes, and
// punctuation are stripped before comparing.
func issuerMatchesCAA(issuer string, allowed []string) bool {
	clean := stripPunct(issuer)
	for _, a := range allowed {
		// Strip TLD-ish suffix from CAA value first ("letsencrypt.org" ->
		// "letsencrypt"), then drop remaining punctuation. Doing it in the
		// other order would erase the dot and leave us with "letsencryptorg".
		base := a
		if i := strings.LastIndexByte(base, '.'); i > 0 {
			base = base[:i]
		}
		acl := stripPunct(base)
		if acl == "" {
			continue
		}
		if strings.Contains(clean, acl) || strings.Contains(acl, clean) {
			return true
		}
	}
	return false
}

func stripPunct(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}

// fetchCrtShEntries hits crt.sh's JSON endpoint with a wildcard query
// (%.<target>) so we get apex + subdomain hits in one round trip; the lookup
// and CAA-divergence steps share the result. env.HTTP's per-operation
// timeouts and its client budget of three of them bound the request.
func fetchCrtShEntries(ctx context.Context, env *probe.Env, target string) ([]crtShEntry, error) {
	q := url.Values{}
	q.Set("q", "%."+target)
	q.Set("output", "json")
	u := "https://crt.sh/?" + q.Encode()

	resp, err := env.HTTP.GetStrict(ctx, u)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.Status)
	}
	return parseCrtShJSON(resp.Body) // capped by probe.HTTP
}

// parseCrtShJSON tolerates both the canonical array form and a NDJSON-ish
// fallback (one object per line) crt.sh has been known to emit when the
// query result is large. Empty bodies parse to an empty slice.
func parseCrtShJSON(body []byte) ([]crtShEntry, error) {
	trim := strings.TrimSpace(string(body))
	if trim == "" {
		return nil, nil
	}
	if strings.HasPrefix(trim, "[") {
		var out []crtShEntry
		if err := json.Unmarshal([]byte(trim), &out); err != nil {
			return nil, fmt.Errorf("parse crt.sh JSON: %w", err)
		}
		return out, nil
	}
	// NDJSON fallback: one object per line.
	var out []crtShEntry
	for _, line := range strings.Split(trim, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e crtShEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("parse crt.sh NDJSON line: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

// summarizeCrtShEntries computes the headline statistics. now is injectable
// so the test can pin "recent" to a deterministic window.
func summarizeCrtShEntries(entries []crtShEntry, now time.Time) ctSummary {
	s := ctSummary{Total: len(entries)}
	issuerCounts := map[string]int{}
	for _, e := range entries {
		if e.IssuerName != "" {
			issuerCounts[e.IssuerName]++
		}
		if isCurrentlyValid(e, now) {
			s.ValidCount++
		}
		if isRecent(e, now) {
			s.RecentCount++
		}
	}
	s.UniqueIssuers = len(issuerCounts)
	for name := range issuerCounts {
		s.Issuers = append(s.Issuers, name)
	}
	sort.Strings(s.Issuers)
	// Iterate sorted so the tie-break is deterministic: when two issuers are
	// tied on count, the lexicographically earlier name wins. Map iteration
	// order in Go is randomised, which made this comparison flaky.
	for _, name := range s.Issuers {
		if issuerCounts[name] > s.TopIssuerCount {
			s.TopIssuer = name
			s.TopIssuerCount = issuerCounts[name]
		}
	}
	return s
}

func isCurrentlyValid(e crtShEntry, now time.Time) bool {
	t, ok := parseCrtShTime(e.NotAfter)
	if !ok {
		return false
	}
	return t.After(now)
}

func isRecent(e crtShEntry, now time.Time) bool {
	t, ok := parseCrtShTime(e.NotBefore)
	if !ok {
		// Fall back to entry_timestamp if not_before is unparseable — the
		// log entry timestamp is a reasonable proxy for "issued recently".
		t, ok = parseCrtShTime(e.EntryTimestamp)
		if !ok {
			return false
		}
	}
	return now.Sub(t) <= ctRecentWindow && !t.After(now.Add(time.Hour))
}

// parseCrtShTime accepts the half-dozen forms crt.sh has been seen to emit:
// strict RFC 3339, RFC 3339 without timezone, and "YYYY-MM-DD HH:MM:SS".
func parseCrtShTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// RFC 6962 §3.3 identifiers of a SignedCertificateTimestampList carried in a
// certificate extension and in an OCSP singleExtension.
var (
	oidCertSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidOCSPSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}
)

var errMalformedSCTList = errors.New("malformed SCT list")

// sctCounts holds the number of SCTs found on each RFC 6962 §3.3 channel.
type sctCounts struct {
	embedded, tls, ocsp int
}

func (c sctCounts) total() int { return c.embedded + c.tls + c.ocsp }

// countSCTs counts the SCTs on each RFC 6962 §3.3 channel; issuer is the
// leaf's issuer in the verified chain, or nil. An SCT list that does not
// parse is an error rather than zero SCTs, so a list bedrock cannot read is
// not reported as missing.
func countSCTs(state *tls.ConnectionState, issuer *x509.Certificate) (sctCounts, error) {
	var c sctCounts
	if state == nil || len(state.PeerCertificates) == 0 {
		return c, nil
	}
	leaf := state.PeerCertificates[0]
	c.tls = tlsExtensionSCTs(state.SignedCertificateTimestamps, leaf, time.Now())
	var err error
	if c.embedded, err = sctsInExtension(leaf.Extensions, oidCertSCTList); err != nil {
		return c, fmt.Errorf("certificate extension %s: %w", oidCertSCTList, err)
	}
	if c.ocsp, err = stapledSCTs(state.OCSPResponse, leaf, issuer); err != nil {
		return c, fmt.Errorf("OCSP staple extension %s: %w", oidOCSPSCTList, err)
	}
	return c, nil
}

// tlsExtensionSCTs counts the SCTs from the TLS extension that are
// well-formed RFC 6962 §3.2 v1 SCTs timestamped between leaf's NotBefore and
// now, allowing revocationSkew, so a server still sending the SCTs of the
// certificate it replaced gets no credit for them.
func tlsExtensionSCTs(scts [][]byte, leaf *x509.Certificate, now time.Time) int {
	n := 0
	for _, raw := range scts {
		ts, ok := sctTimestamp(raw)
		if ok && !ts.Before(leaf.NotBefore.Add(-revocationSkew)) &&
			!ts.After(now.Add(revocationSkew)) {
			n++
		}
	}
	return n
}

// sctTimestamp returns the timestamp of raw, a serialized RFC 6962 §3.2
// SignedCertificateTimestamp, and whether raw is a well-formed v1 SCT.
func sctTimestamp(raw []byte) (time.Time, bool) {
	s := cryptobyte.String(raw)
	var version uint8
	var logID []byte
	var ms uint64
	if !s.ReadUint8(&version) || version != 0 || !s.ReadBytes(&logID, 32) || !s.ReadUint64(&ms) {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(ms)), sctTrailerOK(s)
}

// sctTrailerOK reports whether s holds exactly the rest of an SCT: its
// extensions, then a digitally-signed signature with a non-empty value.
func sctTrailerOK(s cryptobyte.String) bool {
	var exts, signature cryptobyte.String
	var algorithms uint16
	return s.ReadUint16LengthPrefixed(&exts) && s.ReadUint16(&algorithms) &&
		s.ReadUint16LengthPrefixed(&signature) && !signature.Empty() && s.Empty()
}

// stapledSCTs counts the SCTs in staple, the stapled OCSP response. They
// count only when the staple validates for leaf against issuer, the leaf's
// issuer in the verified chain, which is what web.ocsp.staple checks too.
func stapledSCTs(staple []byte, leaf, issuer *x509.Certificate) (int, error) {
	if len(staple) == 0 || issuer == nil {
		return 0, nil
	}
	resp, err := parseOCSPForLeaf(staple, leaf, issuer, time.Now())
	if err != nil {
		// web.ocsp.staple reports the invalid staple; its SCTs do not count.
		return 0, nil
	}
	return sctsInExtension(resp.Extensions, oidOCSPSCTList)
}

// sctsInExtension counts the SCTs in the extension with id oid, or returns 0
// when exts has none.
func sctsInExtension(exts []pkix.Extension, oid asn1.ObjectIdentifier) (int, error) {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return sctListLen(ext.Value)
		}
	}
	return 0, nil
}

// sctListLen counts the SCTs in an RFC 6962 §3.3 extension value: a DER
// OCTET STRING holding a u16-length-prefixed list of u16-length-prefixed
// SCTs. Trailing bytes, a truncated entry or an empty entry make the list
// malformed.
func sctListLen(extValue []byte) (int, error) {
	var raw []byte
	rest, err := asn1.Unmarshal(extValue, &raw)
	if err != nil || len(rest) != 0 {
		return 0, errMalformedSCTList
	}
	s := cryptobyte.String(raw)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
		return 0, errMalformedSCTList
	}
	n := 0
	for ; !list.Empty(); n++ {
		var sct cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&sct) || sct.Empty() {
			return 0, errMalformedSCTList
		}
	}
	return n, nil
}

func init() { registry.Register(ctCheck{}) }
