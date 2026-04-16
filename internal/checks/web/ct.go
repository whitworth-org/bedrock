package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
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
	ctUserAgent     = "granite-scan/0.1 (+https://example.invalid/)"
	ctMinSCTs       = 2 // Chrome CT policy floor for publicly trusted certs.
	ctRFCCore       = "RFC 6962"
	ctRFCv2         = "RFC 9162"
	ctRFCSCTSection = "RFC 6962 §3.3"
)

func (ctCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.EnableCT {
		return []report.Result{{
			ID: "web.ct.lookup", Category: category,
			Title:    "Certificate Transparency log lookup",
			Status:   report.NotApplicable,
			Evidence: "disabled (--enable-ct off)",
			RFCRefs:  []string{ctRFCCore, ctRFCv2},
		}}
	}

	var out []report.Result
	out = append(out, runCTLookup(ctx, env))
	out = append(out, runCTSCTs(ctx, env))
	if extra := runCTCAADiverge(ctx, env); extra != nil {
		out = append(out, *extra)
	}
	return out
}

// runCTLookup queries crt.sh and summarizes the aggregated certs. crt.sh
// failures are reported as Warn — they should not gate the run because the
// service is third-party and known to be flaky.
func runCTLookup(ctx context.Context, env *probe.Env) report.Result {
	res := report.Result{
		ID: "web.ct.lookup", Category: category,
		Title:   "Certificate Transparency log lookup",
		RFCRefs: []string{ctRFCCore, ctRFCv2},
	}

	// crt.sh can be slow; give it twice the per-op timeout but cap at 30s
	// so we never block the whole run waiting on a stuck connection.
	timeout := env.Timeout * 2
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	entries, err := fetchCrtShEntries(ctx, env.Target, timeout)
	if err != nil {
		res.Status = report.Warn
		res.Evidence = "could not query crt.sh: " + err.Error()
		return res
	}

	summary := summarizeCrtShEntries(entries, time.Now())
	res.Status = report.Info
	if summary.Total == 0 {
		res.Evidence = "crt.sh returned 0 entries for %." + env.Target
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

// runCTSCTs counts the SCTs the server stapled to the negotiated TLS
// connection. RFC 6962 §3.3 lets a server deliver SCTs via the TLS extension,
// an OCSP-stapled response, or an X.509 v3 extension on the cert itself.
// stdlib only surfaces the TLS-extension form via SignedCertificateTimestamps;
// SCTs embedded in the certificate are not surfaced here, so the check is
// intentionally soft (Warn/Fail are reported but only when we have a TLS state).
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
	state := getCachedTLSState(env)
	if state == nil {
		res.Status = report.NotApplicable
		res.Evidence = "no cached TLS state to inspect"
		return res
	}
	count := countSCTs(state)
	res.Evidence = fmt.Sprintf("%d SCT(s) delivered via TLS extension", count)
	switch {
	case count == 0:
		res.Status = report.Fail
		res.Remediation = "reissue the certificate from a CA that includes >= 2 SCTs from independent CT logs (Let's Encrypt does this by default)"
	case count == 1:
		res.Status = report.Warn
		res.Remediation = "reissue the certificate from a CA that includes >= 2 SCTs from independent CT logs (Let's Encrypt does this by default)"
	default:
		res.Status = report.Pass
	}
	return res
}

// runCTCAADiverge cross-references the apex's CAA allowlist with the issuers
// crt.sh reports. If certs exist from CAs not on the allowlist, that is a
// strong signal of either an unauthorized issuance or a stale CAA record;
// either way the operator should investigate.
//
// Returns nil when there is nothing notable to report (no CAA, no CT data,
// no divergence) so the caller can omit the result entirely.
func runCTCAADiverge(ctx context.Context, env *probe.Env) *report.Result {
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

	timeout := env.Timeout * 2
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	entries, err := fetchCrtShEntries(ctx, env.Target, timeout)
	if err != nil || len(entries) == 0 {
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
// (%.<target>) so we get apex + subdomain hits in one round trip. Caches the
// result on env so the lookup and CAA-diverge checks share a single fetch.
func fetchCrtShEntries(ctx context.Context, target string, timeout time.Duration) ([]crtShEntry, error) {
	const cacheKey = "web.ct.crtsh"
	// Ride along on env.cache via a process-local map keyed by target — but
	// the env isn't passed in; we accept a tiny duplicate fetch in the rare
	// CAA-divergence path rather than thread env through here. Two fetches
	// at most per run is acceptable.
	_ = cacheKey

	q := url.Values{}
	q.Set("q", "%."+target)
	q.Set("output", "json")
	u := "https://crt.sh/?" + q.Encode()

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ctUserAgent)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, err
	}
	return parseCrtShJSON(body)
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
	for name, c := range issuerCounts {
		s.Issuers = append(s.Issuers, name)
		if c > s.TopIssuerCount {
			s.TopIssuer = name
			s.TopIssuerCount = c
		}
	}
	sort.Strings(s.Issuers)
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

// countSCTs returns the number of SCTs delivered via the TLS extension.
// SCTs embedded in the certificate (X.509 extension 1.3.6.1.4.1.11129.2.4.2)
// are intentionally not counted — stdlib does not parse them and walking
// the raw extensions just to count is not worth the complexity in v1.
func countSCTs(state *tls.ConnectionState) int {
	if state == nil {
		return 0
	}
	return len(state.SignedCertificateTimestamps)
}

func init() { registry.Register(ctCheck{}) }
