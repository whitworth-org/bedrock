package email

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// DKIMKey is a parsed DKIM key record (RFC 6376 §3.6.1). DKIM2 (draft-ietf-
// dkim-dkim2-spec) publishes its keys at the same _domainkey location with
// v=DKIM2, so the same parser covers both generations.
type DKIMKey struct {
	Raw     string
	Version string // "v" tag, default "DKIM1"; "DKIM2" for DKIM2 key records
	KeyType string // "k", default "rsa"
	Service string // "s", default "*"
	Flags   string // "t", default ""
	Hashes  string // "h" acceptable hash algorithms, colon-separated, "" = all
	P       string // "p" base64 public key without folding whitespace, "" means revoked
	Tags    map[string]string
}

// ParseDKIM parses a DKIM key TXT record. RFC 6376 §3.2 tag-list syntax:
// tags separated by ";", each "name=value", whitespace around tokens ignored.
// The p= tag is required (RFC 6376 §3.6.1): an empty p= means the key was
// revoked, and the folding whitespace a base64 value may contain is removed.
//
// The parser rejects:
//   - Duplicate tag names (RFC 6376 §3.2 allows only one of each).
//   - A `d=` tag (uncommon in key records but seen in some ESP extensions)
//     whose value contains characters outside the DNS-safe set
//     [a-zA-Z0-9._-]. This keeps mis-issued records from smuggling
//     non-domain content (e.g. whitespace, "@", shell metacharacters)
//     through downstream consumers that log or act on it.
func ParseDKIM(raw string) (*DKIMKey, error) {
	tags, err := parseDKIMTags(raw)
	if err != nil {
		return nil, err
	}
	if d, ok := tags["d"]; ok && !isDNSSafeName(d) {
		return nil, fmt.Errorf("invalid d=%q (must match [a-zA-Z0-9._-])", d)
	}
	version, err := dkimVersion(tags["v"])
	if err != nil {
		return nil, err
	}
	p, ok := tags["p"]
	if !ok {
		return nil, errors.New("missing required p= tag (RFC 6376 §3.6.1)")
	}
	return &DKIMKey{
		Raw:     raw,
		Version: version,
		KeyType: tagOr(tags, "k", "rsa"),
		Service: tagOr(tags, "s", "*"),
		Flags:   tags["t"],
		Hashes:  tags["h"],
		P:       fwsRemover.Replace(p),
		Tags:    tags,
	}, nil
}

// fwsRemover deletes the folding whitespace (SP, HTAB, CR, LF) that RFC
// 6376's base64string allows between characters. Other Unicode spaces are not
// whitespace there, and removing them could join stray bytes into a key.
var fwsRemover = strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")

// parseDKIMTags splits a tag-list (RFC 6376 §3.2) into its tags. Tag names
// are case-sensitive, so duplicates are detected on the exact name.
func parseDKIMTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed tag %q", part)
		}
		name = strings.TrimSpace(name)
		if _, dup := tags[name]; dup {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		tags[name] = strings.TrimSpace(value)
	}
	return tags, nil
}

// tagOr returns the value of the tag name, or def when the record lacks it.
func tagOr(tags map[string]string, name, def string) string {
	if v, ok := tags[name]; ok {
		return v
	}
	return def
}

// dkimVersion normalizes a v= value: absent or DKIM1 is "DKIM1", and DKIM2
// key records (draft-ietf-dkim-dkim2-spec) live at the same _domainkey
// names as DKIM1.
func dkimVersion(v string) (string, error) {
	switch {
	case v == "", strings.EqualFold(v, "DKIM1"):
		return "DKIM1", nil
	case strings.EqualFold(v, "DKIM2"):
		return "DKIM2", nil
	}
	return "", fmt.Errorf("unexpected v=%q (want DKIM1 or DKIM2)", v)
}

// isDNSSafeName reports whether s uses only the limited DNS label character
// set [a-zA-Z0-9._-]. Empty strings are rejected.
func isDNSSafeName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// The selector list is constructed per-run by selectorList(env), which
// combines commonSelectors with ESP-specific extras inferred from SPF (see
// dkim_selectors.go). The actual DNS probing lives in dkim_sweep.go and runs
// once per scan; this check renders the sweep into per-selector results.

func dkimBaseRefs() []string { return []string{"RFC 6376 §3.6.1", "RFC 6376 §3.6.2"} }

// runDKIM reports each selector that publishes a key record of its own, the
// record a _domainkey wildcard gives every other selector, and each selector
// whose lookup failed. When no selector publishes a record, one
// email.dkim.selector.none result covers the whole sweep instead.
func runDKIM(ctx context.Context, env *probe.Env) []report.Result {
	sweep := dkimSweep(ctx, env)
	if sweep == nil {
		return nil
	}
	results, failed := selectorResults(sweep)
	if sweep.Wildcard != nil {
		results = append(results, dkimWildcardResult(sweep))
	}
	if len(results) == 0 {
		return []report.Result{dkimNoneResult(env.Target, sweep, failed)}
	}
	for _, p := range failed {
		results = append(results, dkimSelectorResult(p))
	}
	return results
}

// selectorResults renders the probes that found a key record of their own
// and returns the probes whose lookup failed.
func selectorResults(sweep *DKIMSweep) (results []report.Result, failed []DKIMProbe) {
	for _, p := range sweep.Probes {
		switch {
		case p.Outcome == dkimError:
			failed = append(failed, p)
		case p.Outcome != dkimMissing && !p.FromWildcard:
			results = append(results, dkimSelectorResult(p))
		}
	}
	return results, failed
}

// dkimNoneResult reports that no probed selector publishes a key record. A
// failed lookup may hide the key, so the result is a FAIL only when every
// lookup was answered.
func dkimNoneResult(target string, sweep *DKIMSweep, failed []DKIMProbe) report.Result {
	res := report.Result{
		ID:       "email.dkim.selector.none",
		Category: category,
		Title:    "DKIM key discoverable on a common selector",
		RFCRefs:  dkimBaseRefs(),
	}
	if len(failed) > 0 {
		return checkutil.Inconclusive(res, selectorLookupFailures(failed, len(sweep.Selectors)))
	}
	res.Status = report.Fail
	res.Evidence = "no DKIM key found at any of: " + strings.Join(sweep.Selectors, ", ")
	res.Remediation = dkimKeyRemediation("<selector>._domainkey." + target)
	return res
}

// selectorLookupFailures describes the failed selector lookups out of total,
// naming at most checkutil.MaxListed selectors and quoting the first error.
func selectorLookupFailures(failed []DKIMProbe, total int) error {
	if len(failed) == total {
		return fmt.Errorf("TXT lookups failed for all %d selectors (first error: %s)",
			total, failed[0].Detail)
	}
	names := make([]string, len(failed))
	for i, p := range failed {
		names[i] = p.Selector
	}
	return fmt.Errorf("TXT lookups failed for %d of %d selectors (%s; first error: %s); "+
		"the others publish no key", len(failed), total, checkutil.ListBounded(names, ", "),
		failed[0].Detail)
}

// dkimWildcardResult reports the key record that a _domainkey wildcard gives
// every selector without a record of its own. A revoked wildcard is how a
// domain declares that it signs no mail (M3AAWG parked-domain practice), so
// it is INFO. A wildcard inferred from the selectors' records, because the
// random selectors' lookups failed, is inconclusive.
func dkimWildcardResult(sweep *DKIMSweep) report.Result {
	w := *sweep.Wildcard
	res := dkimSelectorResult(w)
	res.ID = "email.dkim.wildcard"
	res.Title = "DKIM key record from a _domainkey wildcard"
	switch {
	case sweep.WildcardErr != "":
		return checkutil.Inconclusive(res, unconfirmedWildcard(sweep))
	case w.Outcome == dkimFound && w.Key.P == "":
		res.Status, res.Remediation = report.Info, ""
		res.Evidence = w.Name + " revokes every selector without a record of its own (p= empty)"
	case res.Status == report.Pass:
		res.Evidence = w.Name + " answers every selector without a record of its own: " +
			res.Evidence
	}
	return res
}

// unconfirmedWildcard explains a Wildcard that sweep inferred because the
// random selectors' lookups failed, naming the selectors it stands for.
func unconfirmedWildcard(sweep *DKIMSweep) error {
	var shared []string
	for _, p := range sweep.Probes {
		if p.FromWildcard {
			shared = append(shared, p.Selector)
		}
	}
	return fmt.Errorf("whether %s is a wildcard: TXT lookups for random selectors failed "+
		"(%s); %d selectors share its key record and are reported here, not one by one: %s",
		sweep.Wildcard.Name, sweep.WildcardErr, len(shared), checkutil.ListBounded(shared, ", "))
}

// dkimSelectorResult renders one sweep probe as a check result.
func dkimSelectorResult(p DKIMProbe) report.Result {
	res := report.Result{
		ID:       "email.dkim.selector." + p.Selector,
		Category: category,
		Title:    "DKIM selector " + p.Selector + " key record",
		RFCRefs:  dkimBaseRefs(),
	}
	switch p.Outcome {
	case dkimError:
		return checkutil.Inconclusive(res, fmt.Errorf("TXT lookup for %s: %s", p.Name, p.Detail))
	case dkimMalformed:
		res.Status = report.Fail
		res.Evidence = "parse error at " + p.Name + ": " + p.Detail
		res.Remediation = dkimKeyRemediation(p.Name)
	default:
		res = dkimKeyResult(res, p)
	}
	if p.Records > 1 {
		res.Evidence += fmt.Sprintf("; %d TXT records at the selector, where RFC 6376 §3.6.2.2 "+
			"requires one (verifier results are undefined)", p.Records)
		if res.Status == report.Pass {
			res.Status = report.Warn
		}
	}
	return res
}

// dkimKeyResult grades the key of a parsed record into res (see gradeDKIMKey).
func dkimKeyResult(res report.Result, p DKIMProbe) report.Result {
	res.RFCRefs = dkimKeyRefs(p.Key)
	status, text := gradeDKIMKey(p.Key)
	res.Status = status
	if status == report.Pass {
		res.Evidence = fmt.Sprintf("v=%s k=%s, %s", p.Key.Version, p.Key.KeyType, text)
		return res
	}
	res.Evidence = text + " at " + p.Name
	if status == report.Fail {
		res.Remediation = dkimKeyRemediation(p.Name)
	}
	return res
}

func dkimKeyRemediation(name string) string {
	return fmt.Sprintf(`%s. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"`,
		report.InlineValue(name))
}

// dkimKeyRefs augments the base citations: RFC 8301 sets the key-size and
// hash rules gradeDKIMKey applies, RFC 8463 defines ed25519 DKIM keys, and
// DKIM2 key records are governed by the DKIM2 draft.
func dkimKeyRefs(key *DKIMKey) []string {
	refs := append(dkimBaseRefs(), "RFC 8301")
	if key.KeyType == "ed25519" {
		refs = append(refs, "RFC 8463")
	}
	if key.Version == "DKIM2" {
		refs = append(refs, "draft-ietf-dkim-dkim2-spec-04")
	}
	return refs
}

// RFC 8301 §3.2: verifiers reject RSA keys under 1024 bits, and signers
// SHOULD use at least 2048.
const (
	minDKIMRSABits  = 1024
	goodDKIMRSABits = 2048
)

// gradeDKIMKey grades a parsed key record. FAIL means verifiers cannot use
// the key: it is revoked, does not decode, is an RSA key under 1024 bits, or
// its h= list leaves out sha256, the only hash RFC 8301 §3.1 still allows.
// rsa and ed25519 are the registered key types (RFC 6376, RFC 8463); any
// other is a WARN. The text says what is wrong, or describes a PASS key.
func gradeDKIMKey(key *DKIMKey) (report.Status, string) {
	switch {
	case key.P == "":
		return report.Fail, "revoked key (p= empty)"
	case !acceptsSHA256(key.Hashes):
		return report.Fail, fmt.Sprintf("h=%s leaves out sha256, so verifiers cannot use the key "+
			"(RFC 8301 §3.1)", report.ClipValue(key.Hashes))
	case key.KeyType == "rsa":
		return gradeRSAKey(key.P)
	case key.KeyType == "ed25519":
		return gradeEd25519Key(key.P)
	}
	return report.Warn, fmt.Sprintf("k=%q is not a registered DKIM key algorithm (rsa or ed25519)",
		key.KeyType)
}

// acceptsSHA256 reports whether an h= list allows sha256. A record without
// h= allows every hash algorithm (RFC 6376 §3.6.1).
func acceptsSHA256(hashes string) bool {
	if hashes == "" {
		return true
	}
	for _, alg := range strings.Split(hashes, ":") {
		if strings.EqualFold(strings.TrimSpace(alg), "sha256") {
			return true
		}
	}
	return false
}

// gradeRSAKey grades an RSA p= value by its modulus size (RFC 8301 §3.2).
func gradeRSAKey(p string) (report.Status, string) {
	der, err := decodeDKIMBase64(p)
	if err != nil {
		return report.Fail, "k=rsa but p= is not valid base64 (" + err.Error() + ")"
	}
	pub, ok := parseDKIMRSAKey(der)
	if !ok {
		return report.Fail, "k=rsa but p= is not an RSA public key"
	}
	switch bits := pub.N.BitLen(); {
	case bits < minDKIMRSABits:
		return report.Fail, fmt.Sprintf("%d-bit RSA key, which verifiers reject (RFC 8301 §3.2: "+
			"at least %d bits)", bits, minDKIMRSABits)
	case bits < goodDKIMRSABits:
		return report.Warn, fmt.Sprintf("%d-bit RSA key (RFC 8301 §3.2: signers SHOULD use "+
			"at least %d bits)", bits, goodDKIMRSABits)
	default:
		return report.Pass, fmt.Sprintf("%d-bit key", bits)
	}
}

// parseDKIMRSAKey parses a decoded RSA p= value. RFC 6376 §3.6.1 names a
// PKCS#1 RSAPublicKey, but its own key-generation example and nearly every
// publisher use a SubjectPublicKeyInfo, so verifiers accept both.
func parseDKIMRSAKey(der []byte) (*rsa.PublicKey, bool) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		rsaPub, ok := pub.(*rsa.PublicKey)
		return rsaPub, ok
	}
	pub, err := x509.ParsePKCS1PublicKey(der)
	return pub, err == nil
}

// gradeEd25519Key checks that an ed25519 p= value decodes to exactly the
// 32-byte raw public key (RFC 8463 §3, not a DER wrapper).
func gradeEd25519Key(p string) (report.Status, string) {
	raw, err := decodeDKIMBase64(p)
	if err != nil {
		return report.Fail, "k=ed25519 but p= is not valid base64 (" + err.Error() + ")"
	}
	if len(raw) != ed25519.PublicKeySize {
		return report.Fail, fmt.Sprintf("k=ed25519 but p= decodes to %d bytes (want %d)",
			len(raw), ed25519.PublicKeySize)
	}
	return report.Pass, fmt.Sprintf("%d-byte key", ed25519.PublicKeySize)
}

// decodeDKIMBase64 decodes a p= value. RFC 6376's base64string makes the
// trailing "=" padding optional.
func decodeDKIMBase64(p string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(p, "="))
}
