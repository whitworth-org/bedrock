package email

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

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
	P       string // "p" base64 public key, "" means revoked
	Tags    map[string]string
}

// ParseDKIM parses a DKIM key TXT record. RFC 6376 §3.2 tag-list syntax:
// tags separated by ";", each "name=value", whitespace around tokens ignored.
// An empty p= tag means the key was revoked.
//
// The parser rejects:
//   - Duplicate tag names (RFC 6376 §3.2 allows only one of each).
//   - A `d=` tag (uncommon in key records but seen in some ESP extensions)
//     whose value contains characters outside the DNS-safe set
//     [a-zA-Z0-9._-]. This keeps mis-issued records from smuggling
//     non-domain content (e.g. whitespace, "@", shell metacharacters)
//     through downstream consumers that log or act on it.
func ParseDKIM(raw string) (*DKIMKey, error) {
	out := &DKIMKey{
		Raw:     raw,
		Version: "DKIM1",
		KeyType: "rsa",
		Service: "*",
		Tags:    map[string]string{},
	}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, fmt.Errorf("malformed tag %q", part)
		}
		name := strings.TrimSpace(part[:eq])
		value := strings.TrimSpace(part[eq+1:])
		// Tag names are case-sensitive per RFC 6376 §3.2 — track the exact
		// name for duplicate detection rather than folding case.
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		seen[name] = struct{}{}
		out.Tags[name] = value
		switch name {
		case "v":
			out.Version = value
		case "k":
			out.KeyType = value
		case "s":
			out.Service = value
		case "t":
			out.Flags = value
		case "h":
			out.Hashes = value
		case "p":
			out.P = value
		case "d":
			// Some extensions put a domain in the key record; regardless
			// of spec adherence we require it to be DNS-safe so it can't
			// carry out-of-band payloads into logs or reports.
			if !isDNSSafeName(value) {
				return nil, fmt.Errorf("invalid d=%q (must match [a-zA-Z0-9._-])", value)
			}
		}
	}
	switch {
	case out.Version == "", strings.EqualFold(out.Version, "DKIM1"):
		out.Version = "DKIM1"
	case strings.EqualFold(out.Version, "DKIM2"):
		// DKIM2 key records (draft-ietf-dkim-dkim2-spec) live at the same
		// _domainkey names as DKIM1.
		out.Version = "DKIM2"
	default:
		return nil, fmt.Errorf("unexpected v=%q (want DKIM1 or DKIM2)", out.Version)
	}
	return out, nil
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

func runDKIM(ctx context.Context, env *probe.Env) []report.Result {
	sweep := dkimSweep(ctx, env)
	if sweep == nil {
		return nil
	}
	results := make([]report.Result, 0, len(sweep.Probes))
	for _, p := range sweep.Probes {
		results = append(results, dkimSelectorResult(p))
	}

	// If every selector probe is NotApplicable (no record), surface a
	// single Fail aggregating the situation. This keeps the report from
	// being a wall of N/A entries while still flagging that DKIM is not
	// detectable from common selectors.
	allMissing := true
	for _, r := range results {
		if r.Status != report.NotApplicable {
			allMissing = false
			break
		}
	}
	if allMissing {
		return []report.Result{{
			ID:       "email.dkim.selector.none",
			Category: category,
			Title:    "DKIM key discoverable on a common selector",
			Status:   report.Fail,
			Evidence: "no DKIM key found at any of: " + strings.Join(sweep.Selectors, ", "),
			Remediation: fmt.Sprintf(
				`<selector>._domainkey.%s. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"`,
				env.Target,
			),
			RFCRefs: dkimBaseRefs(),
		}}
	}

	// Drop NotApplicable entries from the report — only show selectors
	// that were actually published.
	out := results[:0]
	for _, r := range results {
		if r.Status != report.NotApplicable {
			out = append(out, r)
		}
	}
	return out
}

// dkimSelectorResult renders one sweep probe as a check result.
func dkimSelectorResult(p DKIMProbe) report.Result {
	id := "email.dkim.selector." + p.Selector
	title := "DKIM selector " + p.Selector + " key record"
	res := report.Result{ID: id, Category: category, Title: title, RFCRefs: dkimBaseRefs()}

	switch p.Outcome {
	case dkimMissing:
		res.Status = report.NotApplicable
		res.Evidence = "no record at " + p.Name
		return res
	case dkimError:
		res.Status = report.NotApplicable
		res.Evidence = "lookup error: " + p.Detail
		return res
	case dkimMalformed:
		res.Status = report.Fail
		res.Evidence = "parse error at " + p.Name + ": " + p.Detail
		res.Remediation = dkimKeyRemediation(p.Name)
		return res
	}

	key := p.Key
	if key.P == "" {
		// Empty p= tag = revoked key per RFC 6376 §3.6.1.
		res.Status = report.Fail
		res.Evidence = "key at " + p.Name + " is revoked (p= empty)"
		res.Remediation = dkimKeyRemediation(p.Name)
		return res
	}

	res.RFCRefs = dkimKeyRefs(key)
	if issue, bad := dkimKeyIssue(key); bad {
		res.Status = report.Warn
		res.Evidence = issue + " at " + p.Name
		return res
	}
	res.Status = report.Pass
	res.Evidence = fmt.Sprintf("v=%s k=%s p=<%d bytes>", key.Version, key.KeyType, len(key.P))
	return res
}

func dkimKeyRemediation(name string) string {
	return fmt.Sprintf(`%s. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"`, name)
}

// dkimKeyRefs augments the base citations: RFC 8463 defines ed25519 DKIM
// keys, and DKIM2 key records are governed by the DKIM2 draft.
func dkimKeyRefs(key *DKIMKey) []string {
	refs := dkimBaseRefs()
	if key.KeyType == "ed25519" {
		refs = append(refs, "RFC 8463")
	}
	if key.Version == "DKIM2" {
		refs = append(refs, "draft-ietf-dkim-dkim2-spec-04")
	}
	return refs
}

// dkimKeyIssue validates the k= algorithm. rsa and ed25519 are the
// registered DKIM key types (RFC 6376, RFC 8463); an ed25519 p= must decode
// to exactly the 32-byte raw public key (RFC 8463 §3, not a DER wrapper).
func dkimKeyIssue(key *DKIMKey) (string, bool) {
	switch key.KeyType {
	case "rsa":
		return "", false
	case "ed25519":
		raw, err := base64.StdEncoding.DecodeString(key.P)
		if err != nil {
			return "k=ed25519 but p= is not valid base64 (" + err.Error() + ")", true
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Sprintf("k=ed25519 but p= decodes to %d bytes (want %d)",
				len(raw), ed25519.PublicKeySize), true
		}
		return "", false
	default:
		return fmt.Sprintf("k=%q is not a registered DKIM key algorithm (rsa or ed25519)",
			key.KeyType), true
	}
}
