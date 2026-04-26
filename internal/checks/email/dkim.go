package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// DKIMKey is a parsed DKIM key record (RFC 6376 §3.6.1).
type DKIMKey struct {
	Raw     string
	Version string // "v" tag, default "DKIM1"
	KeyType string // "k", default "rsa"
	Service string // "s", default "*"
	Flags   string // "t", default ""
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
	if out.Version != "" && !strings.EqualFold(out.Version, "DKIM1") {
		return nil, fmt.Errorf("unexpected v=%q (want DKIM1)", out.Version)
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

// The default selector list is constructed per-run by selectorList(env),
// which combines commonSelectors with ESP-specific extras inferred from SPF
// (see dkim_selectors.go). Order is deterministic; every found selector is
// reported regardless of position.

type dkimCheck struct{}

func (dkimCheck) ID() string       { return "email.dkim" }
func (dkimCheck) Category() string { return category }

func (dkimCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	refs := []string{"RFC 6376 §3.6.1", "RFC 6376 §3.6.2"}
	selectors := selectorList(env)
	results := make([]report.Result, 0, len(selectors))

	for _, sel := range selectors {
		// Mid-flight ctx gate so a cancelled scan stops walking the
		// selector list instead of issuing one TXT lookup per selector.
		if err := ctx.Err(); err != nil {
			break
		}
		results = append(results, probeDKIMSelector(ctx, env, sel, refs))
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
			Evidence: "no DKIM key found at any of: " + strings.Join(selectors, ", "),
			Remediation: fmt.Sprintf(
				`<selector>._domainkey.%s. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"`,
				env.Target,
			),
			RFCRefs: refs,
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

func probeDKIMSelector(ctx context.Context, env *probe.Env, selector string, refs []string) report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	id := "email.dkim.selector." + selector
	title := "DKIM selector " + selector + " key record"
	name := selector + "._domainkey." + env.Target

	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil {
		if errors.Is(err, probe.ErrNXDOMAIN) {
			return report.Result{ID: id, Category: category, Title: title, Status: report.NotApplicable, Evidence: "no record at " + name, RFCRefs: refs}
		}
		return report.Result{ID: id, Category: category, Title: title, Status: report.NotApplicable, Evidence: "lookup error: " + err.Error(), RFCRefs: refs}
	}
	if len(txt) == 0 {
		return report.Result{ID: id, Category: category, Title: title, Status: report.NotApplicable, Evidence: "no record at " + name, RFCRefs: refs}
	}

	// Concatenate per RFC 6376 §3.6.2.2 already done by LookupTXT; pick
	// the first record that looks DKIM-shaped.
	var raw string
	for _, t := range txt {
		if strings.Contains(t, "p=") || strings.Contains(strings.ToLower(t), "v=dkim1") {
			raw = t
			break
		}
	}
	if raw == "" {
		raw = txt[0]
	}

	parsed, err := ParseDKIM(raw)
	if err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "parse error at " + name + ": " + err.Error(),
			Remediation: fmt.Sprintf(`%s. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"`, name),
			RFCRefs:     refs,
		}
	}

	if parsed.P == "" {
		// Empty p= tag = revoked key per RFC 6376 §3.6.1.
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "key at " + name + " is revoked (p= empty)",
			Remediation: fmt.Sprintf(`%s. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"`, name),
			RFCRefs:     refs,
		}
	}

	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("k=%s p=<%d bytes>", parsed.KeyType, len(parsed.P)),
		RFCRefs:  refs,
	}
}
