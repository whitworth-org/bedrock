package bimi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/report"
)

// Record is a parsed BIMI assertion record. Tag syntax mirrors DMARC: a
// semicolon-separated tag-list of "name=value" pairs (BIMI Group draft §4).
type Record struct {
	Raw     string
	Version string // "v" tag, must be "BIMI1"
	L       string // "l" SVG location URL (REQUIRED for evidence)
	A       string // "a" Verified Mark Certificate URL (REQUIRED for Gmail)
	Tags    map[string]string
}

// ParseRecord parses a BIMI TXT record. Whitespace around tags is tolerated.
// Empty l= is the spec-defined "self-asserted decline" (publisher opts out
// of indicators); we surface it but the check downstream may still Fail it
// for Gmail's purposes.
func ParseRecord(raw string) (*Record, error) {
	r := &Record{Raw: raw, Tags: map[string]string{}}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, fmt.Errorf("malformed tag %q (no '=')", part)
		}
		name := strings.ToLower(strings.TrimSpace(part[:eq]))
		value := strings.TrimSpace(part[eq+1:])
		// Reject duplicate tag names — a single BIMI record MUST NOT carry
		// the same tag twice (the spec allows only one of each). A repeat
		// is almost always either operator error or an attempt to smuggle
		// conflicting values past a naive last-wins parser.
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		seen[name] = struct{}{}
		r.Tags[name] = value
		switch name {
		case "v":
			r.Version = value
		case "l":
			r.L = value
		case "a":
			r.A = value
		}
	}
	if r.Version == "" {
		return nil, errors.New("missing v= tag")
	}
	if !strings.EqualFold(r.Version, "BIMI1") {
		return nil, fmt.Errorf("unexpected v=%q (want BIMI1)", r.Version)
	}
	return r, nil
}

// httpsURL returns nil when the URL is well-formed HTTPS; otherwise an error
// describing the defect. BIMI requires HTTPS for both the SVG and the VMC.
//
// Hardening rules beyond "scheme == https":
//   - Userinfo (https://user:pass@host/...) is rejected. It is never used in
//     legitimate BIMI publishing and is a classic tool for URL-obfuscation
//     phishing (the `@` splits the displayed authority from the real one).
//   - IP-literal hosts (dotted IPv4 and bracketed [IPv6]) are rejected.
//     Operators publish BIMI for hostnames, not IPs; allowing IP literals
//     here just widens the attack surface for the downstream fetchers.
func httpsURL(s string) error {
	if s == "" {
		return errors.New("empty URL")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	if u.User != nil {
		return errors.New("userinfo not permitted in URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("missing host")
	}
	// net.ParseIP handles both dotted IPv4 and bare IPv6 forms. url.Hostname()
	// strips the surrounding [] from IPv6 literals, so "[::1]" comes back as
	// "::1" and we catch it here.
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("host %q is an IP literal; hostname required", host)
	}
	return nil
}

// Cache key for the parsed BIMI record. Used by the SVG and VMC checks so
// they don't re-query DNS or re-parse the record.
const cacheKeyBIMIRecord = "bimi.record.parsed"

type recordCheck struct{}

func (recordCheck) ID() string       { return "bimi.txt" }
func (recordCheck) Category() string { return category }

func (recordCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "bimi.txt"
	const title = "BIMI assertion record (default._bimi)"
	refs := []string{"BIMI Group draft §4", "Gmail BIMI requirements"}

	name := "default._bimi." + env.Target
	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil {
		if errors.Is(err, probe.ErrNXDOMAIN) {
			return []report.Result{{
				ID: id, Category: category, Title: title,
				Status:      report.Fail,
				Evidence:    "no TXT record at " + name,
				Remediation: bimiTXTRemediation(env.Target),
				RFCRefs:     refs,
			}}
		}
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "TXT lookup failed: " + err.Error(),
			Remediation: bimiTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	var bimiRecords []string
	for _, t := range txt {
		if hasBIMIPrefix(strings.TrimSpace(t)) {
			bimiRecords = append(bimiRecords, t)
		}
	}

	switch len(bimiRecords) {
	case 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no v=BIMI1 record at " + name,
			Remediation: bimiTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	case 1:
		// fall through
	default:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("multiple v=BIMI1 records (%d) at %s", len(bimiRecords), name),
			Remediation: bimiTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	parsed, err := ParseRecord(bimiRecords[0])
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "parse error: " + err.Error(),
			Remediation: bimiTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	env.CachePut(cacheKeyBIMIRecord, parsed)

	var results []report.Result

	// l= URL must be present and HTTPS (BIMI Group draft §4.4).
	if err := httpsURL(parsed.L); err != nil {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "l= tag invalid: " + err.Error(),
			Remediation: bimiTXTRemediation(env.Target),
			RFCRefs:     refs,
		})
	}

	// a= URL is required for Gmail. The BIMI draft makes it optional but
	// Gmail will not display the indicator without a valid VMC, so we
	// treat it as a hard requirement.
	if err := httpsURL(parsed.A); err != nil {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "a= tag invalid (Gmail requires VMC): " + err.Error(),
			Remediation: bimiTXTRemediation(env.Target),
			RFCRefs:     refs,
		})
	}

	if len(results) == 0 {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: parsed.Raw,
			RFCRefs:  refs,
		})
	}
	return results
}

func hasBIMIPrefix(s string) bool {
	const p = "v=BIMI1"
	if len(s) < len(p) {
		return false
	}
	return strings.EqualFold(s[:len(p)], p)
}

func bimiTXTRemediation(domain string) string {
	return fmt.Sprintf(
		`default._bimi.%s. IN TXT "v=BIMI1; l=https://%s/bimi/logo.svg; a=https://%s/bimi/vmc.pem"`,
		domain, domain, domain,
	)
}
