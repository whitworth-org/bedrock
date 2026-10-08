package bimi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// ensureRecord returns the BIMI record that bimi.txt graded, or nil when
// the lookup failed or found no parsable v=BIMI1 record; bimi.txt reports
// why.
func ensureRecord(ctx context.Context, env *probe.Env) *Record {
	return ensureRecordLookup(ctx, env).value()
}

// ensureRecordLookup looks up and grades the default._bimi TXT record at
// most once per scan however many checks ask (see probe.Shared), so bimi.txt
// and the checks that use the record see the same answer. Its product is
// the first v=BIMI1 record when that parses, whatever bimi.txt makes of it.
func ensureRecordLookup(ctx context.Context, env *probe.Env) *outcome[*Record] {
	return probe.Shared(env, cacheKeyBIMIRecord, func() *outcome[*Record] {
		return lookupRecord(ctx, env)
	})
}

// lookupRecord looks up the TXT record set at default._bimi.<target> and
// grades it. A lookup error other than NXDOMAIN leaves the record unknown,
// so it is Inconclusive.
func lookupRecord(ctx context.Context, env *probe.Env) *outcome[*Record] {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	res := recordBase()
	name := "default._bimi." + env.Target
	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return &outcome[*Record]{result: checkutil.Inconclusive(res, err)}
	}
	evidence, usable := gradeRecordTXT(name, txt, err)
	res.Evidence = evidence
	if usable {
		res.Status = report.Pass
	} else {
		res.Status = report.Fail
		res.Remediation = bimiTXTRemediation(env.Target)
	}
	return &outcome[*Record]{result: res, product: firstRecord(txt)}
}

// firstRecord parses the first v=BIMI1 string in txt, or returns nil.
func firstRecord(txt []string) *Record {
	records := bimiRecords(txt)
	if len(records) == 0 {
		return nil
	}
	parsed, err := ParseRecord(records[0])
	if err != nil {
		return nil
	}
	return parsed
}

// bimiRecords returns the TXT strings that start with v=BIMI1.
func bimiRecords(txt []string) []string {
	var out []string
	for _, t := range txt {
		if hasBIMIPrefix(strings.TrimSpace(t)) {
			out = append(out, t)
		}
	}
	return out
}

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

// Cache key of the default._bimi lookup (*outcome[*Record]), which
// ensureRecordLookup alone stores.
const cacheKeyBIMIRecord = "bimi.record"

type recordCheck struct{}

func (recordCheck) ID() string       { return "bimi.txt" }
func (recordCheck) Category() string { return category }

func (recordCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	return ensureRecordLookup(ctx, env).results(recordBase())
}

func recordBase() report.Result {
	return report.Result{
		ID: "bimi.txt", Category: category,
		Title:   "BIMI assertion record (default._bimi)",
		RFCRefs: []string{"BIMI Group draft §4", "Gmail BIMI requirements"},
	}
}

// gradeRecordTXT grades the TXT strings at name, where lookupErr is nil or
// NXDOMAIN. It returns the evidence and whether the record is usable: the
// record itself when it is, otherwise every problem found, l= and a=
// alike.
func gradeRecordTXT(name string, txt []string, lookupErr error) (string, bool) {
	if lookupErr != nil {
		return "no TXT record at " + name, false
	}
	records := bimiRecords(txt)
	switch {
	case len(records) == 0:
		return "no v=BIMI1 record at " + name, false
	case len(records) > 1:
		return fmt.Sprintf("multiple v=BIMI1 records (%d) at %s", len(records), name), false
	}
	parsed, err := ParseRecord(records[0])
	if err != nil {
		return "parse error: " + err.Error(), false
	}
	var problems []string
	// l= must be present and HTTPS (BIMI Group draft §4.4).
	if err := httpsURL(parsed.L); err != nil {
		problems = append(problems, "l= tag invalid: "+err.Error())
	}
	// The draft makes a= optional, but Gmail shows no indicator without a
	// valid VMC, so it is required here.
	if err := httpsURL(parsed.A); err != nil {
		problems = append(problems, "a= tag invalid (Gmail requires VMC): "+err.Error())
	}
	if len(problems) > 0 {
		return strings.Join(problems, "; "), false
	}
	return parsed.Raw, true
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
