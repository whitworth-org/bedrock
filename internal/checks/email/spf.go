package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

// SPF holds a parsed v=spf1 record.
type SPF struct {
	Raw         string
	Mechanisms  []SPFMechanism
	HasRedirect bool
	Redirect    string
	// AllQualifier is the qualifier on the terminating "all" mechanism, or
	// the empty string when the record has no explicit "all". RFC 7208 §4.7
	// treats a missing all as an implicit "?all".
	AllQualifier string
}

// SPFMechanism is one parsed term from an SPF record.
type SPFMechanism struct {
	Qualifier  string // "+", "-", "~", "?" (default "+")
	Name       string // "all", "ip4", "ip6", "a", "mx", "ptr", "include", "exists", "redirect", "exp", or unknown modifier
	Value      string // text after ":" or "="; empty when absent
	IsModifier bool
}

// ParseSPF parses an SPF record (RFC 7208 §4, §5, §6). It is permissive about
// leading/trailing whitespace but otherwise rejects records that don't begin
// with "v=spf1" (RFC 7208 §4.5).
func ParseSPF(raw string) (*SPF, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.EqualFold(trimmed, "v=spf1") && !hasSPFPrefix(trimmed) {
		return nil, errors.New("not an SPF record (missing v=spf1)")
	}
	out := &SPF{Raw: trimmed}
	fields := strings.Fields(trimmed)
	for _, f := range fields[1:] { // skip "v=spf1"
		m, err := parseSPFTerm(f)
		if err != nil {
			return nil, err
		}
		out.Mechanisms = append(out.Mechanisms, m)
		switch {
		case !m.IsModifier && strings.EqualFold(m.Name, "all"):
			out.AllQualifier = m.Qualifier
		case m.IsModifier && strings.EqualFold(m.Name, "redirect"):
			out.HasRedirect = true
			out.Redirect = m.Value
		}
	}
	return out, nil
}

func hasSPFPrefix(s string) bool {
	if len(s) < len("v=spf1") {
		return false
	}
	return strings.EqualFold(s[:len("v=spf1")], "v=spf1")
}

// parseSPFTerm splits one whitespace-separated term into its qualifier,
// name, and value. Modifiers contain "=" before any ":"/"/"; mechanisms
// take ":" or "/" (RFC 7208 §4.6.1).
func parseSPFTerm(term string) (SPFMechanism, error) {
	if term == "" {
		return SPFMechanism{}, errors.New("empty term")
	}
	// Detect modifier vs mechanism: a modifier has "=" before any ":" or "/".
	eq := strings.IndexByte(term, '=')
	colon := strings.IndexByte(term, ':')
	slash := strings.IndexByte(term, '/')
	firstSep := func(idxs ...int) int {
		min := -1
		for _, i := range idxs {
			if i < 0 {
				continue
			}
			if min < 0 || i < min {
				min = i
			}
		}
		return min
	}
	sep := firstSep(colon, slash)
	if eq >= 0 && (sep < 0 || eq < sep) {
		// modifier: name=value
		return SPFMechanism{
			Name:       term[:eq],
			Value:      term[eq+1:],
			IsModifier: true,
		}, nil
	}
	// mechanism: optional qualifier + name + optional :value or /cidr
	q := ""
	rest := term
	switch term[0] {
	case '+', '-', '~', '?':
		q = string(term[0])
		rest = term[1:]
	}
	name := rest
	value := ""
	if sep >= 0 {
		// recompute sep relative to rest
		colon2 := strings.IndexByte(rest, ':')
		slash2 := strings.IndexByte(rest, '/')
		s := firstSep(colon2, slash2)
		name = rest[:s]
		value = rest[s+1:]
		if rest[s] == '/' {
			// preserve the slash so callers see the CIDR
			value = rest[s:]
		}
	}
	if name == "" {
		return SPFMechanism{}, fmt.Errorf("malformed mechanism %q", term)
	}
	return SPFMechanism{Qualifier: q, Name: name, Value: value}, nil
}

// CountDNSLookups returns the number of terms that would cause a DNS query
// during evaluation (RFC 7208 §4.6.4: limit is 10).
func (s *SPF) CountDNSLookups() int {
	n := 0
	for _, m := range s.Mechanisms {
		if m.IsModifier {
			if strings.EqualFold(m.Name, "redirect") {
				n++
			}
			continue
		}
		switch strings.ToLower(m.Name) {
		case "include", "a", "mx", "ptr", "exists":
			n++
		}
	}
	return n
}

type spfCheck struct{}

func (spfCheck) ID() string       { return "email.spf.record" }
func (spfCheck) Category() string { return category }

func (spfCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "email.spf.record"
	const title = "SPF record present and well-formed"
	refs := []string{"RFC 7208 §3", "RFC 7208 §4.6.4", "RFC 7208 §11"}

	txt, err := env.DNS.LookupTXT(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "TXT lookup failed: " + err.Error(),
			Remediation: spfRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	var spfRecords []string
	for _, t := range txt {
		if hasSPFPrefix(strings.TrimSpace(t)) {
			spfRecords = append(spfRecords, t)
		}
	}

	switch len(spfRecords) {
	case 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no v=spf1 TXT record at apex",
			Remediation: spfRemediation(env.Target),
			RFCRefs:     refs,
		}}
	case 1:
		// fall through
	default:
		// RFC 7208 §3.2: more than one SPF record yields permerror.
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("multiple v=spf1 records (%d) — permerror", len(spfRecords)),
			Remediation: spfRemediation(env.Target),
			RFCRefs:     append(refs, "RFC 7208 §3.2"),
		}}
	}

	parsed, err := ParseSPF(spfRecords[0])
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "parse error: " + err.Error(),
			Remediation: spfRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	env.CachePut(probe.CacheKeySPF, parsed)

	if lookups := parsed.CountDNSLookups(); lookups > 10 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("DNS-lookup terms = %d (limit 10): %s", lookups, parsed.Raw),
			Remediation: spfRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	switch parsed.AllQualifier {
	case "-":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: parsed.Raw,
			RFCRefs:  refs,
		}}
	case "~":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "softfail (~all); prefer -all once monitoring is clean: " + parsed.Raw,
			RFCRefs:  refs,
		}}
	case "?":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "neutral (?all) provides no enforcement: " + parsed.Raw,
			RFCRefs:  refs,
		}}
	case "+":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "+all permits anyone to send: " + parsed.Raw,
			Remediation: spfRemediation(env.Target),
			RFCRefs:     append(refs, "RFC 7208 §11.4"),
		}}
	default:
		// Implicit ?all (no terminating all).
		if parsed.HasRedirect {
			return []report.Result{{
				ID: id, Category: category, Title: title,
				Status:   report.Pass,
				Evidence: "redirect=" + parsed.Redirect + ": " + parsed.Raw,
				RFCRefs:  refs,
			}}
		}
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "no terminating all mechanism (implicit ?all): " + parsed.Raw,
			RFCRefs:  refs,
		}}
	}
}

func spfRemediation(domain string) string {
	return fmt.Sprintf(`%s. IN TXT "v=spf1 -all"`, domain)
}
