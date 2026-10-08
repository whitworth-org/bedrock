package email

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// SPF holds a parsed v=spf1 record.
type SPF struct {
	Raw         string
	Mechanisms  []SPFMechanism
	HasRedirect bool
	Redirect    string
	// AllQualifier is the qualifier of the first "all" mechanism, where
	// evaluation ends (RFC 7208 §5.1), and "+" for a bare "all" (§4.6.2). It
	// is the empty string when the record has no "all"; RFC 7208 §4.7 treats
	// a missing all as an implicit "?all".
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
		case isAll(m) && out.AllQualifier == "":
			// Normalizing a bare "all" to "+" keeps a later "all" from
			// replacing the first.
			out.AllQualifier = cmp.Or(m.Qualifier, "+")
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

func isAll(m SPFMechanism) bool {
	return !m.IsModifier && strings.EqualFold(m.Name, "all")
}

// evaluated returns the mechanisms a receiver can evaluate: those up to and
// including the first "all" (RFC 7208 §5.1).
func (s *SPF) evaluated() []SPFMechanism {
	var out []SPFMechanism
	for _, m := range s.Mechanisms {
		if !m.IsModifier {
			out = append(out, m)
		}
		if isAll(m) {
			break
		}
	}
	return out
}

// CountDNSLookups returns the number of terms that would cause a DNS query
// during evaluation (RFC 7208 §4.6.4: limit is 10). Evaluation ends at the
// first "all" (§5.1), and a redirect beside an "all" is never followed
// (§6.1).
func (s *SPF) CountDNSLookups() int {
	n := 0
	if s.HasRedirect && s.AllQualifier == "" {
		n++
	}
	for _, m := range s.evaluated() {
		switch strings.ToLower(m.Name) {
		case "include", "a", "mx", "ptr", "exists":
			n++
		}
	}
	return n
}

// openRange returns the first evaluated ip4 or ip6 mechanism that passes
// every address of its family, as +all does: a pass qualifier and a prefix
// length of 0.
func (s *SPF) openRange() (SPFMechanism, bool) {
	for _, m := range s.evaluated() {
		pass := m.Qualifier == "" || m.Qualifier == "+"
		family := strings.ToLower(m.Name)
		prefix, err := netip.ParsePrefix(m.Value)
		if pass && (family == "ip4" || family == "ip6") && err == nil && prefix.Bits() == 0 {
			return m, true
		}
	}
	return SPFMechanism{}, false
}

// lookupTXT returns the TXT strings at name. NXDOMAIN returns none and no
// error, because it proves the name publishes no record.
func lookupTXT(ctx context.Context, env *probe.Env, name string) ([]string, error) {
	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return nil, fmt.Errorf("TXT lookup for %s: %w", name, err)
	}
	return txt, nil
}

func runSPF(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	res := report.Result{
		ID: "email.spf.record", Category: category, Title: "SPF record present and well-formed",
		RFCRefs: []string{"RFC 7208 §3", "RFC 7208 §4.6.4", "RFC 7208 §11"},
	}
	txt, err := lookupTXT(ctx, env, env.Target)
	if err != nil {
		return []report.Result{checkutil.Inconclusive(res, err)}
	}

	var spfRecords []string
	for _, t := range txt {
		if hasSPFPrefix(strings.TrimSpace(t)) {
			spfRecords = append(spfRecords, t)
		}
	}
	if len(spfRecords) == 0 {
		return []report.Result{spfFail(res, env.Target, "no v=spf1 TXT record at apex")}
	}
	if len(spfRecords) > 1 {
		// RFC 7208 §3.2: more than one SPF record yields permerror.
		res.RFCRefs = append(res.RFCRefs, "RFC 7208 §3.2")
		return []report.Result{spfFail(res, env.Target,
			fmt.Sprintf("multiple v=spf1 records (%d) — permerror", len(spfRecords)))}
	}

	parsed, err := ParseSPF(spfRecords[0])
	if err != nil {
		return []report.Result{spfFail(res, env.Target, "parse error: "+err.Error())}
	}
	env.CachePut(probe.CacheKeySPF, parsed)
	return []report.Result{gradeSPF(res, env.Target, parsed)}
}

// gradeSPF grades domain's parsed SPF record into res.
func gradeSPF(res report.Result, domain string, parsed *SPF) report.Result {
	if lookups := parsed.CountDNSLookups(); lookups > 10 {
		return spfFail(res, domain,
			fmt.Sprintf("DNS-lookup terms = %d (limit 10): %s", lookups, parsed.Raw))
	}
	if m, ok := parsed.openRange(); ok {
		res.RFCRefs = append(res.RFCRefs, "RFC 7208 §5.6")
		return spfFail(res, domain, m.Qualifier+m.Name+":"+m.Value+
			" permits anyone to send, like +all: "+parsed.Raw)
	}
	switch parsed.AllQualifier {
	case "-":
		res.Status, res.Evidence = report.Pass, parsed.Raw
	case "~":
		res.Status = report.Warn
		res.Evidence = "softfail (~all); prefer -all once monitoring is clean: " + parsed.Raw
	case "?":
		res.Status = report.Warn
		res.Evidence = "neutral (?all) provides no enforcement: " + parsed.Raw
	case "+":
		res.RFCRefs = append(res.RFCRefs, "RFC 7208 §11.4")
		return spfFail(res, domain, "+all permits anyone to send: "+parsed.Raw)
	default:
		// No "all": the redirect decides, else an implicit ?all.
		if parsed.HasRedirect {
			res.Status, res.Evidence = report.Pass, "redirect="+parsed.Redirect+": "+parsed.Raw
		} else {
			res.Status = report.Warn
			res.Evidence = "no terminating all mechanism (implicit ?all): " + parsed.Raw
		}
	}
	return res
}

func spfFail(res report.Result, domain, evidence string) report.Result {
	res.Status = report.Fail
	res.Evidence = evidence
	res.Remediation = spfRemediation(domain)
	return res
}

func spfRemediation(domain string) string {
	return fmt.Sprintf(`%s. IN TXT "v=spf1 -all"`, domain)
}
