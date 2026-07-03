package email

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// DMARC is the parsed view of a DMARC TXT record (RFC 9989 §4.7; RFC 9989
// obsoletes RFC 7489). Exported so the BIMI Gmail-gate check can read it via
// env.CacheGet(probe.CacheKeyDMARC).
type DMARC struct {
	Raw             string
	Policy          string   // p=    (none/quarantine/reject)
	SubdomainPolicy string   // sp=   (none/quarantine/reject), defaults to Policy when absent
	NPPolicy        string   // np=   (none/quarantine/reject), non-existent-subdomain policy; np<-sp<-p
	NPExplicit      bool     // true when np= was published literally (not inherited)
	Pct             int      // pct=, default 100 — REMOVED in RFC 9989 (App. A.6); kept for transitional records
	PctPresent      bool     // true when pct= was published literally
	Adkim           string   // adkim= (r/s), default "r"
	Aspf            string   // aspf=  (r/s), default "r"
	Fo              string   // fo=    failure-reporting options (0/1/d/s, colon-separated)
	TestMode        string   // t=     (y/n), default "n" — RFC 9989 §4.7, supersedes pct
	PSD             string   // psd=   (y/n/u), default "u" — RFC 9989 §4.7
	Rua             []string // rua= URIs
	Ruf             []string // ruf= URIs
	Tags            map[string]string
}

// ParseDMARC parses a v=DMARC1 TXT record. The parser is intentionally
// strict: duplicate tags, a misplaced v= tag, or an out-of-range pct= are
// all rejected so a malformed record never silently resolves to a more
// permissive policy than the operator intended.
func ParseDMARC(raw string) (*DMARC, error) {
	trimmed := strings.TrimSpace(raw)
	out := &DMARC{
		Raw:      trimmed,
		Pct:      100,
		Adkim:    "r",
		Aspf:     "r",
		TestMode: "n",
		PSD:      "u",
		Tags:     map[string]string{},
	}
	parts := strings.Split(trimmed, ";")
	// RFC 9989 §4.7: v=DMARC1 MUST be the first tag. We require it to appear
	// as the first non-empty "name=value" pair with the exact value "DMARC1"
	// (case-insensitive) terminated by ';' or the end of the record — not
	// merely as a prefix, which would accept "v=DMARC12345" and friends.
	seen := map[string]struct{}{}
	firstTag := true
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, fmt.Errorf("malformed tag %q", part)
		}
		name := strings.ToLower(strings.TrimSpace(part[:eq]))
		value := strings.TrimSpace(part[eq+1:])
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		seen[name] = struct{}{}
		if firstTag {
			if name != "v" {
				return nil, errors.New("not a DMARC record (missing v=DMARC1 first)")
			}
			if !strings.EqualFold(value, "DMARC1") {
				return nil, fmt.Errorf("unexpected v=%q (want DMARC1)", value)
			}
			firstTag = false
		}
		out.Tags[name] = value
		switch name {
		case "v":
			// Already validated above; nothing more to do.
		case "p":
			if !validDMARCPolicy(value) {
				return nil, fmt.Errorf("invalid p=%q", value)
			}
			out.Policy = strings.ToLower(value)
		case "sp":
			if !validDMARCPolicy(value) {
				return nil, fmt.Errorf("invalid sp=%q", value)
			}
			out.SubdomainPolicy = strings.ToLower(value)
		case "pct":
			out.PctPresent = true
			n, err := parseStrictPct(value)
			if err != nil {
				return nil, fmt.Errorf("invalid pct=%q: %s", value, err.Error())
			}
			out.Pct = n
		case "adkim":
			if value != "r" && value != "s" {
				return nil, fmt.Errorf("invalid adkim=%q", value)
			}
			out.Adkim = value
		case "aspf":
			if value != "r" && value != "s" {
				return nil, fmt.Errorf("invalid aspf=%q", value)
			}
			out.Aspf = value
		case "np":
			if !validDMARCPolicy(value) {
				return nil, fmt.Errorf("invalid np=%q", value)
			}
			out.NPPolicy = strings.ToLower(value)
			out.NPExplicit = true
		case "t":
			lv := strings.ToLower(value)
			if lv != "y" && lv != "n" {
				return nil, fmt.Errorf("invalid t=%q (want y or n)", value)
			}
			out.TestMode = lv
		case "psd":
			lv := strings.ToLower(value)
			if lv != "y" && lv != "n" && lv != "u" {
				return nil, fmt.Errorf("invalid psd=%q (want y, n, or u)", value)
			}
			out.PSD = lv
		case "fo":
			if err := validateFo(value); err != nil {
				return nil, fmt.Errorf("invalid fo=%q: %s", value, err.Error())
			}
			out.Fo = value
		case "rua":
			uris, err := parseReportURIs(value)
			if err != nil {
				return nil, fmt.Errorf("invalid rua=%q: %s", value, err.Error())
			}
			out.Rua = uris
		case "ruf":
			uris, err := parseReportURIs(value)
			if err != nil {
				return nil, fmt.Errorf("invalid ruf=%q: %s", value, err.Error())
			}
			out.Ruf = uris
		}
	}
	if firstTag {
		// Record was empty or whitespace only.
		return nil, errors.New("not a DMARC record (missing v=DMARC1)")
	}
	if out.Policy == "" {
		// p= is required (RFC 9989 §4.7); the only exception is a "report-only"
		// child record (e.g. *._report._dmarc.example.com) which our caller
		// does not query.
		return nil, errors.New("missing required p= tag")
	}
	if out.SubdomainPolicy == "" {
		out.SubdomainPolicy = out.Policy
	}
	if out.NPPolicy == "" {
		// RFC 9989 §4.7: np defaults to sp, which itself defaults to p. Since
		// sp is already resolved above, inheriting from it yields np<-sp<-p.
		out.NPPolicy = out.SubdomainPolicy
	}
	return out, nil
}

// parseStrictPct returns the pct= integer, rejecting anything but 1-3 ASCII
// digits with no sign / no leading zeros (except the single digit "0") and
// the range 0-100. strconv.Atoi accepts sign prefixes and leading zeros,
// which we don't want for a DMARC tag value.
func parseStrictPct(v string) (int, error) {
	if v == "" {
		return 0, errors.New("empty")
	}
	if len(v) > 3 {
		return 0, errors.New("more than 3 digits")
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, errors.New("non-digit character")
		}
	}
	// Reject leading zero unless the value is exactly "0".
	if len(v) > 1 && v[0] == '0' {
		return 0, errors.New("leading zero")
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 100 {
		return 0, errors.New("out of range 0-100")
	}
	return n, nil
}

// parseReportURIs validates a comma-separated list of DMARC report URIs.
// Each URI must use the mailto: or https:// scheme; http://, file://, and
// anything else is rejected so report handlers aren't pointed at attacker-
// controlled endpoints that receive aggregate reports (which can leak
// recipient addresses for reflection).
func parseReportURIs(v string) ([]string, error) {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// DMARC spec allows a "!size" suffix after the URI; strip it for
		// scheme validation.
		uri := p
		if bang := strings.IndexByte(uri, '!'); bang >= 0 {
			uri = uri[:bang]
		}
		lower := strings.ToLower(uri)
		switch {
		case strings.HasPrefix(lower, "mailto:"):
			// accepted
		case strings.HasPrefix(lower, "https://"):
			// accepted
		default:
			return nil, fmt.Errorf("URI %q is neither mailto: nor https://", p)
		}
		out = append(out, p)
	}
	return out, nil
}

func validDMARCPolicy(v string) bool {
	switch strings.ToLower(v) {
	case "none", "quarantine", "reject":
		return true
	}
	return false
}

// validateFo validates the DMARC fo= tag (RFC 9989 §4.7): a colon-separated
// list whose elements are each one of "0", "1", "d", "s". Order and
// duplicates are not significant; only unknown tokens are rejected.
func validateFo(v string) error {
	if v == "" {
		return errors.New("empty")
	}
	for _, tok := range strings.Split(v, ":") {
		switch strings.TrimSpace(tok) {
		case "0", "1", "d", "s":
		default:
			return fmt.Errorf("unknown option %q", tok)
		}
	}
	return nil
}

func runDMARC(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "email.dmarc.record"
	const title = "DMARC record present and well-formed"
	refs := []string{"RFC 9989 §4.7", "RFC 9989 §4.8", "RFC 9989 §11"}

	name := "_dmarc." + env.Target
	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "TXT lookup failed: " + err.Error(),
			Remediation: dmarcRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	var records []string
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			records = append(records, t)
		}
	}

	switch len(records) {
	case 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no v=DMARC1 TXT record at " + name,
			Remediation: dmarcRemediation(env.Target),
			RFCRefs:     refs,
		}}
	case 1:
		// fall through
	default:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("multiple v=DMARC1 records (%d) at %s", len(records), name),
			Remediation: dmarcRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	parsed, err := ParseDMARC(records[0])
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "parse error: " + err.Error(),
			Remediation: dmarcRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	// Cache for downstream consumers (BIMI). Only cache successful parses.
	env.CachePut(probe.CacheKeyDMARC, parsed)

	// RFC 9989 modifiers surfaced as evidence (not status gates) so a record's
	// headline verdict stays driven by p=/pct while operators still see the
	// non-existent-subdomain policy, test mode, and pct deprecation.
	extra := fmt.Sprintf(" sp=%s np=%s t=%s psd=%s", parsed.SubdomainPolicy, parsed.NPPolicy, parsed.TestMode, parsed.PSD)
	if parsed.PctPresent {
		extra += "; pct= is deprecated in RFC 9989 (use t=y for test mode)"
	}
	if parsed.TestMode == "y" {
		extra += "; t=y: monitoring only, policy not enforced"
	}

	switch {
	case parsed.Policy == "reject" && parsed.Pct == 100:
		ev := fmt.Sprintf("p=reject pct=100 adkim=%s aspf=%s rua=%v", parsed.Adkim, parsed.Aspf, parsed.Rua)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Pass, Evidence: ev + extra, RFCRefs: refs}}
	case parsed.Policy == "quarantine" && parsed.Pct == 100:
		ev := fmt.Sprintf("p=quarantine pct=100 adkim=%s aspf=%s rua=%v", parsed.Adkim, parsed.Aspf, parsed.Rua)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Warn,
			Evidence: ev + "; consider p=reject" + extra, RFCRefs: refs}}
	case parsed.Policy == "none":
		ev := fmt.Sprintf("p=none — reports only, no enforcement (rua=%v)", parsed.Rua)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Warn, Evidence: ev + extra, RFCRefs: refs}}
	default:
		ev := fmt.Sprintf("p=%s pct=%d — partial enforcement", parsed.Policy, parsed.Pct)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Warn, Evidence: ev + extra, RFCRefs: refs}}
	}
}

func dmarcRemediation(domain string) string {
	return fmt.Sprintf(
		`_dmarc.%s. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`,
		domain, domain,
	)
}

// dmarcOnces holds a sync.Once per Env so the _dmarc TXT lookup runs at most
// once per scan even when the parallel registry fires email.dmarc.record and
// email.dmarc.np concurrently. The record check (runDMARC) populates the cache
// on its own lookup; ensureDMARC lets the np consumer prime it race-free when
// it happens to run first. Mirrors the bimi package's ensureRecord primitive.
var (
	dmarcOnceMu sync.Mutex
	dmarcOnces  = map[*probe.Env]*sync.Once{}
)

// ensureDMARC performs the _dmarc TXT lookup for env.Target exactly once and
// stores the parsed *DMARC under probe.CacheKeyDMARC. It is a silent priming
// primitive: it returns no Result and swallows lookup/parse errors because
// runDMARC reports those through its own structured result. It caches only a
// single well-formed record, matching runDMARC's contract (0 or multiple
// v=DMARC1 records cache nothing). Consumers that read the cache call this
// first so they don't depend on winning a scheduling race against runDMARC.
func ensureDMARC(ctx context.Context, env *probe.Env) {
	if env == nil {
		return
	}
	if _, ok := env.CacheGet(probe.CacheKeyDMARC); ok {
		return
	}
	dmarcOnceMu.Lock()
	o, ok := dmarcOnces[env]
	if !ok {
		o = &sync.Once{}
		dmarcOnces[env] = o
	}
	dmarcOnceMu.Unlock()
	o.Do(func() {
		cctx, cancel := env.WithTimeout(ctx)
		defer cancel()
		txt, err := env.DNS.LookupTXT(cctx, "_dmarc."+env.Target)
		if err != nil {
			return
		}
		var records []string
		for _, t := range txt {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
				records = append(records, t)
			}
		}
		if len(records) != 1 {
			return
		}
		parsed, err := ParseDMARC(records[0])
		if err != nil {
			return
		}
		env.CachePut(probe.CacheKeyDMARC, parsed)
	})
}

// EnsureDMARC primes probe.CacheKeyDMARC with the parsed DMARC record for
// env.Target exactly once per scan. It exists so consumers in other packages
// — specifically the BIMI Gmail gate — can read the DMARC verdict race-free
// regardless of check scheduling, without importing this package's parser.
func EnsureDMARC(ctx context.Context, env *probe.Env) { ensureDMARC(ctx, env) }

// runDMARCNonExistentPolicy evaluates the RFC 9989 §4.7 `np` tag — the policy
// a Domain Owner applies to mail from *non-existent* subdomains of the
// Organizational Domain. It is the headline new externally-observable control
// in DMARCbis: it lets an operator reject spoofed mail from never-provisioned
// subdomains independently of `sp`. Because this check runs in the same Email
// category as its producer (runDMARC) with no ordering guarantee, it calls
// ensureDMARC first to prime the shared cache race-free, then reads the parse.
// When no single well-formed DMARC record exists there is no np to evaluate,
// so it reports N/A and defers the underlying diagnosis to email.dmarc.record.
func runDMARCNonExistentPolicy(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.dmarc.np"
	const title = "DMARC non-existent subdomain policy (np)"
	refs := []string{"RFC 9989 §4.7"}

	ensureDMARC(ctx, env)

	cached, ok := env.CacheGet(probe.CacheKeyDMARC)
	if !ok || cached == nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no DMARC record to evaluate np against (see email.dmarc.record)",
			RFCRefs:  refs,
		}}
	}
	parsed, ok := cached.(*DMARC)
	if !ok || parsed == nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "DMARC cache present but unrecognized shape",
			RFCRefs:  refs,
		}}
	}

	source := "explicit"
	if !parsed.NPExplicit {
		source = fmt.Sprintf("inherited from sp=%s", parsed.SubdomainPolicy)
	}

	switch parsed.NPPolicy {
	case "reject":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("np=reject (%s) — mail from non-existent subdomains is rejected", source),
			RFCRefs:  refs,
		}}
	case "quarantine":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    fmt.Sprintf("np=quarantine (%s) — consider np=reject for non-existent subdomains", source),
			Remediation: dmarcNPRemediation(env.Target),
			RFCRefs:     refs,
		}}
	default:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    fmt.Sprintf("np=%s (%s) — non-existent subdomains are not protected from spoofing", parsed.NPPolicy, source),
			Remediation: dmarcNPRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
}

func dmarcNPRemediation(domain string) string {
	return fmt.Sprintf(
		`_dmarc.%s. IN TXT "v=DMARC1; p=reject; np=reject; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`,
		domain, domain,
	)
}
