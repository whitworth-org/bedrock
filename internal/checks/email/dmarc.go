package email

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// DMARC is the parsed view of a DMARC TXT record (RFC 9989 §4.7; RFC 9989
// obsoletes RFC 7489 and RFC 9091). Exported so the BIMI Gmail-gate check
// can read it via env.CacheGet(probe.CacheKeyDMARC).
type DMARC struct {
	Raw             string
	Policy          string   // p=    (none/quarantine/reject)
	SubdomainPolicy string   // sp=   (none/quarantine/reject), defaults to Policy when absent
	NPPolicy        string   // np=   (none/quarantine/reject), non-existent-subdomain policy; np<-sp<-p
	NPExplicit      bool     // true when np= was published literally (not inherited)
	Pct             int      // pct=, default 100 — REMOVED in RFC 9989; kept for transitional records
	PctPresent      bool     // true when pct= was published literally
	Adkim           string   // adkim= (r/s), default "r"
	Aspf            string   // aspf=  (r/s), default "r"
	Fo              string   // fo=    failure-reporting options (0/1/d/s, colon-separated)
	TestMode        string   // t=     (y/n), default "n" — RFC 9989 §4.7, supersedes pct
	PSD             string   // psd=   (y/n/u), default "u" — RFC 9989 §4.7
	Rua             []string // rua= URIs (aggregate reports, RFC 9990)
	Ruf             []string // ruf= URIs (failure reports, RFC 9991)
	// RetiredTags lists tags present in the record that RFC 9989 removed
	// (pct, rf, ri), in record order. DMARCbis receivers ignore them.
	RetiredTags []string
	Tags        map[string]string
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
			out.RetiredTags = append(out.RetiredTags, "pct")
			n, err := parseStrictPct(value)
			if err != nil {
				return nil, fmt.Errorf("invalid pct=%q: %s", value, err.Error())
			}
			out.Pct = n
		case "rf", "ri":
			// Failure-report format and aggregate interval — removed in
			// RFC 9989 alongside pct. Values are not validated (their
			// registries are retired); presence alone is worth surfacing.
			out.RetiredTags = append(out.RetiredTags, name)
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

// parseReportURIs validates a comma-separated list of DMARC report URIs
// (rua= aggregate destinations, RFC 9990; ruf= failure destinations, RFC
// 9991, which updates RFC 6591). Each URI must use the mailto: or https://
// scheme; http://, file://, and anything else is rejected so report handlers
// aren't pointed at attacker-controlled endpoints that receive aggregate
// reports (which can leak recipient addresses for reflection).
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

const (
	dmarcRecordID    = "email.dmarc.record"
	dmarcRecordTitle = "DMARC record present and well-formed"
)

// dmarcRecordRefs: §4.7 record syntax, §4.8 policy discovery (tree walk);
// RFC 9990 covers the rua= aggregate-report destinations surfaced in
// evidence.
func dmarcRecordRefs() []string {
	return []string{"RFC 9989 §4.7", "RFC 9989 §4.8", "RFC 9990"}
}

func runDMARC(ctx context.Context, env *probe.Env) []report.Result {
	walk := ensureDMARCWalk(ctx, env)
	if walk == nil || len(walk.Steps) == 0 {
		return dmarcRecordFail(env, "DMARC tree walk could not run (no DNS queries executed)")
	}

	author := walk.Steps[0]
	if ev, bad := dmarcAuthorProblem(author); bad {
		return dmarcRecordFail(env, ev)
	}
	if author.Outcome == walkFound {
		return dmarcExactResult(author.Record)
	}
	if walk.Policy != nil {
		return dmarcInheritedResult(env, walk)
	}
	return dmarcRecordFail(env, fmt.Sprintf(
		"no v=DMARC1 record at _dmarc.%s or any tree-walk ancestor (RFC 9989 §4.8, %d of %d queries)",
		env.Target, walk.Queries, maxWalkQueries,
	))
}

func dmarcRecordFail(env *probe.Env, evidence string) []report.Result {
	return []report.Result{{
		ID: dmarcRecordID, Category: category, Title: dmarcRecordTitle,
		Status:      report.Fail,
		Evidence:    evidence,
		Remediation: dmarcRemediation(env.Target),
		RFCRefs:     dmarcRecordRefs(),
	}}
}

// dmarcAuthorProblem maps a defective author-domain walk step to Fail
// evidence. NXDOMAIN/NODATA are not defects — they hand over to the tree
// walk.
func dmarcAuthorProblem(step DMARCWalkStep) (string, bool) {
	switch step.Outcome {
	case walkError:
		return "TXT lookup failed: " + step.Detail, true
	case walkMultiple:
		return fmt.Sprintf("multiple v=DMARC1 records (%s) at %s", step.Detail, step.QueryName), true
	case walkMalformed:
		return "parse error: " + step.Detail, true
	}
	return "", false
}

// dmarcPolicyStatus maps a policy and the RFC 9989 t= flag to a verdict.
// t=y steps the effective policy down one level (reject→quarantine,
// quarantine→none), so a tested policy is not yet full enforcement.
func dmarcPolicyStatus(policy, testMode string) (report.Status, string) {
	if testMode == "y" {
		stepped := "none"
		if policy == "reject" {
			stepped = "quarantine"
		}
		note := fmt.Sprintf("; t=y — effective policy %s while testing (RFC 9989 §4.7)", stepped)
		return report.Warn, note
	}
	if policy == "reject" {
		return report.Pass, ""
	}
	return report.Warn, ""
}

// dmarcModifierNotes surfaces the DMARCbis modifiers and retired-tag state
// as evidence suffixes.
func dmarcModifierNotes(p *DMARC) string {
	extra := fmt.Sprintf(" sp=%s np=%s t=%s psd=%s", p.SubdomainPolicy, p.NPPolicy, p.TestMode, p.PSD)
	if len(p.RetiredTags) > 0 {
		extra += fmt.Sprintf("; retired tags present (%s) — removed in RFC 9989, DMARCbis receivers ignore them",
			strings.Join(p.RetiredTags, ", "))
	}
	if p.PctPresent && p.Pct < 100 {
		extra += fmt.Sprintf("; pct=%d no longer samples — replace with t=y for testing, or remove", p.Pct)
	}
	return extra
}

// dmarcRetiredStatus forces at least Warn when pct<100 is published: legacy
// RFC 7489 receivers still sample while DMARCbis receivers enforce at 100%,
// so the record's observed behavior diverges between receiver generations.
func dmarcRetiredStatus(status report.Status, p *DMARC) report.Status {
	if status == report.Pass && p.PctPresent && p.Pct < 100 {
		return report.Warn
	}
	return status
}

func dmarcExactResult(p *DMARC) []report.Result {
	status, note := dmarcPolicyStatus(p.Policy, p.TestMode)
	switch {
	case p.Policy == "quarantine" && p.TestMode != "y":
		note += "; consider p=reject"
	case p.Policy == "none":
		note += " — reports only, no enforcement"
	}
	ev := fmt.Sprintf("p=%s adkim=%s aspf=%s rua=%v", p.Policy, p.Adkim, p.Aspf, p.Rua)
	return []report.Result{{
		ID: dmarcRecordID, Category: category, Title: dmarcRecordTitle,
		Status:   dmarcRetiredStatus(status, p),
		Evidence: ev + note + dmarcModifierNotes(p),
		RFCRefs:  dmarcRecordRefs(),
	}}
}

// dmarcInheritedResult reports coverage discovered above the author domain:
// the org-domain (or PSD) record applies through its subdomain policy.
func dmarcInheritedResult(env *probe.Env, walk *DMARCWalk) []report.Result {
	p := walk.Policy
	eff := p.SubdomainPolicy
	status, note := dmarcPolicyStatus(eff, p.TestMode)
	if status != report.Pass && p.TestMode != "y" {
		note += fmt.Sprintf("; consider strengthening sp= at %s", walk.PolicyDomain)
	}
	ev := fmt.Sprintf(
		"no record at _dmarc.%s; covered by _dmarc.%s via RFC 9989 tree walk (effective policy sp=%s)",
		env.Target, walk.PolicyDomain, eff,
	)
	return []report.Result{{
		ID: dmarcRecordID, Category: category, Title: dmarcRecordTitle,
		Status:   dmarcRetiredStatus(status, p),
		Evidence: ev + note + dmarcModifierNotes(p),
		RFCRefs:  dmarcRecordRefs(),
	}}
}

func dmarcRemediation(domain string) string {
	return fmt.Sprintf(
		`_dmarc.%s. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`,
		domain, domain,
	)
}

// ensureDMARC primes probe.CacheKeyDMARC with the effective DMARC policy
// record for env.Target exactly once per scan, discovered via the RFC 9989
// tree walk (see treewalk.go). It is a silent priming primitive: it returns
// no Result and swallows lookup/parse errors because runDMARC reports those
// through its own structured result. A pre-seeded cache short-circuits the
// walk so hermetic consumers (tests, other packages) stay network-free.
func ensureDMARC(ctx context.Context, env *probe.Env) {
	if env == nil {
		return
	}
	if _, ok := env.CacheGet(probe.CacheKeyDMARC); ok {
		return
	}
	ensureDMARCWalk(ctx, env)
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

	var npResult report.Result
	switch parsed.NPPolicy {
	case "reject":
		npResult = report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("np=reject (%s) — mail from non-existent subdomains is rejected", source),
			RFCRefs:  refs,
		}
	case "quarantine":
		npResult = report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    fmt.Sprintf("np=quarantine (%s) — consider np=reject for non-existent subdomains", source),
			Remediation: dmarcNPRemediation(env.Target),
			RFCRefs:     refs,
		}
	default:
		npResult = report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    fmt.Sprintf("np=%s (%s) — non-existent subdomains are not protected from spoofing", parsed.NPPolicy, source),
			Remediation: dmarcNPRemediation(env.Target),
			RFCRefs:     refs,
		}
	}

	results := []report.Result{npResult}
	// np is only as reliable as the zone's RFC 8020 NXDOMAIN semantics —
	// probe them when a tree walk ran this scan (a pre-seeded DMARC cache,
	// as in hermetic tests, leaves no walk and skips the probe).
	if walk := cachedWalk(env); walk != nil && walk.OrgDomain != "" {
		results = append(results, dmarcNXDomainResult(ctx, env, walk.OrgDomain))
	}
	return results
}

// dmarcNXDomainResult verifies the Organizational Domain's zone returns
// NXDOMAIN for names that do not exist. RFC 9989's np= mechanism leans on
// RFC 8020 ("NXDOMAIN really means NXDOMAIN"): a wildcard, or a resolver
// that answers NOERROR for everything, makes non-existent subdomains
// indistinguishable from real ones and np unenforceable at receivers.
func dmarcNXDomainResult(ctx context.Context, env *probe.Env, org string) report.Result {
	const id = "email.dmarc.np.rfc8020"
	const title = "DMARC np enforceability: NXDOMAIN semantics (RFC 8020)"
	refs := []string{"RFC 9989 §4.7", "RFC 8020"}
	res := report.Result{ID: id, Category: category, Title: title, RFCRefs: refs}

	lctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	ips, err := env.DNS.LookupA(lctx, nonexistentSubdomain(org))
	switch {
	case errors.Is(err, probe.ErrNXDOMAIN):
		res.Status = report.Pass
		res.Evidence = fmt.Sprintf(
			"authoritative DNS returns NXDOMAIN for a nonexistent subdomain of %s — receivers can apply np= (RFC 8020)", org)
	case err != nil:
		res.Status = report.Info
		res.Evidence = "RFC 8020 probe inconclusive: " + err.Error()
	case len(ips) > 0:
		res.Status = report.Warn
		res.Evidence = fmt.Sprintf(
			"wildcard detected: a nonexistent subdomain of %s resolved — receivers cannot tell "+
				"non-existent subdomains apart, so np= will not fire", org)
		res.Remediation = wildcardRemediation(org)
	default:
		res.Status = report.Warn
		res.Evidence = fmt.Sprintf(
			"a nonexistent subdomain of %s returned NOERROR instead of NXDOMAIN — the zone does not "+
				"implement RFC 8020 semantics, degrading np= enforceability", org)
		res.Remediation = wildcardRemediation(org)
	}
	return res
}

func wildcardRemediation(org string) string {
	return fmt.Sprintf(
		"Ensure the %s zone returns NXDOMAIN for names that do not exist (RFC 8020): remove or "+
			"narrow wildcard records so np= can protect non-existent subdomains.", org)
}

// nonexistentSubdomain returns a randomized label that is overwhelmingly
// unlikely to exist (8 random bytes → 16 hex chars), mirroring the DNSSEC
// NSEC probe's approach.
func nonexistentSubdomain(apex string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to a fixed label so the check still
		// runs rather than crashing.
		return "bedrock-np-nx." + apex
	}
	return "bedrock-np-" + hex.EncodeToString(b[:]) + "." + apex
}

func dmarcNPRemediation(domain string) string {
	return fmt.Sprintf(
		`_dmarc.%s. IN TXT "v=DMARC1; p=reject; np=reject; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`,
		domain, domain,
	)
}
