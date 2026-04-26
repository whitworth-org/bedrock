package email

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// DMARC is the parsed view of a DMARC TXT record (RFC 7489 §6.3). Exported
// so the BIMI Gmail-gate check can read it via env.CacheGet(probe.CacheKeyDMARC).
type DMARC struct {
	Raw             string
	Policy          string   // p=  (none/quarantine/reject)
	SubdomainPolicy string   // sp= (none/quarantine/reject), defaults to Policy when absent
	Pct             int      // pct=, default 100
	Adkim           string   // adkim= (r/s), default "r"
	Aspf            string   // aspf=  (r/s), default "r"
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
		Raw:   trimmed,
		Pct:   100,
		Adkim: "r",
		Aspf:  "r",
		Tags:  map[string]string{},
	}
	parts := strings.Split(trimmed, ";")
	// RFC 7489 §6.3: v=DMARC1 MUST be the first tag. We require it to appear
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
		// p= is required (RFC 7489 §6.3); the only exception is a "report-only"
		// child record (e.g. *._report._dmarc.example.com) which our caller
		// does not query.
		return nil, errors.New("missing required p= tag")
	}
	if out.SubdomainPolicy == "" {
		out.SubdomainPolicy = out.Policy
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

func runDMARC(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "email.dmarc.record"
	const title = "DMARC record present and well-formed"
	refs := []string{"RFC 7489 §6.3", "RFC 7489 §6.4", "RFC 7489 §11.2"}

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

	switch {
	case parsed.Policy == "reject" && parsed.Pct == 100:
		ev := fmt.Sprintf("p=reject pct=100 adkim=%s aspf=%s rua=%v", parsed.Adkim, parsed.Aspf, parsed.Rua)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Pass, Evidence: ev, RFCRefs: refs}}
	case parsed.Policy == "quarantine" && parsed.Pct == 100:
		ev := fmt.Sprintf("p=quarantine pct=100 adkim=%s aspf=%s rua=%v", parsed.Adkim, parsed.Aspf, parsed.Rua)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Warn,
			Evidence: ev + "; consider p=reject", RFCRefs: refs}}
	case parsed.Policy == "none":
		ev := fmt.Sprintf("p=none — reports only, no enforcement (rua=%v)", parsed.Rua)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Warn, Evidence: ev, RFCRefs: refs}}
	default:
		ev := fmt.Sprintf("p=%s pct=%d — partial enforcement", parsed.Policy, parsed.Pct)
		return []report.Result{{ID: id, Category: category, Title: title, Status: report.Warn, Evidence: ev, RFCRefs: refs}}
	}
}

func dmarcRemediation(domain string) string {
	return fmt.Sprintf(
		`_dmarc.%s. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`,
		domain, domain,
	)
}
