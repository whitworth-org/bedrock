package email

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
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

// ParseDMARC parses a v=DMARC1 TXT record.
func ParseDMARC(raw string) (*DMARC, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(trimmed), "v=dmarc1") {
		return nil, errors.New("not a DMARC record (missing v=DMARC1)")
	}
	out := &DMARC{
		Raw:   trimmed,
		Pct:   100,
		Adkim: "r",
		Aspf:  "r",
		Tags:  map[string]string{},
	}
	for _, part := range strings.Split(trimmed, ";") {
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
		out.Tags[name] = value
		switch name {
		case "v":
			if !strings.EqualFold(value, "DMARC1") {
				return nil, fmt.Errorf("unexpected v=%q", value)
			}
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
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 100 {
				return nil, fmt.Errorf("invalid pct=%q", value)
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
			out.Rua = splitDMARCURIs(value)
		case "ruf":
			out.Ruf = splitDMARCURIs(value)
		}
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

func validDMARCPolicy(v string) bool {
	switch strings.ToLower(v) {
	case "none", "quarantine", "reject":
		return true
	}
	return false
}

func splitDMARCURIs(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

type dmarcCheck struct{}

func (dmarcCheck) ID() string       { return "email.dmarc.record" }
func (dmarcCheck) Category() string { return category }

func (dmarcCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
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
