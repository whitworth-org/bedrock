package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TLSRPT is the parsed _smtp._tls TXT record (RFC 8460 §3).
type TLSRPT struct {
	Raw     string
	Version string   // "TLSRPTv1"
	Rua     []string // rua= URIs (mailto: or https:)
}

// ParseTLSRPT parses a _smtp._tls TXT record. Duplicate tag names are
// rejected — per RFC 8460 §3 a single record MUST NOT carry the same tag
// twice.
func ParseTLSRPT(raw string) (*TLSRPT, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "v=TLSRPTv1") {
		return nil, errors.New("not a TLS-RPT record (missing v=TLSRPTv1)")
	}
	out := &TLSRPT{Raw: trimmed}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(trimmed, ";") {
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
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		seen[key] = struct{}{}
		switch key {
		case "v":
			out.Version = value
		case "rua":
			for _, u := range strings.Split(value, ",") {
				u = strings.TrimSpace(u)
				if u != "" {
					out.Rua = append(out.Rua, u)
				}
			}
		}
	}
	if len(out.Rua) == 0 {
		// rua is required per RFC 8460 §3.
		return nil, errors.New("missing required rua= tag")
	}
	return out, nil
}

type tlsrptCheck struct{}

func (tlsrptCheck) ID() string       { return "email.tlsrpt.record" }
func (tlsrptCheck) Category() string { return category }

func (tlsrptCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "email.tlsrpt.record"
	const title = "TLS-RPT record present and well-formed"
	refs := []string{"RFC 8460 §3"}

	name := "_smtp._tls." + env.Target
	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "TXT lookup failed: " + err.Error(),
			Remediation: tlsrptRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	var records []string
	for _, t := range txt {
		if strings.HasPrefix(strings.TrimSpace(t), "v=TLSRPTv1") {
			records = append(records, t)
		}
	}

	switch len(records) {
	case 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no v=TLSRPTv1 TXT record at " + name,
			Remediation: tlsrptRemediation(env.Target),
			RFCRefs:     refs,
		}}
	case 1:
		// fall through
	default:
		// RFC 8460 §3: if the count is not exactly one, senders MUST treat
		// the recipient as not implementing TLS-RPT.
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("multiple v=TLSRPTv1 records (%d) at %s", len(records), name),
			Remediation: tlsrptRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	parsed, err := ParseTLSRPT(records[0])
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "parse error: " + err.Error(),
			Remediation: tlsrptRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("rua=%v", parsed.Rua),
		RFCRefs:  refs,
	}}
}

func tlsrptRemediation(domain string) string {
	return fmt.Sprintf(`_smtp._tls.%s. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@%s"`, domain, domain)
}
