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

// STSPolicy holds a parsed MTA-STS policy file (RFC 8461 §3.2).
type STSPolicy struct {
	Raw     string
	Version string   // "STSv1"
	Mode    string   // "enforce" / "testing" / "none"
	MaxAge  int      // seconds
	MX      []string // host patterns; "*." prefix permitted per §3.2
}

// ParseSTSPolicy parses the policy file body. Lines are CRLF-or-LF separated;
// each line is "key: value" with case-sensitive key names per RFC 8461 §3.2.
func ParseSTSPolicy(body string) (*STSPolicy, error) {
	out := &STSPolicy{Raw: body}
	// Normalize line endings. Spec uses CRLF but we accept either.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return nil, fmt.Errorf("malformed line %q", line)
		}
		key := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		switch key {
		case "version":
			out.Version = value
		case "mode":
			out.Mode = value
		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid max_age %q", value)
			}
			out.MaxAge = n
		case "mx":
			out.MX = append(out.MX, value)
		}
	}
	if out.Version != "STSv1" {
		return nil, fmt.Errorf("unexpected version %q", out.Version)
	}
	switch out.Mode {
	case "enforce", "testing", "none":
	default:
		return nil, fmt.Errorf("invalid mode %q", out.Mode)
	}
	return out, nil
}

// extractSTSID returns the id= value from a v=STSv1 TXT record, or "" if absent.
func extractSTSID(raw string) string {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(part[:eq]), "id") {
			return strings.TrimSpace(part[eq+1:])
		}
	}
	return ""
}

type mtastsTXTCheck struct{}

func (mtastsTXTCheck) ID() string       { return "email.mtasts.txt" }
func (mtastsTXTCheck) Category() string { return category }

func (mtastsTXTCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "email.mtasts.txt"
	const title = "MTA-STS TXT record present and well-formed"
	refs := []string{"RFC 8461 §3.1"}

	name := "_mta-sts." + env.Target
	txt, err := env.DNS.LookupTXT(ctx, name)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "TXT lookup failed: " + err.Error(),
			Remediation: mtastsTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	var records []string
	for _, t := range txt {
		if strings.HasPrefix(strings.TrimSpace(t), "v=STSv1") {
			records = append(records, t)
		}
	}

	switch len(records) {
	case 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no v=STSv1 TXT record at " + name,
			Remediation: mtastsTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	case 1:
		// fall through
	default:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("multiple v=STSv1 records (%d) at %s", len(records), name),
			Remediation: mtastsTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	if extractSTSID(records[0]) == "" {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "v=STSv1 record missing id= tag: " + records[0],
			Remediation: mtastsTXTRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: records[0],
		RFCRefs:  refs,
	}}
}

type mtastsPolicyCheck struct{}

func (mtastsPolicyCheck) ID() string       { return "email.mtasts.policy" }
func (mtastsPolicyCheck) Category() string { return category }

func (mtastsPolicyCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.mtasts.policy"
	const title = "MTA-STS policy file fetched and well-formed"
	refs := []string{"RFC 8461 §3.2"}

	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "skipped: --no-active",
			RFCRefs:  refs,
		}}
	}

	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	url := "https://mta-sts." + env.Target + "/.well-known/mta-sts.txt"
	resp, err := env.HTTP.Get(ctx, url)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "GET " + url + " failed: " + err.Error(),
			Remediation: mtastsPolicyRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	if resp.Status != 200 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("GET %s returned HTTP %d", url, resp.Status),
			Remediation: mtastsPolicyRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	parsed, err := ParseSTSPolicy(string(resp.Body))
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "policy parse error: " + err.Error(),
			Remediation: mtastsPolicyRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}

	switch parsed.Mode {
	case "enforce":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("mode=enforce max_age=%d mx=%v", parsed.MaxAge, parsed.MX),
			RFCRefs:  refs,
		}}
	case "testing":
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: fmt.Sprintf("mode=testing — promote to enforce when monitoring is clean (max_age=%d mx=%v)", parsed.MaxAge, parsed.MX),
			RFCRefs:  refs,
		}}
	default: // "none"
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "mode=none disables enforcement",
			Remediation: mtastsPolicyRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
}

func mtastsTXTRemediation(domain string) string {
	return fmt.Sprintf(`_mta-sts.%s. IN TXT "v=STSv1; id=20260416000000Z"`, domain)
}

func mtastsPolicyRemediation(domain string) string {
	return fmt.Sprintf(
		"https://mta-sts.%s/.well-known/mta-sts.txt :\n"+
			"version: STSv1\nmode: enforce\nmx: <your-mx-host>\nmax_age: 604800",
		domain,
	)
}
