package email

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// STSPolicy holds a parsed MTA-STS policy file (RFC 8461 §3.2).
type STSPolicy struct {
	Raw     string
	Version string   // "STSv1"
	Mode    string   // "enforce" / "testing" / "none"
	MaxAge  int      // seconds
	MX      []string // host patterns; "*." prefix permitted per §3.2
}

// Resource caps for MTA-STS policy files. RFC 8461 doesn't pin a hard
// ceiling on entries; these are defensive and sit well above any
// legitimate deployment.
const (
	// maxSTSMXEntries caps the number of mx: lines in a policy. Real
	// deployments have a handful; 64 is generous.
	maxSTSMXEntries = 64

	// maxSTSMXHostLen is the RFC 1035 maximum length for a fully qualified
	// DNS name (excluding the trailing dot); any mx: value longer than
	// this cannot legally refer to a host.
	maxSTSMXHostLen = 253
)

// ParseSTSPolicy parses the policy file body. Lines are CRLF-or-LF separated;
// each line is "key: value". The parser:
//   - Normalises line endings (CRLF/LF both accepted).
//   - Lower-cases the key before dispatch, i.e. "Mode:" and "mode:" both
//     resolve to the same field (case-insensitive key matching).
//   - Rejects duplicate version / mode / max_age keys (RFC 8461 §3.2 allows
//     only one of each singleton field).
//   - Caps mx: entries at maxSTSMXEntries and the length of each mx: value
//     at maxSTSMXHostLen to bound resource use on malformed policies.
func ParseSTSPolicy(body string) (*STSPolicy, error) {
	out := &STSPolicy{Raw: body}
	// Normalize line endings. Spec uses CRLF but we accept either.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	sawVersion, sawMode, sawMaxAge := false, false, false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return nil, fmt.Errorf("malformed line %q", report.ClipValue(line))
		}
		// Lower-case the key so the dispatch is case-insensitive. Keeping
		// the original case available via line[:colon] would be fine too
		// but the switch would have to fold it anyway.
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		switch key {
		case "version":
			if sawVersion {
				return nil, errors.New("duplicate version key")
			}
			sawVersion = true
			out.Version = value
		case "mode":
			if sawMode {
				return nil, errors.New("duplicate mode key")
			}
			sawMode = true
			out.Mode = value
		case "max_age":
			if sawMaxAge {
				return nil, errors.New("duplicate max_age key")
			}
			sawMaxAge = true
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid max_age %q", report.ClipValue(value))
			}
			out.MaxAge = n
		case "mx":
			if len(out.MX) >= maxSTSMXEntries {
				return nil, fmt.Errorf("too many mx entries (>%d)", maxSTSMXEntries)
			}
			if len(value) > maxSTSMXHostLen {
				return nil, fmt.Errorf("mx value %d bytes exceeds cap %d", len(value), maxSTSMXHostLen)
			}
			out.MX = append(out.MX, value)
		}
	}
	if out.Version != "STSv1" {
		return nil, fmt.Errorf("unexpected version %q", report.ClipValue(out.Version))
	}
	switch out.Mode {
	case "enforce", "testing", "none":
	default:
		return nil, fmt.Errorf("invalid mode %q", report.ClipValue(out.Mode))
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

func runMTASTSTXT(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.mtasts.txt"
	const title = "MTA-STS TXT record present and well-formed"
	refs := []string{"RFC 8461 §3.1"}

	base := report.Result{ID: id, Category: category, Title: title, RFCRefs: refs}
	if publishesNullMX(ctx, env) {
		return []report.Result{nullMXNotApplicable(base)}
	}
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	name := "_mta-sts." + env.Target
	txt, err := lookupTXT(ctx, env, name)
	if err != nil {
		return []report.Result{checkutil.Inconclusive(base, err)}
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

func runMTASTSPolicy(ctx context.Context, env *probe.Env) []report.Result {
	res := report.Result{
		ID: "email.mtasts.policy", Category: category,
		Title: "MTA-STS policy file fetched and well-formed", RFCRefs: []string{"RFC 8461 §3.2"},
	}
	if !env.Active {
		res.Status, res.Evidence = report.NotApplicable, "skipped: --no-active"
		return []report.Result{res}
	}
	if publishesNullMX(ctx, env) {
		return []report.Result{nullMXNotApplicable(res)}
	}

	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	// RFC 8461 §3.3: the policy fetch MUST use a valid TLS chain and MUST
	// NOT follow redirects. GetStrict enforces both.
	resp, err := env.HTTP.GetStrict(ctx, mtastsPolicyURL(env.Target))
	return []report.Result{gradeSTSPolicy(ctx, res, env.Target, resp, err)}
}

func mtastsPolicyURL(domain string) string {
	return "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
}

// gradeSTSPolicy grades the fetch of domain's policy file into res. A fetch
// that could not complete is inconclusive. Any other fetch error, such as a
// certificate that does not verify, fails, as do a status other than 200,
// including a redirect, and a policy that does not parse (RFC 8461 §3.3).
func gradeSTSPolicy(
	ctx context.Context, res report.Result, domain string, resp *probe.Response, err error,
) report.Result {
	url := mtastsPolicyURL(domain)
	if err != nil {
		if checkutil.Incomplete(ctx, err) {
			return checkutil.Inconclusive(res, err)
		}
		return stsPolicyFail(res, domain, "GET "+url+" failed: "+err.Error())
	}
	if resp.Status != 200 {
		return stsPolicyFail(res, domain, fmt.Sprintf("GET %s returned HTTP %d", url, resp.Status))
	}

	parsed, err := ParseSTSPolicy(string(resp.Body))
	if err != nil {
		return stsPolicyFail(res, domain, "policy parse error: "+err.Error())
	}

	switch parsed.Mode {
	case "enforce":
		res.Status = report.Pass
		res.Evidence = fmt.Sprintf("mode=enforce max_age=%d mx=%v", parsed.MaxAge, parsed.MX)
	case "testing":
		res.Status = report.Warn
		res.Evidence = fmt.Sprintf("mode=testing — promote to enforce when monitoring is clean "+
			"(max_age=%d mx=%v)", parsed.MaxAge, parsed.MX)
	default: // "none"
		return stsPolicyFail(res, domain, "mode=none disables enforcement")
	}
	return res
}

func stsPolicyFail(res report.Result, domain, evidence string) report.Result {
	res.Status = report.Fail
	res.Evidence = evidence
	res.Remediation = mtastsPolicyRemediation(domain)
	return res
}

// nullMXNotApplicable reworks res for a domain that publishes null MX: it
// accepts no mail (RFC 7505), so no inbound transport policy applies.
func nullMXNotApplicable(res report.Result) report.Result {
	res.Status = report.NotApplicable
	res.Evidence = "domain publishes null MX (RFC 7505)"
	return res
}

// mtastsTXTRemediation leaves the id as a placeholder: senders refetch the
// policy only when the id changes (RFC 8461 §3.1), so a fixed one is wrong.
func mtastsTXTRemediation(domain string) string {
	return fmt.Sprintf(`_mta-sts.%s. IN TXT "v=STSv1; id=<YYYYMMDDhhmmssZ>"`,
		report.InlineValue(domain))
}

func mtastsPolicyRemediation(domain string) string {
	return fmt.Sprintf(
		"https://mta-sts.%s/.well-known/mta-sts.txt :\n"+
			"version: STSv1\nmode: enforce\nmx: <your-mx-host>\nmax_age: 604800",
		report.InlineValue(domain),
	)
}
