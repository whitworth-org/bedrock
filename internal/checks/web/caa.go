package web

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runCAA implements RFC 8659 CAA. CAA is a DNS-only check, so it runs
// regardless of env.Active. Absence is a Warn (CAs default to allow);
// presence with valid issue/issuewild/iodef tags is a Pass.
func runCAA(ctx context.Context, env *probe.Env) []report.Result {
	cctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	id := "web.caa"
	title := "CAA records present (RFC 8659)"
	refs := []string{"RFC 8659 §3", "RFC 8659 §4"}

	records, err := env.DNS.LookupCAA(cctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    "CAA lookup failed: " + err.Error(),
			Remediation: caaRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	if len(records) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    "no CAA records at apex (any CA is permitted to issue)",
			Remediation: caaRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	hasIssue := false
	hasWild := false
	hasIodef := false
	var summary []string
	for _, rec := range records {
		tag := strings.ToLower(rec.Tag)
		summary = append(summary, fmt.Sprintf("%d %s %q", rec.Flag, tag, rec.Value))
		switch tag {
		case "issue":
			hasIssue = true
		case "issuewild":
			hasWild = true
		case "iodef":
			hasIodef = true
		}
	}
	if !hasIssue {
		// RFC 8659 §4.2: no "issue" property = no CA may issue. Likely a
		// misconfiguration; flag as Warn so operators are aware.
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    "CAA present but no 'issue' tag (no CA permitted): " + strings.Join(summary, "; "),
			Remediation: caaRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	notes := []string{"issue ✓"}
	if hasWild {
		notes = append(notes, "issuewild ✓")
	}
	if hasIodef {
		notes = append(notes, "iodef ✓")
	} else {
		notes = append(notes, "iodef (recommended) absent")
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("%s — %s", strings.Join(notes, ", "), strings.Join(summary, "; ")),
		RFCRefs:  refs,
	}}
}

func caaRemediation(domain string) string {
	return fmt.Sprintf(`%s. IN CAA 0 issue "letsencrypt.org"
%s. IN CAA 0 issuewild ";"
%s. IN CAA 0 iodef "mailto:security@%s"`, domain, domain, domain, domain)
}
