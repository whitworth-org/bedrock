package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runDMARCRejectDKIM audits the RFC 9989 requirement that a domain
// publishing p=reject MUST apply valid DKIM signatures and MUST NOT rely on
// SPF alone — DKIM is what survives forwarding, and under reject a broken
// identifier means lost mail.
//
// Status policy: never Fail. Selector probing is a heuristic — a key on a
// custom selector is invisible to the sweep — so absence of discovery is
// strong advice (Warn), not proof of misconfiguration.
func runDMARCRejectDKIM(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.dmarc.reject_dkim"
	const title = "p=reject requires DKIM, not SPF alone (RFC 9989)"
	refs := []string{"RFC 9989", "RFC 6376"}

	walk := EnsureDMARCWalk(ctx, env)
	if walk == nil || walk.Policy == nil {
		res := report.Result{ID: id, Category: category, Title: title, RFCRefs: refs}
		return []report.Result{noPolicyResult(walk, res,
			"no DMARC record; the requirement applies to p=reject publishers")}
	}
	policy := walk.EffectivePolicy()
	if policy != "reject" {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: fmt.Sprintf("effective policy is %s — the RFC 9989 DKIM requirement applies to reject", policy),
			RFCRefs:  refs,
		}}
	}

	sweep := dkimSweep(ctx, env)
	if sweep == nil {
		return nil
	}
	var live []string
	for _, p := range sweep.Found() {
		if status, _ := gradeDKIMKey(p.Key); status != report.Fail {
			live = append(live, p.Selector)
		}
	}
	if len(live) > 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Pass,
			Evidence: "p=reject with discoverable DKIM key(s) at: " + strings.Join(live, ", ") +
				" — satisfies RFC 9989 (MUST apply DKIM; MUST NOT rely on SPF alone)",
			RFCRefs: refs,
		}}
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status: report.Warn,
		Evidence: fmt.Sprintf(
			"p=reject but no usable DKIM key discoverable across %d common selectors — "+
				"RFC 9989: reject publishers MUST apply DKIM and MUST NOT rely on SPF alone, "+
				"since only DKIM survives forwarding (probing is heuristic; a custom selector "+
				"may exist)",
			len(sweep.Selectors)),
		Remediation: dkimKeyRemediation("<selector>._domainkey." + env.Target),
		RFCRefs:     refs,
	}}
}
