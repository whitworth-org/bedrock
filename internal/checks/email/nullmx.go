package email

import (
	"context"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runNullMX detects RFC 7505 Null MX. A single MX with preference 0 and host
// "." asserts the domain accepts no mail. The check is purely informational —
// it tells the operator whether their domain is mail-accepting or not.
func runNullMX(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.nullmx"
	const title = "Null MX (RFC 7505) declaration"
	refs := []string{"RFC 7505 §3"}

	mxs, err := targetMX(ctx, env)
	if err != nil {
		res := report.Result{ID: id, Category: category, Title: title, RFCRefs: refs}
		return []report.Result{checkutil.Inconclusive(res, err)}
	}

	if isNullMX(mxs) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "domain advertises null MX (0 .) — accepts no mail",
			RFCRefs:  refs,
		}}
	}
	if len(mxs) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no MX records — null MX not applicable",
			RFCRefs:  refs,
		}}
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Info,
		Evidence: "domain accepts mail (no null MX declared)",
		RFCRefs:  refs,
	}}
}
