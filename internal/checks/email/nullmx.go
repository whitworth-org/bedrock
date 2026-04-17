package email

import (
	"context"
	"errors"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

type nullMXCheck struct{}

func (nullMXCheck) ID() string       { return "email.nullmx" }
func (nullMXCheck) Category() string { return category }

// Run detects RFC 7505 Null MX. A single MX with preference 0 and host "."
// asserts the domain accepts no mail. The check is purely informational —
// it tells the operator whether their domain is mail-accepting or not.
func (nullMXCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	const id = "email.nullmx"
	const title = "Null MX (RFC 7505) declaration"
	refs := []string{"RFC 7505 §3"}

	mxs, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "MX lookup failed: " + err.Error(),
			RFCRefs: refs,
		}}
	}

	// Cache the MX set for downstream checks (cheap to redo, but keeps the
	// shape used by other categories).
	env.CachePut(probe.CacheKeyMX, mxs)

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
