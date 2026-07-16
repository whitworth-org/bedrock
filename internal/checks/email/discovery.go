package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runDMARCDiscovery reports how DMARC policy discovery resolved for the
// target: the RFC 9989 DNS tree walk (the DMARCbis replacement for the
// Public Suffix List), the Organizational Domain it derived and by which
// rule, and any records on the path the walk had to ignore. RFC 9990
// aggregate reports carry the same distinction in their discovery_method
// field (psl vs treewalk).
func runDMARCDiscovery(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.dmarc.discovery"
	const title = "DMARC discovery: RFC 9989 tree walk and Organizational Domain"
	refs := []string{"RFC 9989 §4.8", "RFC 9990"}

	walk := ensureDMARCWalk(ctx, env)
	if walk == nil || len(walk.Steps) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "tree walk could not run (no DNS queries executed)",
			RFCRefs:  refs,
		}}
	}

	found := foundSteps(walk.Steps)
	if len(found) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable,
			Evidence: fmt.Sprintf("no v=DMARC1 records on the tree walk (%d of %d queries); see email.dmarc.record",
				walk.Queries, maxWalkQueries),
			RFCRefs: refs,
		}}
	}

	domains := make([]string, 0, len(found))
	for _, s := range found {
		domains = append(domains, s.Domain)
	}
	ev := fmt.Sprintf("organizational domain %s (rule: %s); policy from _dmarc.%s; records at: %s; queries %d/%d",
		walk.OrgDomain, walk.OrgRule, walk.PolicyDomain, strings.Join(domains, ", "),
		walk.Queries, maxWalkQueries)

	if anomalies := walkAnomalies(walk); len(anomalies) > 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: ev + "; anomalies: " + strings.Join(anomalies, "; "),
			RFCRefs:  refs,
		}}
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: ev,
		RFCRefs:  refs,
	}}
}

// walkAnomalies lists conditions the tree walk tolerated but an operator
// should know about: records the walk had to ignore and a psd=y declaration
// on the author domain itself (the scan target claims to be a public
// suffix).
func walkAnomalies(walk *DMARCWalk) []string {
	var out []string
	for _, s := range walk.Steps {
		switch s.Outcome {
		case walkMultiple:
			out = append(out, fmt.Sprintf("%s v=DMARC1 records at %s (ignored)", s.Detail, s.QueryName))
		case walkMalformed:
			out = append(out, fmt.Sprintf("%s is malformed: %s (ignored)", s.QueryName, s.Detail))
		case walkError:
			out = append(out, fmt.Sprintf("%s lookup failed: %s", s.QueryName, s.Detail))
		}
	}
	if first := walk.Steps[0]; first.Outcome == walkFound && first.Record.PSD == "y" {
		out = append(out, "author domain declares psd=y (scan target is a public suffix)")
	}
	return out
}
