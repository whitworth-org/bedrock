package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runAAAAApex: RFC 3596 — AAAA on the apex. Many production zones still don't
// publish IPv6, so this is a Warn (not Fail) when missing.
func runAAAAApex(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	v6, err := env.DNS.LookupAAAA(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID:       "dns.aaaa.apex",
			Category: category,
			Title:    "Apex AAAA",
			Status:   report.Warn,
			Evidence: "lookup error: " + err.Error(),
			RFCRefs:  []string{"RFC 3596"},
		}}
	}
	if len(v6) == 0 {
		return []report.Result{{
			ID:       "dns.aaaa.apex",
			Category: category,
			Title:    "No AAAA record at apex (IPv6 not advertised)",
			Status:   report.Warn,
			Evidence: "AAAA RRset is empty",
			RFCRefs:  []string{"RFC 3596"},
		}}
	}
	var ips []string
	for _, ip := range v6 {
		ips = append(ips, ip.String())
	}
	return []report.Result{{
		ID:       "dns.aaaa.apex",
		Category: category,
		Title:    fmt.Sprintf("Apex publishes %d AAAA record(s)", len(v6)),
		Status:   report.Pass,
		Evidence: strings.Join(ips, ", "),
		RFCRefs:  []string{"RFC 3596"},
	}}
}
