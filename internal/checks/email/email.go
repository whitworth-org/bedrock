// Package email implements SMTP-transport and email-authentication checks.
//
// SMTP/MIME: RFC 5321, 5322, 1652, 1869, 1870, 2045-2049, 2047, 2920, 3207,
// 3461, 3464, 4954.
// Authentication: RFC 7208 (SPF); RFC 6376 (DKIM) plus its DKIM2 successor
// draft-ietf-dkim-dkim2-spec; RFC 9989 (DMARC, obsoletes 7489 and 9091) with
// RFC 9990 (aggregate reporting) and RFC 9991 (failure reporting, updates
// 6591); RFC 8617 (ARC, headed to Historic per
// draft-ietf-dmarc-arc-to-historic).
// Transport security: RFC 8461 (MTA-STS), 8460 (TLS-RPT), 7672 (DANE),
// 7505 (Null MX).
//
// The DMARC tree walk (RFC 9989 §4.8) and DKIM selector sweep each run once
// per scan and publish their results to env.CachePut, so downstream checks
// (np, ARC, the BIMI Gmail gate, DKIM2 readiness) consume them without
// re-querying the resolver.
package email

import (
	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/registry"
)

const category = "Email"

func init() {
	registry.Register(checkutil.Wrap("email.spf.record", category, runSPF))
	registry.Register(checkutil.Wrap("email.dkim", category, runDKIM))
	registry.Register(checkutil.Wrap("email.dkim2.readiness", category, runDKIM2Readiness))
	registry.Register(checkutil.Wrap("email.dmarc.record", category, runDMARC))
	registry.Register(checkutil.Wrap("email.dmarc.discovery", category, runDMARCDiscovery))
	registry.Register(checkutil.Wrap("email.dmarc.np", category, runDMARCNonExistentPolicy))
	registry.Register(checkutil.Wrap("email.dmarc.extdest", category, runDMARCExtDest))
	registry.Register(checkutil.Wrap("email.dmarc.reject_dkim", category, runDMARCRejectDKIM))
	registry.Register(checkutil.Wrap("email.mtasts.txt", category, runMTASTSTXT))
	registry.Register(checkutil.Wrap("email.mtasts.policy", category, runMTASTSPolicy))
	registry.Register(checkutil.Wrap("email.tlsrpt.record", category, runTLSRPT))
	registry.Register(checkutil.Wrap("email.dane", category, runDANE))
	registry.Register(checkutil.Wrap("email.nullmx", category, runNullMX))
	registry.Register(checkutil.Wrap("email.smtp.starttls", category, runSTARTTLS))
	registry.Register(checkutil.Wrap("email.google_workspace_mx", category, runGoogleWorkspaceMX))
}
