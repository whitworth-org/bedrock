// Package email implements SMTP-transport and email-authentication checks.
//
// SMTP/MIME: RFC 5321, 5322, 1652, 1869, 1870, 2045-2049, 2047, 2920, 3207,
// 3461, 3464, 4954.
// Authentication: RFC 7208 (SPF), 6376 (DKIM), 7489 (DMARC).
// Transport security: RFC 8461 (MTA-STS), 8460 (TLS-RPT), 7672 (DANE),
// 7505 (Null MX).
//
// The DMARC check publishes its parsed record to env.CachePut so the BIMI
// Gmail-gate check can consume it without re-querying the resolver.
package email

import (
	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/registry"
)

const category = "Email"

func init() {
	registry.Register(checkutil.Wrap("email.spf.record", category, runSPF))
	registry.Register(checkutil.Wrap("email.dkim", category, runDKIM))
	registry.Register(checkutil.Wrap("email.dmarc.record", category, runDMARC))
	registry.Register(checkutil.Wrap("email.mtasts.txt", category, runMTASTSTXT))
	registry.Register(checkutil.Wrap("email.mtasts.policy", category, runMTASTSPolicy))
	registry.Register(checkutil.Wrap("email.tlsrpt.record", category, runTLSRPT))
	registry.Register(checkutil.Wrap("email.dane", category, runDANE))
	registry.Register(checkutil.Wrap("email.nullmx", category, runNullMX))
	registry.Register(checkutil.Wrap("email.smtp.starttls", category, runSTARTTLS))
	registry.Register(checkutil.Wrap("email.google_workspace_mx", category, runGoogleWorkspaceMX))
}
