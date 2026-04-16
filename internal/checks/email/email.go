// Package email implements SMTP-transport and email-authentication checks.
//
// SMTP/MIME: RFC 5321, 5322, 1652, 1869, 1870, 2045-2049, 2047, 2920, 3207,
// 3461, 3464, 4954.
// Authentication: RFC 7208 (SPF), 6376 (DKIM), 7489 (DMARC).
// Transport security: RFC 8461 (MTA-STS), 8460 (TLS-RPT), 7672 (DANE), 7505 (Null MX).
package email

import (
	"context"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
)

func init() { registry.Register(stub{}) }

type stub struct{}

func (stub) ID() string       { return "email.stub" }
func (stub) Category() string { return "Email" }
func (stub) Run(_ context.Context, env *probe.Env) []report.Result {
	return []report.Result{{
		ID:       "email.stub",
		Category: "Email",
		Title:    "Email category placeholder — no checks implemented yet",
		Status:   report.Info,
		Evidence: "target=" + env.Target,
		RFCRefs:  []string{"RFC 5321", "RFC 7208", "RFC 7489"},
	}}
}
