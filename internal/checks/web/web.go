// Package web implements WWW-tier checks: TLS posture, certificates,
// security headers, cookies, mixed content, and CAA.
//
// TLS posture is scored against the Mozilla Server-Side TLS profiles, loaded
// from the canonical machine-readable config:
//   https://github.com/mozilla/server-side-tls/blob/gh-pages/json/server-side-tls-conf-5.0.json
// (a snapshot lives at testdata/mozilla-server-side-tls-5.0.json and is
// embedded into the binary by mozilla_tls.go).
//
// v5.0 ships three profiles: Modern, Intermediate, Old (Legacy). A
// Post-Quantum profile is forward-looking — when Mozilla publishes one,
// refresh the JSON and bump expectedMozillaVersion. The profile a server
// matches is reported as the TLS check's evidence; failing to meet at least
// Intermediate is a Fail.
//
// Specs: RFC 7525 (BCP 195), 6698 (DANE/TLSA), 7817 (server identity for
// email TLS), 8659 (CAA), plus W3C/WHATWG/browser specs for HSTS, CSP,
// cookie attributes, etc.
package web

import (
	"context"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
)

func init() { registry.Register(stub{}) }

type stub struct{}

func (stub) ID() string       { return "web.stub" }
func (stub) Category() string { return "WWW" }
func (stub) Run(_ context.Context, env *probe.Env) []report.Result {
	return []report.Result{{
		ID:       "web.stub",
		Category: "WWW",
		Title:    "WWW category placeholder — no checks implemented yet (incl. Mozilla TLS profile scoring)",
		Status:   report.Info,
		Evidence: "target=" + env.Target,
		RFCRefs:  []string{"RFC 7525", "RFC 8659"},
	}}
}
