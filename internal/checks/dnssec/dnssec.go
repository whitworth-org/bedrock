// Package dnssec implements DNSSEC chain, algorithm, and NSEC3 checks.
//
// Backed by RFC 4033/4034/4035 (core), 4509 (SHA-256 DS), 5011 (auto trust
// anchors), 5155 (NSEC3), 6605 (ECDSA), 6781 (operational), 8624 (algorithm
// requirements), 3658 (delegation signer).
package dnssec

import (
	"context"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
)

func init() { registry.Register(stub{}) }

type stub struct{}

func (stub) ID() string       { return "dnssec.stub" }
func (stub) Category() string { return "DNSSEC" }
func (stub) Run(_ context.Context, env *probe.Env) []report.Result {
	return []report.Result{{
		ID:       "dnssec.stub",
		Category: "DNSSEC",
		Title:    "DNSSEC category placeholder — no checks implemented yet",
		Status:   report.Info,
		Evidence: "target=" + env.Target,
		RFCRefs:  []string{"RFC 4033", "RFC 4034", "RFC 4035"},
	}}
}
