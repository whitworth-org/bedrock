// Package bimi implements BIMI checks aligned with Gmail's requirements.
//
// BIMI has no IETF RFC; the spec is the BIMI Group draft plus Gmail's
// vendor requirements. v1 covers:
//   - default._bimi TXT record presence and structure (v=BIMI1; l=...; a=...)
//   - DMARC enforcement gate: p=quarantine|reject, pct=100, adkim=s, aspf=s
//   - SVG fetch + Tiny PS conformance subset
//   - VMC/CMC PEM fetch + chain validation + logo hash match
package bimi

import (
	"context"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
)

func init() { registry.Register(stub{}) }

type stub struct{}

func (stub) ID() string       { return "bimi.stub" }
func (stub) Category() string { return "BIMI" }
func (stub) Run(_ context.Context, env *probe.Env) []report.Result {
	return []report.Result{{
		ID:       "bimi.stub",
		Category: "BIMI",
		Title:    "BIMI category placeholder — no checks implemented yet",
		Status:   report.Info,
		Evidence: "target=" + env.Target,
		RFCRefs:  []string{"BIMI Group draft", "Gmail BIMI requirements"},
	}}
}
