// Package dns implements DNS zone and nameserver checks.
//
// Backed by RFC 1034/1035 (core), 1912 (operational), 2181 (clarifications),
// 2308 (negative caching), 2782 (SRV), 3596 (AAAA), 3597 (unknown RRs),
// 5936 (AXFR). DNSSEC is in package dnssec.
package dns

import (
	"context"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"
)

func init() { registry.Register(stub{}) }

// stub is a placeholder so the category appears in output until real
// checks land. Returns Info, never Fail.
type stub struct{}

func (stub) ID() string       { return "dns.stub" }
func (stub) Category() string { return "DNS" }
func (stub) Run(_ context.Context, env *probe.Env) []report.Result {
	return []report.Result{{
		ID:       "dns.stub",
		Category: "DNS",
		Title:    "DNS category placeholder — no checks implemented yet",
		Status:   report.Info,
		Evidence: "target=" + env.Target,
		RFCRefs:  []string{"RFC 1034", "RFC 1035"},
	}}
}
