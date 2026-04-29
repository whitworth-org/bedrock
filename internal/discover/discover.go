// Package discover implements passive subdomain enumeration and a subset of
// WWW-tier checks (TLS handshake reachability, certificate chain validation,
// and SAN match) against each discovered host.
//
// Enumeration is gated behind env.Subdomains (wired to the --subdomains
// flag in main). When disabled the check returns a single NotApplicable
// result. When enabled, four key-free passive sources are queried in
// parallel; results are deduplicated, filtered to in-scope hosts (apex or
// subdomain of the target), and — when active probing is permitted —
// each host is dialed on :443 with a strict TLS verifier.
//
// Discovered hosts are cached under probe.CacheKeySubdomains so any
// downstream check can reuse the list without re-enumerating.
package discover

import (
	"context"
	"fmt"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// Category is the report category under which all discovery results render.
const category = "Subdomain"

type discoverCheck struct{}

func (discoverCheck) ID() string       { return "subdomain.discover" }
func (discoverCheck) Category() string { return category }

// Run gates on env.Subdomains, runs passive enumeration, caches the list,
// and (when env.Active) probes each host with a minimal TLS reachability
// + cert validation check.
func (discoverCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Subdomains {
		return []report.Result{{
			ID:       "subdomain.discover",
			Category: category,
			Title:    "Subdomain enumeration",
			Status:   report.Info,
			Evidence: "disabled (--subdomains off)",
		}}
	}

	hosts, notes := enumerate(ctx, env, env.Target, env.Timeout)

	out := append([]report.Result{}, notes...)
	out = append(out, report.Result{
		ID:       "subdomain.discover",
		Category: category,
		Title:    "Subdomain enumeration",
		Status:   report.Info,
		Evidence: fmt.Sprintf("discovered %d subdomains via passive sources", len(hosts)),
	})

	if env.Active {
		out = append(out, probeHosts(ctx, env, hosts)...)
		out = append(out, fingerprintHosts(ctx, env, hosts)...)
	}

	env.CachePut(probe.CacheKeySubdomains, hosts)
	return out
}

func init() { registry.Register(discoverCheck{}) }
