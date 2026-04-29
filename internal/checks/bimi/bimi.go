// Package bimi implements BIMI checks aligned with Gmail's vendor
// requirements. There is no IETF RFC for BIMI; the spec is the BIMI Group
// draft (https://bimigroup.org/) and Gmail's BIMI configuration guide.
//
// Cross-check data flow: recordCheck publishes the parsed TXT record to the
// shared cache that the SVG and VMC checks consume. Under the parallel
// registry the BIMI checks no longer execute in registration order, so we
// wrap each downstream check with bimiPrelude which calls ensureRecord
// (a sync.Once-protected TXT lookup) before delegating to the original
// Run. svgFetch's bytes / digest are best-effort: vmc gracefully degrades
// when those cache entries are missing.
package bimi

import (
	"context"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// BIMI lives under the broader Email security category in user-facing
// output rather than as a top-level category of its own.
const category = "Email"

// prelude wraps an existing Check so that calls to Run first ensure the
// shared BIMI record cache is populated. This protects the SVG / VMC / Gmail
// gates against a parallel registry where recordCheck might not have run
// yet. The prelude does no work for recordCheck itself (ensureRecord is
// idempotent and the record check exposes the same lookup logic).
type prelude struct {
	inner registry.Check
}

func (p prelude) ID() string       { return p.inner.ID() }
func (p prelude) Category() string { return p.inner.Category() }
func (p prelude) Run(ctx context.Context, env *probe.Env) []report.Result {
	ensureRecord(ctx, env)
	return p.inner.Run(ctx, env)
}

func init() {
	registry.Register(recordCheck{})
	registry.Register(prelude{svgFetchCheck{}})
	registry.Register(prelude{svgProfileCheck{}})
	registry.Register(prelude{svgAspectCheck{}})
	registry.Register(prelude{vmcFetchCheck{}})
	registry.Register(prelude{vmcChainCheck{}})
	registry.Register(prelude{vmcLogotypeCheck{}})
	registry.Register(prelude{gmailGateCheck{}})
}
