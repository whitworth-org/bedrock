// Package bimi implements BIMI checks aligned with Gmail's vendor
// requirements. There is no IETF RFC for BIMI; the spec is the BIMI Group
// draft (https://bimigroup.org/) and Gmail's BIMI configuration guide.
//
// The registry runs these checks in parallel and in no particular order, so
// no check reads what another check left behind. Each one calls the lazy
// producers it depends on instead: ensureRecord (the default._bimi TXT
// record), ensureSVG (the l= logo), ensureVMC (the a= certificate) and
// ensureVMCLeaf (the VMC leaf, once its chain verified). Each producer runs
// at most once per scan through probe.Shared, in whichever check asks first,
// so a check run on its own reports what it reports in a full scan.
package bimi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
	"github.com/whitworth-org/bedrock/internal/version"
)

// BIMI lives under the broader Email security category in user-facing
// output rather than as a top-level category of its own.
const category = "Email"

func init() {
	registry.Register(recordCheck{})
	registry.Register(svgFetchCheck{})
	registry.Register(svgProfileCheck{})
	registry.Register(svgAspectCheck{})
	registry.Register(vmcFetchCheck{})
	registry.Register(vmcChainCheck{})
	registry.Register(vmcLogotypeCheck{})
	registry.Register(gmailGateCheck{})
}

// outcome is what a lazy producer made: the result of the check it backs
// and the product the other checks use, which is the parsed record, or the
// fetched body or verified leaf only when that result is PASS.
type outcome[T any] struct {
	result  report.Result
	product T
}

// value returns o's product, or the zero T when o is nil: probe.Shared
// gives nil to every later caller after a producer panicked.
func (o *outcome[T]) value() T {
	if o == nil {
		var zero T
		return zero
	}
	return o.product
}

// results returns o's result. When o is nil (see value) it returns base as
// Info, since the panic was reported against the check that ran the
// producer.
func (o *outcome[T]) results(base report.Result) []report.Result {
	if o == nil {
		base.Status = report.Info
		base.Evidence = "check did not complete; see registry.panic"
		return []report.Result{base}
	}
	return []report.Result{o.result}
}

// getVerified GETs rawURL, an https URL from the BIMI record. DoStrict
// verifies the TLS chain of every hop and follows at most 8 redirects, each
// to https. Anything but a 200 with a complete, non-empty body is an error.
func getVerified(ctx context.Context, env *probe.Env, rawURL string) (*probe.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := env.HTTP.DoStrict(req)
	switch {
	case err != nil:
		return nil, err
	case resp.Status != http.StatusOK:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	case len(resp.Body) == 0:
		return nil, errors.New("empty body")
	case resp.Truncated:
		return nil, errors.New("body exceeds the 1 MiB fetch cap")
	}
	return resp, nil
}

// fetchFailed grades err, returned by getVerified for rawURL under ctx.
// A probe that could not complete is Inconclusive; anything else, such as a
// certificate failure, a refused connection, NXDOMAIN or a bad response, is
// the publisher's answer, so it returns fail with the error as evidence.
func fetchFailed(ctx context.Context, fail report.Result, rawURL string, err error) report.Result {
	if checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(fail, err)
	}
	fail.Evidence = "GET " + rawURL + " failed: " + err.Error()
	return fail
}
