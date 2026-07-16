package email

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
)

// The DKIM selector sweep is shared state: the DKIM selector check, the
// DKIM2-readiness check, and the DMARC reject-readiness check all need to
// know which selectors publish keys. Probing ~44 selectors is the most
// expensive DNS work in the Email category, so the sweep runs exactly once
// per scan and is shared via probe.CacheKeyDKIM.

// DKIMProbe outcomes.
const (
	dkimFound     = "found"     // record present and parsed
	dkimMissing   = "missing"   // NXDOMAIN or no TXT at the selector
	dkimMalformed = "malformed" // record present but failed to parse
	dkimError     = "error"     // lookup failed (timeout, SERVFAIL, ...)
)

// DKIMProbe is the outcome of probing one selector.
type DKIMProbe struct {
	Selector string
	Name     string // "<selector>._domainkey.<target>"
	Outcome  string // one of the dkim* constants above
	Raw      string // the TXT string examined (found/malformed)
	Key      *DKIMKey
	Detail   string // lookup/parse error text
}

// DKIMSweep is the cached result of probing the full selector list.
// Exported (like DMARC) because it crosses check boundaries via
// probe.CacheKeyDKIM.
type DKIMSweep struct {
	Selectors []string // the deterministic probe list
	Probes    []DKIMProbe
}

// Found returns the probes that yielded a parsed key, in sweep order.
func (s *DKIMSweep) Found() []DKIMProbe {
	var out []DKIMProbe
	for _, p := range s.Probes {
		if p.Outcome == dkimFound {
			out = append(out, p)
		}
	}
	return out
}

var (
	dkimSweepOnceMu sync.Mutex
	dkimSweepOnces  = map[*probe.Env]*sync.Once{}
)

// dkimSweep probes the selector list for env.Target exactly once per scan
// and returns the cached result. The first caller's ctx drives the sweep;
// each query carries its own env timeout.
func dkimSweep(ctx context.Context, env *probe.Env) *DKIMSweep {
	if env == nil {
		return nil
	}
	if s := cachedSweep(env); s != nil {
		return s
	}
	onceFor(&dkimSweepOnceMu, dkimSweepOnces, env).Do(func() {
		env.CachePut(probe.CacheKeyDKIM, runDKIMSweep(ctx, env))
	})
	return cachedSweep(env)
}

func cachedSweep(env *probe.Env) *DKIMSweep {
	v, ok := env.CacheGet(probe.CacheKeyDKIM)
	if !ok {
		return nil
	}
	s, ok := v.(*DKIMSweep)
	if !ok {
		return nil
	}
	return s
}

func runDKIMSweep(ctx context.Context, env *probe.Env) *DKIMSweep {
	selectors := selectorList(env)
	sweep := &DKIMSweep{Selectors: selectors}
	for _, sel := range selectors {
		// Mid-flight ctx gate so a cancelled scan stops walking the
		// selector list instead of issuing one TXT lookup per selector.
		if ctx.Err() != nil {
			break
		}
		sweep.Probes = append(sweep.Probes, probeDKIMSelector(ctx, env, sel))
	}
	return sweep
}

func probeDKIMSelector(ctx context.Context, env *probe.Env, selector string) DKIMProbe {
	p := DKIMProbe{
		Selector: selector,
		Name:     selector + "._domainkey." + env.Target,
	}
	lctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	txt, err := env.DNS.LookupTXT(lctx, p.Name)
	if errors.Is(err, probe.ErrNXDOMAIN) {
		p.Outcome = dkimMissing
		return p
	}
	if err != nil {
		p.Outcome = dkimError
		p.Detail = err.Error()
		return p
	}
	if len(txt) == 0 {
		p.Outcome = dkimMissing
		return p
	}
	p.Raw = pickDKIMTXT(txt)
	key, perr := ParseDKIM(p.Raw)
	if perr != nil {
		p.Outcome = dkimMalformed
		p.Detail = perr.Error()
		return p
	}
	p.Outcome = dkimFound
	p.Key = key
	return p
}

// pickDKIMTXT picks the TXT string that looks DKIM-shaped (concatenation per
// RFC 6376 §3.6.2.2 is already done by LookupTXT).
func pickDKIMTXT(txt []string) string {
	for _, t := range txt {
		lower := strings.ToLower(t)
		if strings.Contains(t, "p=") ||
			strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "v=dkim2") {
			return t
		}
	}
	return txt[0]
}
