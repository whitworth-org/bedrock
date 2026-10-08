package email

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
)

// The DKIM selector sweep is shared state: the DKIM selector check, the
// DKIM2-readiness check, and the DMARC reject-readiness check all need to
// know which selectors publish keys. Probing ~44 selectors is the most
// expensive DNS work in the Email category, so the sweep runs exactly once
// per scan, dkimSweepConcurrency lookups at a time, and is shared via
// probe.CacheKeyDKIM.

// dkimSweepConcurrency caps the selector lookups the sweep keeps in flight.
const dkimSweepConcurrency = 8

// DKIMProbe outcomes.
const (
	dkimFound     = "found"     // record present and parsed
	dkimMissing   = "missing"   // NXDOMAIN or no DKIM key record at the selector
	dkimMalformed = "malformed" // record present but failed to parse
	dkimError     = "error"     // lookup failed (timeout, SERVFAIL, ...)
)

// DKIMProbe is the outcome of probing one selector.
type DKIMProbe struct {
	Selector string
	Name     string // "<selector>._domainkey.<target>"
	Outcome  string // one of the dkim* constants above
	Raw      string // the key record examined (found/malformed)
	Records  int    // TXT records at Name (found/malformed)
	Key      *DKIMKey
	Detail   string // lookup/parse error text
	// FromWildcard is set when the selector got the same TXT records as a
	// random selector (see DKIMSweep.Wildcard): the record is the
	// wildcard's, not one published for this selector.
	FromWildcard bool
}

// DKIMSweep is the cached result of probing the full selector list.
// Exported (like DMARC) because it crosses check boundaries via
// probe.CacheKeyDKIM.
type DKIMSweep struct {
	Selectors []string    // the deterministic probe list
	Probes    []DKIMProbe // one per selector, in Selectors order
	// Wildcard is the key record a random selector got, so it answers every
	// selector without a record of its own. Its Selector is "*" and its Name
	// "*._domainkey.<target>"; it is nil when that selector got no DKIM
	// record. When the random selectors' lookups failed, Wildcard is the
	// record that most answered selectors share, if any (see sharedRecord),
	// and WildcardErr holds the lookup error.
	Wildcard    *DKIMProbe
	WildcardErr string
}

// Found returns the probes that yielded a parsed key of their own, not the
// wildcard's, in sweep order.
func (s *DKIMSweep) Found() []DKIMProbe {
	var out []DKIMProbe
	for _, p := range s.Probes {
		if p.Outcome == dkimFound && !p.FromWildcard {
			out = append(out, p)
		}
	}
	return out
}

// noKeyResultID names the email.dkim result that explains an empty Found
// when no selector published a record: the wildcard's, if there is one.
func (s *DKIMSweep) noKeyResultID() string {
	if s.Wildcard != nil {
		return "email.dkim.wildcard"
	}
	return "email.dkim.selector.none"
}

// dkimSweep probes the selector list for env.Target at most once per scan
// and returns the cached result. The first caller's ctx drives the sweep;
// each query carries its own env timeout.
func dkimSweep(ctx context.Context, env *probe.Env) *DKIMSweep {
	if env == nil {
		return nil
	}
	return probe.Shared(env, probe.CacheKeyDKIM, func() *DKIMSweep {
		return runDKIMSweep(ctx, env)
	})
}

// runDKIMSweep probes every selector in the list and, beside them, a random
// selector, which only a wildcard answers, dkimSweepConcurrency lookups at a
// time. It then marks the selectors that got the wildcard's records.
func runDKIMSweep(ctx context.Context, env *probe.Env) *DKIMSweep {
	selectors := selectorList(env)
	sweep := &DKIMSweep{Selectors: selectors, Probes: make([]DKIMProbe, len(selectors))}
	txts := make([][]string, len(selectors))
	var wild DKIMProbe
	var wildTXT []string
	checkutil.ForEach(len(selectors)+1, dkimSweepConcurrency, func(i int) {
		// Call 0 starts early, so even a retried random lookup overlaps the list.
		if i == 0 {
			wild, wildTXT = probeRandomSelector(ctx, env)
			return
		}
		sweep.Probes[i-1], txts[i-1] = probeDKIMSelector(ctx, env, selectors[i-1])
	})
	if wild.Outcome == dkimError {
		if i := sharedRecord(sweep.Probes, txts); i >= 0 {
			sweep.WildcardErr = wild.Detail
			wild, wildTXT = sweep.Probes[i], txts[i]
		}
	}
	if wild.Outcome == dkimFound || wild.Outcome == dkimMalformed {
		// Report the wildcard by its owner name, never by the random label
		// or the selector that stood in for it.
		wild.Selector, wild.Name = "*", "*._domainkey."+env.Target
		sweep.Wildcard = &wild
		for i := range sweep.Probes {
			sweep.Probes[i].FromWildcard = sameTXT(txts[i], wildTXT)
		}
	}
	return sweep
}

// probeRandomSelector probes a random selector, and another once if that
// lookup fails, so that one lost query does not hide a wildcard.
func probeRandomSelector(ctx context.Context, env *probe.Env) (DKIMProbe, []string) {
	p, txt := probeDKIMSelector(ctx, env, strings.ToLower(rand.Text()))
	if p.Outcome == dkimError {
		p, txt = probeDKIMSelector(ctx, env, strings.ToLower(rand.Text()))
	}
	return p, txt
}

// sharedRecord returns the index of the first probe whose key records at
// least two selectors, and more than half of those whose lookup was
// answered, got; or -1. Only a wildcard explains a record that most
// selectors share, so it stands in for the random selector's lookup when
// that failed.
func sharedRecord(probes []DKIMProbe, txts [][]string) int {
	answered := 0
	for _, p := range probes {
		if p.Outcome != dkimError {
			answered++
		}
	}
	for i, p := range probes {
		if p.Outcome != dkimFound && p.Outcome != dkimMalformed {
			continue
		}
		if n := countTXT(txts, txts[i]); n >= 2 && 2*n > answered {
			return i
		}
	}
	return -1
}

// countTXT returns how many of sets hold the same TXT strings as set.
func countTXT(sets [][]string, set []string) int {
	n := 0
	for _, s := range sets {
		if sameTXT(s, set) {
			n++
		}
	}
	return n
}

// probeDKIMSelector looks up the selector's key record and returns the
// outcome with the TXT strings the lookup returned.
func probeDKIMSelector(ctx context.Context, env *probe.Env, selector string) (DKIMProbe, []string) {
	p := DKIMProbe{
		Selector: selector,
		Name:     selector + "._domainkey." + env.Target,
	}
	// A cancelled scan stops sending lookups for the selectors still queued.
	if err := ctx.Err(); err != nil {
		p.Outcome, p.Detail = dkimError, err.Error()
		return p, nil
	}
	lctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	txt, err := env.DNS.LookupTXT(lctx, p.Name)
	switch {
	case errors.Is(err, probe.ErrNXDOMAIN):
		p.Outcome = dkimMissing
	case err != nil:
		p.Outcome, p.Detail = dkimError, err.Error()
	default:
		classifyDKIM(&p, txt)
	}
	return p, txt
}

// classifyDKIM sets p's outcome from the TXT records at p.Name (LookupTXT
// has already joined each record's strings, RFC 6376 §3.6.2.2). Records
// that are not DKIM key records are ignored. Of several key records, the
// first in sorted order is examined, so the verdict does not follow the
// order in which the resolver returns them.
func classifyDKIM(p *DKIMProbe, txt []string) {
	var records []string
	for _, t := range txt {
		if isDKIMRecord(t) {
			records = append(records, t)
		}
	}
	if len(records) == 0 {
		p.Outcome = dkimMissing
		return
	}
	slices.Sort(records)
	p.Raw, p.Records = records[0], len(txt)
	key, err := ParseDKIM(p.Raw)
	if err != nil {
		p.Outcome, p.Detail = dkimMalformed, err.Error()
		return
	}
	p.Outcome, p.Key = dkimFound, key
}

// isDKIMRecord reports whether the TXT string t is a DKIM key record rather
// than other TXT data at the same name, such as an SPF record a wildcard
// returns. RFC 6376 §3.6.1 discards a record whose first tag is v= with any
// value but DKIM1 (or DKIM2, draft-ietf-dkim-dkim2-spec); a record without a
// leading v= tag is a key record when it has a tag named p.
func isDKIMRecord(t string) bool {
	first, _, _ := strings.Cut(t, ";")
	if name, value, ok := strings.Cut(first, "="); ok && strings.TrimSpace(name) == "v" {
		_, err := dkimVersion(strings.TrimSpace(value))
		return err == nil
	}
	for _, tag := range strings.Split(t, ";") {
		if name, _, ok := strings.Cut(tag, "="); ok && strings.TrimSpace(name) == "p" {
			return true
		}
	}
	return false
}

// sameTXT reports whether a and b hold the same TXT strings in any order.
func sameTXT(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
