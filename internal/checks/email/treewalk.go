package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// This file implements the RFC 9989 DNS tree walk — the DMARCbis replacement
// for the Public Suffix List. Discovery climbs from the Author Domain toward
// the root (at most maxWalkQueries lookups), collects every v=DMARC1 record
// on the path, then derives the Organizational Domain from psd= declarations
// published by the domain owners themselves rather than from a static list.

// maxWalkQueries caps the tree walk at eight DNS queries (RFC 9989): names
// of up to seven labels were observed in real use, so the cap clears actual
// traffic while bounding the work for pathologically deep names.
const maxWalkQueries = 8

// DMARCWalkStep outcomes.
const (
	walkFound     = "found"     // exactly one well-formed v=DMARC1 record
	walkNXDomain  = "nxdomain"  // name does not exist
	walkNoData    = "nodata"    // name exists, no v=DMARC1 TXT
	walkMultiple  = "multiple"  // more than one v=DMARC1 record (invalid)
	walkMalformed = "malformed" // single record failed to parse
	walkError     = "error"     // lookup failed (timeout, SERVFAIL, ...)
)

// DMARCWalkStep is one query of the RFC 9989 tree walk.
type DMARCWalkStep struct {
	Domain    string // policy domain queried, e.g. "example.com"
	QueryName string // "_dmarc.example.com"
	Outcome   string // one of the walk* constants above
	Record    *DMARC // non-nil only when Outcome == walkFound
	Detail    string // lookup/parse error text or record count
}

// DMARCWalk is the cached outcome of one tree walk for a scan target.
// Exported (like DMARC) because it crosses check boundaries via
// probe.CacheKeyDMARCWalk.
type DMARCWalk struct {
	Author       string          // the Author Domain the walk started from
	Steps        []DMARCWalkStep // in query order, longest name first
	OrgDomain    string          // Organizational Domain; "" when no records found
	OrgRule      string          // "psd=n" | "psd=y-one-below" | "fewest-labels" | ""
	PolicyDomain string          // domain whose record supplies the effective policy
	Policy       *DMARC          // effective policy record; nil when none applies
	Queries      int             // DNS queries actually issued

	// stopped says why the walk ended before its last query: the scan's
	// context ended first.
	stopped error
}

// errWalkPanicked is why a consumer of the shared walk has none: the check
// whose goroutine ran the walk panicked, and the registry reports that.
var errWalkPanicked = errors.New("DMARC tree walk: no result, because the check that ran it " +
	"panicked; see its registry.panic result")

// dmarcWalkNames returns the _dmarc-prefixed query names for the RFC 9989
// tree walk, longest first. Names of up to eight labels shed one label per
// step; longer names jump straight to their last seven labels after the
// initial query so the total never exceeds maxWalkQueries.
func dmarcWalkNames(domain string) []string {
	if domain == "" {
		return nil
	}
	labels := strings.Split(domain, ".")
	n := len(labels)
	names := make([]string, 0, min(n, maxWalkQueries))
	names = append(names, "_dmarc."+domain)
	start := n - 1
	if n > maxWalkQueries {
		start = maxWalkQueries - 1
	}
	for k := start; k >= 1; k-- {
		names = append(names, "_dmarc."+strings.Join(labels[n-k:], "."))
	}
	return names
}

// dmarcTXTRecords filters TXT strings down to those that begin with the
// v=DMARC1 version tag (the same filter runDMARC has always applied).
func dmarcTXTRecords(txt []string) []string {
	var records []string
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			records = append(records, t)
		}
	}
	return records
}

// walkStep performs and classifies a single tree-walk query.
func walkStep(ctx context.Context, env *probe.Env, qname string) DMARCWalkStep {
	step := DMARCWalkStep{
		Domain:    strings.TrimPrefix(qname, "_dmarc."),
		QueryName: qname,
	}
	lctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	txt, err := env.DNS.LookupTXT(lctx, qname)
	if errors.Is(err, probe.ErrNXDOMAIN) {
		step.Outcome = walkNXDomain
		return step
	}
	if err != nil {
		step.Outcome = walkError
		step.Detail = err.Error()
		return step
	}
	records := dmarcTXTRecords(txt)
	switch len(records) {
	case 0:
		step.Outcome = walkNoData
	case 1:
		parsed, perr := ParseDMARC(records[0])
		if perr != nil {
			step.Outcome = walkMalformed
			step.Detail = perr.Error()
			return step
		}
		step.Outcome = walkFound
		step.Record = parsed
	default:
		step.Outcome = walkMultiple
		step.Detail = fmt.Sprintf("%d", len(records))
	}
	return step
}

// dmarcTreeWalk executes the full walk for env.Target and derives the
// Organizational Domain and effective policy record.
func dmarcTreeWalk(ctx context.Context, env *probe.Env) *DMARCWalk {
	walk := &DMARCWalk{Author: env.Target}
	names := dmarcWalkNames(env.Target)
	for _, qname := range names {
		if err := ctx.Err(); err != nil {
			walk.stopped = fmt.Errorf("DMARC tree walk stopped after %d of %d queries: %w",
				len(walk.Steps), len(names), err)
			break
		}
		walk.Steps = append(walk.Steps, walkStep(ctx, env, qname))
	}
	walk.Queries = len(walk.Steps)
	walk.OrgDomain, walk.OrgRule = selectOrgDomain(env.Target, walk.Steps)
	walk.PolicyDomain, walk.Policy = selectPolicyRecord(env.Target, walk.OrgDomain, walk.Steps)
	return walk
}

// foundSteps returns the steps that yielded a well-formed record, preserving
// walk order (longest name first).
func foundSteps(steps []DMARCWalkStep) []DMARCWalkStep {
	var out []DMARCWalkStep
	for _, s := range steps {
		if s.Outcome == walkFound {
			out = append(out, s)
		}
	}
	return out
}

// selectOrgDomain applies the RFC 9989 Organizational Domain rules over the
// records found on the walk, longest name to shortest:
//
//  1. A record declaring psd=n marks its own domain as the Organizational
//     Domain.
//  2. A record declaring psd=y (other than where the walk began) marks the
//     domain one label below it, along the Author Domain's path.
//  3. Otherwise the found record with the fewest labels wins.
func selectOrgDomain(author string, steps []DMARCWalkStep) (string, string) {
	found := foundSteps(steps)
	if len(found) == 0 {
		return "", ""
	}
	for _, s := range found {
		if s.Record.PSD == "n" {
			return s.Domain, "psd=n"
		}
		if s.Record.PSD == "y" && s.Domain != author {
			return childTowards(author, s.Domain), "psd=y-one-below"
		}
	}
	return found[len(found)-1].Domain, "fewest-labels"
}

// childTowards returns the name one label below parent on the path from
// author up to parent (RFC 9989 rule 2: a psd=y record marks the domain one
// label below it as the Organizational Domain).
func childTowards(author, parent string) string {
	al := strings.Split(author, ".")
	pn := len(strings.Split(parent, "."))
	if len(al) <= pn {
		return author
	}
	return strings.Join(al[len(al)-pn-1:], ".")
}

// selectPolicyRecord picks the record whose policy applies to the author:
// the Author Domain's own record, else the Organizational Domain's, else —
// when only a public-suffix record exists on the path — the fewest-labels
// record, which supplies the PSD's protective default (RFC 9989).
func selectPolicyRecord(author, org string, steps []DMARCWalkStep) (string, *DMARC) {
	found := foundSteps(steps)
	for _, want := range []string{author, org} {
		for _, s := range found {
			if s.Domain == want {
				return s.Domain, s.Record
			}
		}
	}
	if len(found) > 0 {
		last := found[len(found)-1]
		return last.Domain, last.Record
	}
	return "", nil
}

// EnsureDMARCWalk runs the tree walk for env.Target at most once per scan
// and returns it. It also publishes the effective policy record under
// probe.CacheKeyDMARC for the consumers that read only that record (np, the
// BIMI Gmail gate). The first caller's ctx drives the walk; each query
// carries its own env timeout. The result is nil only when env is nil or
// the walk panicked.
func EnsureDMARCWalk(ctx context.Context, env *probe.Env) *DMARCWalk {
	if env == nil {
		return nil
	}
	walk := probe.Shared(env, probe.CacheKeyDMARCWalk, func() *DMARCWalk {
		return dmarcTreeWalk(ctx, env)
	})
	// Publish after Shared, from every caller: np reads CacheKeyDMARC and then
	// the walk, and a caller that finds the walk cached must not return before
	// the record is published.
	if walk != nil && walk.Policy != nil {
		env.CachePut(probe.CacheKeyDMARC, walk.Policy)
	}
	return walk
}

// EffectivePolicy returns the DMARC policy that applies to the Author
// Domain: p= of its own record, or sp= of a record inherited from an
// ancestor (RFC 9989 §4.10.1). It returns "" when no record applies.
func (w *DMARCWalk) EffectivePolicy() string {
	if w == nil || w.Policy == nil {
		return ""
	}
	if w.inherited() {
		return w.Policy.SubdomainPolicy
	}
	return w.Policy.Policy
}

// inherited reports whether the policy record belongs to an ancestor of the
// Author Domain rather than to the Author Domain itself.
func (w *DMARCWalk) inherited() bool {
	return w.PolicyDomain != w.Author
}

// Incomplete returns why the walk's outcome is uncertain, or nil: there is
// no walk because the check that ran it panicked, the walk stopped early
// because the scan was interrupted, it issued no queries, or one of them
// failed (timeout, SERVFAIL, ...). A failed or missing query can hide a
// record, so a missing record is not proven missing, and the Organizational
// Domain, or the record that applies when the Author Domain has none of its
// own, may differ from the one the walk selected.
func (w *DMARCWalk) Incomplete() error {
	switch {
	case w == nil:
		return errWalkPanicked
	case w.stopped != nil:
		return w.stopped
	case len(w.Steps) == 0:
		return errors.New("DMARC tree walk issued no queries")
	}
	for _, s := range w.Steps {
		if s.Outcome == walkError {
			return fmt.Errorf("TXT lookup for %s: %s", s.QueryName, s.Detail)
		}
	}
	return nil
}

// noPolicyResult is res for a check that grades the DMARC record that
// applies, when walk found none: N/A with evidence, or inconclusive when the
// walk is incomplete and so may have missed the record.
func noPolicyResult(walk *DMARCWalk, res report.Result, evidence string) report.Result {
	if err := walk.Incomplete(); err != nil {
		return checkutil.Inconclusive(res, err)
	}
	res.Status = report.NotApplicable
	res.Evidence = evidence
	return res
}

func cachedWalk(env *probe.Env) *DMARCWalk {
	v, ok := env.CacheGet(probe.CacheKeyDMARCWalk)
	if !ok {
		return nil
	}
	w, ok := v.(*DMARCWalk)
	if !ok {
		return nil
	}
	return w
}
