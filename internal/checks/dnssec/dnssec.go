// Package dnssec implements DNSSEC chain, algorithm, and NSEC3 checks, plus
// the root KSK sentinel test of the resolvers bedrock queries.
//
// Backed by RFC 4033/4034/4035 (core), 4509 (SHA-256 DS), 5011 (auto trust
// anchors), 5155 (NSEC3), 6605 (ECDSA), 6781 (operational), 8509 (root key
// trust anchor sentinel), 8624 (algorithm requirements), 3658 (delegation
// signer).
package dnssec

import (
	"context"
	"fmt"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
)

// init registers the DNSSEC checks. The chain check, algorithm check, and
// NSEC check all share a per-run cache populated by ensureChainData; the
// helper uses probe.Shared so the data is fetched exactly once regardless
// of which check happens to run first under the parallel registry.
func init() {
	registry.Register(checkutil.Wrap("dnssec.chain", category, runChain))
	registry.Register(checkutil.Wrap("dnssec.algorithms", category, runAlgorithms))
	registry.Register(checkutil.Wrap("dnssec.nsec", category, runNSEC))
	registry.Register(checkutil.Wrap(sentinelID, category, runSentinel))
}

const category = "DNSSEC"

// cacheKeyChain caches the *chainData the dnssec checks share (private to
// this package).
const cacheKeyChain = "dnssec.chain.data"

// chainData holds the DS and DNSKEY answers that the chain, algorithms, nsec
// and cds checks share. It is computed once per run via probe.Shared.
type chainData struct {
	keyResp *mdns.Msg
	dsErr   error
	keyErr  error
	dsSet   []*mdns.DS
	keySet  []*mdns.DNSKEY
	signed  bool // both DS and DNSKEY published
}

// ensureChainData fetches the DS and DNSKEY RRsets for env.Target at most
// once per Env, even when chain, algorithms, nsec, and cds run in parallel
// under the registry's worker pool. It never returns nil.
func ensureChainData(ctx context.Context, env *probe.Env) *chainData {
	cd := probe.Shared(env, cacheKeyChain, func() *chainData { return fetchChainData(ctx, env) })
	if cd == nil {
		// fetchChainData panicked under another check, whose result reports
		// the panic; describe the chain as unknown rather than unsigned.
		return &chainData{dsErr: fmt.Errorf(
			"DS/DNSKEY fetch for %s failed in another DNSSEC check; see its registry.panic result",
			env.Target)}
	}
	return cd
}

// fetchChainData queries the DS and DNSKEY RRsets with checking disabled, so
// a validating resolver hands over a bogus zone's records for the chain check
// to diagnose. The resolver client gives each query its own --timeout budget.
func fetchChainData(ctx context.Context, env *probe.Env) *chainData {
	dsResp, dsErr := queryApexCD(ctx, env, mdns.TypeDS)
	keyResp, keyErr := queryApexCD(ctx, env, mdns.TypeDNSKEY)
	dsSet := extractDS(dsResp)
	keySet := extractDNSKEY(keyResp)
	return &chainData{
		keyResp: keyResp,
		dsErr:   dsErr,
		keyErr:  keyErr,
		dsSet:   dsSet,
		keySet:  keySet,
		signed:  len(dsSet) > 0 && len(keySet) > 0,
	}
}

// queryApexCD sends a DO+CD query for qtype at env.Target and checks the
// reply's rcode (see checkRcode).
func queryApexCD(ctx context.Context, env *probe.Env, qtype uint16) (*mdns.Msg, error) {
	return checkRcode(env.DNS.ExchangeCheckingDisabled(ctx, env.Target, qtype))
}

// checkRcode returns resp, or an error when the exchange failed or the
// resolver answered with an rcode other than NOERROR and NXDOMAIN, such as
// SERVFAIL or REFUSED, which says nothing about whether the records exist.
// NXDOMAIN reads as an empty answer.
func checkRcode(resp *mdns.Msg, err error) (*mdns.Msg, error) {
	switch {
	case err != nil:
		return nil, err
	case resp.Rcode != mdns.RcodeSuccess && resp.Rcode != mdns.RcodeNameError:
		return nil, &probe.RcodeError{Rcode: resp.Rcode}
	}
	return resp, nil
}
