// Package dnssec implements DNSSEC chain, algorithm, and NSEC3 checks.
//
// Backed by RFC 4033/4034/4035 (core), 4509 (SHA-256 DS), 5011 (auto trust
// anchors), 5155 (NSEC3), 6605 (ECDSA), 6781 (operational), 8624 (algorithm
// requirements), 3658 (delegation signer).
package dnssec

import (
	"context"
	"sync"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
)

// init registers the DNSSEC checks. The chain check, algorithm check, and
// NSEC check all share a per-run cache populated by ensureChainData; the
// helper uses CacheGetOrSet so the data is fetched exactly once regardless
// of which check happens to run first under the parallel registry.
func init() {
	registry.Register(checkutil.Wrap("dnssec.chain", category, runChain))
	registry.Register(checkutil.Wrap("dnssec.algorithms", category, runAlgorithms))
	registry.Register(checkutil.Wrap("dnssec.nsec", category, runNSEC))
}

const category = "DNSSEC"

// Cache keys shared between the dnssec checks (private to this package).
const (
	cacheKeyDS     = "dnssec.ds"     // []*mdns.DS
	cacheKeyDNSKEY = "dnssec.dnskey" // []*mdns.DNSKEY
	cacheKeySigned = "dnssec.signed" // bool — true when both DS and DNSKEY present
)

// chainData holds the artefacts of the DS+DNSKEY queries that all three
// dnssec checks need. It is computed once per run via CacheGetOrSet.
type chainData struct {
	dsResp  *mdns.Msg
	keyResp *mdns.Msg
	dsErr   error
	keyErr  error
	dsSet   []*mdns.DS
	keySet  []*mdns.DNSKEY
	signed  bool
}

// chainOnceMu guards chainOnces; chainOnces holds one *sync.Once per Env so
// the DS+DNSKEY queries fire exactly once per scan even when chain,
// algorithms, nsec, and cds run in parallel under the registry's worker
// pool.
//
// Why not env.CacheGetOrSet: that helper holds the cache mutex for the full
// duration of the producer, which would serialise every other check's
// CacheGet / CachePut against our DNS round-trip. Using a separate Once
// keeps the producer outside the cache lock entirely.
var (
	chainOnceMu sync.Mutex
	chainOnces  = map[*probe.Env]*sync.Once{}
	chainData_  = map[*probe.Env]*chainData{}
)

func chainOnceFor(env *probe.Env) (*sync.Once, *chainData) {
	chainOnceMu.Lock()
	defer chainOnceMu.Unlock()
	o, ok := chainOnces[env]
	if !ok {
		o = &sync.Once{}
		chainOnces[env] = o
	}
	return o, chainData_[env]
}

func storeChainData(env *probe.Env, cd *chainData) {
	chainOnceMu.Lock()
	chainData_[env] = cd
	chainOnceMu.Unlock()
}

// ensureChainData fetches the DS and DNSKEY RRsets for env.Target exactly
// once per Env. Sub-keys (cacheKeyDS / cacheKeyDNSKEY / cacheKeySigned) are
// populated in the same call so existing helper functions keep working
// without further plumbing.
func ensureChainData(ctx context.Context, env *probe.Env) *chainData {
	once, cached := chainOnceFor(env)
	if cached != nil {
		return cached
	}
	once.Do(func() {
		cctx, cancel := env.WithTimeout(ctx)
		defer cancel()

		dsResp, dsErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeDS)
		keyResp, keyErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeDNSKEY)

		dsSet := extractDS(dsResp)
		keySet := extractDNSKEY(keyResp)
		signed := len(dsSet) > 0 && len(keySet) > 0

		// Mirror to the legacy single-purpose cache keys so existing helpers
		// (cachedDNSKEYs, cachedDSs, the cacheKeySigned reads in nsec /
		// algorithms) continue to function.
		env.CachePut(cacheKeyDS, dsSet)
		env.CachePut(cacheKeyDNSKEY, keySet)
		env.CachePut(cacheKeySigned, signed)

		storeChainData(env, &chainData{
			dsResp:  dsResp,
			keyResp: keyResp,
			dsErr:   dsErr,
			keyErr:  keyErr,
			dsSet:   dsSet,
			keySet:  keySet,
			signed:  signed,
		})
	})
	_, cd := chainOnceFor(env)
	return cd
}
