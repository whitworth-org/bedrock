// Package probe owns shared network primitives: the DNS resolver wrapper,
// the HTTPS client, and the Env that checks consume.
//
// Network primitives live here so flag-driven concerns (resolver address,
// timeouts, --no-active mode) are configured exactly once.
package probe

import (
	"context"
	"sync"
	"time"
)

// Env carries everything a check needs to run. Built once per invocation
// in main and passed to every check. Cache lets dependent checks reuse
// records (e.g. the BIMI Gmail-gate reads the parsed DMARC record).
type Env struct {
	Target  string // ASCII / Punycode-normalized apex
	Timeout time.Duration
	Active  bool // when false, skip outbound TCP beyond DNS

	// Subdomains is true when the operator passed --subdomains and the
	// discovery package should enumerate hosts to scan in addition to apex+www.
	Subdomains bool
	// EnableRBL gates the optional DNSBL/RBL check (third-party queries).
	EnableRBL bool
	// EnableCT gates the Certificate Transparency lookup (queries crt.sh).
	EnableCT bool

	DNS  *DNS
	HTTP *HTTP

	// cacheMu guards cache and onces. Both maps are allocated on first
	// write, so a zero-value Env is usable.
	cacheMu sync.RWMutex
	cache   map[string]any
	onces   map[string]*sync.Once
}

// NewEnv builds an Env using a single resolver spec (or the system resolver
// when spec is empty). It is a shorthand for tests: an invalid spec only
// surfaces as an error on the first lookup. The CLI calls NewEnvMulti, which
// returns that error up front.
func NewEnv(target string, timeout time.Duration, active bool, resolver string) *Env {
	return &Env{
		Target:  target,
		Timeout: timeout,
		Active:  active,
		DNS:     NewDNS(resolver, timeout),
		HTTP:    NewHTTP(timeout),
	}
}

// NewEnvMulti builds an Env that knows several upstreams. Single-shot
// lookups use the first upstream; the DNS.ExchangeAll* methods reach them
// all, as the dnssec.sentinel check does.
func NewEnvMulti(target string, timeout time.Duration, active bool, resolvers []string) (*Env, error) {
	d, err := NewMultiDNS(resolvers, timeout)
	if err != nil {
		return nil, err
	}
	return &Env{
		Target:  target,
		Timeout: timeout,
		Active:  active,
		DNS:     d,
		HTTP:    NewHTTP(timeout),
	}, nil
}

// CacheGet / CachePut let checks share parsed records.
// Keys are convention-based, e.g. "dmarc.parsed", "spf.record".
func (e *Env) CacheGet(key string) (any, bool) {
	e.cacheMu.RLock()
	defer e.cacheMu.RUnlock()
	v, ok := e.cache[key]
	return v, ok
}

// CachePut stores v under key, replacing any earlier value. Stored values
// are shared by reference between checks, so they must not be mutated.
func (e *Env) CachePut(key string, v any) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.putLocked(key, v)
}

// putLocked stores v under key; the caller holds cacheMu for writing.
func (e *Env) putLocked(key string, v any) {
	if e.cache == nil {
		e.cache = map[string]any{}
	}
	e.cache[key] = v
}

// Shared returns the value cached under key, calling produce at most once
// per Env and key to create it. An existing entry, such as one a test seeded
// with CachePut, is returned without calling produce; a nil or wrong-typed
// entry yields the zero T instead of a panic. Concurrent callers for one key
// wait for the first caller's produce, which runs outside the cache lock, so
// other keys stay usable meanwhile. Its result is stored under key unless a
// CachePut stored a value first, in which case that value wins.
//
// produce runs under the first caller's context and timeout, and every
// waiting caller gets its result. It must not call Shared with its own key,
// which deadlocks, nor store key itself: a caller that finds that entry
// returns at once, possibly before produce has finished. If produce panics,
// the panic reaches the first caller and every later caller gets the zero
// T, so every consumer must handle the zero value.
func Shared[T any](e *Env, key string, produce func() T) T {
	v, ok := e.CacheGet(key)
	if !ok {
		e.onceFor(key).Do(func() { e.putIfAbsent(key, produce()) })
		v, _ = e.CacheGet(key)
	}
	t, _ := v.(T)
	return t
}

// onceFor returns the sync.Once guarding key's producer, creating it on
// first use.
func (e *Env) onceFor(key string) *sync.Once {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if e.onces == nil {
		e.onces = map[string]*sync.Once{}
	}
	o, ok := e.onces[key]
	if !ok {
		o = new(sync.Once)
		e.onces[key] = o
	}
	return o
}

// putIfAbsent stores v under key unless key already holds a value.
func (e *Env) putIfAbsent(key string, v any) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if _, ok := e.cache[key]; !ok {
		e.putLocked(key, v)
	}
}

// WithTimeout returns a context bounded by the env's per-operation timeout.
func (e *Env) WithTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, e.Timeout)
}
