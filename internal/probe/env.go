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

	DNS  *DNS
	HTTP *HTTP

	cacheMu sync.RWMutex
	cache   map[string]any
}

func NewEnv(target string, timeout time.Duration, active bool, resolver string) *Env {
	return &Env{
		Target:  target,
		Timeout: timeout,
		Active:  active,
		DNS:     NewDNS(resolver, timeout),
		HTTP:    NewHTTP(timeout),
		cache:   map[string]any{},
	}
}

// CacheGet / CachePut let checks share parsed records.
// Keys are convention-based, e.g. "dmarc.parsed", "spf.record".
func (e *Env) CacheGet(key string) (any, bool) {
	e.cacheMu.RLock()
	defer e.cacheMu.RUnlock()
	v, ok := e.cache[key]
	return v, ok
}

func (e *Env) CachePut(key string, v any) {
	e.cacheMu.Lock()
	e.cache[key] = v
	e.cacheMu.Unlock()
}

// WithTimeout returns a context bounded by the env's per-operation timeout.
func (e *Env) WithTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, e.Timeout)
}
