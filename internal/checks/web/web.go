// Package web implements WWW-tier checks: TLS posture, certificates,
// HTTP→HTTPS redirect hygiene, security headers, cookies, mixed content,
// and CAA.
//
// TLS posture is scored against the embedded TLS profile dataset
// (tls-profiles-v5.json) loaded by tls_profiles.go. v5 ships three profiles:
// Modern, Intermediate, Old (Legacy). A Post-Quantum profile is forward-
// looking — when added, refresh the JSON and bump expectedProfilesVersion.
// The matched profile is reported as the TLS check's evidence; failing to
// meet at least Old is a Fail.
//
// Specs: RFC 7525 (BCP 195), 6698 (DANE/TLSA), 7817 (server identity for
// email TLS), 8659 (CAA), 6797 (HSTS), plus W3C/WHATWG/browser specs for
// CSP, cookie attributes, etc.
package web

import (
	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/registry"
)

const category = "WWW"

func init() {
	// Order is no longer load-bearing — the registry runs checks within a
	// category in parallel. tlsCheck still produces a cached
	// *tls.ConnectionState that certCheck prefers when available; certCheck
	// has its own fallback path when the cache is missed.
	registry.Register(checkutil.Wrap("web.tls.profile", category, runTLS))
	registry.Register(checkutil.Wrap("web.cert", category, runCert))
	registry.Register(checkutil.Wrap("web.redirect", category, runRedirect))
	registry.Register(checkutil.Wrap("web.hsts", category, runHSTS))
	registry.Register(checkutil.Wrap("web.headers", category, runHeaders))
	registry.Register(checkutil.Wrap("web.cookies", category, runCookies))
	registry.Register(checkutil.Wrap("web.caa", category, runCAA))
	registry.Register(checkutil.Wrap("web.mixedcontent", category, runMixedContent))
}
