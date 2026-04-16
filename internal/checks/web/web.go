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

import "granite-scan/internal/registry"

const category = "WWW"

func init() {
	// Order matters only loosely — the registry runs them sequentially within
	// the category. tlsCheck runs first so it can populate the cached
	// *tls.ConnectionState that several other checks consume.
	registry.Register(tlsCheck{})
	registry.Register(certCheck{})
	registry.Register(redirectCheck{})
	registry.Register(hstsCheck{})
	registry.Register(headersCheck{})
	registry.Register(cookiesCheck{})
	registry.Register(caaCheck{})
	registry.Register(mixedContentCheck{})
}
