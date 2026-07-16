package probe

// Cache keys used to share parsed records across checks. Centralized here
// so producers and consumers don't drift — for example, BIMI's Gmail-gate
// check reads CacheKeyDMARC after Email's DMARC check populates it.
const (
	CacheKeyDMARC = "email.dmarc.parsed" // *email.DMARC (defined by checks/email)
	// CacheKeyDMARCWalk carries the full RFC 9989 DNS tree-walk outcome
	// (*email.DMARCWalk): every step queried, the Organizational Domain, and
	// the effective policy record. CacheKeyDMARC holds just that effective
	// record for consumers that only need the policy (BIMI, ARC).
	CacheKeyDMARCWalk = "email.dmarc.walk"
	// CacheKeyDKIM carries the shared DKIM selector sweep (*email.DKIMSweep)
	// so the DKIM, DKIM2-readiness, and DMARC reject-readiness checks probe
	// the selector list exactly once per scan.
	CacheKeyDKIM   = "email.dkim.sweep"
	CacheKeySPF    = "email.spf.parsed"
	CacheKeyMX     = "email.mx"      // []probe.MX
	CacheKeyTLSCxn = "web.tls.state" // *tls.ConnectionState from main HTTPS GET
	// CacheKeySubdomains carries the discovered subdomain list ([]string)
	// from the discover package to subsequent per-host checks.
	CacheKeySubdomains = "discover.subdomains"
	// CacheKeyHTTPSRoot is the GET / against https://<apex>/ shared between
	// hsts/headers/cookies/mixedcontent/http2 to avoid N parallel root GETs.
	CacheKeyHTTPSRoot = "web.https.root"
)
