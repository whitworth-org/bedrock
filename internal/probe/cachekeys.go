package probe

// Cache keys used to share parsed records across checks. Centralized here
// so producers and consumers don't drift — for example, BIMI's Gmail-gate
// check reads CacheKeyDMARC after Email's DMARC check populates it.
const (
	CacheKeyDMARC = "email.dmarc.parsed" // *email.DMARC (defined by checks/email)
	// CacheKeyDMARCWalk carries the full RFC 9989 DNS tree-walk outcome
	// (*email.DMARCWalk): every step queried, the Organizational Domain, and
	// the effective policy record. CacheKeyDMARC holds just that effective
	// record for consumers that only need the record (np, the BIMI Gmail gate).
	CacheKeyDMARCWalk = "email.dmarc.walk"
	// CacheKeyDKIM carries the shared DKIM selector sweep (*email.DKIMSweep)
	// so the DKIM, DKIM2-readiness, and DMARC reject-readiness checks probe
	// the selector list exactly once per scan.
	CacheKeyDKIM = "email.dkim.sweep"
	CacheKeySPF  = "email.spf.parsed"
	// CacheKeyMX carries the one lookup of the target's MX RRset that the
	// email checks share (defined by checks/email).
	CacheKeyMX = "email.mx"
	// CacheKeyTLSCxn + ":" + host carries the one TLS handshake with host
	// that the WWW TLS profile, certificate, OCSP, CRL and CT checks share
	// (defined by checks/web).
	CacheKeyTLSCxn = "web.tls.state"
	// CacheKeyTLSFingerprint + ":" + host carries the ServerHello capture
	// from host that the JA3S and JA4S checks share (defined by checks/web).
	CacheKeyTLSFingerprint = "web.tls.fingerprint.cap"
	// CacheKeySubdomains carries the discovered subdomain list ([]string)
	// from the discover package to subsequent per-host checks.
	CacheKeySubdomains = "discover.subdomains"
	// CacheKeyHTTPSRoot carries the response to, or error from, the one GET
	// of https://<apex>/ that the hsts, headers, cookies, mixedcontent and
	// http3 checks share (defined by checks/web).
	CacheKeyHTTPSRoot = "web.https.root"
)
