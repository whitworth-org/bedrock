# bedrock

A single-binary CLI auditor for DNS, DNSSEC, Email (incl. BIMI), and Web / TLS. Every finding cites an RFC; every `FAIL` includes a copy-pasteable remediation snippet.

- Single static binary, no runtime dependencies.
- Runs locally: no upload, no account, no telemetry. Optional third-party lookups (crt.sh, DNSBLs) are off by default.
- Deterministic output: results are sorted by `(category, id)`; categories run in parallel.
- SSRF-safe probes: every probe connection (HTTP, TLS, SMTP, AXFR, QUIC) refuses RFC 1918, loopback, link-local, ULA, CGNAT, multicast, reserved, and cloud-metadata addresses so attacker-influenced DNS cannot reach internal endpoints. A resolver given as an IP address is checked against the same list; one given by name is checked only when DoH dials it, since UDP and DoT dial the name unchecked.
- Exit code reflects posture (`0` clean, `1` at least one `FAIL`, `2` usage error).

## Install

Requires **Go 1.27.1** or newer.

### Preferred: `go install`

```bash
go install github.com/whitworth-org/bedrock@latest
```

Or pin a specific release:

```bash
go install github.com/whitworth-org/bedrock@v1.3.0
```

The binary is placed in `$GOBIN` (or `$GOPATH/bin`, which defaults to `~/go/bin` when `GOPATH` is unset). Make sure that directory is on your `PATH`:

```bash
export PATH="$HOME/go/bin:$PATH"
bedrock --version
```

### From source

```bash
git clone https://github.com/whitworth-org/bedrock.git
cd bedrock
make build        # CGO-less static binary, version ldflags embedded
./bedrock --version
```

### Pre-built binaries

Each `v*` tag push publishes linux / macOS / windows × amd64 / arm64 archives, plus a `checksums.txt`, to the [Releases page](https://github.com/whitworth-org/bedrock/releases). Built by `.github/workflows/release.yml` via goreleaser.

## Quick start

```bash
bedrock example.org              # default audit, text report on a terminal
bedrock example.org | jq .       # canonical JSON for tooling
bedrock --json example.org       # JSON on a terminal too
bedrock --no-active example.org  # DNS-only — no outbound TCP
```

## Usage

```
bedrock [flags] <domain>
```

`<domain>` may be an IDN; it is Punycode-normalised, lowercased, and any trailing dot is stripped.

### Flags

| Flag                | Default         | Effect                                                                                               |
|---------------------|-----------------|------------------------------------------------------------------------------------------------------|
| `--version`         | —               | Print the version line and exit.                                                                    |
| `--json`            | off             | Print JSON even when stdout is a terminal. Command line only: there is no config key.                |
| `--no-color`        | colour on TTY   | No colour in the terminal report, as with a non-empty `NO_COLOR` or `TERM=dumb`. JSON is never coloured. |
| `--no-active`       | probes on       | Skip active probes (SMTP STARTTLS, HTTPS GETs, MTA-STS fetch, VMC fetch, QUIC dial).                 |
| `--resolver`        | system resolver | `host[:port]`, preset (`cloudflare` / `google` / `quad9` / `opendns`), `<preset>-dot`, `<preset>-doh`, `tls://host`, `https://url`. |
| `--resolvers`       | —               | CSV of resolvers. The first serves every lookup; `dnssec.sentinel` tests each one.                   |
| `--timeout`         | `5s`            | Per-operation timeout, greater than zero (each DNS query, each HTTPS GET, each handshake).           |
| `--config`          | —               | Path to a JSON config file. Flag values override config values.                                      |
| `--only`            | —               | CSV of categories to include (`DNS`, `DNSSEC`, `Email`, `WWW`, `Subdomain`).                         |
| `--exclude`         | —               | CSV of categories to exclude.                                                                        |
| `--ids`             | —               | CSV of specific check IDs to include (e.g. `web.hsts,email.dmarc.record`), plus the run-level `dns.resolver.unreachable` and `registry.panic.*` results. A warning on stderr names entries that match no result. |
| `--severity`        | —               | Minimum severity to show: `info`, `pass`, `warn`, `fail`. `N/A` is always shown.                     |
| `--subdomains`      | off             | Enumerate subdomains via passive sources (hackertarget, anubis, threatcrowd, wayback) and probe each.|
| `--enable-ct`       | off             | Query Certificate Transparency via crt.sh.                                                           |
| `--enable-rbl`      | off             | Query DNSBLs (Spamhaus, Barracuda, SpamCop, SORBS, PSBL). Listings produce `WARN`, not `FAIL`.       |
| `--baseline`        | —               | Path to a previous JSON report; surface regressions against it.                                      |
| `--regression-only` | off             | Requires `--baseline`: exit non-zero only on NEW failures (ignores pre-existing `FAIL`s).            |

### Resolver forms

```bash
bedrock --resolver cloudflare        example.org     # 1.1.1.1:53 (UDP)
bedrock --resolver cloudflare-dot    example.org     # 1.1.1.1:853 (DoT, RFC 7858)
bedrock --resolver cloudflare-doh    example.org     # https://cloudflare-dns.com/dns-query (DoH, RFC 8484)
bedrock --resolver tls://one.one.one.one example.org # explicit DoT (by DNS name, not IP address)
bedrock --resolver https://dns.quad9.net/dns-query example.org   # explicit DoH
bedrock --resolvers cloudflare,google,quad9 example.org          # lookups use cloudflare; dnssec.sentinel tests all three
```

Private-IP / loopback / metadata resolvers given as IP addresses, and probes of such addresses, are rejected by default; a resolver given by name is checked only when DoH dials it. Set `BEDROCK_ALLOW_PRIVATE_RESOLVER=1` for hermetic test labs only.

### Root KSK rollover readiness

`dnssec.sentinel` tests the resolvers bedrock uses (the system resolvers, `--resolver`, or each of `--resolvers`), not the target, and sends nothing about the target. It reads the active root zone KSKs from the root DNSKEY RRset, verifies which of them sign it, and asks each resolver directly (RFC 8509 §4.2) for `root-key-sentinel-is-ta-<tag>.arpa` and `root-key-sentinel-not-ta-<tag>.arpa` for every KSK. The names sit under the signed `arpa` zone because a resolver that mirrors the root zone (RFC 8806) can skip the sentinel for root names. The RFC's third, deliberately bogus query would need a third-party zone, so the check leaves it out and reads the AD bit instead; a forwarder that strips AD therefore reads as not validating.

- `PASS`: every resolver trusts a KSK that signs the root DNSKEY RRset and every other active KSK. Once KSK-2024 (38696) signs the root on 2026-10-11, a resolver that has dropped the retiring KSK-2017 (20326) still passes, with a note.
- `WARN`: a resolver does not yet trust an active KSK (the key is absent, or still in the RFC 5011 30-day hold-down), or cannot validate the root at all: it fails every sentinel name yet returns the root DNSKEY RRset with checking disabled. The remediation names each such resolver and lists the keys it needs as commented-out DS records to confirm against IANA's `root-anchors.xml`.
- `INFO`: a resolver does not validate, shows no sentinel processing, does not answer, or gives answers that fit no RFC 8509 pattern (rewritten, not recursive, or from local zone data). The test is also skipped, as `INFO`, when no resolver returns a usable root DNSKEY RRset or the RRset lists more than four active KSKs.

`INFO` is not evidence of readiness. The sentinel is optional (RFC 8509 §1), and BIND skips it for answers it synthesizes from cached NSEC records (RFC 8198, `synth-from-dnssec`, on by default); `+EDE29` in the evidence marks such answers when the resolver reports them. The check never reports `FAIL`, so it does not change the exit code. As of October 2026, Cloudflare processes the sentinel over DoT and DoH; Google Public DNS and OpenDNS do not, and Quad9 often answers these names from cached NSEC records, so those three read as `INFO`.

```bash
bedrock --no-active --ids dnssec.sentinel --resolver cloudflare-dot example.org
```

`--ids` filters only the report: the target is still audited, and this check still queries every resolver. `--only` and `--exclude` skip whole categories, so `--exclude DNSSEC` skips this check. After changing a resolver's trust anchors, flush its cache before testing again, because its earlier answers for these fixed names can stay cached for up to its negative-cache TTL, often an hour. Plain-UDP presets are labelled `<name>-udp` because they reach whatever answers port 53 on your network, which can be a transparent interceptor rather than the named provider; the `-dot` and `-doh` presets test the provider itself. System resolvers appear as `system-1`, `system-2`, and so on, in `/etc/resolv.conf` order, so reports do not carry local network addresses.

### Configuration file

JSON; keys mirror long-form flag names with hyphens replaced by underscores.

```json
{
  "resolver": "cloudflare-doh",
  "timeout": "10s",
  "only": ["Email", "WWW"],
  "severity": "warn",
  "enable_ct": true,
  "enable_rbl": false,
  "subdomains": false,
  "baseline": "./baseline.json",
  "regression_only": true
}
```

```bash
bedrock --config audit.json example.org
```

A `timeout` that does not parse gets a warning on stderr, and the scan uses the default.

## What bedrock checks

Each check returns one of: **PASS**, **WARN**, **FAIL**, **INFO**, **N/A**. Only `FAIL` affects the exit code. When a probe could not complete (a timeout, a reset connection, an unreachable network, a temporary DNS failure such as `SERVFAIL` or `REFUSED`, an SSRF refusal, or an interrupted scan), a check that grades the target reports `WARN` with evidence starting `could not determine:`, and an informational check stays `INFO` and quotes the error. A refused connection and `NXDOMAIN` are answers from the target and are graded as such. Checks of content fetched over a TLS chain that did not verify report `N/A` with evidence `TLS chain invalid; see web.cert.*`.

### DNS

| Check ID                 | What it verifies                                                                 |
|--------------------------|----------------------------------------------------------------------------------|
| `dns.zone.mname`         | SOA MNAME appears in the apex NS RRset (RFC 1912 §2.2, RFC 1996).                |
| `dns.zone.soa`           | SOA refresh / retry / expire / minimum within recommended windows (RFC 2308).    |
| `dns.zone.mx`            | Apex MX count and well-formedness.                                               |
| `dns.ns.count`           | At least 2 authoritative NS records (RFC 1034 §4.1, RFC 1912 §2.8).              |
| `dns.ns.diversity`       | NSes span ≥2 distinct /24 prefixes (RFC 2182 §3.1).                              |
| `dns.ns.ipv6`            | Each NS advertises AAAA (RFC 3596).                                              |
| `dns.aaaa.apex`          | Apex publishes an AAAA record (RFC 3596).                                        |
| `dns.cname.apex`         | Apex is NOT a CNAME (RFC 1912 §2.4, RFC 2181 §10.3).                             |
| `dns.cname.chain`        | `www.` CNAME chain is sane.                                                      |
| `dns.dangling.summary`   | Probes common hosts (`www`, `api`, `mail`, `cdn`, …) for dangling CNAMEs.        |
| `dns.axfr.<ns>`          | Each authoritative NS refuses AXFR from the public Internet (RFC 5936 §6); an answer holding only the SOA passes. At most 8 nameservers are probed, 4 at a time; a `dns.axfr` `INFO` result names the rest. |
| `dns.resolver.unreachable` | `FAIL` when the resolver answered none of the scan's DNS queries (it sent no reply, or only errors such as `SERVFAIL` or `REFUSED`), so every DNS result is inconclusive. Reported even when `--only` or `--exclude` skips the DNS category or `--ids` names other checks. |

### DNSSEC

| Check ID                  | What it verifies                                                                |
|---------------------------|---------------------------------------------------------------------------------|
| `dnssec.signed`           | DS at parent and DNSKEY at apex.                                                |
| `dnssec.chain.ds_match`   | A DS at the parent matches a published zone key (RFC 4034 §5, RFC 4035 §5.2).   |
| `dnssec.chain.dnskey_rrsig` | RRSIG over DNSKEY by a DS-referenced key verifies and is within its validity period (RFC 4035 §5.2, §5.3). |
| `dnssec.chain.soa_rrsig`  | RRSIG over the apex SOA verifies and is within its validity period (RFC 4035 §5.3). |
| `dnssec.algorithm.dnskey` | DNSKEY algorithm is MUST / RECOMMENDED (RFC 8624 §3.1).                         |
| `dnssec.algorithm.ds`     | DS digest type is MUST (SHA-256 or SHA-384) (RFC 8624 §3.3).                    |
| `dnssec.nsec.type`        | Authenticated denial of existence: NSEC or NSEC3 with safe iterations.          |
| `dnssec.cds.published`    | CDS/CDNSKEY self-consistency (RFC 7344 §3).                                     |
| `dnssec.cds.matches_ds`   | CDS digests match the DS at the parent (RFC 7344 §4).                           |
| `dnssec.cds.signed`       | CDS RRset carries an RRSIG (RFC 7344 §4.1).                                     |
| `dnssec.sentinel`         | Resolvers in use validate the root and trust its active KSKs (RFC 8509 §3).     |

### Email

| Check ID                                     | What it verifies                                                                 |
|----------------------------------------------|----------------------------------------------------------------------------------|
| `email.spf.record`                           | Exactly one `v=spf1` TXT, valid syntax, terminating `-all` / `~all`. `+all` FAILs, and so does a pass-qualified `ip4:0.0.0.0/0` or `ip6:::/0`, which permits every sender the same way. |
| `email.dkim.selector.<name>`                 | Probes ~44 well-known selectors plus ESP-specific ones derived from SPF includes; accepts `v=DKIM1` and `v=DKIM2` records, validates `k=` (`rsa`/`ed25519`) and that ed25519 keys decode to 32 bytes (RFC 8463). An RSA key under 1024 bits, or an `h=` list without `sha256`, FAILs; a 1024–2047-bit RSA key WARNs (RFC 8301 §3.1, §3.2). |
| `email.dkim.wildcard`                        | A `*._domainkey` wildcard key, reported once instead of under every selector it answers; `INFO` when its empty `p=` revokes them. |
| `email.dkim2.readiness`                      | DNS-observable DKIM2 signals (draft-ietf-dkim-dkim2-spec): `PASS` on published `v=DKIM2` keys, `INFO` on ed25519-only or DKIM1/rsa-only posture. Never fails: DKIM2 is a draft. |
| `email.dmarc.record`                         | Effective DMARC policy via the RFC 9989 §4.8 DNS tree walk (≤8 queries; replaces the Public Suffix List): strict tag parsing, `rua`/`ruf` scheme allowlist, duplicate-tag rejection, `np`/`psd`/`t` tags, retired `pct`/`rf`/`ri` flagged, `t=y` steps the effective policy down one level. Subdomains inherit the organizational record through `sp=`. |
| `email.dmarc.discovery`                      | How discovery resolved: Organizational Domain and the RFC 9989 selection rule (`psd=n`, `psd=y` one-below, fewest labels), the policy domain, queries used, and any malformed/multiple records the walk ignored. |
| `email.dmarc.np`                             | Non-existent-subdomain policy (RFC 9989 §4.7): `PASS` on `np=reject`, `WARN` on quarantine/none; notes explicit vs inherited (`np`←`sp`←`p`). |
| `email.dmarc.np.rfc8020`                     | np enforceability: probes a random nonexistent subdomain of the Organizational Domain; `PASS` on NXDOMAIN (RFC 8020), `WARN` on wildcard or NOERROR zones where receivers cannot apply `np=`. |
| `email.dmarc.extdest`                        | RFC 9990 external-destination consent: `rua`/`ruf` hosts outside the Organizational Domain must publish `v=DMARC1` at `<policy-domain>._report._dmarc.<dest>`, or compliant generators refuse to report. |
| `email.dmarc.reject_dkim`                    | RFC 9989 `p=reject` requirement: publishers MUST apply DKIM and MUST NOT rely on SPF alone; `WARN` when no DKIM key is discoverable on common selectors. |
| `email.mtasts.txt`                           | `_mta-sts` TXT well-formed, `v=STSv1`, `id=` opaque token. `N/A` for a domain that publishes null MX. |
| `email.mtasts.policy`                        | HTTPS fetch of `mta-sts.<domain>/.well-known/mta-sts.txt` (no redirects, TLS 1.2 floor, strict chain). `N/A` for a domain that publishes null MX. |
| `email.tlsrpt.record`                        | `_smtp._tls` TXT, `v=TLSRPTv1`, valid `rua=` schemes. `N/A` for a domain that publishes null MX. |
| `email.dane.<mx-host>`                       | TLSA under `_25._tcp.<mx>`; usage/selector/matching validation; DNSSEC AD-bit enforced. Covers the 10 most preferred MX hosts; an `email.dane` `INFO` result names the rest. |
| `email.nullmx`                               | RFC 7505 null-MX declaration (`0 .`).                                            |
| `email.smtp.starttls.<mx-host>`              | Connect to each of the 10 most preferred MX hosts, EHLO, STARTTLS advertisement, handshake success + version; an `email.smtp.starttls` `INFO` result names the rest. |
| `email.arc.*`                                | ARC deployment guidance (DKIM availability, DMARC enforcement alignment); RFC 8617 is headed to Historic, so guidance steers new deployments toward DKIM2. |
| `email.rbl` (opt-in via `--enable-rbl`)      | Apex and MX IPs vs Spamhaus, Barracuda, SpamCop, SORBS, Surriel PSBL.            |
| `email.google_workspace_mx`                  | **INFO only** — detects legacy `ASPMX.L.GOOGLE.COM` layout and recommends migration to the new single `SMTP.GOOGLE.COM` MX. Silent for non-Google MX and domains already on the new form. |

### DMARCbis and DKIM2

DMARC policy discovery follows RFC 9989 (DMARCbis, obsoletes RFC 7489 and RFC 9091): a DNS
tree walk of at most eight queries replaces the Public Suffix List, so a subdomain with no
`_dmarc` record of its own is evaluated against the organizational record it actually
inherits. Aggregate and failure reporting are audited per RFC 9990 and RFC 9991.

```bash
# Just the DMARCbis surface: effective policy, discovery, np, reporting consent
bedrock --no-active --ids email.dmarc.record,email.dmarc.discovery,email.dmarc.np,email.dmarc.extdest example.org

# DKIM2 posture alongside the p=reject DKIM requirement
bedrock --no-active --ids email.dkim2.readiness,email.dmarc.reject_dkim example.org
```

DKIM2 (draft-ietf-dkim-dkim2-spec) keys live at the same `<selector>._domainkey.<domain>`
location as DKIM1 and sign with ed25519, so a published key record looks like:

```
sel1._domainkey.example.org. IN TXT "v=DKIM2; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
```

The `Message-Instance` / `DKIM2-Signature` chain of custody exists only in mail flow — a
DNS scan can verify published keys and algorithms, not live signature chains.

### BIMI

| Check ID              | What it verifies                                                                      |
|-----------------------|---------------------------------------------------------------------------------------|
| `bimi.txt`            | `default._bimi` TXT: `v=BIMI1`, `l=` URL, `a=` URL (required for Gmail display).      |
| `bimi.svg.fetch`      | SVG fetched over HTTPS with correct `Content-Type`; size cap 1 MiB.                   |
| `bimi.svg.profile`    | SVG conforms to Tiny PS: allowlisted elements/attributes, no DOCTYPE/entities/scripts, ≤4096 tokens, ≤32 depth. |
| `bimi.svg.aspect`     | `viewBox` is square (1:1).                                                            |
| `bimi.vmc.fetch`      | VMC PEM fetched over HTTPS via the strict client.                                     |
| `bimi.vmc.chain`      | Leaf passes BIMI EKU gate (`1.3.6.1.5.5.7.3.31` VMC or `…3.32` CMC); chain validates against system roots; ≤16 PEM blocks. |
| `bimi.vmc.logotype`   | RFC 3709 LogotypeExtn ASN.1 decoded; SHA-256 of SVG matches the hash in the cert.     |
| `bimi.gmail.dmarc`    | Gmail BIMI requirements: DMARC `quarantine`/`reject` enforced, also by the Organizational Domain's record (no `sp=none`, no `t=y` test mode, no sampling via retired `pct`). Strict alignment is recommended in the evidence, not required. |

### Web / TLS

| Check ID                              | What it verifies                                                                    |
|---------------------------------------|-------------------------------------------------------------------------------------|
| `web.tls.version.<host>`              | Negotiated TLS version (≥1.2; TLS 1.3 preferred).                                   |
| `web.tls.profile.<host>`              | Matches Mozilla `modern`, `intermediate`, or `old` profile (cipher + cert key).     |
| `web.tls.curves`                      | Accepted EC curves: X25519, P-256, P-384; weaker curves flagged.                    |
| `web.cert.chain`                      | Leaf + intermediates chain to a trusted system root.                                |
| `web.cert.expiry`                     | Not expiring within 30 days.                                                        |
| `web.cert.lifespan`                   | Issued lifespan ≤ CA/Browser-forum recommendation.                                  |
| `web.cert.key`                        | Key strength (RSA ≥2048, EC ≥256).                                                  |
| `web.cert.san`                        | Leaf SAN covers the host (RFC 6125 §6.4).                                           |
| `web.cert.sig`                        | Signature algorithm is not SHA-1.                                                   |
| `web.hsts`                            | `Strict-Transport-Security` present, `max-age ≥ 31536000`, `includeSubDomains`.     |
| `web.header.csp`                      | `Content-Security-Policy` present.                                                  |
| `web.header.x-frame-options`          | Clickjacking: `X-Frame-Options: DENY/SAMEORIGIN` or CSP `frame-ancestors`.          |
| `web.header.x-content-type-options`   | `X-Content-Type-Options: nosniff`.                                                  |
| `web.header.referrer-policy`          | `Referrer-Policy` present.                                                          |
| `web.header.permissions-policy`       | `Permissions-Policy` present.                                                       |
| `web.cookies`                         | `Set-Cookie` attributes: `Secure`, `HttpOnly`, `SameSite`.                          |
| `web.caa`                             | CAA RRset present (RFC 8659).                                                       |
| `web.securitytxt`                     | RFC 9116 `security.txt` at `/.well-known/`: required `Contact`/`Expires`, HTTPS URIs, freshness. |
| `web.redirect.<host>`                 | HTTP→HTTPS redirect chain (no protocol downgrade, no cross-host hop).               |
| `web.mixedcontent`                    | Apex body (first 1 MiB) scanned for `http://` src/href references.                  |
| `web.http2`                           | HTTP/2 advertised via ALPN (`h2`).                                                  |
| `web.http3`                           | HTTP/3 via Alt-Svc or direct QUIC dial.                                             |
| `web.ocsp.staple`                     | Server staples an OCSP response (RFC 6066 §8); `N/A` when the leaf certificate names no OCSP responder. |
| `web.ocsp.responder`                  | Independent OCSP responder reachable.                                               |
| `web.crl.status`                      | CRL distribution point reachable; leaf not listed.                                  |
| `web.ct.lookup` (opt-in `--enable-ct`)| Certificate Transparency entries observed in crt.sh (RFC 9162).                     |
| `web.tls.fingerprint.ja3s.<host>`     | JA3S server TLS fingerprint (Salesforce, MD5 over cleartext ServerHello). `INFO`.   |
| `web.tls.fingerprint.ja4s.<host>`     | JA4S server TLS fingerprint (FoxIO; human-readable, SHA-256 truncated). `INFO`.     |

### Subdomain discovery (opt-in `--subdomains`)

Passive third-party sources: hackertarget, anubis, threatcrowd, wayback. These are external services with varying coverage and freshness, and querying them may disclose the domains under investigation. Discovered hosts are probed for TLS reachability and certificate hygiene; with active probing on they are also fingerprinted (`subdomain.tls.fingerprint.{ja3s,ja4s}.<host>`, INFO). Hostnames must match `^[a-zA-Z0-9._-]+$` at both the source-parse and enumerate stages (the underscore is permitted so service labels like `_dmarc` survive — an injection-safety filter, not an RFC 1123 validator); malformed lines are rejected before any DNS lookup.

## Output

The format depends on where stdout goes: a terminal gets a text report; a pipe, a file, or `--json` gets JSON. A program that reads bedrock's output through a pseudo-terminal (`ssh -t`, `docker run -t`, `script`, `expect`) therefore gets the text report. Better not to allocate one (`ssh -T`, `docker run` without `-t`): stdout is then a pipe, which gets JSON and no progress lines. Where a pseudo-terminal cannot be avoided, pass `--json` and keep stderr, which shares the terminal, out of the stream: `ssh -t host 'bedrock --json example.org 2>/dev/null'`, or set `CI=1` (`docker run -t -e CI=1 ...`).

### Terminal report

The report runs from least to most important, so the last screen holds the fixes and the result: a header; checks that did not run or do not apply, grouped by reason; one line per `PASS` and `INFO`; each `WARN` and `FAIL` in full, with evidence, references, and fix; with `--baseline`, the new failures; a summary per category; and a verdict that names the exit code. Each fix follows a `fix (N lines):` label and is printed unindented, so most fixes paste as-is. The start and end of a run on a terminal:

```
$ bedrock example.org
bedrock: scanning example.org: 57 checks, active probes, timeout 5s
bedrock report for example.org (84 results, 1.2s)
[... N/A, PASS, INFO and WARN sections, then the other FAIL blocks ...]
FAIL  web.redirect.www.example.org  HTTP→HTTPS redirect (www.example.org)
      evidence: plain HTTP did not redirect to HTTPS (final: http://www.example.org/)
      refs: RFC 7525 §3.1.1
      fix (5 lines):
server {
    listen 80;
    server_name example.org www.example.org;
    return 301 https://$host$request_uri;
}

Summary for example.org
DNS         0 FAIL   1 WARN  10 PASS   1 INFO   0 N/A
DNSSEC      0 FAIL   0 WARN  10 PASS   1 INFO   0 N/A
Email       1 FAIL   2 WARN   4 PASS   9 INFO  11 N/A
Subdomain   0 FAIL   0 WARN   0 PASS   1 INFO   0 N/A
WWW         5 FAIL   4 WARN  16 PASS   8 INFO   0 N/A
Total       6 FAIL   7 WARN  40 PASS  20 INFO  11 N/A

Result: FAIL. 6 FAIL (Email 1, WWW 5), 7 WARN. Exit code 1.
```

Colour marks only bedrock's own words: status words, section headings, non-zero `FAIL` and `WARN` counts, and the verdict. `--no-color` (config `"no_color": true`), a non-empty `NO_COLOR`, or `TERM=dumb` turns it off; `FORCE_COLOR` and `CLICOLOR_FORCE` are ignored.

### Progress on stderr

While a scan runs, stderr gets progress lines that are appended, never redrawn: a start line, a heartbeat at 3 s and every 10 s after that naming up to two checks not done yet (running, or queued for a worker), and a line on interrupt. They appear only when stderr is a terminal, `CI` is unset or empty, and stdout is a terminal or a file; never with a pipe, so `| less` and `| jq` stay clean. `2>/dev/null` hides them. When those conditions hold and stdout is a file, stderr also ends with the verdict, the checks an interrupt cut short, and up to ten failing IDs, so `bedrock example.org > report.json` still shows the result.

Ctrl-C or SIGTERM stops the scan and prints the partial report. The exit code follows the results it holds, which can include a `FAIL` from a check the interrupt cut short. The terminal report says `INCOMPLETE` and lists the checks that did not finish, by check name: a check can report its results under other IDs (`dns.dangling` reports `dns.dangling.summary`), and the results a cut-short check did report may reflect the interrupt rather than the target. With `--only` or `--exclude`, the list keeps to the categories the report shows. The JSON has no such marker, so stderr always says `INCOMPLETE`: in the verdict when progress is on, otherwise in a single verdict line. A second Ctrl-C ends bedrock at once, without a report.

Warnings and errors also go to stderr, one `bedrock: ` line each, whatever stderr is: an `--ids` entry that matches no result (not checked after an interrupt, which can leave a valid ID without one) and a config `timeout` that does not parse. To parse the JSON, keep stderr out of the stream: `bedrock example.org 2>bedrock.log | jq`, not `2>&1 | jq`.

### JSON

```json
{
  "target": "example.org",
  "results": [
    {
      "id": "email.dmarc.record",
      "category": "Email",
      "title": "DMARC record present and well-formed",
      "status": "FAIL",
      "evidence": "p=none observed in _dmarc.example.org TXT",
      "remediation": "_dmarc.example.org. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org\"",
      "rfc_refs": ["RFC 9989 §4.7"]
    }
  ],
  "summary": {
    "categories": [
      { "category": "Email", "counts": { "pass": 0, "warn": 0, "fail": 1, "info": 0, "na": 0, "total": 1 } }
    ],
    "totals": { "pass": 0, "warn": 0, "fail": 1, "info": 0, "na": 0, "total": 1 }
  }
}
```

The `summary` block totals the rendered results per category and per status. It is computed after `--only` / `--exclude` / `--severity` / `--ids` filtering, so the counts always match the `results` array it accompanies. With `--baseline`, a `regressions` array lists the `id` and `title` of each new `FAIL`; it is omitted when there are none.

### Untrusted text

In both formats, every C0 control character except TAB, every C1 control character, and DEL in the report's text is replaced with `U+FFFD`; only a fix keeps its line breaks, normalised to LF. Data from the target therefore cannot carry terminal escape sequences. The terminal report also turns TAB into a space and shows as `\uXXXX` (`\UXXXXXXXX` above U+FFFF) every character that is not graphic or that renders as nothing: format characters such as bidirectional overrides and zero-width spaces, line and paragraph separators, private-use and unassigned code points, fillers, and variation selectors. It never wraps, truncates, or colours text from the target. Progress lines, warnings and errors on stderr get the same treatment. Target text that itself reads `\u202E` looks the same as an escaped character; the JSON report has the exact text.

### Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | No `FAIL` results. `WARN` and `INFO` do not affect exit code.    |
| 1    | At least one `FAIL` (or, with `--regression-only`, a new `FAIL`).|
| 2    | Usage error or invalid flag value, invalid input or configuration, or a failed write. |

## Regression tracking

```bash
bedrock example.org > baseline.json
# … later …
bedrock --baseline baseline.json --regression-only example.org
```

Duplicate IDs in a baseline file cause every current `FAIL` for that ID to be reported as a regression (fails closed: an ambiguous baseline cannot mask a regression). A default run gives every result its own ID; runs with `--enable-rbl` or `--subdomains` are outside that guarantee.

Regenerate the baseline after upgrading bedrock. A release can rename result IDs, and a renamed ID that fails counts once as a regression.

## CI integration

The first run saves the baseline, and later runs fail on `FAIL`s that are new since then. Any run fails when bedrock exits 2. The log gets the number of new `FAIL`s but never text from the target.

```yaml
name: Domain audit
on:
  schedule: [{ cron: '0 6 * * *' }]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with: { go-version: '1.27.1' }
      - run: go install github.com/whitworth-org/bedrock@v1.3.0
      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: baseline.json
          key: bedrock-baseline-${{ github.repository }}
      - run: |
          bedrock example.org > current.json || [ $? -eq 1 ]
          status=0
          if [ -f baseline.json ]; then
            bedrock --baseline baseline.json --regression-only example.org \
              > regression-run.json || status=$?
            jq '.regressions | length' regression-run.json
          fi
          mv current.json baseline.json
          exit "$status"
```

## Development

```bash
make build        # CGO-less static binary with version ldflags
make test         # go test ./...
make test-race    # go test -race -count=1 ./...
make lint         # golangci-lint
make vulncheck    # govulncheck ./...
make fuzz         # short fuzz sweep (targets added incrementally)
make release-check  # goreleaser snapshot (cross-platform)
```

Hermetic tests bypass the SSRF denylist via `BEDROCK_ALLOW_PRIVATE_RESOLVER=1`.

## Project layout

```
main.go                     flag parsing, target normalisation, signal handling, exit codes
internal/registry/          check registration + parallel category execution + panic recovery
internal/probe/             DNS (miekg/dns) + HTTP primitives, named resolvers, DoT, DoH, SSRF-safe dialer
internal/probe/tlsfp/       Native ServerHello parser + JA3S/JA4S fingerprint compute (no third-party deps)
internal/report/            Result type + JSON and terminal-report renderers + terminal sanitisation
internal/tty/               terminal and regular-file detection, colour rules (Windows console via kernel32)
internal/progress/          append-only scan progress lines for stderr
internal/cli/               result filters + JSON config loader
internal/baseline/          baseline diff for --baseline / --regression-only (fail-closed on duplicate IDs)
internal/version/           build-time version, populated via -ldflags
internal/discover/          passive subdomain enumeration (HTTPS-only, hostname allowlist)
internal/checks/dns/        DNS checks
internal/checks/dnssec/     DNSSEC chain, algorithms, NSEC, CDS/CDNSKEY, root KSK sentinel
internal/checks/email/      SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE, Null MX, STARTTLS, ARC, RBL, Google Workspace MX
internal/checks/bimi/       BIMI TXT, SVG Tiny PS, VMC + RFC 3709 logotype ASN.1
internal/checks/web/        TLS profile, certs, HSTS, headers, cookies, CAA, redirect, mixed content, CT, OCSP, CRL, EC curves, HTTP/2, HTTP/3, JA3S/JA4S fingerprints
testdata/golden/            integration-test fixtures
```

## License

MIT (see `LICENSE`). Picked because security teams can drop a permissive tool into proprietary pipelines without involving legal, the license fits on one page, and `miekg/dns`, `quic-go`, and `golang.org/x/*` are all MIT-compatible.

Apache-2.0 is a clean drop-in if you need an explicit patent grant. GPL/AGPL were declined: bedrock is meant to run anywhere, including in closed environments.

## Limitations

- Output is English only.
- Client-side JA3/JA4 (the fingerprint bedrock's own ClientHello presents to a target IDS) is not emitted; bedrock fingerprints what targets serve, not what it sends. Servers that refuse bedrock's stdlib handshake produce a check `FAIL`/`WARN` with no fingerprint.
- Negotiated EC curve is detected via probe-and-detect (suppressed under `--no-active`).
- The DKIM check probes a fixed selector list (44 well-known + ESP-specific derived from SPF includes). Custom per-tenant selectors (e.g. HubSpot's `hs1-<id>-<domain>` pattern) cannot be discovered without the customer ID; NSEC walking under `_domainkey` is deferred.
- VMC chain validation uses `ExtKeyUsageAny` because the BIMI EKU OIDs are not in the Go standard library root-usage table. The BIMI-specific OID gate (`classifyMarkCert`) runs *before* chain verification.
- `--enable-rbl` and `--enable-ct` issue live queries to third-party services; do not enable them for casual or repeated scans of domains you do not operate.
- With `--resolvers`, every lookup goes to the first resolver; only `dnssec.sentinel` queries the others.

---

*Inspired by [hardenize.com](https://www.hardenize.com).*
