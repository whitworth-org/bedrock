# bedrock

A single-binary CLI auditor for DNS, DNSSEC, Email (incl. BIMI), and Web / TLS. Every finding cites an RFC; every `FAIL` includes a copy-pasteable remediation snippet.

- Single static binary, no runtime dependencies.
- Runs locally: no upload, no account, no telemetry. Optional third-party lookups (crt.sh, DNSBLs) are off by default.
- Deterministic output: results are sorted by `(category, id)`; categories run in parallel.
- SSRF-safe HTTP client: denies RFC 1918, loopback, link-local, ULA, CGNAT, and cloud-metadata addresses so attacker-influenced DNS cannot reach internal endpoints.
- Exit code reflects posture (`0` clean, `1` at least one `FAIL`, `2` usage error).

## Install

Requires **Go 1.26** or newer.

### Preferred: `go install`

```bash
go install github.com/whitworth-org/bedrock@latest
```

Or pin a specific release:

```bash
go install github.com/whitworth-org/bedrock@v1.0.1
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
bedrock example.org              # default audit, JSON on stdout (ANSI-coloured on a TTY)
bedrock example.org | jq .       # canonical JSON for tooling
NO_COLOR=1 bedrock example.org   # plain JSON regardless of TTY
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
| `--no-color`        | colour on TTY   | Suppress ANSI colouring. Honoured automatically when stdout is not a terminal or `NO_COLOR` is set.  |
| `--no-active`       | probes on       | Skip active probes (SMTP STARTTLS, HTTPS GETs, MTA-STS fetch, VMC fetch, QUIC dial).                 |
| `--resolver`        | system resolver | `host[:port]`, preset (`cloudflare` / `google` / `quad9` / `opendns`), `<preset>-dot`, `<preset>-doh`, `tls://host`, `https://url`. |
| `--resolvers`       | —               | CSV of multiple resolvers; runs cross-resolver propagation comparison.                               |
| `--timeout`         | `5s`            | Per-operation timeout (each DNS query, each HTTPS GET, each handshake).                              |
| `--config`          | —               | Path to a JSON config file. Flag values override config values.                                      |
| `--only`            | —               | CSV of categories to include (`DNS`, `DNSSEC`, `Email`, `WWW`, `Subdomain`).                         |
| `--exclude`         | —               | CSV of categories to exclude.                                                                        |
| `--ids`             | —               | CSV of specific check IDs to include (e.g. `web.hsts,email.dmarc.record`).                           |
| `--severity`        | —               | Minimum severity to show: `info`, `pass`, `warn`, `fail`. `N/A` is always shown.                     |
| `--subdomains`      | off             | Enumerate subdomains via passive sources (hackertarget, anubis, threatcrowd, wayback) and probe each.|
| `--enable-ct`       | off             | Query Certificate Transparency via crt.sh.                                                           |
| `--enable-rbl`      | off             | Query DNSBLs (Spamhaus, Barracuda, SpamCop, SORBS, PSBL). Listings produce `WARN`, not `FAIL`.       |
| `--baseline`        | —               | Path to a previous JSON report; surface regressions against it.                                      |
| `--regression-only` | off             | With `--baseline`: exit non-zero only on NEW failures (ignores pre-existing `FAIL`s).                |

### Resolver forms

```bash
bedrock --resolver cloudflare        example.org     # 1.1.1.1:53 (UDP)
bedrock --resolver cloudflare-dot    example.org     # 1.1.1.1:853 (DoT, RFC 7858)
bedrock --resolver cloudflare-doh    example.org     # https://cloudflare-dns.com/dns-query (DoH, RFC 8484)
bedrock --resolver tls://1.1.1.1:853 example.org     # explicit DoT
bedrock --resolver https://dns.quad9.net/dns-query example.org   # explicit DoH
bedrock --resolvers cloudflare,google,quad9 example.org          # propagation check
```

Private-IP / loopback / metadata resolvers are rejected by default; set `BEDROCK_ALLOW_PRIVATE_RESOLVER=1` for hermetic test labs only.

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

## What bedrock checks

Each check returns one of: **PASS**, **WARN**, **FAIL**, **INFO**, **N/A**. Only `FAIL` affects the exit code.

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
| `dns.axfr.<ns>`          | Every authoritative NS refuses AXFR from the public Internet (RFC 5936 §6).      |

### DNSSEC

| Check ID                  | What it verifies                                                                |
|---------------------------|---------------------------------------------------------------------------------|
| `dnssec.signed`           | DS at parent and DNSKEY at apex.                                                |
| `dnssec.chain`            | RRSIG over DNSKEY and RRSIG over SOA cryptographically verify.                  |
| `dnssec.algorithm.dnskey` | DNSKEY algorithm is MUST / RECOMMENDED (RFC 8624 §3.1).                         |
| `dnssec.algorithm.ds`     | DS digest type is MUST (SHA-256 or SHA-384) (RFC 8624 §3.3).                    |
| `dnssec.nsec.type`        | Authenticated denial of existence: NSEC or NSEC3 with safe iterations.          |
| `dnssec.cds.published`    | CDS/CDNSKEY self-consistency (RFC 7344 §3).                                     |
| `dnssec.cds.matches_ds`   | CDS digests match the DS at the parent (RFC 7344 §4).                           |
| `dnssec.cds.signed`       | CDS RRset carries an RRSIG (RFC 7344 §4.1).                                     |

### Email

| Check ID                                     | What it verifies                                                                 |
|----------------------------------------------|----------------------------------------------------------------------------------|
| `email.spf.record`                           | Exactly one `v=spf1` TXT, valid syntax, terminating `-all` / `~all`.             |
| `email.dkim.selector.<name>`                 | Probes ~44 well-known selectors plus ESP-specific ones derived from SPF includes.|
| `email.dmarc.record`                         | `_dmarc` TXT exact-match `v=DMARC1`, strict `pct=`, `rua`/`ruf` scheme allowlist, duplicate-tag rejection. |
| `email.mtasts.txt`                           | `_mta-sts` TXT well-formed, `v=STSv1`, `id=` opaque token.                       |
| `email.mtasts.policy`                        | HTTPS fetch of `mta-sts.<domain>/.well-known/mta-sts.txt` (no redirects, TLS 1.2 floor, strict chain). |
| `email.tlsrpt.record`                        | `_smtp._tls` TXT, `v=TLSRPTv1`, valid `rua=` schemes.                            |
| `email.dane.<mx-host>`                       | TLSA under `_25._tcp.<mx>`; usage/selector/matching validation; DNSSEC AD-bit enforced. |
| `email.nullmx`                               | RFC 7505 null-MX declaration (`0 .`).                                            |
| `email.smtp.starttls.<mx-host>`              | Connect to each MX, EHLO, STARTTLS advertisement, handshake success + version.   |
| `email.arc.*`                                | ARC deployment guidance (DKIM availability, DMARC enforcement alignment).        |
| `email.rbl` (opt-in via `--enable-rbl`)      | Apex and MX IPs vs Spamhaus, Barracuda, SpamCop, SORBS, Surriel PSBL.            |
| `email.google_workspace_mx`                  | **INFO only** — detects legacy `ASPMX.L.GOOGLE.COM` layout and recommends migration to the new single `SMTP.GOOGLE.COM` MX. Silent for non-Google MX and domains already on the new form. |

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
| `bimi.gmail.dmarc`    | Gmail BIMI requirements: DMARC enforcement, `pct=100`, strict alignment.              |

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
| `web.redirect.<host>`                 | HTTP→HTTPS redirect chain (no protocol downgrade, no cross-host hop).               |
| `web.mixedcontent`                    | Apex body (first 1 MiB) scanned for `http://` src/href references.                  |
| `web.http2`                           | HTTP/2 advertised via ALPN (`h2`).                                                  |
| `web.http3`                           | HTTP/3 via Alt-Svc or direct QUIC dial.                                             |
| `web.ocsp.staple`                     | Server staples an OCSP response (RFC 6066 §8).                                      |
| `web.ocsp.responder`                  | Independent OCSP responder reachable.                                               |
| `web.crl.status`                      | CRL distribution point reachable; leaf not listed.                                  |
| `web.ct.lookup` (opt-in `--enable-ct`)| Certificate Transparency entries observed in crt.sh (RFC 9162).                     |
| `web.tls.fingerprint.ja3s.<host>`     | JA3S server TLS fingerprint (Salesforce, MD5 over cleartext ServerHello). `INFO`.   |
| `web.tls.fingerprint.ja4s.<host>`     | JA4S server TLS fingerprint (FoxIO; human-readable, SHA-256 truncated). `INFO`.     |

### Subdomain discovery (opt-in `--subdomains`)

Passive sources: **hackertarget**, **anubis**, **threatcrowd**, **wayback**. Each discovered host is probed for TLS reachability and certificate hygiene. Hostnames are allowlisted by regex (`^[a-zA-Z0-9._-]+$`) at source and at enumerate time; malformed lines are rejected pre-parse.

## Output

Output is JSON, always. When stdout is a terminal the JSON is colourised with ANSI; redirect or set `NO_COLOR=1` (or pass `--no-color`) for plain output. ANSI / C0 / C1 / DEL bytes in attacker-controlled evidence are replaced with `U+FFFD` so untrusted DNS TXT, certificate subjects, or HTTP header values cannot inject terminal escapes.

Schema:

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
      "rfc_refs": ["RFC 7489 §6.3"]
    }
  ]
}
```

### Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | No `FAIL` results. `WARN` and `INFO` do not affect exit code.    |
| 1    | At least one `FAIL` (or, with `--regression-only`, a new `FAIL`).|
| 2    | Usage error, invalid target, unreachable resolver, render error. |

## Regression tracking

```bash
bedrock example.org > baseline.json
# … later …
bedrock --baseline baseline.json --regression-only example.org
```

Duplicate IDs in a baseline file cause every current `FAIL` for that ID to be reported as a regression (fails closed — an ambiguous baseline cannot mask a regression).

## CI integration

```yaml
name: Domain audit
on:
  schedule: [{ cron: '0 6 * * *' }]
  workflow_dispatch:
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26' }
      - run: go install github.com/whitworth-org/bedrock@latest
      - uses: actions/cache@v4
        with:
          path: baseline.json
          key: bedrock-baseline-${{ github.repository }}
      - run: |
          bedrock example.org > current.json
          [ -f baseline.json ] && bedrock --baseline baseline.json --regression-only example.org
          mv current.json baseline.json
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

Hermetic tests bypass the resolver-IP denylist via `BEDROCK_ALLOW_PRIVATE_RESOLVER=1`.

## Project layout

```
main.go                     flag parsing, target normalisation, signal handling, exit codes
internal/registry/          check registration + parallel category execution + panic recovery
internal/probe/             DNS (miekg/dns) + HTTP primitives, named resolvers, DoT, DoH, SSRF-safe dialer
internal/probe/tlsfp/       Native ServerHello parser + JA3S/JA4S fingerprint compute (no third-party deps)
internal/report/            Result type + JSON renderer + ANSI colouring + terminal sanitisation
internal/cli/               result filters + JSON config loader
internal/baseline/          baseline diff for --baseline / --regression-only (fail-closed on duplicate IDs)
internal/version/           build-time version, populated via -ldflags
internal/discover/          passive subdomain enumeration (HTTPS-only, hostname allowlist)
internal/checks/dns/        DNS checks
internal/checks/dnssec/     DNSSEC chain, algorithms, NSEC, CDS/CDNSKEY
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
- JA3S and JA4S **server** fingerprints (`web.tls.fingerprint.ja3s.<host>`, `web.tls.fingerprint.ja4s.<host>`) are computed natively by capturing the cleartext ServerHello off the wire — stdlib `crypto/tls` does not expose handshake bytes directly, so a `recordingConn` wraps the underlying `net.Conn` during a stdlib handshake. Client-side JA3/JA4 of bedrock's own outbound TLS is not emitted (and not interesting to most users — bedrock is the client). Negotiated EC curve is detected via probe-and-detect (suppressed under `--no-active`).
- The DKIM check probes a fixed selector list (44 well-known + ESP-specific derived from SPF includes). Custom per-tenant selectors (e.g. HubSpot's `hs1-<id>-<domain>` pattern) cannot be discovered without the customer ID; NSEC walking under `_domainkey` is deferred.
- VMC chain validation uses `ExtKeyUsageAny` because the BIMI EKU OIDs are not in the Go standard library root-usage table. The BIMI-specific OID gate (`classifyMarkCert`) runs *before* chain verification.
- `--enable-rbl` and `--enable-ct` issue live queries to third-party services; do not enable them for casual or repeated scans of domains you do not operate.
- The `--resolvers` propagation check returns the first successful answer; divergence appears as a `dns.propagation` evidence string rather than a separate check.

---

*Inspired by [hardenize.com](https://www.hardenize.com).*
