# bedrock

A single-binary command-line auditor for a domain's **DNS**, **DNSSEC**, **Email** (incl. BIMI), and **Web / TLS** posture. Every finding cites an RFC section; every `FAIL` ships a copy-pasteable remediation snippet.

- Single static binary, no runtime dependencies.
- All logic is local: no upload, no account, no third-party telemetry (optional third-party lookups — crt.sh, DNSBLs — are off by default and must be enabled explicitly).
- Deterministic output: results are sorted by `(category, id)`; categories run in parallel.
- Safe by default: the HTTP client denylists RFC 1918 / loopback / link-local / ULA / CGNAT / cloud-metadata addresses to neutralise SSRF via attacker-influenced DNS.
- Exit code reflects posture (`0` clean, `1` at least one `FAIL`, `2` usage error).

## Install

Requires **Go 1.26** or newer.

```bash
git clone https://github.com/rwhitworth/bedrock.git
cd bedrock
make build
./bedrock --version
```

Install to `$GOPATH/bin`:

```bash
make install
```

Pre-built binaries for linux/macOS/windows × amd64/arm64 are produced by `make release-check` (goreleaser snapshot) or cut by the release workflow on tag push.

## Quick start

```bash
bedrock example.org                      # default audit, text output
bedrock --json example.org | jq .        # canonical JSON
bedrock --md   example.org > report.md   # Markdown table
bedrock --no-active example.org          # DNS-only — no outbound TCP
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
| `--json`            | off             | Emit the report as JSON on stdout. Mutually exclusive with `--md`.                                   |
| `--md`              | off             | Emit a GitHub-flavoured Markdown table. Mutually exclusive with `--json`.                            |
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

### DNS — RFC 1034/1035, 1912, 2181, 2308, 3596, 5936

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

### DNSSEC — RFC 4033/4034/4035, 5155, 7344, 8624

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

### Email — RFC 7208 (SPF), 6376 (DKIM), 7489 (DMARC), 8461 (MTA-STS), 8460 (TLS-RPT), 7672 (DANE), 7505 (Null MX), 3207 (STARTTLS), 8617 (ARC), 5782 (DNSBL)

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

### BIMI (reported under the Email category) — BIMI Group draft + Gmail requirements

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

### Web / TLS — RFC 5280, 6797 (HSTS), 7525 / BCP 195 (TLS), 8659 (CAA), 6962 / 9162 (CT), 9113 (HTTP/2), 9114 (HTTP/3), 6960 (OCSP), 6125 (SAN)

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

### Subdomain discovery (opt-in `--subdomains`)

Passive sources: **hackertarget**, **anubis**, **threatcrowd**, **wayback**. Each discovered host is probed for TLS reachability and certificate hygiene. Hostnames are allowlisted by regex (`^[a-zA-Z0-9._-]+$`) at source and at enumerate time; malformed lines are rejected pre-parse.

## Output

### Text (default)

Colourised when stdout is a terminal; plain when redirected. ANSI / C0 / C1 / DEL bytes in attacker-controlled evidence are replaced with `U+FFFD`.

### JSON (canonical)

Text and Markdown are projections of the same `[]Result`. Schema:

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

### Markdown

GitHub-flavoured table. Multi-line `remediation` renders inside a fenced ` ```bash ` block; meta-characters are backslash-escaped; table-breaking pipes are neutralised.

### Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | No `FAIL` results. `WARN` and `INFO` do not affect exit code.    |
| 1    | At least one `FAIL` (or, with `--regression-only`, a new `FAIL`).|
| 2    | Usage error, invalid target, unreachable resolver, render error. |

## Regression tracking

```bash
bedrock --json example.org > baseline.json
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
      - run: go install github.com/rwhitworth/bedrock@latest
      - uses: actions/cache@v4
        with:
          path: baseline.json
          key: bedrock-baseline-${{ github.repository }}
      - run: |
          bedrock --json example.org > current.json
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
internal/report/            Result type + text / JSON / Markdown renderers + terminal sanitisation
internal/cli/               result filters + JSON config loader
internal/baseline/          baseline diff for --baseline / --regression-only (fail-closed on duplicate IDs)
internal/version/           build-time version, populated via -ldflags
internal/discover/          passive subdomain enumeration (HTTPS-only, hostname allowlist)
internal/checks/dns/        DNS checks
internal/checks/dnssec/     DNSSEC chain, algorithms, NSEC, CDS/CDNSKEY
internal/checks/email/      SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE, Null MX, STARTTLS, ARC, RBL, Google Workspace MX
internal/checks/bimi/       BIMI TXT, SVG Tiny PS, VMC + RFC 3709 logotype ASN.1
internal/checks/web/        TLS profile, certs, HSTS, headers, cookies, CAA, redirect, mixed content, CT, OCSP, CRL, EC curves, HTTP/2, HTTP/3
testdata/golden/            integration-test fixtures
```

## License

Bedrock is distributed under the **MIT License** (see `LICENSE`). MIT was chosen for three reasons:

1. **Permissive**: security teams can drop bedrock into proprietary pipelines without legal review overhead. This is the primary use case.
2. **Short and unambiguous**: the full license fits on one page and is already understood by every corporate policy engine.
3. **Go-ecosystem convention**: `miekg/dns`, `quic-go`, and the `golang.org/x/*` stack are all permissive-licensed; MIT matches without introducing copyleft friction.

If an explicit patent grant or trademark clause is required for your adoption context, **Apache-2.0** is a drop-in upgrade and would not meaningfully constrain downstream use. GPL/AGPL were intentionally declined: bedrock is an observational tool whose value depends on unrestricted deployment into closed environments.

## Limitations

- Output is English only.
- Stdlib `crypto/tls` does not expose received TLS extensions; JA3/JA4 server fingerprinting is therefore not implemented. Negotiated EC curve is detected via probe-and-detect (suppressed under `--no-active`).
- The DKIM check probes a fixed selector list (44 well-known + ESP-specific derived from SPF includes). Custom per-tenant selectors (e.g. HubSpot's `hs1-<id>-<domain>` pattern) cannot be discovered without the customer ID; NSEC walking under `_domainkey` is intentionally deferred.
- VMC chain validation uses `ExtKeyUsageAny` because the BIMI EKU OIDs are not in the Go standard library root-usage table. The BIMI-specific OID gate (`classifyMarkCert`) runs *before* chain verification.
- `--enable-rbl` and `--enable-ct` issue live queries to third-party services; do not enable them for casual or repeated scans of domains you do not operate.
- The `--resolvers` propagation check returns the first successful answer for normal lookups; divergence is surfaced via a separate `dns.propagation` evidence string rather than as an independent check.

---

*Inspired by [hardenize.com](https://www.hardenize.com).*
