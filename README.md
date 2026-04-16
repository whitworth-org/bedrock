# bedrock

A single-binary command-line auditor for a domain's **DNS**, **DNSSEC**, **Email**, and **WWW (TLS/headers/cookies)** posture. Inspired by [Hardenize](https://www.hardenize.com), but local: no upload, no account, no third-party telemetry. Every failed check ships a copy-pasteable record/header to fix it, and every result cites the RFC section that defines the requirement.

```
$ bedrock example.org
DNS
  PASS  dns.zone.serial          SOA serial monotonically advances
  PASS  dns.ns.count             3 authoritative NSes (>= 2 required)
  WARN  dns.zone.soa.minimum     SOA MINIMUM 300 < 3600 (RFC 2308)
Email
  PASS  email.spf.lookup         v=spf1 include:_spf.google.com ~all
  FAIL  email.dmarc.policy       p=none — no enforcement
        fix: _dmarc.example.org. IN TXT "v=DMARC1; p=quarantine; rua=mailto:..."
  ...
WWW
  PASS  web.tls.profile          matches "intermediate" profile
  PASS  web.cert.chain           leaf + intermediates chain to a trusted root
  ...

53 checks · 41 PASS · 6 WARN · 5 FAIL · 1 N/A
```

## What it checks

| Category   | Specs                                                                                 | Examples                                                                  |
|------------|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **DNS**    | RFC 1034/1035, 1912, 2181, 2308, 3596, 5936                                           | NS count, SOA hygiene, AAAA, AXFR refusal, CNAME-at-apex, dangling DNS    |
| **DNSSEC** | RFC 4033/4034/4035, 5155, 6605, 8624                                                  | DS↔DNSKEY chain, RRSIG verification, NSEC3 iterations, algorithm strength |
| **Email**  | RFC 7208 (SPF), 6376 (DKIM), 7489 (DMARC), 8460 (TLS-RPT), 8461 (MTA-STS), 7672 (DANE), 7505 (Null MX), 3207 (STARTTLS), plus BIMI Group draft + Gmail vendor requirements | record presence and validity, DMARC enforcement, MX STARTTLS handshake, TLSA matching, `default._bimi` TXT, SVG Tiny PS conformance, VMC PEM with logotype OID |
| **WWW**    | RFC 7525 (BCP 195), 5280, 6797 (HSTS), 8659 (CAA) plus W3C/WHATWG specs               | TLS profile match, full chain, expiry, key strength, HSTS, CSP, cookies, mixed content, HTTP→HTTPS redirect |

Each check returns one of: **PASS**, **WARN**, **FAIL**, **INFO**, **N/A**. Only **FAIL** affects the exit code.

## Install

`bedrock` is a single static binary built from this repository. Requires **Go 1.26** or newer.

```bash
git clone <this repo> bedrock
cd bedrock
go build -o bedrock .
./bedrock example.org
```

To install the binary on `$PATH`:

```bash
go build -o "$(go env GOPATH)/bin/bedrock" .
```

To install the man page (macOS / Linux):

```bash
sudo install -m 644 man/bedrock.1 /usr/local/share/man/man1/
```

## Usage

```
bedrock [flags] <domain>
```

| Flag                | Default            | Effect                                                                                                |
|---------------------|--------------------|-------------------------------------------------------------------------------------------------------|
| `--version`         | —                  | Print the version line and exit.                                                                     |
| `--json`            | off                | Emit the report as JSON to stdout. `target`, `results[]` schema.                                     |
| `--md`              | off                | Emit the report as GitHub-flavored Markdown.                                                          |
| `--no-active`       | off (probes on)    | Skip outbound TCP beyond DNS — no SMTP, no HTTPS, no VMC fetch.                                       |
| `--resolver`        | system resolver    | `host:port`, preset (`cloudflare`/`google`/`quad9`/`opendns`), `<preset>-dot`/`-doh`, `tls://`, `https://`. |
| `--resolvers`       | —                  | CSV of multiple resolvers; runs propagation comparison (e.g. `cloudflare,google,quad9`).             |
| `--timeout`         | `5s`               | Per-operation timeout (each DNS query, each HTTPS GET, each handshake).                              |
| `--config`          | —                  | Path to a JSON config file (flag values override config values).                                     |
| `--only`            | —                  | CSV of categories to include (e.g. `Email,WWW`).                                                     |
| `--exclude`         | —                  | CSV of categories to exclude.                                                                         |
| `--ids`             | —                  | CSV of specific check IDs to include.                                                                 |
| `--severity`        | —                  | Minimum severity to show: `info`/`pass`/`warn`/`fail`. `N/A` always shown.                           |
| `--enable-ct`       | off                | Look up Certificate Transparency entries via crt.sh (third-party).                                    |
| `--enable-rbl`      | off                | Query third-party DNSBLs (Spamhaus, Barracuda, SpamCop, SORBS, PSBL).                                |
| `--subdomains`      | off                | Enumerate subdomains via passive sources and probe each.                                              |
| `--baseline`        | —                  | Path to a previous JSON report; surface regressions vs that baseline.                                 |
| `--regression-only` | off                | With `--baseline`: exit non-zero only on NEW failures vs baseline.                                   |

`<domain>` may be an IDN; it is normalised to ASCII (Punycode) and lowercased. A trailing dot is stripped.

### Resolver examples

```bash
bedrock --resolver cloudflare example.org           # 1.1.1.1:53 (UDP)
bedrock --resolver cloudflare-dot example.org       # 1.1.1.1:853 (DoT)
bedrock --resolver cloudflare-doh example.org       # https://cloudflare-dns.com/dns-query (DoH)
bedrock --resolver tls://1.1.1.1:853 example.org    # explicit DoT
bedrock --resolvers cloudflare,google,quad9 example.org  # propagation check
```

### JSON config example

```json
{
  "resolver": "cloudflare-doh",
  "timeout": "10s",
  "only": ["Email", "WWW"],
  "severity": "warn",
  "enable_ct": true
}
```

```bash
bedrock --config audit.json example.org
```

## Output formats

The JSON output is the source of truth — text and Markdown are projections of the same `[]Result`. Schema:

```json
{
  "target": "example.org",
  "results": [
    {
      "id": "email.dmarc.policy",
      "category": "Email",
      "title": "DMARC policy is enforced",
      "status": "FAIL",
      "evidence": "p=none observed in _dmarc.example.org TXT",
      "remediation": "_dmarc.example.org. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org\"",
      "rfc_refs": ["RFC 7489 §6.3"]
    }
  ]
}
```

Pipe through `jq` for ad-hoc filtering:

```bash
bedrock --json example.org | jq '.results[] | select(.status == "FAIL")'
```

Render to a file for review:

```bash
bedrock --md example.org > example.org.report.md
```

## Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | No `FAIL` results. WARNs and INFOs do not affect exit code.      |
| 1    | At least one `FAIL`.                                             |
| 2    | Usage error, invalid target, unreachable resolver, render error. |

This makes `bedrock` safe to drop into CI:

```yaml
- name: Audit production domain
  run: bedrock --json example.org > posture.json
```

## Active vs passive

By default the tool performs **active probes**: HTTPS GETs against the apex and `www`, an SMTP STARTTLS handshake against each MX, an HTTPS fetch of the MTA-STS policy, and an HTTPS fetch of the BIMI VMC. Passing `--no-active` confines the run to DNS lookups only — useful for auditing third-party domains where you don't want to make TCP connections.

`--no-active` results in `N/A` for every check that requires a connection. The check still appears in the report so the schema is stable.

## Reproducible runs

DNS answers vary by recursive resolver (split-horizon DNS, NXDOMAIN rewriting, geo-routed CDNs). For deterministic output, pin the resolver:

```bash
bedrock --resolver 1.1.1.1:53 example.org
bedrock --resolver 9.9.9.9:53 example.org
```

The check ordering and category groupings are deterministic; categories run in parallel but results are sorted by `(category, id)` before rendering.

## Examples

```bash
# Basic audit, terminal output (color when stdout is a TTY)
bedrock whitworth.org

# JSON for piping into jq, dashboards, or alerting
bedrock --json whitworth.org | jq '.results | group_by(.category) | map({category: .[0].category, fails: map(select(.status=="FAIL")) | length})'

# DNS-only mode for a third-party domain you don't want to probe
bedrock --no-active partner.example.com

# Loosen the timeout for a slow nameserver
bedrock --timeout 15s slow.example.com

# Write a Markdown report to disk
bedrock --md example.org > posture.md

# Pin a recursive resolver, then check that 3 resolvers agree on what they serve
bedrock --resolvers cloudflare,google,quad9 example.org

# Enumerate subdomains via passive sources, probe each
bedrock --subdomains example.org

# Enable Certificate Transparency lookups (third-party crt.sh API)
bedrock --enable-ct example.org

# Compare against yesterday's report; exit non-zero only on NEW failures
bedrock --json example.org > today.json
bedrock --baseline yesterday.json --regression-only example.org
```

### CI/CD regression gate (GitHub Actions example)

```yaml
name: Domain audit
on:
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch:
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26' }
      - run: go install ./...
      - name: Restore baseline
        uses: actions/cache@v4
        with:
          path: baseline.json
          key: granite-baseline-${{ github.repository }}
      - name: Audit
        run: |
          bedrock --json example.org > current.json
          if [ -f baseline.json ]; then
            bedrock --baseline baseline.json --regression-only example.org
          fi
          mv current.json baseline.json
```

## Project layout

```
main.go                       flag parsing, target normalization, exit codes
internal/registry/            check registration + parallel category execution
internal/probe/               DNS (miekg/dns) + HTTP primitives, named resolvers, DoT, DoH, multi-resolver
internal/report/              Result type + text/JSON/Markdown renderers
internal/cli/                 result filters + JSON config loader
internal/baseline/            baseline diff for --baseline / --regression-only
internal/version/             build-time version, populated via -ldflags
internal/discover/            passive subdomain enumeration (lifted from subfinder, MIT)
internal/checks/dns/          RFC 1034/35, 1912, 2181, 2308, 3596, 5936 checks
internal/checks/dnssec/       RFC 4033-35, 5155, 6605, 8624 + CDS/CDNSKEY (RFC 7344, 8078)
internal/checks/email/        SPF, DKIM (40+ ESP selectors), DMARC, MTA-STS, TLS-RPT, DANE,
                              Null MX, STARTTLS, ARC (RFC 8617), DNSBL/RBL (RFC 5782)
internal/checks/web/          TLS profile, certs, HSTS, CSP, cookies, CAA, mixed content,
                              CT (crt.sh + SCT count), OCSP staple/responder, CRL,
                              EC curves, HTTP/2 ALPN, HTTP/3 (QUIC)
internal/checks/bimi/         BIMI TXT, SVG Tiny PS, VMC + CMC + RFC 3709 ASN.1 logotype decode
testdata/golden/              integration-test fixtures (regenerable with `go test -update`)
```

## Limitations

- Output is English only.
- Stdlib `crypto/tls` does not expose received TLS extensions; JA3/JA4 server fingerprinting is therefore not implemented (it would require `refraction-networking/utls`). Negotiated EC curve is detected via probe-and-detect (`--no-active` skips this).
- The DKIM check probes ~44 well-known selectors plus ESP-specific ones detected from SPF includes (Salesforce, Mailgun, Microsoft 365, etc.). Custom per-tenant selectors (e.g. HubSpot's `hs1-<id>-<domain>` pattern) cannot be discovered without the customer ID; NSEC walking under `_domainkey` for DNSSEC-NSEC zones is intentionally deferred.
- VMC chain validation uses `ExtKeyUsageAny` because the BIMI EKU OID (`1.3.6.1.5.5.7.3.31` for VMC, `1.3.6.1.5.5.7.3.32` for CMC) is not in the Go standard library root usage table. The logotype extension is now decoded via real RFC 3709 ASN.1 (replacing the previous SHA-256 byte-search).
- `--enable-rbl` issues live queries to third-party DNSBL providers; do not enable it for casual or repeated scans of domains you do not operate.
- `--enable-ct` queries crt.sh; for high-volume monitoring use a private CT log mirror instead.
- The `--resolvers` propagation check returns the first successful answer for normal lookups; the divergence comparison is surfaced separately as a `dns.propagation` evidence string when a future check consumes it.
