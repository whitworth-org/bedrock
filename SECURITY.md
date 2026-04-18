# Security Policy

Vulnerabilities in `bedrock` are handled privately.

## Supported versions

Only the latest minor release line receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting:
https://github.com/whitworth-org/bedrock/security/advisories/new
(or, in the repo, **Security** → **Report a vulnerability**). The report stays private to the maintainer until a fix is published.

Include:

- The issue and its impact.
- Reproduction steps, plus the exact version (`bedrock --version`) and CLI flags used.
- Any PoC input or target (only against assets you are authorized to test).

## What to expect

- Acknowledgement within **3 business days**.
- Triage within **10 business days**.
- Coordinated disclosure once a fix is ready, with a GitHub Security Advisory (and a CVE, if it qualifies).

## Out of scope

- Findings that require the operator to pass attacker-controlled CLI flags (i.e. self-targeting).
- Issues in third-party services `bedrock` only queries (DNS resolvers, BIMI logo hosts, CT logs).
- Dependency CVEs already tracked upstream — report those upstream.

## Do not

- Open a public issue, PR, or discussion about the vulnerability before it is fixed.
- Test against systems you do not own or have explicit permission to test.
