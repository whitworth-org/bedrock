# Security Policy

`bedrock` is a security-auditing tool. Reports of security issues in `bedrock`
itself are taken seriously and handled privately.

## Supported versions

Only the latest minor release line receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's
**Private Vulnerability Reporting**:

1. Go to https://github.com/whitworth-org/bedrock/security/advisories/new
2. Or, from the repository, click **Security** → **Report a vulnerability**.

This keeps the report private to the maintainer until a fix is published.

Please include:

- A clear description of the issue and its impact.
- Reproduction steps, including the exact `bedrock` version
  (`bedrock --version`) and command-line arguments.
- Any proof-of-concept input or target (use only assets you are
  authorized to test).

## What to expect

- Acknowledgement within **3 business days** of the report.
- An initial triage assessment within **10 business days**.
- Coordinated disclosure once a fix is available; a GitHub Security
  Advisory will be published and a CVE requested where applicable.

## Out of scope

- Findings that depend on attacker-controlled command-line arguments
  passed by the operator (e.g. self-targeting flags).
- Issues in third-party services that `bedrock` only queries
  (DNS resolvers, BIMI logo hosts, CT logs, etc.).
- Vulnerabilities in dependencies that are already tracked upstream
  and have an in-flight fix; please report those upstream.

## Please do not

- Open a public GitHub issue, pull request, or discussion describing
  the vulnerability before it is fixed.
- Run intrusive tests against systems you do not own or have explicit
  permission to test.
