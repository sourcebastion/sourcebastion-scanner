# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.7.x   | Yes       |
| < 1.7   | No        |

## Reporting a Vulnerability

**Do not report security vulnerabilities via public GitHub issues.**

Use [GitHub private vulnerability reporting](https://github.com/sourcebastion/sourcebastion-scanner/security/advisories/new).
It is enabled for this repository and keeps the report private by default.
Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

Reports are read and triaged on a best-effort basis. No acknowledgement or fix
window is promised: an unowned deadline would be misleading. Status updates
and disclosure timing are coordinated in the private advisory.

## Responsible Disclosure

We follow responsible disclosure practices. After a fix is released, you are welcome to publish details of the vulnerability. Please coordinate timing with us so users have time to update.

## Scope

In scope:
- ez-appsec CLI (`ez_appsec/` package)
- GitHub Actions workflow template (`.github/workflows/github-scan.yml`)
- GitLab CI template (`gitlab/scan.yml`)
- Docker images (`ghcr.io/ez-appsec/ez-appsec`)

Out of scope:
- Vulnerabilities in the intentionally-vulnerable test projects used for integration testing
- Vulnerabilities in upstream scanners (gitleaks, semgrep, kics, grype) — report those to their respective maintainers
