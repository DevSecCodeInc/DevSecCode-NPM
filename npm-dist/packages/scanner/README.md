# @devseccode/scanner

> Gamified local SAST backed by packaged DevSecCode public/starter Core
> artifacts. Find SQL injection, hardcoded secrets, XSS, and other CWE
> classics with one npm install.

## Try it now

```bash
npx @devseccode/scanner hunt .
```

No signup and no separate Core install. npm installs the matching platform
public/starter artifact automatically; your source code stays on your machine.

## What it does

- **9 high-precision CWE rule families** — SQL injection, XSS, command
  injection, path traversal, hardcoded secrets, broken crypto, cleartext
  HTTP, XXE, and CSRF — across Python, JavaScript / TypeScript, Go,
  Java, and Rust.
- **Infrastructure scanning** for Dockerfiles and Kubernetes manifests.
- **Gamified TUI** (`hunt`) — a scan map, encounter cards, and a triage
  flow designed to be run more than once.
- **Standard outputs** — SARIF (for GitHub Code Scanning), JUnit (for
  CI test runners), JSON (for downstream tooling), and a colorized
  terminal report.
- **Single npm install** — the parent package carries the Node CLI/UX and the
  matching optional platform package carries the public/starter Core backend
  artifact.

## Install

```bash
# One-shot:
npx @devseccode/scanner hunt .

# Global:
npm install -g @devseccode/scanner
devseccode --help                # or `dsc` for short

# Project-local (recommended for CI):
npm install --save-dev @devseccode/scanner
npx devseccode scan . --format sarif --output devseccode.sarif
```

## Common commands

```bash
devseccode hunt .                                       # gamified scan
devseccode scan . --format sarif --output out.sarif     # CI-friendly
devseccode scan . --format json --output out.json       # tooling-friendly
devseccode list-rules                                   # public ruleset
devseccode explain deva.cwe-89.python-sql-injection     # rule details
devseccode init                                         # drop a .dsc.yml
```

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx @devseccode/scanner scan . --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

The SARIF output lights up GitHub's native **Security** tab.

## Supported platforms

The parent package declares one public/starter Core-artifact
`optionalDependencies` entry per platform. `npm` installs only the package that
matches your machine; the rest are skipped by the `os` / `cpu` fields.

| Target                                | Package                                 |
| ------------------------------------- | --------------------------------------- |
| macOS Apple Silicon (`darwin-arm64`)  | `@devseccode/scanner-darwin-arm64`      |
| Linux x64                             | `@devseccode/scanner-linux-x64`         |
| Windows x64                           | `@devseccode/scanner-win32-x64`         |

Linux arm64 and Intel Mac (`darwin-x64`) are planned expansion targets and are
not published in this release. Alpine / musl Linux is not supported; run from a
Debian or Ubuntu sidecar in CI.

## Privacy

`devseccode hunt` and `devseccode scan` are fully local. No code,
telemetry, or analytics leaves your machine.

## The DevSecCode IDE

This package is intentionally focused — a curated rule subset and basic
outputs, free and frictionless to install. The full **DevSecCode IDE**
adds the complete rule library, compliance mapping (NIST 800-53,
HIPAA, FedRAMP, SOC 2, ISO 27001, PCI DSS, and more), SBOM and
dependency CVE enrichment, audit-grade signed evidence packages,
POA&M generation, git-history credential scanning, and guided
remediation workflows.

→ [devseccode.com](https://devseccode.com)

## Repository

Source, issue tracker, and changelog:
[github.com/DevSecCode/DevSecCode-NPM](https://github.com/DevSecCode/DevSecCode-NPM)

## License

Proprietary — All Rights Reserved. Installing or using this package
means you accept the DevSecCode End User License Agreement in
[LICENSE](./LICENSE). Redistribution, modification, reverse
engineering, and use to build a competing product are not permitted.
