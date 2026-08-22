# DevSecCode Scanner

> Gamified local SAST. Find SQL injection, hardcoded secrets, XSS, and other
> CWE classics in your codebase — no SaaS dashboard, no Python toolchain, no
> CI gate required.

[![npm version](https://img.shields.io/npm/v/@devseccode/scanner.svg?color=cb3837)](https://www.npmjs.com/package/@devseccode/scanner)
[![npm downloads](https://img.shields.io/npm/dw/@devseccode/scanner.svg?color=cb3837)](https://www.npmjs.com/package/@devseccode/scanner)
[![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-blue)](#supported-platforms)
[![license](https://img.shields.io/badge/license-Proprietary-orange)](./LICENSE.txt)

![demo](./docs/demo.gif)

## Try it now

```bash
npx @devseccode/scanner hunt .
```

No signup and no separate Core install. npm installs the parent CLI package
plus the matching platform public/starter Core artifact package automatically;
your source code stays on your machine.

## What it does

- **High-precision SAST rules** across 9 CWE families — SQL injection,
  XSS, command injection, path traversal, hardcoded secrets, broken
  crypto, cleartext HTTP, XXE, and CSRF — for Python, JavaScript /
  TypeScript, Go, Java, and Rust.
- **Infrastructure scanning** for Dockerfiles and Kubernetes manifests.
- **Gamified hunts** — XP, levels, achievements, streaks, quests, and shield
  scores designed to make repeated scanning useful.
- **Standard outputs** — SARIF (for GitHub code scanning), JUnit (for
  CI test runners), JSON (for downstream tooling), and a colorized
  terminal report.
- **Single npm install** — the parent package owns the Node CLI and local UX;
  the matching optional platform package carries the DevSecCode public/starter
  Core backend artifact. No Python install or separate Core checkout is required.

## Install

```bash
# One-shot (recommended for first-timers):
npx @devseccode/scanner hunt .

# Global:
npm install -g @devseccode/scanner
devseccode --help                 # or `dsc` for short

# Project-local (recommended for CI):
npm install --save-dev @devseccode/scanner
npx devseccode scan . --format sarif --output devseccode.sarif
```

## Common commands

```bash
devseccode hunt .                                       # gamified scan
devseccode scan . --format sarif --output out.sarif     # CI-friendly scan
devseccode scan . --format json --output out.json       # tooling-friendly
devseccode list-rules                                   # what's in the public ruleset
devseccode explain deva.cwe-89.python-sql-injection     # rule details
devseccode init                                         # drop a .dsc.yml
```

`devseccode --help` lists every subcommand; `devseccode <subcommand>
--help` documents its flags.

## Use in GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload below

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

The SARIF output lights up GitHub's native **Security** tab — the same
place CodeQL findings appear.

## Supported platforms

| Platform                              | Status                                  |
| ------------------------------------- | --------------------------------------- |
| macOS Apple Silicon (`darwin-arm64`)  | Public/starter Core artifact package   |
| Linux x64                             | Public/starter Core artifact package (glibc; not Alpine / musl) |
| Linux arm64                           | Planned after Core publishes and validates this target |
| Windows x64                           | Public/starter Core artifact package   |
| Intel Mac (`darwin-x64`)              | Not in this release — GitHub retired the macos-13 runner pool |

For Alpine / musl Linux, run from a Debian or Ubuntu sidecar in CI.

## Privacy

The scanner is **fully local**. There is no telemetry, no analytics, and no
code upload. The CLI starts or reuses the packaged local public/starter Core
backend and talks to it through authenticated loopback `/v1/*` routes.

## The DevSecCode IDE

The npm scanner is intentionally focused — it ships only a curated public
starter rule subset and basic outputs as a free, frictionless entry point. The
full **DevSecCode IDE** keeps the complete rule library, compliance
mapping (NIST 800-53, HIPAA, FedRAMP, SOC 2, ISO 27001, PCI DSS, and
more), SBOM and dependency CVE enrichment, audit-grade signed
evidence packages, POA&M generation, git-history credential
scanning, and guided remediation workflows.

→ [devseccode.com](https://devseccode.com)

## Project layout

```
engine/                Legacy scanner implementation retained during migration
npm-dist/              npm packaging for the Core-backed CLI
  packages/scanner/    Parent Node CLI/UX package (@devseccode/scanner)
  packages/scanner-*/  Per-platform public/starter Core artifact packages
  scripts/             Public/starter Core artifact assembly and publish helpers
.github/workflows/     Manual candidate and exact-version promotion pipelines
resources/sample-vulns/ Tiny fixtures the test scripts scan as a smoke check
```

## Contributing

Bug reports and feature requests are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md).
Code PRs are not accepted under the current license; the same document
explains why.

## License

Proprietary — All Rights Reserved. See [LICENSE.txt](./LICENSE.txt) for
the full End User License Agreement. The scanner is free to use locally
for your internal business purposes; redistribution, modification, and
use to build a competing product are not permitted.
