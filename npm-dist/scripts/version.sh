#!/usr/bin/env bash
# Echo the npm wrapper package version. The Core engine version is independent
# and is reported at runtime from Core /v1/meta.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
node -e 'process.stdout.write(`${require(process.argv[1]).version}\n`)' \
  "$ROOT/npm-dist/packages/scanner/package.json"
