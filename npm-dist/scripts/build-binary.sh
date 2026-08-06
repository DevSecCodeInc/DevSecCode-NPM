#!/usr/bin/env bash
# Legacy placeholder. The Core migration no longer builds a PyInstaller
# scanner binary from this repository for npm distribution.

set -euo pipefail

cat >&2 <<'MSG'
build-binary.sh is retired for the Core-backed npm package.

Build DevSecCode-Core backend artifacts in the Core repository, then run:
  bash npm-dist/scripts/assemble-platform-pkg.sh <target> <core-artifact-dir>
MSG

exit 2
