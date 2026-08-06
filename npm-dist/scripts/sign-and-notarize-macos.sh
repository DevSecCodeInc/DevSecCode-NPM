#!/usr/bin/env bash
# Legacy placeholder. macOS signing/notarization now belongs to the
# DevSecCode-Core backend artifact before npm platform package assembly.

set -euo pipefail

cat >&2 <<'MSG'
sign-and-notarize-macos.sh is retired for the Core-backed npm package.

Sign and notarize the macOS dsc-backend artifact in DevSecCode-Core, then
assemble the npm platform package from the verified public/starter Core artifact output.
MSG

exit 2
