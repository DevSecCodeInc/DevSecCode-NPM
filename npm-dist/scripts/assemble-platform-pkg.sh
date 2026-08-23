#!/usr/bin/env bash
# Assemble a platform optional dependency from DevSecCode Core public/starter
# release artifacts. The package contains the approved public Core artifact
# archive plus devseccode-core-artifacts.json; the parent @devseccode/scanner
# package owns the public CLI and starts the packaged backend through
# @devseccode/core-launcher.
#
# Usage:
#   bash npm-dist/scripts/assemble-platform-pkg.sh <target> <core-artifact-dir>
#
# Where <target> is one of darwin-arm64, linux-x64, linux-arm64, win32-x64.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
NPM_DIST="$ROOT/npm-dist"

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <target> <core-artifact-dir>" >&2
  exit 2
fi

TARGET="$1"
CORE_ARTIFACT_DIR="$2"

case "$TARGET" in
  darwin-arm64|linux-x64|linux-arm64|win32-x64) ;;
  *) echo "assemble-platform-pkg: unknown or unsupported target '$TARGET'" >&2; exit 2 ;;
esac

PKG_DIR="$NPM_DIST/packages/scanner-$TARGET"
MANIFEST="$CORE_ARTIFACT_DIR/devseccode-core-artifacts.json"
SIGNATURE="$MANIFEST.sig"
if [[ ! -d "$PKG_DIR" ]]; then
  echo "assemble-platform-pkg: package dir $PKG_DIR not found" >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "assemble-platform-pkg: public/starter Core artifact manifest missing: $MANIFEST" >&2
  exit 1
fi
if [[ ! -f "$SIGNATURE" ]]; then
  echo "assemble-platform-pkg: signed Core artifact manifest missing: $SIGNATURE" >&2
  exit 1
fi

node "$NPM_DIST/scripts/validate-public-core-artifact.js" "$MANIFEST" "$CORE_ARTIFACT_DIR" "$TARGET"

ARCHIVE_INFO="$(node - "$MANIFEST" "$TARGET" <<'JS'
const fs = require("node:fs");
const manifest = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const target = process.argv[3];
const artifact = (manifest.artifacts || []).find((item) => item.target === target);
if (!artifact) {
  console.error(`target ${target} missing from public/starter Core artifact manifest`);
  process.exit(1);
}
if (!artifact.filename || !artifact.sha256 || !artifact.sizeBytes || !artifact.binaryRelativePath) {
  console.error(`target ${target} artifact entry is incomplete`);
  process.exit(1);
}
process.stdout.write(`${artifact.filename}\n${artifact.binaryRelativePath}`);
JS
)"
ARCHIVE_NAME="$(printf '%s\n' "$ARCHIVE_INFO" | sed -n '1p')"
BINARY_RELATIVE_PATH="$(printf '%s\n' "$ARCHIVE_INFO" | sed -n '2p')"

ARCHIVE_SRC="$CORE_ARTIFACT_DIR/$ARCHIVE_NAME"
if [[ ! -f "$ARCHIVE_SRC" ]]; then
  echo "assemble-platform-pkg: public/starter Core artifact archive missing: $ARCHIVE_SRC" >&2
  exit 1
fi

node - "$MANIFEST" "$CORE_ARTIFACT_DIR" "$TARGET" <<'JS'
const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const manifest = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const root = process.argv[3];
const target = process.argv[4];
const artifact = (manifest.artifacts || []).find((item) => item.target === target);
const archive = path.join(root, artifact.filename);
const actualSize = fs.statSync(archive).size;
if (actualSize !== artifact.sizeBytes) {
  console.error(`size mismatch for ${target}: expected ${artifact.sizeBytes}, got ${actualSize}`);
  process.exit(1);
}
const hash = crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
if (hash !== artifact.sha256) {
  console.error(`sha256 mismatch for ${target}: expected ${artifact.sha256}, got ${hash}`);
  process.exit(1);
}
JS

TMP_EXTRACT="$(mktemp -d)"
cleanup_extract() {
  rm -rf "$TMP_EXTRACT"
}
trap cleanup_extract EXIT

tar -xzf "$ARCHIVE_SRC" -C "$TMP_EXTRACT"
if [[ ! -f "$TMP_EXTRACT/$BINARY_RELATIVE_PATH" ]]; then
  echo "assemble-platform-pkg: expected backend missing after extraction: $BINARY_RELATIVE_PATH" >&2
  exit 1
fi

node "$NPM_DIST/scripts/audit-local-checkout-paths.mjs" \
  "$TMP_EXTRACT"

mkdir -p "$PKG_DIR/artifacts"
find "$PKG_DIR/artifacts" -depth -mindepth 1 ! -name .gitkeep -delete
cp "$MANIFEST" "$PKG_DIR/artifacts/devseccode-core-artifacts.json"
cp "$SIGNATURE" "$PKG_DIR/artifacts/devseccode-core-artifacts.json.sig"
cp "$ARCHIVE_SRC" "$PKG_DIR/artifacts/$ARCHIVE_NAME"

if [[ -f "$CORE_ARTIFACT_DIR/$ARCHIVE_NAME.sha256" ]]; then
  cp "$CORE_ARTIFACT_DIR/$ARCHIVE_NAME.sha256" "$PKG_DIR/artifacts/$ARCHIVE_NAME.sha256"
fi

echo "==> Assembled $PKG_DIR from public/starter Core artifact $ARCHIVE_NAME"
