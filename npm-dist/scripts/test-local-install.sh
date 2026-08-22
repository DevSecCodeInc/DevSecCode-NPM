#!/usr/bin/env bash
# Pre-publish clean-install smoke for the Core-backed npm package.
#
# Usage is documented in npm-dist/TESTING.md.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
NPM_DIST="$ROOT/npm-dist"

infer_target() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) echo "darwin-arm64" ;;
    Linux-x86_64|Linux-amd64) echo "linux-x64" ;;
    Linux-aarch64|Linux-arm64) echo "test-local-install: linux-arm64 is planned but not supported in this release" >&2; exit 1 ;;
    *) echo "test-local-install: unsupported host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
  esac
}

TARGET="${DSC_CORE_TARGET:-$(infer_target)}"
CORE_ARTIFACT_DIR="${DSC_CORE_ARTIFACT_DIR:-}"
PREPACKED_DIR="${DSC_PREPACKED_DIR:-}"
if [[ -z "$CORE_ARTIFACT_DIR" && -z "$PREPACKED_DIR" ]]; then
  echo "test-local-install: set DSC_CORE_ARTIFACT_DIR to Core dist/artifacts" >&2
  exit 2
fi

echo "==> Host target: $TARGET"
PACK_DIR="$(mktemp -d)"
export HOME="$PACK_DIR/home"
export DEVSECCODE_HOME="$PACK_DIR/devseccode-home"
export XDG_CACHE_HOME="$PACK_DIR/cache"
mkdir -p "$HOME" "$DEVSECCODE_HOME" "$XDG_CACHE_HOME"

cleanup() {
  local pid=""
  while IFS= read -r pid; do
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in {1..50}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then
        echo "test-local-install: owned Core process $pid did not stop" >&2
      fi
    fi
  done < <(node - "$DEVSECCODE_HOME" <<'JS'
const fs = require("node:fs");
const path = require("node:path");
const root = process.argv[2];
const pending = [root];
while (pending.length) {
  const current = pending.pop();
  let entries = [];
  try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch (_) { continue; }
  for (const entry of entries) {
    const file = path.join(current, entry.name);
    if (entry.isDirectory()) pending.push(file);
    else if (entry.name.endsWith(".json")) {
      try {
        const value = JSON.parse(fs.readFileSync(file, "utf8"));
        if (Number.isInteger(value.pid) && value.pid > 0) process.stdout.write(`${value.pid}\n`);
      } catch (_) {
        // Ignore non-endpoint JSON in the isolated state root.
      }
    }
  }
}
JS
  )
  rm -rf "$PACK_DIR"
}
trap cleanup EXIT INT TERM
if [[ -n "$PREPACKED_DIR" ]]; then
  cp "$PREPACKED_DIR"/devseccode-scanner-*.tgz "$PACK_DIR/"
else
  echo "==> Assembling scanner-$TARGET from $CORE_ARTIFACT_DIR"
  bash "$NPM_DIST/scripts/assemble-platform-pkg.sh" "$TARGET" "$CORE_ARTIFACT_DIR"
  echo "==> Packing parent + scanner-$TARGET tarballs"
  ( cd "$NPM_DIST/packages/scanner" && npm pack --pack-destination "$PACK_DIR" >/dev/null )
  ( cd "$NPM_DIST/packages/scanner-$TARGET" && npm pack --pack-destination "$PACK_DIR" >/dev/null )
fi
ls -la "$PACK_DIR"/*.tgz

PARENT_TGZ="$(ls "$PACK_DIR"/devseccode-scanner-[0-9]*.tgz | head -n1)"
PLATFORM_TGZ="$(ls "$PACK_DIR"/devseccode-scanner-"$TARGET"-*.tgz | head -n1)"

INSTALL_DIR="$PACK_DIR/install"
mkdir -p "$INSTALL_DIR"
( cd "$INSTALL_DIR" && npm init -y >/dev/null )

echo "==> npm install in $INSTALL_DIR"
( cd "$INSTALL_DIR" && npm install --no-fund --no-audit --omit=optional "$PLATFORM_TGZ" "$PARENT_TGZ" )

DEVSECCODE="$INSTALL_DIR/node_modules/.bin/devseccode"
DSC_ALIAS="$INSTALL_DIR/node_modules/.bin/dsc"
[[ -x "$DEVSECCODE" ]] || { echo "FAIL: $DEVSECCODE missing or not executable" >&2; exit 1; }
[[ -x "$DSC_ALIAS" ]] || { echo "FAIL: $DSC_ALIAS missing or not executable" >&2; exit 1; }

echo "==> devseccode --version"
"$DEVSECCODE" --version

if [[ -d "$ROOT/resources/sample-vulns" ]]; then
  echo "==> devseccode scan resources/sample-vulns --format terminal"
  "$DEVSECCODE" scan "$ROOT/resources/sample-vulns" --format terminal --fail-on critical
fi

echo "==> Local Core-backed install smoke passed."
