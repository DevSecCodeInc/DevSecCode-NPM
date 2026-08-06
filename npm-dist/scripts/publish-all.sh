#!/usr/bin/env bash
# Publish every assembled platform package to npm, then the parent.
#
# All packages publish with --access public. The package remains proprietary
# via LICENSE, but public npm access keeps `npx @devseccode/scanner scan .`
# frictionless for first-time users.
#
# CRITICAL: the platform packages must be on the registry BEFORE the
# parent, otherwise the parent's optionalDependencies fail to resolve on
# first npx invocation.
#
# Requires NODE_AUTH_TOKEN (or `npm login`) to be configured. CI sets it
# via the npm setup-node action.
#
# Usage:
#   bash npm-dist/scripts/publish-all.sh             # all platforms + parent
#   bash npm-dist/scripts/publish-all.sh --dry-run   # show what would publish

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
NPM_DIST="$ROOT/npm-dist"

DRY_RUN_FLAGS=()
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN_FLAGS=("--dry-run")
fi
PUBLISH_TAG="${PUBLISH_TAG:-core-migration-canary}"

PARENT_VERSION="$(node -e 'process.stdout.write(require(process.argv[1]).version)' \
  "$NPM_DIST/packages/scanner/package.json")"
if [[ "$PARENT_VERSION" == *-* && "$PUBLISH_TAG" == "latest" ]]; then
  echo "publish-all: refusing to publish prerelease $PARENT_VERSION with the latest dist-tag" >&2
  exit 2
fi

# Fail before the first publish if the package matrix is incomplete. This
# avoids publishing the parent with optional dependencies that cannot resolve.
for target in darwin-arm64 linux-x64 linux-arm64 win32-x64; do
  pkg="$NPM_DIST/packages/scanner-$target"
  manifest="$pkg/artifacts/devseccode-core-artifacts.json"
  [[ -f "$manifest" ]] || { echo "publish-all: $pkg is missing its Core manifest" >&2; exit 1; }
  [[ -f "$manifest.sig" ]] || { echo "publish-all: $pkg is missing its Core manifest signature" >&2; exit 1; }
  platform_version="$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$pkg/package.json")"
  [[ "$platform_version" == "$PARENT_VERSION" ]] || {
    echo "publish-all: $pkg version $platform_version does not match parent $PARENT_VERSION" >&2
    exit 1
  }
done

publish_dir() {
  local dir="$1"
  if [[ ! -f "$dir/package.json" ]]; then
    echo "publish-all: $dir is missing package.json -- skip" >&2
    return 0
  fi
  echo "==> npm publish $dir --tag $PUBLISH_TAG"
  ( cd "$dir" && npm publish --access public --tag "$PUBLISH_TAG" "${DRY_RUN_FLAGS[@]}" )
}

# Platform packages first.
for target in darwin-arm64 linux-x64 linux-arm64 win32-x64; do
  pkg="$NPM_DIST/packages/scanner-$target"
  publish_dir "$pkg"
done

# Then the parent so optionalDependencies always resolve.
publish_dir "$NPM_DIST/packages/scanner"

echo "==> Done."
