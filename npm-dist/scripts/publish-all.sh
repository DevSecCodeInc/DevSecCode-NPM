#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <candidate-directory> [--dry-run]" >&2
  exit 2
fi

CANDIDATE_DIR="$1"
DRY_RUN="${2:-}"
RECORD="$CANDIDATE_DIR/devseccode-npm-release.json"
PUBLISH_TAG="${PUBLISH_TAG:-artifact-v2-candidate}"

[[ -f "$RECORD" ]] || { echo "publish-all: candidate record missing: $RECORD" >&2; exit 1; }
VERSION="$(node -p "require('$RECORD').product.version")"

mapfile -t PACKAGE_ROWS < <(node - "$RECORD" <<'JS'
const record = require(process.argv[2]);
for (const item of record.packages) {
  process.stdout.write(`${item.name}\t${item.filename}\t${item.integrity}\n`);
}
JS
)

for row in "${PACKAGE_ROWS[@]}"; do
  IFS=$'\t' read -r name filename expected_integrity <<<"$row"
  [[ -f "$CANDIDATE_DIR/$filename" ]] || { echo "publish-all: package missing: $filename" >&2; exit 1; }
  published_integrity="$(npm view "$name@$VERSION" dist.integrity 2>/dev/null || true)"
  if [[ -n "$published_integrity" && "$published_integrity" != "$expected_integrity" ]]; then
    echo "publish-all: npm already contains different bytes for $name@$VERSION" >&2
    exit 1
  fi
done

for row in "${PACKAGE_ROWS[@]}"; do
  IFS=$'\t' read -r name filename expected_integrity <<<"$row"
  published_integrity="$(npm view "$name@$VERSION" dist.integrity 2>/dev/null || true)"
  if [[ -n "$published_integrity" ]]; then
    echo "==> $name@$VERSION already contains the accepted bytes"
    continue
  fi
  flags=(--access public --tag "$PUBLISH_TAG" --provenance)
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    flags+=(--dry-run)
  fi
  echo "==> npm publish $filename --tag $PUBLISH_TAG"
  npm publish "$CANDIDATE_DIR/$filename" "${flags[@]}"
done

echo "==> Candidate package publication complete."
