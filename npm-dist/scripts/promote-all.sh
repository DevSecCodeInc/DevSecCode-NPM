#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <candidate-directory>" >&2
  exit 2
fi

CANDIDATE_DIR="$1"
RECORD="$CANDIDATE_DIR/devseccode-npm-release.json"
PROMOTION_TAG="${PROMOTION_TAG:-latest}"

[[ -f "$RECORD" ]] || { echo "promote-all: candidate record missing: $RECORD" >&2; exit 1; }
VERSION="$(node -p "require('$RECORD').product.version")"

mapfile -t PACKAGE_ROWS < <(node - "$RECORD" <<'JS'
const record = require(process.argv[2]);
for (const item of record.packages) {
  process.stdout.write(`${item.name}\t${item.integrity}\n`);
}
JS
)

for row in "${PACKAGE_ROWS[@]}"; do
  IFS=$'\t' read -r name expected_integrity <<<"$row"
  published_integrity="$(npm view "$name@$VERSION" dist.integrity)"
  if [[ "$published_integrity" != "$expected_integrity" ]]; then
    echo "promote-all: registry bytes do not match accepted candidate for $name@$VERSION" >&2
    exit 1
  fi
done

for row in "${PACKAGE_ROWS[@]}"; do
  IFS=$'\t' read -r name expected_integrity <<<"$row"
  echo "==> npm dist-tag add $name@$VERSION $PROMOTION_TAG"
  npm dist-tag add "$name@$VERSION" "$PROMOTION_TAG"
done

echo "==> Exact candidate versions promoted to $PROMOTION_TAG."
