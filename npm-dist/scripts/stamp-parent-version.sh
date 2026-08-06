#!/usr/bin/env bash
# Pin every platform optionalDependency to the parent npm wrapper version.
# The npm wrapper version is independent from the Core engine version; Core
# engine/contract versions are reported at runtime from /v1/meta.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PARENT_PACKAGE="$ROOT/npm-dist/packages/scanner/package.json"

node - "$PARENT_PACKAGE" <<'JS'
const fs = require("node:fs");
const path = process.argv[2];
const data = JSON.parse(fs.readFileSync(path, "utf8"));
const version = data.version;
if (!version) {
  console.error("parent package.json is missing version");
  process.exit(1);
}
const deps = data.optionalDependencies || {};
for (const name of Object.keys(deps)) {
  deps[name] = version;
}
data.optionalDependencies = deps;
fs.writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
console.log(`==> Stamped optionalDependencies with parent version=${version}`);
JS
