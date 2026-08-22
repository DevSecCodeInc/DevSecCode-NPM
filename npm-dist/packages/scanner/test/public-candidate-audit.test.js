"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const auditModule = import(pathToFileURL(path.resolve(
  __dirname,
  "../../../scripts/audit-public-candidate.mjs",
)).href);

const parentMembers = [
  "package/LICENSE",
  "package/README.md",
  "package/bin/dsc.js",
  "package/lib/artifact-trust.js",
  "package/lib/cli.js",
  "package/lib/config.js",
  "package/lib/core.js",
  "package/lib/renderers.js",
  "package/lib/results.js",
  "package/lib/scanner.js",
  "package/lib/severity.js",
  "package/lib/state.js",
  "package/package.json",
  "package/trust/artifact-ed25519-public.pem",
];

test("exact public parent file allowlist is accepted", async () => {
  const { auditParentMembers } = await auditModule;
  assert.doesNotThrow(() => auditParentMembers(parentMembers));
});

test("scanner implementation source cannot enter the public parent tarball", async () => {
  const { auditParentMembers } = await auditModule;
  assert.throws(
    () => auditParentMembers([...parentMembers, "package/engine/src/scanner.py"]),
    /unapproved file/,
  );
});

test("platform tarball accepts only the signed Core payload layout", async () => {
  const { auditPlatformMembers } = await auditModule;
  const archive = "devseccode-core-public-starter-darwin-arm64.tar.gz";
  assert.doesNotThrow(() => auditPlatformMembers([
    "package/LICENSE",
    "package/README.md",
    "package/package.json",
    "package/artifacts/devseccode-core-artifacts.json",
    "package/artifacts/devseccode-core-artifacts.json.sig",
    `package/artifacts/${archive}`,
    `package/artifacts/${archive}.sha256`,
  ], archive));
  assert.throws(() => auditPlatformMembers([
    "package/LICENSE",
    "package/README.md",
    "package/package.json",
    "package/artifacts/devseccode-core-artifacts.json",
    "package/artifacts/devseccode-core-artifacts.json.sig",
    `package/artifacts/${archive}`,
    "package/core/private-model.bin",
  ], archive), /unapproved file/);
});
