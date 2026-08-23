"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const script = path.resolve(__dirname, "../../../scripts/audit-local-checkout-paths.mjs");
const auditModule = import(pathToFileURL(script).href);

function fixture() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "devseccode-local-path-audit-"));
}

test("safe binary and text payloads pass the local checkout path audit", async (t) => {
  const root = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "nested"));
  fs.writeFileSync(path.join(root, "nested", "backend.bin"), Buffer.from([0, 1, 2, 255]));
  fs.writeFileSync(path.join(root, "metadata.txt"), "public-starter\n");
  const { findLocalCheckoutPaths } = await auditModule;
  assert.deepEqual(findLocalCheckoutPaths(root), []);
  assert.equal(spawnSync(process.execPath, [script, root]).status, 0);
});

for (const [name, leakedPath] of [
  ["macOS", "/Users/matt/Projects/dsc/DevSecCode-Core/backend"],
  ["Linux", "/home/runner/work/DevSecCode-Core/DevSecCode-Core/backend"],
  ["Windows user", "C:\\Users\\matt\\Projects\\dsc\\DevSecCode-Core\\backend"],
  ["Windows runner", "C:\\a\\DevSecCode-Core\\DevSecCode-Core\\backend"],
]) {
  test(`${name} checkout paths are rejected`, async (t) => {
    const root = fixture();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    fs.writeFileSync(path.join(root, "backend.bin"), Buffer.from(`prefix\0${leakedPath}\0suffix`, "latin1"));
    const { findLocalCheckoutPaths } = await auditModule;
    const findings = findLocalCheckoutPaths(root);
    assert.ok(findings.some((finding) => leakedPath.includes(finding.value)));
    const result = spawnSync(process.execPath, [script, root], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /public artifact contains local checkout paths/);
    assert.match(result.stderr, /backend\.bin/);
  });
}

test("audit execution errors are distinct from path findings", () => {
  const missing = path.join(os.tmpdir(), "devseccode-local-path-audit-missing");
  const result = spawnSync(process.execPath, [script, missing], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /audit-local-checkout-paths:/);
});
