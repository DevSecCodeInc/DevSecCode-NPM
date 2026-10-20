"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const script = path.resolve(__dirname, "../../../scripts/qualify-core-input.mjs");
const qualification = import(pathToFileURL(script).href);
const root = path.resolve(path.sep, "work", "checkout one");

function sarif(uri, overrides = {}) {
  return {
    version: "2.1.0",
    runs: [{
      originalUriBaseIds: { SRCROOT: { uri: `${pathToFileURL(root).href}/` } },
      results: [{
        ruleId: "deva.cwe-78.python-command-injection",
        locations: [{
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: "SRCROOT" },
            region: { startLine: 6 },
          },
        }],
      }],
      ...overrides,
    }],
  };
}

test("scope check accepts only findings inside the allowed paths", async () => {
  const { scopeViolations } = await qualification;
  assert.deepEqual(scopeViolations(["app/target.py", "app/target.py"], ["app/target.py"]), []);
  assert.deepEqual(scopeViolations(["app/sibling.py"], ["app/target.py"]), ["app/sibling.py"]);
  assert.deepEqual(scopeViolations(["app/a.py", "excluded/b.py"], ["app", "excluded"], ["excluded"]), ["excluded/b.py"]);
  assert.deepEqual(scopeViolations(["../outside.py"], ["app"]), ["../outside.py"]);
  assert.deepEqual(scopeViolations(["application/x.py"], ["app"]), ["application/x.py"]);
});

test("finding paths are reported relative to the scanned workspace", async () => {
  const { findingPaths } = await qualification;
  const results = { findings: [{ filePath: path.join(root, "src", "a.py") }, { filePath: "lib/b.py" }] };
  assert.deepEqual(findingPaths(results, root), ["src/a.py", "lib/b.py"]);
  assert.throws(() => findingPaths({ findings: [{}] }, root), /no file path/);
});

test("portable SARIF requires encoded SRCROOT-relative locations", async () => {
  const { sarifPortabilityProblems } = await qualification;
  assert.deepEqual(sarifPortabilityProblems(sarif("src/web%20app%20%231.py"), root), []);
  assert.match(sarifPortabilityProblems(sarif(pathToFileURL(path.join(root, "a.py")).href), root).join("\n"), /portable relative/);
  assert.match(sarifPortabilityProblems(sarif("src/web app #1.py"), root).join("\n"), /percent-encoded/);
  const unbased = sarif("a.py");
  delete unbased.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId;
  assert.match(sarifPortabilityProblems(unbased, root).join("\n"), /not relative to SRCROOT/);
  const leaked = sarif("a.py", { properties: { workspace: root } });
  assert.match(sarifPortabilityProblems(leaked, root).join("\n"), /leaks/);
  const elsewhere = path.resolve(path.sep, "other");
  assert.match(sarifPortabilityProblems(sarif("a.py"), elsewhere).join("\n"), /not the scanned workspace/);
  assert.match(sarifPortabilityProblems(sarif("a.py", { results: [] }), root).join("\n"), /no results/);
});

test("relocated SARIF compares by rule, base and relative location", async () => {
  const { sarifLocations } = await qualification;
  assert.deepEqual(sarifLocations(sarif("a.py")), sarifLocations(sarif("a.py")));
  assert.notDeepEqual(sarifLocations(sarif("a.py")), sarifLocations(sarif("b.py")));
});

test("scanner crashes are rejected and never read as clean success", async () => {
  const { cleanSuccess, crashRejected } = await qualification;
  const crashed = { status: "complete", errors: ["opengrep failed: opengrep produced no JSON output (exit 0)"], findings: [] };
  assert.equal(crashRejected(crashed), true);
  assert.equal(cleanSuccess(crashed), false);
  assert.equal(crashRejected({ status: "error", errors: [] }), true);
  const clean = { status: "complete", errors: [], findings: [] };
  assert.equal(crashRejected(clean), false);
  assert.equal(cleanSuccess(clean), true);
  assert.equal(cleanSuccess({ status: "complete" }), false);
});

test("every simulated crash mode is a failure shape Core must reject", async () => {
  const { CRASH_MODES } = await qualification;
  assert.deepEqual(Object.keys(CRASH_MODES).sort(), [
    "empty-exit-0",
    "empty-exit-2-fatal",
    "json-not-a-report",
    "null-report",
  ]);
  for (const mode of Object.values(CRASH_MODES)) {
    let report = null;
    try {
      report = JSON.parse(mode.stdout);
    } catch (_) {
      // Empty output is a crash shape.
    }
    assert.equal(Array.isArray(report && report.results), false);
  }
});
