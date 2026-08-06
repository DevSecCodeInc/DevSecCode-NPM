"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  ConfigError,
  buildScanOptions,
  findConfigFile,
  loadConfig,
  parseConfig,
  validateCoreSupportedConfig,
} = require("../lib/config");

test("parseConfig accepts the init YAML subset", () => {
  const parsed = parseConfig(`
version: 1
scan:
  paths:
    - "."
  ignore:
    - "node_modules/"
detectors:
  enabled: all
  disabled: []
fail_on: high
`);

  assert.equal(parsed.version, 1);
  assert.deepEqual(parsed.scan.paths, ["."]);
  assert.deepEqual(parsed.scan.ignore, ["node_modules/"]);
  assert.equal(parsed.detectors.enabled, "all");
});

test("findConfigFile walks up to the git root", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-config-"));
  fs.mkdirSync(path.join(dir, ".git"));
  fs.mkdirSync(path.join(dir, "a", "b"), { recursive: true });
  const config = path.join(dir, ".dsc.yml");
  fs.writeFileSync(config, "version: 1\n", "utf8");

  assert.equal(findConfigFile(path.join(dir, "a", "b")), config);
});

test("custom language filters are rejected until Core supports them", () => {
  assert.throws(
    () => validateCoreSupportedConfig({
      scan: { languages: ["python"] },
      detectors: { enabled: "all", disabled: [] },
    }),
    ConfigError,
  );
});

test("buildScanOptions maps supported flags to Core request shape", () => {
  const options = buildScanOptions(
    {
      diff: true,
      threads: 2,
      noCache: true,
      scanProfile: "precision",
      minConfidence: 0.7,
      includeSuppressed: true,
      ignorePatterns: ["dist"],
    },
    {
      scan: { ignore: ["node_modules"] },
      detectors: { enabled: "all", disabled: [] },
      compliance: ["HIPAA"],
      fail_on: "critical",
    },
    "/tmp/project",
  );

  assert.equal(options.targetPath, "/tmp/project");
  assert.equal(options.diffOnly, true);
  assert.equal(options.threads, 2);
  assert.equal(options.useCache, false);
  assert.equal(options.scanProfile, "precision");
  assert.equal(options.minConfidence, 0.7);
  assert.deepEqual(options.ignorePatterns, ["node_modules", "dist"]);
  assert.deepEqual(options.complianceFrameworks, ["HIPAA"]);
});

test("loadConfig treats invalid YAML as a config error", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-bad-config-"));
  fs.writeFileSync(path.join(dir, ".dsc.yml"), "version\n", "utf8");
  assert.throws(() => loadConfig(dir), ConfigError);
});
