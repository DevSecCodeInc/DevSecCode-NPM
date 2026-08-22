"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { formatJson, formatJunit, formatTerminal } = require("../lib/renderers");
const { applySeverityOverrides, normalizeScanResult } = require("../lib/results");
const { normalizeSeverity } = require("../lib/severity");
const { buildReport, loadProfile, recordHunt, saveProfile, statePath } = require("../lib/state");

test("normalizeScanResult adapts Core camelCase findings", () => {
  const result = normalizeScanResult({
    scanId: "scan-1",
    status: "complete",
    findings: [{
      ruleId: "deva.cwe-798.test",
      cwe: "CWE-798",
      severity: "CRITICAL",
      filePath: "app.js",
      lineStart: 2,
      message: "Hardcoded secret",
      metadata: { precisionTier: "high" },
    }],
    filesScanned: 1,
    scanDurationMs: 10,
    scannerVersion: "0.3.0",
  });

  assert.equal(result.findings[0].severity, "critical");
  assert.equal(result.findings[0].ruleId, "deva.cwe-798.test");
  assert.equal(result.filesScanned, 1);
});

test("Core numeric rule severities map to public labels", () => {
  assert.equal(normalizeSeverity(10), "info");
  assert.equal(normalizeSeverity(20), "low");
  assert.equal(normalizeSeverity(30), "medium");
  assert.equal(normalizeSeverity(40), "high");
  assert.equal(normalizeSeverity(50), "critical");
});

test("severity overrides are presentation-only on the normalized result copy", () => {
  const result = normalizeScanResult({
    findings: [{ ruleId: "r1", severity: "LOW", filePath: "a", lineStart: 1 }],
  });
  const adjusted = applySeverityOverrides(result, { R1: "critical" });

  assert.equal(result.findings[0].severity, "low");
  assert.equal(adjusted.findings[0].severity, "critical");
});

test("json-lines renderer emits findings plus summary", () => {
  const result = normalizeScanResult({
    findings: [{ ruleId: "r1", severity: "HIGH", filePath: "a", lineStart: 1 }],
    filesScanned: 1,
  });
  const lines = formatJson(result, { jsonLines: true }).trim().split("\n").map(JSON.parse);

  assert.equal(lines.length, 2);
  assert.equal(lines[0].rule_id, "r1");
  assert.equal(lines[1].summary.findings, null);
});

test("terminal renderer includes summary counts", () => {
  const result = normalizeScanResult({
    findings: [{ ruleId: "r1", severity: "HIGH", filePath: "a", lineStart: 1, message: "msg" }],
    filesScanned: 3,
  });
  const text = formatTerminal(result);

  assert.match(text, /HIGH/);
  assert.match(text, /1 findings/);
  assert.match(text, /Scanned 3 files/);
});

test("JUnit renderer preserves the public finding contract", () => {
  const result = normalizeScanResult({
    findings: [{
      ruleId: "deva.cwe-79.test",
      severity: "HIGH",
      filePath: "a&b.js",
      lineStart: 3,
      column: 2,
      message: 'unsafe <HTML> "sink"',
      fixSuggestion: "escape & sanitize",
    }],
  });
  const text = formatJunit(result);

  assert.match(text, /<testsuite name="dsc" tests="1" failures="1" errors="0">/);
  assert.match(text, /a&amp;b\.js:3/);
  assert.match(text, /unsafe &lt;HTML&gt; &quot;sink&quot;/);
  assert.match(text, /Fix: escape &amp; sanitize/);
});

test("profile state honors DEVSECCODE_HOME and preserves fields", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-home-"));
  const oldHome = process.env.DEVSECCODE_HOME;
  process.env.DEVSECCODE_HOME = dir;
  try {
    const profile = loadProfile();
    profile.hunter_class = "sentinel";
    saveProfile(profile);
    const reloaded = loadProfile();
    const result = normalizeScanResult({
      findings: [{ ruleId: "r1", severity: "CRITICAL", filePath: "a", lineStart: 1, message: "secret" }],
      filesScanned: 1,
    });
    const record = recordHunt(reloaded, result.findings, "/tmp/project");
    saveProfile(reloaded);
    const report = buildReport(result, ["/tmp/project"], record, false);

    assert.equal(loadProfile().hunter_class, "sentinel");
    assert.ok(fs.existsSync(statePath("profile.json")));
    assert.equal(report.total_findings, 1);
    assert.equal(report.finding_details[0].rule_id, "r1");
  } finally {
    if (oldHome == null) delete process.env.DEVSECCODE_HOME;
    else process.env.DEVSECCODE_HOME = oldHome;
  }
});
