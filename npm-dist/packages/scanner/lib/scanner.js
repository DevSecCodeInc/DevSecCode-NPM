"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
  buildScanOptions,
  loadConfig,
  parseSeverityOverrides,
  resolveScanTargets,
  validateCoreSupportedConfig,
} = require("./config");
const { commandCapabilities, coreRequest, ensureCoreForCommand, fetchCoreText } = require("./core");
const { applySeverityOverrides, normalizeScanResult } = require("./results");
const { formatJson, formatJunit, formatTerminal } = require("./renderers");
const { meetsSeverity, normalizeSeverity } = require("./severity");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runCoreScan(args, options = {}) {
  const configTarget = path.resolve(args.path || process.cwd());
  if (!fs.existsSync(configTarget)) {
    const err = new Error(`Target path does not exist: ${configTarget}`);
    err.exitCode = 2;
    throw err;
  }
  const { config, configPath } = loadConfig(configTarget);
  validateCoreSupportedConfig(config);
  const overrides = parseSeverityOverrides((config.detectors || {}).severity_override);
  const targets = resolveScanTargets(args.path, config, configPath);
  const connection = await ensureCoreForCommand(
    commandCapabilities(options.command || "scan", args.format || "terminal"),
  );

  const results = [];
  const scanIds = [];
  for (const target of targets) {
    const scanOptions = buildScanOptions(args, config, target);
    const started = await coreRequest(connection, "/v1/scan/start", {
      method: "POST",
      body: JSON.stringify({ options: scanOptions }),
    });
    const scanId = started.scanId || started.scan_id;
    scanIds.push(scanId);
    let latest = null;
    for (;;) {
      latest = await coreRequest(connection, `/v1/scan/${encodeURIComponent(scanId)}/results`, {});
      const status = String(latest.status || "").toLowerCase();
      if (status === "complete") break;
      if (status === "error") {
        const err = new Error((latest.errors || []).join("; ") || "Core scan failed");
        err.exitCode = 1;
        throw err;
      }
      await sleep(250);
    }
    results.push(normalizeScanResult(latest));
  }

  let result = mergeResults(results);
  result = applySeverityOverrides(result, overrides);
  return {
    connection,
    result,
    targets,
    scanIds,
    failOn: normalizeSeverity(args.failOn || config.fail_on || "high"),
  };
}

function mergeResults(results) {
  if (results.length === 1) return results[0];
  const merged = {
    scanId: results.map((r) => r.scanId).join(","),
    status: "complete",
    findings: [],
    filesScanned: 0,
    scanDurationMs: 0,
    scannerVersion: results.find((r) => r.scannerVersion)?.scannerVersion || "",
    errors: [],
    countsBySeverity: {},
    countsByPrecisionTier: {},
    advisoryCount: 0,
    suppressedCount: 0,
    complianceReport: null,
    llmStatus: null,
    llmStatusDetail: null,
  };
  for (const result of results) {
    merged.findings.push(...result.findings);
    merged.filesScanned += result.filesScanned;
    merged.scanDurationMs += result.scanDurationMs;
    merged.errors.push(...result.errors);
    merged.advisoryCount += result.advisoryCount;
    merged.suppressedCount += result.suppressedCount;
    for (const [key, value] of Object.entries(result.countsBySeverity || {})) {
      merged.countsBySeverity[key] = (merged.countsBySeverity[key] || 0) + Number(value || 0);
    }
    for (const [key, value] of Object.entries(result.countsByPrecisionTier || {})) {
      merged.countsByPrecisionTier[key] = (merged.countsByPrecisionTier[key] || 0) + Number(value || 0);
    }
  }
  merged.findings.sort((a, b) => {
    const sev = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return (sev[b.severity] - sev[a.severity]) ||
      a.filePath.localeCompare(b.filePath) ||
      a.lineStart - b.lineStart ||
      a.ruleId.localeCompare(b.ruleId);
  });
  return merged;
}

function scanExitCode(result, failOn) {
  return result.findings.some((finding) => meetsSeverity(finding.severity, failOn)) ? 1 : 0;
}

async function formatScanOutput(format, scanContext, args) {
  const { connection, result, scanIds } = scanContext;
  if (format === "terminal") return formatTerminal(result, { verbose: args.verbose });
  if (format === "json") return formatJson(result, { jsonLines: args.jsonLines });
  if (format === "junit") return formatJunit(result);
  if (format === "sarif") {
    if (scanIds.length > 1) {
      const err = new Error(`${format} export currently supports one scan target at a time`);
      err.exitCode = 2;
      throw err;
    }
    return fetchCoreText(connection, `/v1/scan/${encodeURIComponent(scanIds[0])}/export?format=${format}`);
  }
  const err = new Error(`Unknown format: ${format}`);
  err.exitCode = 2;
  throw err;
}

function writeOutput(text, outputPath) {
  if (outputPath) {
    fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
    fs.writeFileSync(outputPath, text, "utf8");
  } else {
    process.stdout.write(text);
  }
}

module.exports = {
  formatScanOutput,
  runCoreScan,
  scanExitCode,
  writeOutput,
};
