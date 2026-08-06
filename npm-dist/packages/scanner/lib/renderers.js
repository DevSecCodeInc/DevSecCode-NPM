"use strict";

const { resultToLegacyJson } = require("./results");
const { severityLabel } = require("./severity");

const COLORS = Object.freeze({
  critical: "\x1b[1;31m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[34m",
  info: "\x1b[2m",
});
const RESET = "\x1b[0m";

function formatTerminal(result, options = {}) {
  const lines = [];
  if (result.errors.length) {
    lines.push(`${COLORS.medium}Scanner warnings/errors:${RESET}`);
    for (const err of result.errors) lines.push(`  - ${err}`);
    lines.push("");
  }

  for (const finding of result.findings) {
    const color = COLORS[finding.severity] || "";
    const loc = `${finding.filePath}:${finding.lineStart}:${Math.max(finding.column, 1)}`;
    lines.push(`${color}${severityLabel(finding.severity)}${RESET} ${loc} ${finding.ruleId} ${finding.message}`);
    if (finding.snippet) lines.push(`    ${String(finding.snippet).trimEnd()}`);
    if (finding.fixSuggestion) lines.push(`    Fix: ${finding.fixSuggestion}`);
    if (options.verbose && finding.confidence != null) {
      lines.push(`    Confidence: ${finding.confidence}`);
    }
    lines.push("");
  }

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of result.findings) counts[finding.severity] += 1;
  const seconds = (result.scanDurationMs / 1000).toFixed(2);
  lines.push(
    `${result.findings.length} findings ` +
      `(critical=${counts.critical}, high=${counts.high}, medium=${counts.medium}, ` +
      `low=${counts.low}, info=${counts.info}). ` +
      `Scanned ${result.filesScanned} files in ${seconds}s.`,
  );
  return `${lines.join("\n").trimEnd()}\n`;
}

function formatJson(result, options = {}) {
  const legacy = resultToLegacyJson(result);
  if (!options.jsonLines) return `${JSON.stringify(legacy, null, 2)}\n`;
  const lines = result.findings.map((finding) => JSON.stringify(resultToLegacyJson({ ...result, findings: [finding] }).findings[0]));
  lines.push(JSON.stringify({ summary: { ...legacy, findings: null } }));
  return `${lines.join("\n")}\n`;
}

function renderRuleTable(rules) {
  const rows = [["ID", "CWE", "Severity", "Languages", "Tier", "Confidence"]];
  for (const rule of rules) {
    const metadata = rule.metadata || {};
    rows.push([
      String(rule.id || rule.ruleId || ""),
      String(rule.cwe || metadata.cwe || ""),
      String(rule.severity || metadata.severity || ""),
      Array.isArray(rule.languages) ? rule.languages.join(",") : String(rule.languages || ""),
      String(rule.precision_tier || rule.precisionTier || metadata.precision_tier || metadata.precisionTier || ""),
      rule.confidence == null ? String(metadata.confidence || "") : Number(rule.confidence).toFixed(2),
    ]);
  }
  const widths = rows[0].map((_, col) => Math.max(...rows.map((row) => row[col].length)));
  return `${rows.map((row) => row.map((cell, i) => cell.padEnd(widths[i])).join("  ")).join("\n")}\n`;
}

function showQuests() {
  return [
    "DevSecCode quests",
    "",
    "First Blood       Hardcoded secrets",
    "Injection Hunter  SQLi, XSS, command injection, path traversal",
    "Crypto Clean-up   Weak crypto and cleartext transport",
    "Container Guard   Dockerfile and Kubernetes checks",
    "Boss Fight        SARIF in CI",
    "",
  ].join("\n");
}

function showIde() {
  return [
    "DevSecCode IDE unlocks the full campaign:",
    "",
    "- Complete rule library and compliance mapping",
    "- SBOM, audit evidence, POA&M, and guided remediation workflows",
    "- Git-history analysis and richer project context",
    "",
  ].join("\n");
}

function showInitResult(targetPath, existed, force) {
  if (existed && !force) {
    return `Config already exists: ${targetPath}\nUse --force to overwrite it.\n`;
  }
  return `${existed ? "Rewrote" : "Created"} DevSecCode config: ${targetPath}\n`;
}

module.exports = {
  formatJson,
  formatTerminal,
  renderRuleTable,
  showIde,
  showInitResult,
  showQuests,
};
