"use strict";

const { normalizeSeverity } = require("./severity");

function normalizeFinding(raw) {
  const metadata = raw.metadata && typeof raw.metadata === "object" ? raw.metadata : {};
  return {
    ruleId: raw.ruleId || raw.rule_id || "",
    cwe: raw.cwe || "",
    severity: normalizeSeverity(raw.severity || "info"),
    filePath: raw.filePath || raw.file_path || "",
    lineStart: Number(raw.lineStart || raw.line_start || 1),
    lineEnd: Number(raw.lineEnd || raw.line_end || raw.lineStart || raw.line_start || 1),
    column: Number(raw.column || 1),
    message: raw.message || "",
    fixSuggestion: raw.fixSuggestion || raw.fix_suggestion || null,
    snippet: raw.snippet || null,
    metadata,
    fingerprint: raw.fingerprint || metadata.fingerprint || null,
    occurrenceId: raw.occurrenceId || raw.occurrence_id || metadata.occurrence_id || null,
    confidence: raw.confidence == null ? metadata.confidence : raw.confidence,
    reachability: raw.reachability || "unknown",
    entryPoints: raw.entryPoints || raw.entry_points || [],
    triageLabel: raw.triageLabel || raw.triage_label || "untriaged",
    triageConfidence: Number(raw.triageConfidence || raw.triage_confidence || 0),
    triageReasoning: raw.triageReasoning || raw.triage_reasoning || null,
  };
}

function normalizeScanResult(raw) {
  const findings = Array.isArray(raw.findings) ? raw.findings.map(normalizeFinding) : [];
  return {
    scanId: raw.scanId || raw.scan_id || "",
    status: raw.status || "complete",
    findings,
    filesScanned: Number(raw.filesScanned || raw.files_scanned || 0),
    scanDurationMs: Number(raw.scanDurationMs || raw.scan_duration_ms || 0),
    scannerVersion: raw.scannerVersion || raw.scanner_version || "",
    errors: Array.isArray(raw.errors) ? raw.errors.map(String) : [],
    countsBySeverity: raw.countsBySeverity || raw.counts_by_severity || countBy(findings, (f) => f.severity.toUpperCase()),
    countsByPrecisionTier: raw.countsByPrecisionTier || raw.counts_by_precision_tier || {},
    advisoryCount: Number(raw.advisoryCount || raw.advisory_count || 0),
    suppressedCount: Number(raw.suppressedCount || raw.suppressed_count || 0),
    complianceReport: raw.complianceReport || raw.compliance_report || null,
    llmStatus: raw.llmStatus || raw.llm_status || null,
    llmStatusDetail: raw.llmStatusDetail || raw.llm_status_detail || null,
  };
}

function countBy(items, keyFn) {
  const out = {};
  for (const item of items) {
    const key = keyFn(item);
    out[key] = (out[key] || 0) + 1;
  }
  return out;
}

function applySeverityOverrides(result, overrides) {
  if (!overrides || Object.keys(overrides).length === 0) return result;
  return {
    ...result,
    findings: result.findings.map((finding) => {
      const override = overrides[finding.ruleId.toUpperCase()] || overrides[finding.cwe.toUpperCase()];
      return override ? { ...finding, severity: override } : finding;
    }),
  };
}

function resultToLegacyJson(result) {
  return {
    findings: result.findings.map((finding) => ({
      rule_id: finding.ruleId,
      cwe: finding.cwe,
      severity: finding.severity.toUpperCase(),
      file_path: finding.filePath,
      line_start: finding.lineStart,
      line_end: finding.lineEnd,
      column: finding.column,
      message: finding.message,
      fix_suggestion: finding.fixSuggestion,
      snippet: finding.snippet,
      metadata: finding.metadata,
      fingerprint: finding.fingerprint,
      occurrence_id: finding.occurrenceId,
      confidence: finding.confidence,
      reachability: finding.reachability,
      entry_points: finding.entryPoints,
      triage_label: finding.triageLabel,
      triage_confidence: finding.triageConfidence,
      triage_reasoning: finding.triageReasoning,
    })),
    files_scanned: result.filesScanned,
    scan_duration_ms: result.scanDurationMs,
    scanner_version: result.scannerVersion,
    errors: result.errors,
    counts_by_severity: result.countsBySeverity,
    counts_by_precision_tier: result.countsByPrecisionTier,
    advisory_count: result.advisoryCount,
    suppressed_count: result.suppressedCount,
    compliance_report: result.complianceReport,
    llm_status: result.llmStatus,
    llm_status_detail: result.llmStatusDetail,
  };
}

module.exports = {
  applySeverityOverrides,
  countBy,
  normalizeFinding,
  normalizeScanResult,
  resultToLegacyJson,
};
