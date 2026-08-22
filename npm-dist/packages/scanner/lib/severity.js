"use strict";

const ORDER = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});
const CORE_NUMERIC_SEVERITY = Object.freeze({
  10: "info",
  20: "low",
  30: "medium",
  40: "high",
  50: "critical",
});

function normalizeSeverity(value, fallback = "info") {
  if (typeof value === "number" && Object.prototype.hasOwnProperty.call(CORE_NUMERIC_SEVERITY, value)) {
    return CORE_NUMERIC_SEVERITY[value];
  }
  const key = String(value || fallback).trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(ORDER, key)) {
    return key;
  }
  throw new Error(`Invalid severity: ${value}`);
}

function severityValue(value) {
  return ORDER[normalizeSeverity(value)];
}

function severityLabel(value) {
  return normalizeSeverity(value).toUpperCase();
}

function meetsSeverity(value, threshold) {
  return severityValue(value) >= severityValue(threshold);
}

module.exports = {
  ORDER,
  meetsSeverity,
  normalizeSeverity,
  severityLabel,
  severityValue,
};
