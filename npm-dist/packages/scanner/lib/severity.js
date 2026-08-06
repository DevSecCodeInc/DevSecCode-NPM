"use strict";

const ORDER = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

function normalizeSeverity(value, fallback = "info") {
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
