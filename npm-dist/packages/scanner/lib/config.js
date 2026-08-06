"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { normalizeSeverity } = require("./severity");

const DEFAULT_LANGUAGES = Object.freeze([
  "python",
  "javascript",
  "typescript",
  "go",
  "java",
  "ruby",
  "rust",
  "json",
  "yaml",
  "toml",
  "ini",
  "xml",
  "html",
  "dockerfile",
  "dockercompose",
  "terraform",
  "requirements",
  "lockfile",
  "gomod",
  "gradle",
  "runtime",
  "swift",
  "objc",
  "plist",
  "kotlin",
  "php",
  "csharp",
  "dart",
  "c",
  "cpp",
]);

const DEFAULT_CONFIG = Object.freeze({
  version: 1,
  scan: {
    paths: ["."],
    ignore: [],
    languages: [...DEFAULT_LANGUAGES],
  },
  detectors: {
    enabled: "all",
    disabled: [],
    severity_override: {},
  },
  compliance: [],
  fail_on: "high",
  quality: {
    profile: "balanced",
  },
  suppressions: {},
});

const INIT_LANGUAGES = Object.freeze([
  "python",
  "javascript",
  "typescript",
  "go",
  "java",
  "ruby",
  "rust",
  "php",
  "csharp",
  "dockerfile",
  "yaml",
  "json",
]);

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigError";
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function parseScalar(value) {
  const raw = String(value).trim();
  const lowered = raw.toLowerCase();
  if (raw === "") return "";
  if (lowered === "null" || lowered === "none") return null;
  if (lowered === "true") return true;
  if (lowered === "false") return false;
  if (/^-?\d+$/.test(raw)) return Number.parseInt(raw, 10);
  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    return raw.slice(1, -1);
  }
  if (
    (raw.startsWith("[") && raw.endsWith("]")) ||
    (raw.startsWith("{") && raw.endsWith("}"))
  ) {
    try {
      return JSON.parse(raw);
    } catch (_) {
      return raw;
    }
  }
  return raw;
}

function stripJsonComments(text) {
  return text
    .split(/\r?\n/)
    .filter((line) => line.trim() && !line.trimStart().startsWith("#"))
    .join("\n");
}

function parseConfig(text) {
  try {
    const parsed = JSON.parse(stripJsonComments(text));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
  } catch (_) {
    // Fall through to the small YAML subset used by `devseccode init`.
  }

  const root = {};
  const stack = [{ indent: 0, container: root, parent: null, parentKey: null }];
  const current = () => stack[stack.length - 1];

  for (const rawLine of text.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trimStart().startsWith("#")) continue;

    const indent = rawLine.length - rawLine.trimStart().length;
    const line = rawLine.trim();

    while (stack.length > 1 && indent < current().indent) {
      stack.pop();
    }

    let frame = current();
    let container = frame.container;

    if (line.startsWith("- ")) {
      if (!Array.isArray(container)) {
        if (
          container &&
          typeof container === "object" &&
          !Array.isArray(container) &&
          Object.keys(container).length === 0 &&
          frame.parent &&
          typeof frame.parentKey === "string"
        ) {
          const list = [];
          frame.parent[frame.parentKey] = list;
          frame.container = list;
          container = list;
        } else {
          throw new ConfigError("Invalid YAML structure: list item without list context");
        }
      }
      container.push(parseScalar(line.slice(2)));
      continue;
    }

    const colon = line.indexOf(":");
    if (colon < 0) {
      throw new ConfigError(`Invalid YAML line (missing ':'): ${rawLine}`);
    }
    if (!container || typeof container !== "object" || Array.isArray(container)) {
      throw new ConfigError("Invalid YAML structure: mapping inside list is not supported");
    }

    const key = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (!value) {
      container[key] = {};
      stack.push({
        indent: indent + 1,
        container: container[key],
        parent: container,
        parentKey: key,
      });
    } else {
      container[key] = parseScalar(value);
    }
  }

  return root;
}

function deepMerge(base, override) {
  const out = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    if (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      out[key] &&
      typeof out[key] === "object" &&
      !Array.isArray(out[key])
    ) {
      out[key] = deepMerge(out[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function findGitRoot(start) {
  let cur = fs.statSync(start).isFile() ? path.dirname(start) : start;
  cur = path.resolve(cur);
  for (;;) {
    if (fs.existsSync(path.join(cur, ".git"))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

function findConfigFile(start, filename = ".dsc.yml") {
  let cur = path.resolve(start);
  if (fs.existsSync(cur) && fs.statSync(cur).isFile()) {
    cur = path.dirname(cur);
  }
  const gitRoot = findGitRoot(cur);
  for (;;) {
    const candidate = path.join(cur, filename);
    if (fs.existsSync(candidate)) return candidate;
    if (gitRoot && cur === gitRoot) return null;
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

function loadConfig(start) {
  const configPath = findConfigFile(start);
  if (!configPath) {
    return { config: clone(DEFAULT_CONFIG), configPath: null };
  }
  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = parseConfig(raw);
    return { config: deepMerge(clone(DEFAULT_CONFIG), parsed), configPath };
  } catch (err) {
    throw new ConfigError(`Failed to read config ${configPath}: ${err.message}`);
  }
}

function resolveScanTargets(pathArg, config, configPath) {
  if (pathArg) return [path.resolve(pathArg)];
  const paths = config && config.scan && Array.isArray(config.scan.paths) ? config.scan.paths : null;
  if (!paths) return [process.cwd()];
  const base = configPath ? path.dirname(configPath) : process.cwd();
  const seen = new Set();
  const targets = [];
  for (const raw of paths) {
    const text = String(raw || "").trim();
    if (!text) continue;
    const resolved = path.resolve(path.isAbsolute(text) ? text : path.join(base, text));
    if (!seen.has(resolved)) {
      seen.add(resolved);
      targets.push(resolved);
    }
  }
  return targets.length ? targets : [process.cwd()];
}

function parseSeverityOverrides(raw) {
  if (raw == null) return {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ConfigError("detectors.severity_override must be a mapping of rule->severity.");
  }
  const out = {};
  for (const [key, value] of Object.entries(raw)) {
    out[String(key).toUpperCase()] = normalizeSeverity(value);
  }
  return out;
}

function arraysEqual(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  return a.every((value, index) => String(value) === String(b[index]));
}

function validateCoreSupportedConfig(config) {
  const scan = config.scan || {};
  const detectors = config.detectors || {};
  const languages = Array.isArray(scan.languages) ? scan.languages : [];
  const enabled = detectors.enabled == null ? "all" : detectors.enabled;
  const disabled = Array.isArray(detectors.disabled) ? detectors.disabled : [];

  const unsupported = [];
  if (
    languages.length &&
    !arraysEqual(languages, DEFAULT_LANGUAGES) &&
    !arraysEqual(languages, INIT_LANGUAGES)
  ) {
    unsupported.push("scan.languages");
  }
  if (!(typeof enabled === "string" && enabled.toLowerCase() === "all")) {
    unsupported.push("detectors.enabled");
  }
  if (disabled.length > 0) {
    unsupported.push("detectors.disabled");
  }
  if (unsupported.length) {
    throw new ConfigError(
      `This Core build does not support configured ${unsupported.join(", ")} yet. ` +
        "Remove those filters or migrate with a Core artifact that supports them.",
    );
  }
}

function buildScanOptions(args, config, targetPath) {
  const scan = config.scan || {};
  const compliance = Array.isArray(config.compliance) ? config.compliance : [];
  const ignorePatterns = [];
  for (const item of Array.isArray(scan.ignore) ? scan.ignore : []) {
    const text = String(item).trim();
    if (text && !ignorePatterns.includes(text)) ignorePatterns.push(text);
  }
  for (const item of args.ignorePatterns || []) {
    const text = String(item).trim();
    if (text && !ignorePatterns.includes(text)) ignorePatterns.push(text);
  }

  const failOn = args.failOn || config.fail_on || "high";
  normalizeSeverity(failOn);

  return {
    targetPath,
    threads: Number.isInteger(args.threads) ? args.threads : 4,
    diffOnly: Boolean(args.diff),
    useCache: !Boolean(args.noCache),
    failOn,
    complianceFrameworks: compliance.map(String),
    scanProfile: args.scanProfile || (config.quality && config.quality.profile) || "balanced",
    minConfidence: Number.isFinite(args.minConfidence) ? args.minConfidence : 0,
    includeSuppressed: Boolean(args.includeSuppressed),
    ignorePatterns,
    llmEnabled: false,
  };
}

const INIT_TEMPLATE = `# DevSecCode public CLI configuration
version: 1

scan:
  paths:
    - "."
  ignore:
    - "tests/"
    - "migrations/"
    - "node_modules/"
  languages:
    - "python"
    - "javascript"
    - "typescript"
    - "go"
    - "java"
    - "ruby"
    - "rust"
    - "php"
    - "csharp"
    - "dockerfile"
    - "yaml"
    - "json"

detectors:
  enabled: all
  disabled: []
  severity_override: {}

fail_on: high
`;

module.exports = {
  ConfigError,
  DEFAULT_CONFIG,
  DEFAULT_LANGUAGES,
  INIT_LANGUAGES,
  INIT_TEMPLATE,
  buildScanOptions,
  findConfigFile,
  loadConfig,
  parseConfig,
  parseSeverityOverrides,
  resolveScanTargets,
  validateCoreSupportedConfig,
};
