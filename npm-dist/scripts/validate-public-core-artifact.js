"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  TRUSTED_ARTIFACT_PUBLIC_KEY,
  verifyManifestSignature,
} = require("../packages/scanner/lib/artifact-trust");

const REQUIRED_PROFILE = "public-starter";
const REQUIRED_SCHEMA = "devseccode-core-artifacts/v1";
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_PUBLIC_RULEPACK_FILES = 32;

const BANNED_MEMBER_PATTERNS = [
  /(^|\/)compliance_seeds(\/|$)/,
  /(^|\/)models?(\/|$)/,
  /(^|\/)model_assets?(\/|$)/,
  /(^|\/)premium(\/|$)/,
  /(^|\/)private(\/|$)/,
  /(^|\/)enterprise(\/|$)/,
  /(^|\/)sboms?(\/|$)/,
  /(^|\/)dsc\/presets\/(ccpa|cis|cis-v8|cmmc|deep|dora|eu-cra|fedramp|gdpr|hipaa|hitrust|iso27001|iso27701|nis2|nist|nist-csf|openclaw|owasp|owasp-2025|owasp-asvs|pci|pci-dss|sans|sans-top25|soc2|strict|supply-chain)\.ya?ml$/,
];

function die(message) {
  console.error(`validate-public-core-artifact: ${message}`);
  process.exit(1);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    die(`cannot read JSON ${file}: ${err.message}`);
  }
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function archiveMembers(archive) {
  const result = spawnSync("tar", ["-tzf", archive], { encoding: "utf8" });
  if (result.status !== 0) {
    die(`cannot list tar archive ${archive}: ${result.stderr || result.stdout}`);
  }
  const members = result.stdout.split(/\r?\n/).filter(Boolean);
  const verbose = spawnSync("tar", ["-tvzf", archive], { encoding: "utf8" });
  if (verbose.status !== 0) {
    die(`cannot inspect tar member types in ${archive}: ${verbose.stderr || verbose.stdout}`);
  }
  const verboseLines = verbose.stdout.split(/\r?\n/);
  const hardLinks = verboseLines.filter((line) => /^h/.test(line));
  if (hardLinks.length) {
    die(`target archive must not contain hard links:\n${hardLinks.slice(0, 20).join("\n")}`);
  }
  for (const line of verboseLines.filter((item) => /^l/.test(item))) {
    const marker = line.lastIndexOf(" -> ");
    if (marker < 0) die(`cannot validate archive symlink: ${line}`);
    safeRelativePath(line.slice(marker + 4), "archive symlink target");
  }
  return members;
}

function safeRelativePath(value, label) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.includes("\0")) {
    die(`${label} must be a non-empty portable relative path`);
  }
  const normalized = path.posix.normalize(value.replace(/^\.\//, ""));
  if (normalized === ".." || normalized.startsWith("../") || path.posix.isAbsolute(normalized)) {
    die(`${label} escapes the artifact root: ${value}`);
  }
  return normalized;
}

function manifestProfile(manifest) {
  return manifest.artifactProfile || manifest.profile || manifest.distributionProfile || manifest.sku;
}

function artifactProfile(manifest, artifact) {
  return artifact.artifactProfile || artifact.profile || artifact.distributionProfile || artifact.sku || manifestProfile(manifest);
}

function validateMetadata(manifest, artifact, target) {
  if (manifest.schemaVersion !== REQUIRED_SCHEMA) {
    die(`target ${target} manifest schema must be ${REQUIRED_SCHEMA}`);
  }
  const profile = artifactProfile(manifest, artifact);
  if (profile !== REQUIRED_PROFILE) {
    die(
      `target ${target} artifact profile must be ${REQUIRED_PROFILE}; got ${profile || "missing"}. ` +
      "Full/private Core artifacts must never be packaged for public npm.",
    );
  }
  if (manifest.publicNpm !== true && artifact.publicNpm !== true) {
    die(`target ${target} manifest must explicitly set publicNpm: true`);
  }
  if (manifest.containsFullCore !== false || artifact.containsFullCore !== false) {
    die(`target ${target} manifest and artifact must explicitly declare containsFullCore: false`);
  }
  if (manifest.containsPrivateAssets !== false || artifact.containsPrivateAssets !== false) {
    die(`target ${target} manifest and artifact must explicitly declare containsPrivateAssets: false`);
  }
}

function validateArchive(root, manifest, artifact, target) {
  if (!artifact.filename || !artifact.sha256 || !artifact.sizeBytes || !artifact.binaryRelativePath) {
    die(`target ${target} artifact entry is incomplete`);
  }
  if (artifact.target !== target) die(`artifact target mismatch: expected ${target}, got ${artifact.target}`);
  const filename = safeRelativePath(artifact.filename, `target ${target} filename`);
  if (path.posix.basename(filename) !== filename) {
    die(`target ${target} artifact filename must not contain directories`);
  }
  const binaryRelativePath = safeRelativePath(
    artifact.binaryRelativePath,
    `target ${target} binaryRelativePath`,
  );
  const archive = path.join(root, filename);
  if (!fs.existsSync(archive)) die(`archive missing for ${target}: ${archive}`);
  const actualSize = fs.statSync(archive).size;
  if (!Number.isSafeInteger(artifact.sizeBytes) || artifact.sizeBytes <= 0 || artifact.sizeBytes > MAX_ARCHIVE_BYTES) {
    die(`target ${target} sizeBytes must be between 1 and ${MAX_ARCHIVE_BYTES}`);
  }
  if (actualSize !== artifact.sizeBytes) {
    die(`size mismatch for ${target}: expected ${artifact.sizeBytes}, got ${actualSize}`);
  }
  const actualHash = sha256File(archive);
  if (actualHash !== artifact.sha256) {
    die(`sha256 mismatch for ${target}: expected ${artifact.sha256}, got ${actualHash}`);
  }

  const banned = [];
  const rulepackMembers = [];
  let expectedBinaryFound = false;
  for (const member of archiveMembers(archive)) {
    const normalized = safeRelativePath(member, `target ${target} archive member`);
    const comparable = normalized.toLowerCase();
    if (BANNED_MEMBER_PATTERNS.some((pattern) => pattern.test(comparable))) {
      banned.push(member);
    }
    if (/(^|\/)rulepacks\/_expanded\/.*\.ya?ml$/.test(comparable)) {
      rulepackMembers.push(member);
    }
    if (normalized === binaryRelativePath) expectedBinaryFound = true;
  }
  if (banned.length) {
    die(
      `target ${target} archive contains private/full-Core npm-banned payloads:\n` +
      banned.slice(0, 40).map((item) => `  - ${item}`).join("\n"),
    );
  }
  if (!expectedBinaryFound) {
    die(`target ${target} archive does not contain declared backend ${binaryRelativePath}`);
  }

  const declaredRules = artifact.publicRuleIds || manifest.publicRuleIds || artifact.starterRuleIds || manifest.starterRuleIds;
  if (!Array.isArray(declaredRules) || declaredRules.length === 0 || declaredRules.some((id) => typeof id !== "string" || !id)) {
    die(`target ${target} must declare a non-empty public/starter rule id allowlist`);
  }
  if (new Set(declaredRules).size !== declaredRules.length) {
    die(`target ${target} public/starter rule id allowlist contains duplicates`);
  }
  const maxRulepackFiles = Number(artifact.maxRulepackFiles || manifest.maxRulepackFiles || declaredRules.length);
  if (!Number.isInteger(maxRulepackFiles) || maxRulepackFiles < 1 || maxRulepackFiles > MAX_PUBLIC_RULEPACK_FILES) {
    die(`target ${target} maxRulepackFiles must be between 1 and ${MAX_PUBLIC_RULEPACK_FILES}`);
  }
  if (rulepackMembers.length > maxRulepackFiles) {
    die(
      `target ${target} contains ${rulepackMembers.length} rulepack files, above declared public limit ${maxRulepackFiles}`,
    );
  }
}

function main() {
  const [manifestPath, artifactRoot, target, publicKeyPath = TRUSTED_ARTIFACT_PUBLIC_KEY] = process.argv.slice(2);
  if (!manifestPath || !artifactRoot || !target) {
    die("usage: validate-public-core-artifact.js <manifest> <artifact-root> <target> [trusted-public-key]");
  }
  try {
    verifyManifestSignature(manifestPath, publicKeyPath);
  } catch (err) {
    die(err.message);
  }
  const manifest = readJson(manifestPath);
  const artifact = (manifest.artifacts || []).find((item) => item.target === target);
  if (!artifact) die(`target ${target} missing from artifact manifest`);
  validateMetadata(manifest, artifact, target);
  validateArchive(artifactRoot, manifest, artifact, target);
}

main();
