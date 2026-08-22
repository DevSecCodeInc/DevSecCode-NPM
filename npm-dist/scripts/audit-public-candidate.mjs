import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const TARGETS = ["darwin-arm64", "linux-x64", "win32-x64"];
const PARENT_FILES = new Set([
  "package/LICENSE",
  "package/README.md",
  "package/bin/dsc.js",
  "package/lib/artifact-trust.js",
  "package/lib/cli.js",
  "package/lib/config.js",
  "package/lib/core.js",
  "package/lib/renderers.js",
  "package/lib/results.js",
  "package/lib/scanner.js",
  "package/lib/severity.js",
  "package/lib/state.js",
  "package/package.json",
  "package/trust/artifact-ed25519-public.pem",
]);
const PLATFORM_FIXED_FILES = new Set([
  "package/LICENSE",
  "package/README.md",
  "package/package.json",
  "package/artifacts/.gitkeep",
  "package/artifacts/devseccode-core-artifacts.json",
  "package/artifacts/devseccode-core-artifacts.json.sig",
]);

function fail(message) {
  throw new Error(message);
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) fail(result.stderr || result.stdout || `${command} failed`);
  return result.stdout;
}

function normalizedMember(value) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.includes("\0")) {
    fail("candidate tarball contains an invalid member name");
  }
  const normalized = path.posix.normalize(value.replace(/^\.\//, ""));
  if (normalized === ".." || normalized.startsWith("../") || path.posix.isAbsolute(normalized)) {
    fail(`candidate tarball member escapes package root: ${value}`);
  }
  return normalized;
}

export function packageMembers(tarball) {
  const members = run("tar", ["-tzf", tarball])
    .split(/\r?\n/)
    .filter(Boolean)
    .map(normalizedMember)
    .filter(Boolean);
  if (new Set(members).size !== members.length) fail(`candidate tarball has duplicate members: ${tarball}`);
  const verbose = run("tar", ["-tvzf", tarball]).split(/\r?\n/).filter(Boolean);
  if (verbose.some((line) => /^[lh]/.test(line))) fail(`candidate tarball contains links: ${tarball}`);
  return members;
}

export function auditParentMembers(members) {
  const files = members.filter((member) => !member.endsWith("/") && member !== "package");
  const unexpected = files.filter((member) => !PARENT_FILES.has(member));
  if (unexpected.length) fail(`public parent package contains an unapproved file: ${unexpected[0]}`);
  const missing = [...PARENT_FILES].filter((member) => !files.includes(member));
  if (missing.length) fail(`public parent package is missing a required file: ${missing[0]}`);
}

export function auditPlatformMembers(members, archiveFilename) {
  const allowed = new Set([
    ...PLATFORM_FIXED_FILES,
    `package/artifacts/${archiveFilename}`,
    `package/artifacts/${archiveFilename}.sha256`,
  ]);
  const files = members.filter((member) => !member.endsWith("/") && member !== "package");
  const unexpected = files.filter((member) => !allowed.has(member));
  if (unexpected.length) fail(`public platform package contains an unapproved file: ${unexpected[0]}`);
  for (const required of [
    "package/package.json",
    "package/artifacts/devseccode-core-artifacts.json",
    "package/artifacts/devseccode-core-artifacts.json.sig",
    `package/artifacts/${archiveFilename}`,
  ]) {
    if (!files.includes(required)) fail(`public platform package is missing a required file: ${required}`);
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function extract(tarball, destination) {
  fs.mkdirSync(destination, { recursive: true });
  run("tar", ["-xzf", tarball, "-C", destination]);
}

function sameBytes(left, right, label) {
  if (!fs.readFileSync(left).equals(fs.readFileSync(right))) fail(`${label} differs from the accepted Core candidate`);
}

function expectedPackageNames() {
  return [
    ...TARGETS.map((target) => `@devseccode/scanner-${target}`),
    "@devseccode/scanner",
  ];
}

function auditCandidate(candidateDirectory, publicKeyPath) {
  const record = readJson(path.join(candidateDirectory, "devseccode-npm-release.json"));
  if (record.schemaVersion !== "devseccode-npm-release/v1" || record.product?.edition !== "public-starter") {
    fail("candidate record is not the public-starter release contract");
  }
  const expectedNames = expectedPackageNames();
  const actualNames = (record.packages || []).map((item) => item.name).sort();
  if (JSON.stringify(actualNames) !== JSON.stringify([...expectedNames].sort())) {
    fail("candidate package matrix is not the approved public package set");
  }
  const coreManifest = path.join(candidateDirectory, "core", "devseccode-core-artifacts.json");
  const coreSignature = `${coreManifest}.sig`;
  const manifest = readJson(coreManifest);
  if (
    manifest.schemaVersion !== "devseccode-core-artifacts/v2" ||
    manifest.artifactProfile !== "public-starter" ||
    manifest.publicNpm !== true ||
    manifest.containsFullCore !== false ||
    manifest.containsPrivateAssets !== false
  ) {
    fail("accepted Core manifest violates the public-starter boundary");
  }
  const artifacts = new Map((manifest.artifacts || []).map((artifact) => [artifact.target, artifact]));
  if (artifacts.size !== TARGETS.length || TARGETS.some((target) => !artifacts.has(target))) {
    fail("accepted Core manifest target matrix is not the public NPM matrix");
  }

  const extractionRoot = fs.mkdtempSync(path.join(os.tmpdir(), "devseccode-npm-public-audit-"));
  try {
    for (const item of record.packages) {
      const tarball = path.join(candidateDirectory, item.filename);
      const members = packageMembers(tarball);
      const packageRoot = path.join(extractionRoot, item.name.replace(/[^A-Za-z0-9_.-]/g, "_"));
      if (item.name === "@devseccode/scanner") {
        auditParentMembers(members);
        extract(tarball, packageRoot);
        const packed = readJson(path.join(packageRoot, "package", "package.json"));
        if (packed.name !== item.name || packed.version !== record.product.version) {
          fail("packed public parent identity does not match the candidate record");
        }
        continue;
      }

      const target = item.target;
      const artifact = artifacts.get(target);
      if (!artifact || item.name !== `@devseccode/scanner-${target}`) {
        fail(`packed public platform identity is invalid: ${item.name}`);
      }
      auditPlatformMembers(members, artifact.filename);
      extract(tarball, packageRoot);
      const packedRoot = path.join(packageRoot, "package");
      const packed = readJson(path.join(packedRoot, "package.json"));
      if (packed.name !== item.name || packed.version !== record.product.version) {
        fail(`packed public platform identity does not match the candidate record: ${item.name}`);
      }
      const artifactRoot = path.join(packedRoot, "artifacts");
      sameBytes(path.join(artifactRoot, "devseccode-core-artifacts.json"), coreManifest, `${target} manifest`);
      sameBytes(path.join(artifactRoot, "devseccode-core-artifacts.json.sig"), coreSignature, `${target} signature`);
      const validator = path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        "validate-public-core-artifact.js",
      );
      const args = [
        validator,
        path.join(artifactRoot, "devseccode-core-artifacts.json"),
        artifactRoot,
        target,
      ];
      if (publicKeyPath) args.push(publicKeyPath);
      run(process.execPath, args);
    }
  } finally {
    fs.rmSync(extractionRoot, { recursive: true, force: true });
  }
  process.stdout.write("Exact public NPM candidate IP boundary audit passed.\n");
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  const [candidateDirectory, publicKeyPath] = process.argv.slice(2);
  if (!candidateDirectory) fail("usage: audit-public-candidate.mjs <candidate-directory> [trusted-public-key]");
  auditCandidate(path.resolve(candidateDirectory), publicKeyPath ? path.resolve(publicKeyPath) : undefined);
}
