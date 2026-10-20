// Qualify an exact Core public-starter candidate as NPM input (refresh spec NPM-R1).
//
// Downloads and verifies the signed candidate with NPM's own fail-closed
// download and validation scripts, proves that tampered bytes are rejected,
// then starts the host target's real starter runtime and demonstrates scan
// scope isolation, cache invalidation, portable SARIF paths and scanner-crash
// rejection. Writes a JSON evidence record and exits non-zero on any failure.
//
// usage: node npm-dist/scripts/qualify-core-input.mjs \
//   <empty-work-dir> <core-version> <core-source-commit> <candidate-id> [evidence.json]

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const scannerRoot = path.resolve(scriptDirectory, "../packages/scanner");
const TARGETS = ["darwin-arm64", "linux-x64", "linux-arm64", "win32-x64"];
const PROFILE = "public-starter";
const SCAN_DEADLINE_MS = 180_000;

// Flask command injection: matched by the public starter CWE-78 rules.
export const VULNERABLE_PYTHON = [
  "import flask",
  "import os",
  "",
  "def run():",
  '    command = flask.request.args["cmd"]',
  "    os.system(command)",
  "",
].join("\n");
export const CLEAN_PYTHON = "def run():\n    return 'ok'\n";

function fail(message) {
  throw new Error(message);
}

// ---------------------------------------------------------------------------
// Pure checks (unit-tested without a Core runtime)

export function findingPaths(results, root) {
  return (results.findings || []).map((finding) => {
    const raw = finding.filePath || finding.file_path;
    if (typeof raw !== "string" || !raw) fail("finding has no file path");
    const absolute = path.isAbsolute(raw) ? raw : path.join(root, raw);
    return path.relative(root, absolute).split(path.sep).join("/");
  });
}

// Every finding must be inside one of the allowed relative paths (files or
// directories), and none may come from an excluded one.
export function scopeViolations(relativePaths, allowed, excluded = []) {
  const inside = (value, entry) => value === entry || value.startsWith(`${entry}/`);
  return relativePaths.filter((value) =>
    value.startsWith("../") ||
    !allowed.some((entry) => inside(value, entry)) ||
    excluded.some((entry) => inside(value, entry)));
}

// Portable SARIF: every result location is a relative, percent-encoded URI
// resolved against SRCROOT, and the workspace root appears only in
// originalUriBaseIds.
export function sarifPortabilityProblems(sarif, workspaceRoot) {
  const problems = [];
  const runs = Array.isArray(sarif?.runs) ? sarif.runs : [];
  if (runs.length !== 1) return ["SARIF must contain exactly one run"];
  const run = runs[0];
  const results = Array.isArray(run.results) ? run.results : [];
  if (results.length === 0) problems.push("SARIF has no results to check");
  const rootUri = run.originalUriBaseIds?.SRCROOT?.uri;
  if (typeof rootUri !== "string" || !rootUri.endsWith("/")) {
    problems.push("SARIF SRCROOT base URI is missing");
  } else if (fileURLToPath(rootUri).replace(/[\\/]$/, "") !== workspaceRoot) {
    problems.push(`SARIF SRCROOT ${rootUri} is not the scanned workspace`);
  }
  for (const result of results) {
    for (const location of result.locations || []) {
      const artifact = location.physicalLocation?.artifactLocation || {};
      const uri = artifact.uri;
      if (artifact.uriBaseId !== "SRCROOT") problems.push(`location ${uri} is not relative to SRCROOT`);
      if (typeof uri !== "string" || !uri) {
        problems.push("location has no URI");
        continue;
      }
      if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri) || uri.startsWith("/") || uri.includes("\\")) {
        problems.push(`location URI ${uri} is not a portable relative URI`);
      }
      if (/[ #]/.test(uri)) problems.push(`location URI ${uri} is not percent-encoded`);
    }
  }
  const { originalUriBaseIds: _ignored, ...rest } = run;
  const body = JSON.stringify({ ...sarif, runs: [rest] });
  const roots = [workspaceRoot, workspaceRoot.split(path.sep).join("/")];
  if (roots.some((value) => body.includes(value))) {
    problems.push("workspace root path leaks outside originalUriBaseIds");
  }
  return problems;
}

export function sarifLocations(sarif) {
  return (sarif.runs?.[0]?.results || []).flatMap((result) =>
    (result.locations || []).map((location) => {
      const physical = location.physicalLocation || {};
      return `${result.ruleId}|${physical.artifactLocation?.uriBaseId}|${physical.artifactLocation?.uri}|${physical.region?.startLine}`;
    })).sort();
}

// A crashed or malformed scanner run must never look like a clean scan.
export function crashRejected(results) {
  const status = String(results.status || "").toLowerCase();
  const errors = Array.isArray(results.errors) ? results.errors : [];
  if (status === "error") return true;
  return status === "complete" && errors.some((item) => /opengrep/i.test(String(item)));
}

export function cleanSuccess(results) {
  return String(results.status || "").toLowerCase() === "complete" &&
    Array.isArray(results.errors) && results.errors.length === 0;
}

// ---------------------------------------------------------------------------
// Runtime helpers

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function runNode(args) {
  const result = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { status: result.status, output: `${result.stdout || ""}${result.stderr || ""}`.trim() };
}

function requireEmptyDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true });
  if (fs.readdirSync(directory).length !== 0) fail(`work directory must be empty: ${directory}`);
  return fs.realpathSync(directory);
}

function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

function isolatedEnvironment(work, extra = {}) {
  const env = {};
  for (const name of ["PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR", "ComSpec", "PATHEXT"]) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  const home = path.join(work, "home");
  fs.mkdirSync(home, { recursive: true });
  return {
    ...env,
    HOME: home,
    USERPROFILE: home,
    DSC_STATE_DIR: path.join(work, "state"),
    LC_ALL: "C.UTF-8",
    LANG: "C.UTF-8",
    ...extra,
  };
}

async function freeLoopbackPort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function startCore(launcher, runtime, work, name, extraEnv = {}) {
  const instance = path.join(work, "instances", name);
  fs.mkdirSync(instance, { recursive: true });
  const connection = await launcher.ensureCore({
    binaryPath: runtime.binaryPath,
    endpointFile: path.join(instance, "endpoint.json"),
    expectedEngineVersion: runtime.engineVersion,
    requiredArtifactProfile: PROFILE,
    requiredCapabilities: ["scan.workspace", "scan.export.sarif"],
    startArgs: ["--host", "127.0.0.1", "--port", String(await freeLoopbackPort())],
    startEnv: isolatedEnvironment(instance, extraEnv),
    timeoutMs: 60_000,
  });
  if (connection.owned === false) fail(`refusing to reuse an unowned Core endpoint for ${name}`);
  return connection;
}

async function scan(launcher, connection, options) {
  const started = await launcher.request(connection.endpoint, "/v1/scan/start", {
    method: "POST",
    body: JSON.stringify({ options: { useCache: false, ...options } }),
  });
  const scanId = started.scanId || started.scan_id;
  if (typeof scanId !== "string" || !scanId) fail("Core returned no scan ID");
  const deadline = Date.now() + SCAN_DEADLINE_MS;
  for (;;) {
    const results = await launcher.request(
      connection.endpoint,
      `/v1/scan/${encodeURIComponent(scanId)}/results`,
    );
    const status = String(results.status || "").toLowerCase();
    if (["complete", "error", "cancelled"].includes(status)) return { scanId, ...results };
    if (Date.now() > deadline) fail(`scan ${scanId} did not finish (last status ${status})`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

async function sarifFor(launcher, connection, scanId) {
  const body = await launcher.request(
    connection.endpoint,
    `/v1/scan/${encodeURIComponent(scanId)}/export?format=sarif`,
  );
  return typeof body === "string" ? JSON.parse(body) : body;
}

function summary(results, root) {
  return {
    status: results.status,
    errors: results.errors || [],
    filesScanned: results.filesScanned,
    cacheHits: results.cacheHits,
    cacheMisses: results.cacheMisses,
    findings: findingPaths(results, root).sort(),
  };
}

function check(record, name, passed, details) {
  record.demonstrations[name] = { passed: Boolean(passed), ...details };
  process.stdout.write(`${passed ? "PASS" : "FAIL"} ${name}\n`);
}

// ---------------------------------------------------------------------------
// Steps

function verifyCandidate(record, work, coreVersion, sourceCommit, candidateId) {
  const artifacts = path.join(work, "core");
  fs.mkdirSync(artifacts);
  const download = runNode([
    path.join(scriptDirectory, "download-public-core-candidate.mjs"),
    artifacts, coreVersion, sourceCommit, candidateId,
  ]);
  if (download.status !== 0) fail(`candidate download/verification failed:\n${download.output}`);
  const manifestPath = path.join(artifacts, "devseccode-core-artifacts.json");
  for (const target of TARGETS) {
    const validation = runNode([
      path.join(scriptDirectory, "validate-public-core-artifact.js"), manifestPath, artifacts, target,
    ]);
    if (validation.status !== 0) fail(`${target} public-starter validation failed:\n${validation.output}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const signature = JSON.parse(fs.readFileSync(`${manifestPath}.sig`, "utf8"));
  record.input = {
    coreVersion: manifest.engineVersion,
    sourceCommit: manifest.sourceCommit,
    candidateId: manifest.publication.candidateId,
    profile: manifest.artifactProfile,
    immutableBaseUrl: manifest.publication.immutableBaseUrl,
    releasePath: manifest.publication.releasePath,
    contractVersion: manifest.contractVersion,
    manifestSha256: sha256File(manifestPath),
    manifestSignatureSha256: sha256File(`${manifestPath}.sig`),
    signingKeyId: signature.keyId,
    pinnedPublicKeySha256: sha256File(path.join(scannerRoot, "trust", "artifact-ed25519-public.pem")),
    launcher: require(path.join(scannerRoot, "node_modules", "@devseccode", "core-launcher", "package.json")).version,
    publicRuleIdCount: manifest.publicRuleIds.length,
    maxRulepackFiles: manifest.maxRulepackFiles,
    targets: Object.fromEntries(manifest.artifacts.map((artifact) => [artifact.target, {
      filename: artifact.filename,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
      binarySha256: artifact.binarySha256,
    }])),
  };
  return { artifacts, manifestPath };
}

function proveTamperRejection(record, launcher, work, artifacts, target) {
  const { verifyManifestSignature } = require(path.join(scannerRoot, "lib", "artifact-trust.js"));
  const manifestPath = path.join(artifacts, "devseccode-core-artifacts.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const artifact = manifest.artifacts.find((item) => item.target === target);

  const tamperedManifest = path.join(work, "tampered-manifest");
  fs.mkdirSync(tamperedManifest);
  const manifestBytes = fs.readFileSync(manifestPath);
  manifestBytes[manifestBytes.length - 2] ^= 0x01;
  fs.writeFileSync(path.join(tamperedManifest, "devseccode-core-artifacts.json"), manifestBytes);
  fs.copyFileSync(`${manifestPath}.sig`, path.join(tamperedManifest, "devseccode-core-artifacts.json.sig"));
  let manifestRejected = false;
  try {
    verifyManifestSignature(path.join(tamperedManifest, "devseccode-core-artifacts.json"));
  } catch (_) {
    manifestRejected = true;
  }

  const tamperedArchive = path.join(work, "tampered-archive");
  fs.mkdirSync(tamperedArchive);
  fs.copyFileSync(manifestPath, path.join(tamperedArchive, "devseccode-core-artifacts.json"));
  fs.copyFileSync(`${manifestPath}.sig`, path.join(tamperedArchive, "devseccode-core-artifacts.json.sig"));
  const archiveBytes = fs.readFileSync(path.join(artifacts, artifact.filename));
  archiveBytes[Math.floor(archiveBytes.length / 2)] ^= 0x01;
  fs.writeFileSync(path.join(tamperedArchive, artifact.filename), archiveBytes);
  let archiveError = "";
  try {
    launcher.verifyArtifactArchive({
      artifactRoot: tamperedArchive,
      manifestPath: path.join(tamperedArchive, "devseccode-core-artifacts.json"),
      publicKeyPath: path.join(scannerRoot, "trust", "artifact-ed25519-public.pem"),
      target,
      requiredArtifactProfile: PROFILE,
    });
  } catch (error) {
    archiveError = String(error.message || error);
  }
  check(record, "tamperRejection", manifestRejected && archiveError !== "", {
    manifestByteFlipRejected: manifestRejected,
    archiveByteFlipRejected: archiveError !== "",
    archiveError: archiveError.slice(0, 200),
  });
  fs.rmSync(tamperedArchive, { recursive: true, force: true });
}

function extractRuntime(launcher, work, artifacts, target) {
  const root = path.join(work, "runtime");
  fs.mkdirSync(root);
  for (const name of ["devseccode-core-artifacts.json", "devseccode-core-artifacts.json.sig"]) {
    fs.copyFileSync(path.join(artifacts, name), path.join(root, name));
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "devseccode-core-artifacts.json"), "utf8"));
  const artifact = manifest.artifacts.find((item) => item.target === target);
  fs.copyFileSync(path.join(artifacts, artifact.filename), path.join(root, artifact.filename));
  return launcher.extractArtifactArchive({
    artifactRoot: root,
    manifestPath: path.join(root, "devseccode-core-artifacts.json"),
    publicKeyPath: path.join(scannerRoot, "trust", "artifact-ed25519-public.pem"),
    target,
    requiredArtifactProfile: PROFILE,
    verifyArchive: true,
  });
}

async function demonstrateScope(record, launcher, connection, fixtures) {
  const root = path.join(fixtures, "scope");
  write(path.join(root, "app", "target.py"), VULNERABLE_PYTHON);
  write(path.join(root, "app", "sibling.py"), VULNERABLE_PYTHON);
  write(path.join(root, "excluded", "ignored.py"), VULNERABLE_PYTHON);
  write(path.join(root, ".dsc_cache", "cache.py"), VULNERABLE_PYTHON);

  const details = {};
  let passed = true;
  for (const useCache of [false, true]) {
    const single = await scan(launcher, connection, { targetPath: path.join(root, "app", "target.py"), useCache });
    const singlePaths = findingPaths(single, root);
    const singleOk = cleanSuccess(single) && singlePaths.length > 0 &&
      scopeViolations(singlePaths, ["app/target.py"]).length === 0;
    const workspace = await scan(launcher, connection, {
      targetPath: root, ignorePatterns: ["excluded/"], useCache,
    });
    const workspacePaths = findingPaths(workspace, root);
    const workspaceOk = cleanSuccess(workspace) &&
      workspacePaths.includes("app/target.py") && workspacePaths.includes("app/sibling.py") &&
      scopeViolations(workspacePaths, ["app"], ["excluded", ".dsc_cache"]).length === 0;
    details[useCache ? "warmCache" : "noCache"] = {
      singleFileTarget: summary(single, root),
      workspaceWithIgnore: summary(workspace, root),
    };
    passed = passed && singleOk && workspaceOk;
  }
  check(record, "scopeIsolation", passed, details);
}

async function demonstrateCache(record, launcher, connection, fixtures) {
  const root = path.join(fixtures, "cache");
  const first = path.join(root, "first.py");
  const second = path.join(root, "second.py");
  write(first, VULNERABLE_PYTHON);
  write(second, CLEAN_PYTHON);
  const cold = await scan(launcher, connection, { targetPath: root, useCache: true });
  const warm = await scan(launcher, connection, { targetPath: root, useCache: true });
  // Swap the vulnerable and clean contents. Size changes too, so the edit is
  // visible even on filesystems with coarse modification times.
  write(first, `${CLEAN_PYTHON}# edited\n`);
  write(second, `${VULNERABLE_PYTHON}# edited\n`);
  const edited = await scan(launcher, connection, { targetPath: root, useCache: true });
  const fresh = await scan(launcher, connection, { targetPath: root, useCache: false });
  const unique = (results) => [...new Set(findingPaths(results, root))].sort();
  const passed = [cold, warm, edited, fresh].every(cleanSuccess) &&
    JSON.stringify(unique(cold)) === JSON.stringify(["first.py"]) &&
    JSON.stringify(unique(warm)) === JSON.stringify(["first.py"]) &&
    Number(warm.cacheHits) >= 2 && Number(warm.cacheMisses) === 0 &&
    JSON.stringify(unique(edited)) === JSON.stringify(["second.py"]) &&
    Number(edited.cacheMisses) >= 2 &&
    JSON.stringify(unique(edited)) === JSON.stringify(unique(fresh));
  check(record, "cacheInvalidation", passed, {
    cold: summary(cold, root),
    warmUnchanged: summary(warm, root),
    afterEdit: summary(edited, root),
    noCacheReference: summary(fresh, root),
  });
}

async function demonstrateSarif(record, launcher, connection, fixtures) {
  const relative = path.join("src", "web app #1.py");
  const roots = [path.join(fixtures, "sarif", "checkout one"), path.join(fixtures, "sarif", "elsewhere", "checkout-two")];
  const exports = [];
  for (const root of roots) {
    write(path.join(root, relative), VULNERABLE_PYTHON);
    write(path.join(root, "lib", "util.py"), VULNERABLE_PYTHON);
    const results = await scan(launcher, connection, { targetPath: root });
    const sarif = await sarifFor(launcher, connection, results.scanId);
    exports.push({ root, results, sarif, problems: sarifPortabilityProblems(sarif, root) });
  }
  const [one, two] = exports;
  const sameLocations = JSON.stringify(sarifLocations(one.sarif)) === JSON.stringify(sarifLocations(two.sarif));
  const passed = exports.every((item) => cleanSuccess(item.results) && item.problems.length === 0) && sameLocations;
  check(record, "portableSarif", passed, {
    locations: sarifLocations(one.sarif),
    srcroot: exports.map((item) => item.sarif.runs?.[0]?.originalUriBaseIds?.SRCROOT?.uri),
    problems: exports.map((item) => item.problems),
    identicalAfterRelocation: sameLocations,
  });
}

// The stub stands in for the bundled scanner; the Core runtime under test is
// unchanged. Each mode imitates a failure the 983d1d7 fix must reject.
export const CRASH_MODES = {
  "empty-exit-0": { stdout: "", stderr: "", code: 0 },
  "empty-exit-2-fatal": { stdout: "", stderr: "Fatal error: exception Sys_error(\"missing config\")", code: 2 },
  "json-not-a-report": { stdout: "{}", stderr: "", code: 0 },
  "null-report": { stdout: "null", stderr: "", code: 0 },
};
const VALID_EMPTY_REPORT = { stdout: '{"results":[],"errors":[],"paths":{"scanned":[]}}', stderr: "", code: 0 };

function writeScannerStub(directory) {
  const stub = path.join(directory, "opengrep");
  const modeFile = path.join(directory, "mode.json");
  write(stub, [
    `#!${process.execPath}`,
    "const fs = require('node:fs');",
    "if (process.argv.includes('--version')) { process.stdout.write('1.20.0\\n'); process.exit(0); }",
    `const mode = JSON.parse(fs.readFileSync(${JSON.stringify(modeFile)}, 'utf8'));`,
    "process.stdout.write(mode.stdout); process.stderr.write(mode.stderr); process.exitCode = mode.code;",
    "",
  ].join("\n"));
  fs.chmodSync(stub, 0o755);
  return { stub, modeFile };
}

async function demonstrateCrashRejection(record, launcher, runtime, work, fixtures) {
  if (process.platform === "win32") {
    check(record, "scannerCrashRejection", false, { skipped: "scanner stub is POSIX-only" });
    return;
  }
  const root = path.join(fixtures, "crash");
  write(path.join(root, "app.py"), VULNERABLE_PYTHON);
  const { stub, modeFile } = writeScannerStub(path.join(work, "scanner-stub"));
  const connection = await startCore(launcher, runtime, work, "crash", { DSC_OPENGREP_BINARY: stub });
  const outcomes = {};
  let passed = true;
  try {
    for (const [name, mode] of Object.entries(CRASH_MODES)) {
      write(modeFile, JSON.stringify(mode));
      const results = await scan(launcher, connection, { targetPath: root });
      const rejected = crashRejected(results) && (results.findings || []).length === 0;
      outcomes[name] = { rejected, ...summary(results, root) };
      passed = passed && rejected;
    }
    write(modeFile, JSON.stringify(VALID_EMPTY_REPORT));
    const control = await scan(launcher, connection, { targetPath: root });
    outcomes["valid-empty-report-control"] = { cleanSuccess: cleanSuccess(control), ...summary(control, root) };
    passed = passed && cleanSuccess(control);
  } finally {
    await launcher.stopBackend(connection);
  }
  check(record, "scannerCrashRejection", passed, { outcomes });
}

export async function main(argv = process.argv.slice(2)) {
  const [workArg, coreVersion, sourceCommit, candidateId, evidenceArg] = argv;
  if (!workArg || !coreVersion || !sourceCommit || !candidateId) {
    fail("usage: qualify-core-input.mjs <empty-work-dir> <core-version> <core-source-commit> <candidate-id> [evidence.json]");
  }
  const target = `${process.platform}-${process.arch === "amd64" ? "x64" : process.arch}`;
  if (!TARGETS.includes(target)) fail(`unsupported host target ${target}`);
  const work = requireEmptyDirectory(path.resolve(workArg));
  const evidencePath = path.resolve(evidenceArg || path.join(work, "core-input-evidence.json"));
  const launcher = require(path.join(scannerRoot, "node_modules", "@devseccode", "core-launcher"));
  const record = {
    schemaVersion: "devseccode-npm-core-input-qualification/v1",
    generatedAt: new Date().toISOString(),
    host: { target, node: process.version, os: `${os.type()} ${os.release()}` },
    demonstrations: {},
  };

  const { artifacts } = verifyCandidate(record, work, coreVersion, sourceCommit, candidateId);
  process.stdout.write("PASS candidateVerification (signature, hashes, profile, four targets)\n");
  proveTamperRejection(record, launcher, work, artifacts, target);
  const runtime = extractRuntime(launcher, work, artifacts, target);
  record.runtime = { target, binarySha256: launcher.sha256File(runtime.binaryPath), engineVersion: runtime.engineVersion };

  const fixtures = path.join(work, "fixtures");
  fs.mkdirSync(fixtures);
  const connection = await startCore(launcher, runtime, work, "main");
  try {
    record.runtime.meta = {
      engineVersion: connection.meta.engineVersion,
      artifactProfile: connection.meta.artifactProfile,
      contractVersion: connection.meta.contractVersion,
    };
    await demonstrateScope(record, launcher, connection, fixtures);
    await demonstrateCache(record, launcher, connection, fixtures);
    await demonstrateSarif(record, launcher, connection, fixtures);
  } finally {
    await launcher.stopBackend(connection);
  }
  await demonstrateCrashRejection(record, launcher, runtime, work, fixtures);

  record.passed = Object.values(record.demonstrations).every((item) => item.passed);
  fs.writeFileSync(evidencePath, `${JSON.stringify(record, null, 2)}\n`);
  process.stdout.write(`${record.passed ? "PASS" : "FAIL"} evidence written to ${evidencePath}\n`);
  if (!record.passed) process.exitCode = 1;
  return record;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`qualify-core-input: ${error.stack || error.message || error}\n`);
    process.exitCode = 1;
  });
}
