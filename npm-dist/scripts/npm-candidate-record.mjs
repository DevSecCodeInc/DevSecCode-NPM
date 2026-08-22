import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PACKAGE_TARGETS = ["darwin-arm64", "linux-x64", "win32-x64"];
const MAX_PACKAGE_BYTES = 100 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function sha(file, algorithm, encoding) {
  return crypto.createHash(algorithm).update(fs.readFileSync(file)).digest(encoding);
}

function fileIdentity(file) {
  const sizeBytes = fs.statSync(file).size;
  return {
    sizeBytes,
    sha256: sha(file, "sha256", "hex"),
    integrity: `sha512-${sha(file, "sha512", "base64")}`,
  };
}

function assertPackageSize(file, sizeBytes) {
  if (sizeBytes > MAX_PACKAGE_BYTES) {
    fail(`candidate package exceeds the 100 MiB release limit: ${path.basename(file)}`);
  }
}

function expectedPackages(version) {
  return [
    ...PACKAGE_TARGETS.map((target) => ({
      name: `@devseccode/scanner-${target}`,
      target,
      filename: `devseccode-scanner-${target}-${version}.tgz`,
    })),
    {
      name: "@devseccode/scanner",
      target: null,
      filename: `devseccode-scanner-${version}.tgz`,
    },
  ];
}

function validateExpected(value, expected) {
  if (value.schemaVersion !== "devseccode-npm-release/v1") fail("NPM candidate record schema mismatch");
  if (value.product?.name !== "@devseccode/scanner") fail("NPM candidate product mismatch");
  if (value.product?.version !== expected.npmVersion) fail("NPM candidate version mismatch");
  if (value.product?.sourceCommit !== expected.npmSourceCommit) fail("NPM source commit mismatch");
  if (value.product?.edition !== "public-starter") fail("NPM candidate edition mismatch");
  if (value.core?.version !== expected.coreVersion) fail("Core version mismatch");
  if (value.core?.sourceCommit !== expected.coreSourceCommit) fail("Core source commit mismatch");
  if (value.core?.candidateId !== expected.coreCandidateId) fail("Core candidate ID mismatch");
  if (value.core?.profile !== "public-starter") fail("Core profile mismatch");
  if (value.core?.manifestSchemaVersion !== "devseccode-core-artifacts/v2") fail("Core manifest schema mismatch");
  if (value.launcher?.packageName !== "@devseccode/core-launcher") fail("Core launcher package mismatch");
  if (value.launcher?.version !== "0.6.0") fail("Core launcher version mismatch");
  if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(value.launcher?.integrity || "")) fail("Core launcher integrity is invalid");
}

const [operation, directory, npmVersion, npmSourceCommit, coreVersion, coreSourceCommit, coreCandidateId] = process.argv.slice(2);
if (![operation, directory, npmVersion, npmSourceCommit, coreVersion, coreSourceCommit, coreCandidateId].every(Boolean)) {
  fail("usage: npm-candidate-record.mjs <create|verify> <directory> <npm-version> <npm-source> <core-version> <core-source> <core-candidate-id>");
}
if (!/^[0-9a-f]{40}$/.test(npmSourceCommit) || !/^[0-9a-f]{40}$/.test(coreSourceCommit)) fail("source commits must be full SHAs");
const expected = { npmVersion, npmSourceCommit, coreVersion, coreSourceCommit, coreCandidateId };
const recordPath = path.join(directory, "devseccode-npm-release.json");
const manifestPath = path.join(directory, "core", "devseccode-core-artifacts.json");
const signaturePath = `${manifestPath}.sig`;

if (operation === "create") {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const launcherIntegrity = process.env.CORE_LAUNCHER_INTEGRITY || "";
  if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(launcherIntegrity)) fail("CORE_LAUNCHER_INTEGRITY is invalid");
  const packages = expectedPackages(npmVersion).map((item) => {
    const file = path.join(directory, item.filename);
    if (!fs.statSync(file).isFile()) fail(`candidate package missing: ${item.filename}`);
    const identity = fileIdentity(file);
    assertPackageSize(file, identity.sizeBytes);
    return { ...item, ...identity };
  });
  const record = {
    schemaVersion: "devseccode-npm-release/v1",
    product: {
      name: "@devseccode/scanner",
      version: npmVersion,
      sourceCommit: npmSourceCommit,
      edition: "public-starter",
    },
    core: {
      version: coreVersion,
      sourceCommit: coreSourceCommit,
      candidateId: coreCandidateId,
      profile: "public-starter",
      manifestSchemaVersion: manifest.schemaVersion,
      manifestSha256: fileIdentity(manifestPath).sha256,
      signatureSha256: fileIdentity(signaturePath).sha256,
    },
    launcher: {
      packageName: "@devseccode/core-launcher",
      version: "0.6.0",
      integrity: launcherIntegrity,
    },
    packages,
    decision: "candidate",
  };
  validateExpected(record, expected);
  fs.writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
} else if (operation === "verify") {
  const record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
  validateExpected(record, expected);
  if (record.core.manifestSha256 !== fileIdentity(manifestPath).sha256) fail("Core manifest digest mismatch");
  if (record.core.signatureSha256 !== fileIdentity(signaturePath).sha256) fail("Core signature digest mismatch");
  const packages = expectedPackages(npmVersion);
  if (!Array.isArray(record.packages) || record.packages.length !== packages.length) fail("NPM package matrix mismatch");
  for (const expectedPackage of packages) {
    const actual = record.packages.find((item) => item.name === expectedPackage.name);
    if (!actual || actual.target !== expectedPackage.target || actual.filename !== expectedPackage.filename) {
      fail(`NPM package identity mismatch: ${expectedPackage.name}`);
    }
    const identity = fileIdentity(path.join(directory, actual.filename));
    assertPackageSize(actual.filename, identity.sizeBytes);
    if (actual.sizeBytes !== identity.sizeBytes || actual.sha256 !== identity.sha256 || actual.integrity !== identity.integrity) {
      fail(`NPM package bytes mismatch: ${actual.name}`);
    }
  }
  process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
} else {
  fail(`unknown operation: ${operation}`);
}
