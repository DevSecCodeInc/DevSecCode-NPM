"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const validator = path.resolve(__dirname, "../../../scripts/validate-public-core-artifact.js");

function writeFile(root, relativePath, body = "x") {
  const file = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}

function makeArchive(workDir, members) {
  const src = path.join(workDir, "src");
  fs.mkdirSync(src, { recursive: true });
  for (const [relativePath, body] of Object.entries(members)) {
    writeFile(src, relativePath, body);
  }
  const archive = path.join(workDir, "artifact.tar.gz");
  const result = spawnSync("tar", ["-czf", archive, "-C", src, "."], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return archive;
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writeManifest(workDir, archive, overrides = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const signingKeyId = `ed25519:${digest(publicDer).slice(0, 16)}`;
  const sourceCommit = "a".repeat(40);
  const sourceFingerprint = digest("source");
  const packagingFingerprint = digest("packaging");
  const dependencyLockSha256 = digest("lock");
  const buildToolchainFingerprint = digest("toolchain");
  const publicRuleIds = ["starter-rule"];
  const evidence = (name) => ({ filename: name, sha256: digest(name), format: "json" });
  const manifest = {
    schemaVersion: "devseccode-core-artifacts/v2",
    generatedAt: "2026-08-21T00:00:00Z",
    engineVersion: "0.3.6",
    contractVersion: "v1",
    artifactProfile: "public-starter",
    sourceFingerprint,
    sourceCommit,
    packagingFingerprint,
    buildToolchainFingerprints: { "darwin-arm64": buildToolchainFingerprint },
    dependencyLockSha256,
    requiredCapabilities: ["scan.workspace", "scan.export.sarif"],
    publication: {
      channel: "candidate",
      candidateId: `${sourceCommit}-run-1-attempt-1`,
      immutableBaseUrl: `https://pub-${"b".repeat(32)}.r2.dev/candidates/v2/${sourceCommit}-run-1-attempt-1`,
      releasePath: "core/v0.3.6/public-starter",
    },
    signing: {
      algorithm: "ed25519",
      keyId: signingKeyId,
      signatureFilename: "devseccode-core-artifacts.json.sig",
      trustBundleFilename: "artifact-trust.json",
      trustBundleVersion: "v1",
      trustBundleSha256: digest("trust-bundle"),
    },
    sbom: evidence("matrix.spdx.json"),
    provenance: evidence("matrix.provenance.json"),
    publicNpm: true,
    containsFullCore: false,
    containsPrivateAssets: false,
    publicRuleIds,
    starterRuleIds: publicRuleIds,
    maxRulepackFiles: 1,
    artifacts: [{
      target: "darwin-arm64",
      platform: "darwin",
      arch: "arm64",
      filename: path.basename(archive),
      sha256: sha256(archive),
      sizeBytes: fs.statSync(archive).size,
      engineVersion: "0.3.6",
      contractVersion: "v1",
      format: "tar.gz",
      extractDir: "backend",
      binaryRelativePath: "backend/dsc-backend",
      binarySha256: digest("binary"),
      artifactProfile: "public-starter",
      sourceFingerprint,
      sourceCommit,
      packagingFingerprint,
      builtAt: "2026-08-21T00:00:00Z",
      buildEnvironmentFingerprint: digest("environment"),
      buildToolchainFingerprint,
      dependencyLockSha256,
      buildEnvironment: {
        python: "3.13.7",
        pythonImplementation: "CPython",
        platform: "macOS-15-arm64",
        packages: { pyinstaller: "6.15.0" },
      },
      minimumHost: { osFamily: "macOS", version: "15.0" },
      runtimeComponents: [
        { name: "python", version: "3.13.7" },
        { name: "opengrep", version: "1.10.0" },
      ],
      nativeSigning: { status: "signed", method: "test", evidence: evidence("native-signing.json") },
      sbom: evidence("darwin-arm64.spdx.json"),
      provenance: evidence("darwin-arm64.provenance.json"),
      publicNpm: true,
      containsFullCore: false,
      containsPrivateAssets: false,
      publicRuleIds,
      starterRuleIds: publicRuleIds,
      maxRulepackFiles: 1,
      ...overrides,
    }],
  };
  const manifestPath = path.join(workDir, "devseccode-core-artifacts.json");
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const signature = crypto.sign(null, fs.readFileSync(manifestPath), privateKey);
  fs.writeFileSync(`${manifestPath}.sig`, `${JSON.stringify({
    algorithm: "ed25519",
    keyId: signingKeyId,
    signature: signature.toString("base64"),
  }, null, 2)}\n`);
  const publicKeyPath = path.join(workDir, "artifact-ed25519-public.pem");
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));
  return { manifestPath, publicKeyPath };
}

function runValidator(bundle, workDir) {
  return spawnSync(process.execPath, [
    validator,
    bundle.manifestPath,
    workDir,
    "darwin-arm64",
    bundle.publicKeyPath,
  ], {
    encoding: "utf8",
  });
}

test("public Core artifact validator accepts declared starter artifact", () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-public-artifact-"));
  const archive = makeArchive(workDir, {
    "backend/dsc-backend": "binary",
    "rulepacks/_expanded/starter.yml": "id: starter-rule\n",
  });
  const bundle = writeManifest(workDir, archive);

  const result = runValidator(bundle, workDir);
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("public Core artifact validator rejects full/private Core payload markers", () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-private-artifact-"));
  const archive = makeArchive(workDir, {
    "backend/dsc-backend": "binary",
    "rulepacks/_expanded/starter.yml": "id: starter-rule\n",
    "compliance_seeds/pci-dss.json": "{}\n",
  });
  const bundle = writeManifest(workDir, archive);

  const result = runValidator(bundle, workDir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /private\/full-Core npm-banned payloads/);
});

test("public Core artifact validator requires explicit public starter profile", () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-full-artifact-"));
  const archive = makeArchive(workDir, {
    "backend/dsc-backend": "binary",
    "rulepacks/_expanded/starter.yml": "id: starter-rule\n",
  });
  const bundle = writeManifest(workDir, archive, { artifactProfile: "full-core" });

  const result = runValidator(bundle, workDir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /artifact profile must be public-starter/);
});

test("public Core artifact validator rejects explicit full product profile", () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-full-product-artifact-"));
  const archive = makeArchive(workDir, {
    "backend/dsc-backend": "binary",
    "rulepacks/_expanded/starter.yml": "id: starter-rule\n",
  });
  const bundle = writeManifest(workDir, archive, { artifactProfile: "full-product" });

  const result = runValidator(bundle, workDir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /artifact profile must be public-starter/);
});

test("public Core artifact validator rejects a manifest changed after signing", () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-tampered-manifest-"));
  const archive = makeArchive(workDir, {
    "backend/dsc-backend": "binary",
    "rulepacks/_expanded/starter.yml": "id: starter-rule\n",
  });
  const bundle = writeManifest(workDir, archive);
  fs.appendFileSync(bundle.manifestPath, " \n");

  const result = runValidator(bundle, workDir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /signature verification failed/);
});

test("public Core artifact validator rejects a signature from an untrusted key", () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-untrusted-manifest-"));
  const archive = makeArchive(workDir, {
    "backend/dsc-backend": "binary",
    "rulepacks/_expanded/starter.yml": "id: starter-rule\n",
  });
  const bundle = writeManifest(workDir, archive);
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(bundle.publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));

  const result = runValidator(bundle, workDir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /keyId does not match pinned key/);
});
