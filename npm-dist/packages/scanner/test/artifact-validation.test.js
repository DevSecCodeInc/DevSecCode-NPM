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

function writeManifest(workDir, archive, overrides = {}) {
  const manifest = {
    schemaVersion: "devseccode-core-artifacts/v1",
    artifactProfile: "public-starter",
    publicNpm: true,
    containsFullCore: false,
    containsPrivateAssets: false,
    publicRuleIds: ["starter-rule"],
    maxRulepackFiles: 1,
    artifacts: [{
      target: "darwin-arm64",
      filename: path.basename(archive),
      sha256: sha256(archive),
      sizeBytes: fs.statSync(archive).size,
      binaryRelativePath: "backend/dsc-backend",
      artifactProfile: "public-starter",
      publicNpm: true,
      containsFullCore: false,
      containsPrivateAssets: false,
      ...overrides,
    }],
  };
  const manifestPath = path.join(workDir, "devseccode-core-artifacts.json");
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const signature = crypto.sign(null, fs.readFileSync(manifestPath), privateKey);
  fs.writeFileSync(`${manifestPath}.sig`, `${JSON.stringify({
    algorithm: "ed25519",
    keyId: `ed25519:${crypto.createHash("sha256").update(publicDer).digest("hex").slice(0, 16)}`,
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
