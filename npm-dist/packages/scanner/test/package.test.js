"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const pkg = require("../package.json");
const {
  SUPPORTED_TARGETS,
  commandCapabilities,
  endpointFilePath,
  materializeVerifiedArtifact,
  packageNameForTarget,
  startArgsForCore,
} = require("../lib/core");

function readPackageFile(relativePath) {
  return fs.readFileSync(path.resolve(__dirname, "..", relativePath), "utf8");
}

test("parent package ships the Node UX runtime", () => {
  assert.ok(pkg.files.includes("bin/"));
  assert.ok(pkg.files.includes("lib/"));
  assert.ok(pkg.files.includes("trust/"));
  assert.equal(pkg.dependencies["@devseccode/core-launcher"], "0.6.0");
  assert.equal(pkg.engines.node, "^22.0.0 || ^24.0.0");
});

test("capability requirements are per command", () => {
  assert.deepEqual(commandCapabilities("scan", "terminal"), ["scan.workspace"]);
  assert.deepEqual(commandCapabilities("scan", "sarif"), ["scan.workspace", "scan.export.sarif"]);
  assert.deepEqual(commandCapabilities("scan", "junit"), ["scan.workspace"]);
  assert.deepEqual(commandCapabilities("list-rules"), ["rules.list"]);
});

test("optional dependency matrix matches supported targets", () => {
  assert.deepEqual(
    Object.keys(pkg.optionalDependencies).sort(),
    SUPPORTED_TARGETS.map(packageNameForTarget).sort(),
  );
  for (const target of SUPPORTED_TARGETS) {
    assert.equal(pkg.optionalDependencies[packageNameForTarget(target)], pkg.version);
  }
});

test("linux-arm64 platform package is aligned and publishable", () => {
  const platform = require("../../scanner-linux-arm64/package.json");
  assert.equal(platform.private, undefined);
  assert.equal(platform.version, pkg.version);
  assert.equal(pkg.optionalDependencies[platform.name], pkg.version);
  assert.deepEqual(platform.os, ["linux"]);
  assert.deepEqual(platform.cpu, ["arm64"]);
  assert.equal(platform.publishConfig.access, "public");
});

test("Core endpoint discovery stays inside the package state root", () => {
  const oldHome = process.env.DEVSECCODE_HOME;
  const stateRoot = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "dsc-state-"));
  process.env.DEVSECCODE_HOME = stateRoot;
  try {
    assert.equal(endpointFilePath(), path.join(stateRoot, "endpoint.json"));
  } finally {
    if (oldHome == null) delete process.env.DEVSECCODE_HOME;
    else process.env.DEVSECCODE_HOME = oldHome;
  }
});

test("Core backend launch args can avoid fixed default ports", async () => {
  assert.deepEqual(await startArgsForCore({ host: "127.0.0.1", port: 32123 }), [
    "--host",
    "127.0.0.1",
    "--port",
    "32123",
  ]);
});

test("verified Core artifacts materialize into user state, not the installed package", () => {
  const sourceRoot = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "dsc-package-artifact-"));
  const stateRoot = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "dsc-artifact-cache-"));
  const archive = path.join(sourceRoot, "core.tar.gz");
  fs.writeFileSync(archive, "signed archive fixture");
  const digest = crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
  const manifestPath = path.join(sourceRoot, "devseccode-core-artifacts.json");
  fs.writeFileSync(manifestPath, `${JSON.stringify({
    schemaVersion: "devseccode-core-artifacts/v2",
    artifactProfile: "public-starter",
    publicNpm: true,
    containsFullCore: false,
    containsPrivateAssets: false,
    artifacts: [{
      target: "darwin-arm64",
      filename: "core.tar.gz",
      binaryRelativePath: "runtime/dsc-backend",
      sha256: digest,
    }],
  })}\n`);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  fs.writeFileSync(`${manifestPath}.sig`, `${JSON.stringify({
    algorithm: "ed25519",
    keyId: `ed25519:${crypto.createHash("sha256").update(publicDer).digest("hex").slice(0, 16)}`,
    signature: crypto.sign(null, fs.readFileSync(manifestPath), privateKey).toString("base64"),
  })}\n`);
  const publicKeyPath = path.join(sourceRoot, "public.pem");
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));

  const oldHome = process.env.DEVSECCODE_HOME;
  process.env.DEVSECCODE_HOME = stateRoot;
  try {
    const launcher = {
      verifyArtifactArchive: () => ({
        artifact: { sha256: digest },
        archivePath: archive,
      }),
      sha256File: (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
      resolveArtifact: ({ artifactRoot }) => {
        const binaryPath = path.join(artifactRoot, "runtime", "dsc-backend");
        if (!fs.existsSync(binaryPath)) throw new Error("not extracted");
        return { binaryPath, sha256: digest };
      },
      extractArtifactArchive: ({ artifactRoot }) => {
        const binaryPath = path.join(artifactRoot, "runtime", "dsc-backend");
        fs.mkdirSync(path.dirname(binaryPath), { recursive: true });
        fs.writeFileSync(binaryPath, "backend");
        return { binaryPath, sha256: digest };
      },
    };
    const artifact = materializeVerifiedArtifact({
      artifactRoot: sourceRoot,
      manifestPath,
    }, "darwin-arm64", launcher, publicKeyPath);
    assert.ok(artifact.binaryPath.startsWith(stateRoot));
    assert.ok(!fs.existsSync(path.join(sourceRoot, "runtime", "dsc-backend")));
  } finally {
    if (oldHome == null) delete process.env.DEVSECCODE_HOME;
    else process.env.DEVSECCODE_HOME = oldHome;
  }
});

test("platform packages declare artifacts rather than old bin payload files", () => {
  const packagesDir = path.resolve(__dirname, "..", "..");
  for (const target of SUPPORTED_TARGETS) {
    const platformPkg = JSON.parse(
      fs.readFileSync(path.join(packagesDir, `scanner-${target}`, "package.json"), "utf8"),
    );
    assert.ok(platformPkg.files.includes("artifacts/"));
    assert.ok(!platformPkg.files.includes("bin/"));
  }
});

test("platform package artifacts are placeholders or validated public starter payloads", () => {
  const packagesDir = path.resolve(__dirname, "..", "..");
  const validator = path.resolve(__dirname, "../../../scripts/validate-public-core-artifact.js");
  for (const target of SUPPORTED_TARGETS) {
    const artifactDir = path.join(packagesDir, `scanner-${target}`, "artifacts");
    const files = fs.readdirSync(artifactDir).filter((name) => name !== ".gitkeep");
    if (!files.length) continue;
    assert.ok(files.includes("devseccode-core-artifacts.json"), `${target} artifact dir has payloads without manifest`);
    assert.ok(files.includes("devseccode-core-artifacts.json.sig"), `${target} artifact dir has an unsigned manifest`);
    const result = spawnSync(
      process.execPath,
      [validator, path.join(artifactDir, "devseccode-core-artifacts.json"), artifactDir, target],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr || result.stdout);
  }
});

test("runtime does not fall back to a local DevSecCode-Core checkout", () => {
  const runtimeFiles = [
    "bin/dsc.js",
    "lib/cli.js",
    "lib/config.js",
    "lib/core.js",
    "lib/renderers.js",
    "lib/results.js",
    "lib/scanner.js",
    "lib/severity.js",
    "lib/state.js",
  ];
  const banned = [
    "DevSecCode-Core",
    "DevSecCode-Scanner",
    "DevSecCode-IDE",
    "/Users/",
    "DSC_CORE_ARTIFACT_DIR",
    "DSC_CORE_ARTIFACT_MANIFEST",
    "DSC_BACKEND_BINARY",
    "engine/src",
    "resources/sample-vulns",
  ];
  for (const file of runtimeFiles) {
    const text = readPackageFile(file);
    for (const pattern of banned) {
      assert.ok(!text.includes(pattern), `${file} contains banned runtime reference ${pattern}`);
    }
  }
});
