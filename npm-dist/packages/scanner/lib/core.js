"use strict";

const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const pkg = require("../package.json");

const { statePath } = require("./state");
const {
  TRUSTED_ARTIFACT_PUBLIC_KEY,
  verifyManifestSignature,
} = require("./artifact-trust");

const SUPPORTED_TARGETS = Object.freeze([
  "darwin-arm64",
  "linux-x64",
  "win32-x64",
]);

function loadLauncher() {
  try {
    return require("@devseccode/core-launcher");
  } catch (err) {
    throw new Error(
      "@devseccode/core-launcher is not installed. Reinstall @devseccode/scanner so npm installs its runtime dependencies.",
    );
  }
}

function targetKey(platform = process.platform, arch = process.arch) {
  const normalizedArch = arch === "amd64" ? "x64" : arch === "aarch64" ? "arm64" : arch;
  return `${platform}-${normalizedArch}`;
}

function packageNameForTarget(target = targetKey()) {
  return `@devseccode/scanner-${target}`;
}

function resolveManifestInPlatformPackage(target = targetKey()) {
  const pkgName = packageNameForTarget(target);
  const rel = "artifacts/devseccode-core-artifacts.json";
  try {
    return require.resolve(`${pkgName}/${rel}`);
  } catch (_) {
    return null;
  }
}

function resolveArtifactSource(target = targetKey()) {
  const launcher = loadLauncher();
  if (!SUPPORTED_TARGETS.includes(target)) {
    throw new Error(
      `no Core artifact package for ${target}. Supported platforms: ${SUPPORTED_TARGETS.join(", ")}`,
    );
  }

  const packageManifest = resolveManifestInPlatformPackage(target);
  if (!packageManifest) {
    throw new Error(
      `cannot find ${packageNameForTarget(target)} Core artifacts. ` +
        "Reinstall @devseccode/scanner so npm installs the matching optional dependency.",
    );
  }

  return {
    target,
    artifactRoot: path.dirname(packageManifest),
    manifestPath: packageManifest,
    source: "platform-package",
  };
}

function sanitizeError(err) {
  return String(err && err.message ? err.message : err).replace(/Bearer\s+[A-Za-z0-9._~+/-]+/g, "Bearer [redacted]");
}

function endpointFilePath() {
  return statePath("endpoint.json");
}

function copyFileAtomic(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
  fs.copyFileSync(source, temporary);
  try {
    fs.renameSync(temporary, destination);
  } catch (err) {
    try {
      fs.unlinkSync(temporary);
    } catch (_) {
      // Preserve the original rename failure.
    }
    if (!fs.existsSync(destination)) throw err;
  }
}

function materializeVerifiedArtifact(
  source,
  target,
  launcher = loadLauncher(),
  publicKeyPath = TRUSTED_ARTIFACT_PUBLIC_KEY,
) {
  verifyManifestSignature(source.manifestPath, publicKeyPath);
  const verified = launcher.verifyArtifactArchive({
    artifactRoot: source.artifactRoot,
    manifestPath: source.manifestPath,
    publicKeyPath,
    target,
    requiredArtifactProfile: "public-starter",
  });
  const digest = verified.artifact.sha256;
  if (!/^[a-f0-9]{64}$/.test(digest)) {
    throw new Error(`Core artifact has invalid sha256 for ${target}`);
  }

  const cacheRoot = statePath(path.join("core", pkg.version, target, digest.slice(0, 16)));
  const cachedManifest = path.join(cacheRoot, "devseccode-core-artifacts.json");
  const cachedSignature = `${cachedManifest}.sig`;
  const cachedArchive = path.join(cacheRoot, path.basename(verified.archivePath));

  copyFileAtomic(source.manifestPath, cachedManifest);
  copyFileAtomic(`${source.manifestPath}.sig`, cachedSignature);
  if (!fs.existsSync(cachedArchive) || launcher.sha256File(cachedArchive) !== digest) {
    copyFileAtomic(verified.archivePath, cachedArchive);
  }

  verifyManifestSignature(cachedManifest, publicKeyPath);
  let artifact;
  try {
    artifact = launcher.resolveArtifact({
      artifactRoot: cacheRoot,
      manifestPath: cachedManifest,
      publicKeyPath,
      target,
      requiredArtifactProfile: "public-starter",
      verifyArchive: true,
    });
  } catch (_) {
    artifact = launcher.extractArtifactArchive({
      artifactRoot: cacheRoot,
      manifestPath: cachedManifest,
      publicKeyPath,
      target,
      requiredArtifactProfile: "public-starter",
      verifyArchive: true,
    });
  }
  return { ...artifact, cacheRoot };
}

async function chooseAvailablePort(host = "127.0.0.1") {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      server.close(() => {
        if (!address || typeof address !== "object") {
          reject(new Error("failed to allocate a Core backend port"));
          return;
        }
        resolve(address.port);
      });
    });
  });
}

async function startArgsForCore(options = {}) {
  if (Array.isArray(options.startArgs)) return options.startArgs;
  const host = options.host || "127.0.0.1";
  const port = options.port || await chooseAvailablePort(host);
  return ["--host", host, "--port", String(port)];
}

async function ensureCoreForCommand(requiredCapabilities, options = {}) {
  const launcher = loadLauncher();
  const target = options.target || targetKey();
  const source = resolveArtifactSource(target);
  const artifact = materializeVerifiedArtifact(source, target, launcher);
  const endpointFile = statePath(path.join(
    "core",
    "endpoints",
    `${target}-${artifact.sha256.slice(0, 16)}.json`,
  ));

  try {
    const connection = await launcher.ensureCore({
      binaryPath: artifact.binaryPath,
      endpointFile,
      expectedEngineVersion: artifact.engineVersion,
      requiredArtifactProfile: "public-starter",
      requiredCapabilities,
      startArgs: await startArgsForCore(options),
      timeoutMs: options.timeoutMs || 20000,
      intervalMs: options.intervalMs || 250,
    });
    return {
      ...connection,
      artifact,
      diagnostics: {
        target,
        artifactSource: source.source,
        artifactCache: artifact.cacheRoot,
        backend: artifact.binaryPath,
        endpointFile: connection.endpoint && connection.endpoint.endpointFile,
        endpointUrl: connection.endpoint && connection.endpoint.url,
        owned: Boolean(connection.owned),
      },
    };
  } catch (err) {
    const message = sanitizeError(err);
    const details = artifact && artifact.binaryPath ? ` (backend: ${artifact.binaryPath})` : "";
    throw new Error(`${message}${details}`);
  }
}

async function coreRequest(connection, route, init) {
  const launcher = loadLauncher();
  try {
    return await launcher.request(connection.endpoint, route, init);
  } catch (err) {
    throw new Error(sanitizeError(err));
  }
}

async function fetchCoreText(connection, route) {
  const endpoint = connection.endpoint;
  const response = await fetch(`${endpoint.url}${route}`, {
    headers: { Authorization: `Bearer ${endpoint.token}` },
  });
  if (!response.ok) {
    throw new Error(`Core ${route} failed with HTTP ${response.status}`);
  }
  return response.text();
}

function commandCapabilities(command, format) {
  if (command === "scan" && format === "sarif") return ["scan.workspace", "scan.export.sarif"];
  if (command === "scan" && format === "junit") return ["scan.workspace"];
  if (command === "scan") return ["scan.workspace"];
  if (command === "hunt" || command === "map" || command === "watch" || command === "play") {
    return ["scan.workspace"];
  }
  if (command === "list-rules" || command === "explain") return ["rules.list"];
  return [];
}

module.exports = {
  SUPPORTED_TARGETS,
  chooseAvailablePort,
  commandCapabilities,
  endpointFilePath,
  coreRequest,
  ensureCoreForCommand,
  fetchCoreText,
  loadLauncher,
  materializeVerifiedArtifact,
  packageNameForTarget,
  resolveArtifactSource,
  sanitizeError,
  startArgsForCore,
  targetKey,
};
