import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { verifyManifestSignature } = require("../packages/scanner/lib/artifact-trust");

const PUBLIC_R2_BASE_URL = "https://pub-191ac21d4b494237b052c0a3f0b9baee.r2.dev";
const TARGETS = ["darwin-arm64", "linux-x64", "win32-x64"];
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 8192;
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function safeFilename(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    fail(`${label} is not a safe filename`);
  }
  return value;
}

async function download(url, destination, maxBytes, expectedSize, expectedSha256) {
  const response = await fetch(url, { redirect: "error" });
  if (!response.ok || !response.body) fail(`download failed with HTTP ${response.status}: ${url}`);
  const declaredSize = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredSize) && declaredSize > maxBytes) fail(`download exceeds size limit: ${url}`);
  if (expectedSize && Number.isFinite(declaredSize) && declaredSize !== expectedSize) {
    fail(`download content-length mismatch: ${url}`);
  }
  let size = 0;
  const hash = crypto.createHash("sha256");
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      if (size > maxBytes) callback(new Error(`download exceeds size limit: ${url}`));
      else {
        hash.update(chunk);
        callback(null, chunk);
      }
    },
  });
  try {
    await pipeline(Readable.fromWeb(response.body), meter, fs.createWriteStream(destination, { flags: "wx" }));
  } catch (error) {
    fs.rmSync(destination, { force: true });
    throw error;
  }
  if (expectedSize && size !== expectedSize) fail(`download size mismatch: ${url}`);
  const digest = hash.digest("hex");
  if (expectedSha256 && digest !== expectedSha256) fail(`download sha256 mismatch: ${url}`);
  return { size, sha256: digest };
}

const [outputDirectory, coreVersion, coreSourceCommit, candidateId] = process.argv.slice(2);
if (!outputDirectory || !coreVersion || !coreSourceCommit || !candidateId) {
  fail("usage: download-public-core-candidate.mjs <output-dir> <core-version> <core-source-commit> <candidate-id>");
}
if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?$/.test(coreVersion)) fail("Core version is invalid");
if (!/^[0-9a-f]{40}$/.test(coreSourceCommit)) fail("Core source commit is invalid");
if (!new RegExp(`^${coreSourceCommit}-run-[1-9][0-9]*-attempt-[1-9][0-9]*$`).test(candidateId)) {
  fail("Core candidate ID is not bound to the source commit");
}

fs.mkdirSync(outputDirectory, { recursive: true });
const candidateBaseUrl = `${PUBLIC_R2_BASE_URL}/candidates/v2/${candidateId}`;
const releasePath = `core/v${coreVersion}/public-starter`;
const artifactBaseUrl = `${candidateBaseUrl}/${releasePath}`;
const manifestPath = path.join(outputDirectory, "devseccode-core-artifacts.json");
await download(`${artifactBaseUrl}/devseccode-core-artifacts.json`, manifestPath, MAX_MANIFEST_BYTES);
await download(`${artifactBaseUrl}/devseccode-core-artifacts.json.sig`, `${manifestPath}.sig`, MAX_SIGNATURE_BYTES);
verifyManifestSignature(manifestPath);

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
if (manifest.schemaVersion !== "devseccode-core-artifacts/v2") fail("Core manifest is not artifact-v2");
if (manifest.engineVersion !== coreVersion) fail("Core manifest version mismatch");
if (manifest.sourceCommit !== coreSourceCommit) fail("Core manifest source commit mismatch");
if (manifest.artifactProfile !== "public-starter") fail("Core manifest is not public-starter");
if (manifest.publicNpm !== true || manifest.containsFullCore !== false || manifest.containsPrivateAssets !== false) {
  fail("Core manifest violates the public NPM profile boundary");
}
if (manifest.publication?.channel !== "candidate") fail("Core publication channel is not candidate");
if (manifest.publication?.candidateId !== candidateId) fail("Core publication candidate ID mismatch");
if (manifest.publication?.immutableBaseUrl !== candidateBaseUrl) fail("Core immutable base URL mismatch");
if (manifest.publication?.releasePath !== releasePath) fail("Core publication release path mismatch");

const artifacts = Array.isArray(manifest.artifacts) ? manifest.artifacts : [];
if (artifacts.length !== TARGETS.length) fail("Core public-starter target matrix is incomplete");
const byTarget = new Map(artifacts.map((artifact) => [artifact.target, artifact]));
if (byTarget.size !== TARGETS.length || TARGETS.some((target) => !byTarget.has(target))) {
  fail("Core public-starter target matrix does not match the supported NPM targets");
}

for (const target of TARGETS) {
  const artifact = byTarget.get(target);
  const filename = safeFilename(artifact.filename, `${target} artifact filename`);
  if (!Number.isSafeInteger(artifact.sizeBytes) || artifact.sizeBytes < 1 || artifact.sizeBytes > MAX_ARCHIVE_BYTES) {
    fail(`${target} artifact size is invalid`);
  }
  if (!/^[0-9a-f]{64}$/.test(artifact.sha256)) fail(`${target} artifact sha256 is invalid`);
  await download(
    `${artifactBaseUrl}/${filename}`,
    path.join(outputDirectory, filename),
    MAX_ARCHIVE_BYTES,
    artifact.sizeBytes,
    artifact.sha256,
  );
  process.stdout.write(`downloaded ${target} ${filename}\n`);
}
