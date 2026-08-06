"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const TRUSTED_ARTIFACT_PUBLIC_KEY = path.resolve(
  __dirname,
  "..",
  "trust",
  "artifact-ed25519-public.pem",
);

function readBounded(file, maxBytes, label) {
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size > maxBytes) {
    throw new Error(`${label} must be a regular file no larger than ${maxBytes} bytes: ${file}`);
  }
  return fs.readFileSync(file);
}

function decodeSignature(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(value)) {
    throw new Error("Core artifact manifest signature must be canonical base64");
  }
  const signature = Buffer.from(value, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== value) {
    throw new Error("Core artifact manifest signature must be 64-byte Ed25519");
  }
  return signature;
}

function keyId(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return `ed25519:${crypto.createHash("sha256").update(der).digest("hex").slice(0, 16)}`;
}

function verifyManifestSignature(manifestPath, publicKeyPath = TRUSTED_ARTIFACT_PUBLIC_KEY) {
  const manifestBytes = readBounded(manifestPath, 4 * 1024 * 1024, "Core artifact manifest");
  const signaturePath = `${manifestPath}.sig`;
  const signatureBytes = readBounded(signaturePath, 8192, "Core artifact manifest signature");

  let record;
  try {
    record = JSON.parse(signatureBytes.toString("utf8"));
  } catch (err) {
    throw new Error(`Core artifact manifest signature is not valid JSON: ${err.message}`);
  }
  if (!record || record.algorithm !== "ed25519") {
    throw new Error("Core artifact manifest signature algorithm must be ed25519");
  }

  const publicKey = crypto.createPublicKey(readBounded(publicKeyPath, 8192, "Core artifact public key"));
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Core artifact trust key must be Ed25519");
  }
  const expectedKeyId = keyId(publicKey);
  if (record.keyId !== expectedKeyId) {
    throw new Error(`Core artifact manifest signature keyId does not match pinned key ${expectedKeyId}`);
  }
  const signature = decodeSignature(record.signature);
  if (!crypto.verify(null, manifestBytes, publicKey, signature)) {
    throw new Error("Core artifact manifest signature verification failed");
  }
  return { keyId: expectedKeyId, signaturePath };
}

module.exports = {
  TRUSTED_ARTIFACT_PUBLIC_KEY,
  keyId,
  verifyManifestSignature,
};
