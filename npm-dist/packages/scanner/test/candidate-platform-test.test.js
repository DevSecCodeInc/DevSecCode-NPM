"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

test("candidate acceptance resolves Core Launcher through the scanner dependency tree", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-candidate-layout-"));
  const scanner = path.join(root, "node_modules", "@devseccode", "scanner");
  const launcher = path.join(scanner, "node_modules", "@devseccode", "core-launcher");
  fs.mkdirSync(path.join(launcher, "src"), { recursive: true });
  fs.writeFileSync(path.join(scanner, "package.json"), JSON.stringify({
    name: "@devseccode/scanner",
    version: "0.5.0",
  }));
  fs.writeFileSync(path.join(launcher, "package.json"), JSON.stringify({
    name: "@devseccode/core-launcher",
    version: "0.6.0",
    main: "src/index.js",
  }));
  fs.writeFileSync(path.join(launcher, "src", "index.js"), "module.exports = {};\n");
  try {
    const { dependencyPackage } = await import("../../../scripts/candidate-platform-test.mjs");
    assert.equal(dependencyPackage(scanner, "@devseccode/core-launcher").version, "0.6.0");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("candidate cleanup selects both explicitly installed packages", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dsc-candidate-cleanup-"));
  const scope = path.join(root, "@devseccode");
  fs.mkdirSync(path.join(scope, "scanner"), { recursive: true });
  fs.mkdirSync(path.join(scope, "scanner-linux-x64"), { recursive: true });
  try {
    const { installedCandidatePackages } = await import("../../../scripts/candidate-platform-test.mjs");
    assert.deepEqual(installedCandidatePackages(root, "linux-x64"), [
      "@devseccode/scanner",
      "@devseccode/scanner-linux-x64",
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Windows candidate commands bypass cmd shims without a command shell", async () => {
  const { installedCliInvocation, packageManagerInvocation } = await import(
    "../../../scripts/candidate-platform-test.mjs"
  );
  const node = "C:\\hostedtoolcache\\windows\\node\\24.19.0\\x64\\node.exe";
  const modules = "C:\\candidate\\global\\node_modules";
  const shim = "C:\\candidate\\global\\devseccode.cmd";
  assert.deepEqual(packageManagerInvocation("npm", "win32", node), {
    display: "npm.cmd",
    executable: node,
    prefixArgs: ["C:\\hostedtoolcache\\windows\\node\\24.19.0\\x64\\node_modules\\npm\\bin\\npm-cli.js"],
    requiredFiles: ["C:\\hostedtoolcache\\windows\\node\\24.19.0\\x64\\node_modules\\npm\\bin\\npm-cli.js"],
  });
  assert.deepEqual(packageManagerInvocation("npx", "win32", node), {
    display: "npx.cmd",
    executable: node,
    prefixArgs: ["C:\\hostedtoolcache\\windows\\node\\24.19.0\\x64\\node_modules\\npm\\bin\\npx-cli.js"],
    requiredFiles: ["C:\\hostedtoolcache\\windows\\node\\24.19.0\\x64\\node_modules\\npm\\bin\\npx-cli.js"],
  });
  assert.deepEqual(installedCliInvocation(modules, shim, "win32", node), {
    display: shim,
    executable: node,
    prefixArgs: ["C:\\candidate\\global\\node_modules\\@devseccode\\scanner\\bin\\dsc.js"],
    requiredFiles: [
      shim,
      "C:\\candidate\\global\\node_modules\\@devseccode\\scanner\\bin\\dsc.js",
    ],
  });
});
