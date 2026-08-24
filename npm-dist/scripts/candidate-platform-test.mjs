import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const VERSION = process.env.DEVSECCODE_NPM_CANDIDATE_VERSION || "0.5.0";
const PACKAGE = `@devseccode/scanner@${VERSION}`;
const TARGETS = new Set(["darwin-arm64", "linux-x64", "linux-arm64", "win32-x64"]);
const target = `${process.platform}-${process.arch}`;
const root = path.join(os.tmpdir(), `devseccode-npm-candidate-${VERSION}`);
const globalRoot = path.join(root, "global");
const stateRoot = path.join(root, "state");
const homeRoot = path.join(root, "home");
const userConfig = path.join(root, "empty-npmrc");
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");
const sampleProject = path.join(repositoryRoot, "resources", "sample-vulns");
const cli = process.platform === "win32"
  ? path.join(globalRoot, "devseccode.cmd")
  : path.join(globalRoot, "bin", "devseccode");

function fail(message) {
  throw new Error(message);
}

export function packageManagerInvocation(name, platform = process.platform, nodeExecutable = process.execPath) {
  if (name !== "npm" && name !== "npx") fail(`unsupported package manager command: ${name}`);
  if (platform !== "win32") {
    return { display: name, executable: name, prefixArgs: [], requiredFiles: [] };
  }
  const script = path.win32.join(
    path.win32.dirname(nodeExecutable),
    "node_modules",
    "npm",
    "bin",
    `${name}-cli.js`,
  );
  return {
    display: `${name}.cmd`,
    executable: nodeExecutable,
    prefixArgs: [script],
    requiredFiles: [script],
  };
}

export function installedCliInvocation(
  modules,
  shim,
  platform = process.platform,
  nodeExecutable = process.execPath,
) {
  if (platform !== "win32") {
    return { display: shim, executable: shim, prefixArgs: [], requiredFiles: [shim] };
  }
  const entry = path.win32.join(modules, "@devseccode", "scanner", "bin", "dsc.js");
  return {
    display: shim,
    executable: nodeExecutable,
    prefixArgs: [entry],
    requiredFiles: [shim, entry],
  };
}

const npm = packageManagerInvocation("npm");
const npx = packageManagerInvocation("npx");
const registryInstallAttempts = 6;

function childEnvironment(overrides = {}) {
  const environment = {
    ...process.env,
    DEVSECCODE_HOME: stateRoot,
    HOME: homeRoot,
    USERPROFILE: homeRoot,
    npm_config_prefix: globalRoot,
    npm_config_registry: "https://registry.npmjs.org",
    npm_config_userconfig: userConfig,
    ...overrides,
  };
  for (const name of ["NODE_AUTH_TOKEN", "NPM_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]) delete environment[name];
  return environment;
}

function run(command, args, options = {}) {
  const invocation = typeof command === "string"
    ? { display: command, executable: command, prefixArgs: [], requiredFiles: [] }
    : command;
  for (const file of invocation.requiredFiles) {
    if (!fs.existsSync(file)) fail(`required command entry point is missing: ${file}`);
  }
  const childArgs = [...invocation.prefixArgs, ...args];
  process.stdout.write(`\n> ${invocation.display} ${args.join(" ")}\n`);
  const result = spawnSync(invocation.executable, childArgs, {
    cwd: options.cwd || root,
    env: options.inheritCredentials ? process.env : childEnvironment(options.environment),
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
    timeout: 10 * 60 * 1000,
  });
  if (options.capture) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
  }
  if (result.error) throw result.error;
  const allowed = options.allowedExitCodes || [0];
  if (!allowed.includes(result.status) && !options.allowFailure) {
    fail(`${invocation.display} exited with status ${result.status}`);
  }
  if (options.returnResult) return { status: result.status, stdout: result.stdout || "" };
  return result.stdout || "";
}

function globalModules() {
  return run(npm, ["root", "--global"], { capture: true }).trim();
}

function stopCore() {
  if (!fs.existsSync(stateRoot)) return;
  run(process.execPath, [path.join(scriptDirectory, "stop-isolated-core.mjs"), stateRoot]);
}

export function resetIsolatedCoreState(stop = stopCore, directory = stateRoot) {
  stop();
  fs.rmSync(directory, { recursive: true, force: true });
}

export function installedCandidatePackages(modules, platformTarget) {
  const scope = path.join(modules, "@devseccode");
  return ["scanner", `scanner-${platformTarget}`]
    .filter((name) => fs.existsSync(path.join(scope, name)))
    .map((name) => `@devseccode/${name}`);
}

export function requiredCandidatePackages(platformTarget) {
  return ["@devseccode/scanner", `@devseccode/scanner-${platformTarget}`];
}

function pause(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function installRegistryCandidate() {
  const required = requiredCandidatePackages(target);
  for (let attempt = 1; attempt <= registryInstallAttempts; attempt += 1) {
    fs.rmSync(globalRoot, { recursive: true, force: true });
    run(npm, [
      "install", "--global", "--include=optional", "--prefer-online",
      "--no-audit", "--no-fund", PACKAGE,
    ], {
      environment: {
        npm_config_cache: path.join(root, "npm-cache", String(attempt)),
      },
    });
    const modules = globalModules();
    const parentDirectory = path.join(modules, "@devseccode", "scanner");
    const missing = [];
    if (!fs.existsSync(parentDirectory)) missing.push(required[0]);
    if (missing.length === 0) {
      try {
        dependencyPackageRecord(parentDirectory, required[1]);
      } catch {
        missing.push(required[1]);
      }
    }
    if (missing.length === 0) return;
    if (attempt === registryInstallAttempts) {
      fail(`registry install omitted required packages after ${attempt} attempts: ${missing.join(", ")}`);
    }
    process.stdout.write(`Registry install attempt ${attempt} omitted ${missing.join(", ")}; retrying with a fresh cache.\n`);
    pause(10000);
  }
}

function exerciseRegistryNpx() {
  for (let attempt = 1; attempt <= registryInstallAttempts; attempt += 1) {
    const result = run(npx, ["--yes", "--prefer-online", PACKAGE, "--version"], {
      allowFailure: true,
      returnResult: true,
      environment: {
        npm_config_cache: path.join(root, "npx-cache", String(attempt)),
      },
    });
    if (result.status === 0) return;
    if (attempt === registryInstallAttempts) {
      fail(`npx could not install the exact registry candidate after ${attempt} attempts`);
    }
    process.stdout.write(`npx registry install attempt ${attempt} failed; retrying with a fresh cache.\n`);
    pause(10000);
  }
}

function clean() {
  stopCore();
  if (fs.existsSync(globalRoot)) {
    const modules = globalModules();
    const installed = installedCandidatePackages(modules, target);
    if (installed.length) run(npm, ["uninstall", "--global", ...installed]);
    if (fs.existsSync(path.join(modules, "@devseccode", "scanner"))) fail("parent package remains after uninstall");
    if (fs.existsSync(path.join(modules, "@devseccode", `scanner-${target}`))) fail("platform package remains after uninstall");
  }
  if (path.basename(root) !== `devseccode-npm-candidate-${VERSION}`) fail(`refusing to remove unexpected test root: ${root}`);
  fs.rmSync(root, { recursive: true, force: true });
  process.stdout.write(`Removed isolated candidate test: ${root}\n`);
}

function findGitHubCli() {
  const executable = process.platform === "win32" ? "gh.exe" : "gh";
  const probe = spawnSync(executable, ["--version"], { encoding: "utf8" });
  if (probe.status === 0) return executable;
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    const tools = path.join(process.env.LOCALAPPDATA, "DevSecCode", "candidate-test-tools");
    if (fs.existsSync(tools)) {
      const candidates = fs.readdirSync(tools)
        .flatMap((directory) => [path.join(tools, directory, "bin", "gh.exe"), path.join(tools, directory, "gh.exe")])
        .filter((file) => fs.existsSync(file))
        .sort()
        .reverse();
      if (candidates.length) return candidates[0];
    }
  }
  fail("GitHub CLI is required to download the private candidate");
}

function downloadPrivateCandidate() {
  const gh = findGitHubCli();
  const sourceCommit = run("git", ["rev-parse", "HEAD"], {
    capture: true,
    cwd: repositoryRoot,
    inheritCredentials: true,
  }).trim();
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) fail("current NPM commit is not a full Git SHA");
  const runs = JSON.parse(run(gh, [
    "run", "list",
    "--repo", "DevSecCodeInc/DevSecCode-NPM",
    "--workflow", "release-npm.yml",
    "--commit", sourceCommit,
    "--event", "workflow_dispatch",
    "--limit", "20",
    "--json", "databaseId,conclusion",
  ], {
    capture: true,
    cwd: repositoryRoot,
    inheritCredentials: true,
  }));
  const successful = runs.find((runRecord) => runRecord.conclusion === "success");
  if (!successful) fail(`no successful private NPM candidate run exists for ${sourceCommit}`);
  const candidateDirectory = path.join(root, "private-candidate");
  fs.mkdirSync(candidateDirectory, { recursive: true });
  run(gh, [
    "run", "download", String(successful.databaseId),
    "--repo", "DevSecCodeInc/DevSecCode-NPM",
    "--name", "npm-artifact-v2-candidate",
    "--dir", candidateDirectory,
  ], {
    cwd: repositoryRoot,
    inheritCredentials: true,
  });
  process.stdout.write(`Downloaded private candidate run ${successful.databaseId}.\n`);
  return { candidateDirectory, sourceCommit };
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function privateTarballs(candidateDirectory, sourceCommit) {
  const record = JSON.parse(fs.readFileSync(path.join(candidateDirectory, "devseccode-npm-release.json"), "utf8"));
  if (record.schemaVersion !== "devseccode-npm-release/v1") fail("private candidate record schema mismatch");
  if (record.product?.version !== VERSION) fail("private candidate version mismatch");
  if (sourceCommit && record.product?.sourceCommit !== sourceCommit) fail("private candidate source mismatch");
  return ["@devseccode/scanner", `@devseccode/scanner-${target}`].map((name) => {
    const item = record.packages?.find((candidatePackage) => candidatePackage.name === name);
    if (!item) fail(`private candidate is missing ${name}`);
    const file = path.join(candidateDirectory, item.filename);
    if (!fs.existsSync(file) || fs.statSync(file).size !== item.sizeBytes || sha256(file) !== item.sha256) {
      fail(`private candidate bytes do not match the release record: ${name}`);
    }
    return file;
  });
}

export function dependencyPackage(parentDirectory, dependencyName) {
  return dependencyPackageRecord(parentDirectory, dependencyName).metadata;
}

export function dependencyPackageRecord(parentDirectory, dependencyName) {
  const resolveFromParent = createRequire(path.join(parentDirectory, "package.json"));
  const packageFile = resolveFromParent.resolve(`${dependencyName}/package.json`);
  const metadata = JSON.parse(fs.readFileSync(packageFile, "utf8"));
  if (metadata.name !== dependencyName) fail(`installed package metadata mismatch for ${dependencyName}`);
  return { directory: path.dirname(packageFile), metadata };
}

function verifyInstalledPackages() {
  const modules = globalModules();
  const scope = path.join(modules, "@devseccode");
  const parentDirectory = path.join(scope, "scanner");
  const parent = JSON.parse(fs.readFileSync(path.join(parentDirectory, "package.json"), "utf8"));
  const platformRecord = dependencyPackageRecord(parentDirectory, `@devseccode/scanner-${target}`);
  const platform = platformRecord.metadata;
  const launcher = dependencyPackage(parentDirectory, "@devseccode/core-launcher");
  if (parent.version !== VERSION || platform.version !== VERSION) fail("installed scanner version mismatch");
  if (launcher.version !== "0.6.0") fail("installed Core launcher version mismatch");
  const installedPlatforms = [...TARGETS].filter((platformTarget) => {
    try {
      dependencyPackageRecord(parentDirectory, `@devseccode/scanner-${platformTarget}`);
      return true;
    } catch {
      return false;
    }
  });
  if (installedPlatforms.length !== 1 || installedPlatforms[0] !== target) {
    fail(`unexpected platform package selection: ${installedPlatforms.join(", ")}`);
  }
  const artifactFiles = fs.readdirSync(path.join(platformRecord.directory, "artifacts"));
  if (!artifactFiles.includes("devseccode-core-artifacts.json")) fail("Core manifest missing from platform package");
  if (!artifactFiles.includes("devseccode-core-artifacts.json.sig")) fail("Core signature missing from platform package");
  if (artifactFiles.filter((name) => name.endsWith(".tar.gz")).length !== 1) fail("Core archive matrix mismatch");
}

function exerciseInstalledProduct() {
  verifyInstalledPackages();
  const installedCli = installedCliInvocation(globalModules(), cli);
  const versionOutput = run(installedCli, ["--version"], { capture: true });
  if (!versionOutput.includes(`devseccode ${VERSION}`)) fail("CLI version output mismatch");
  if (!versionOutput.includes("core 0.3.6 contract v1")) fail("Core version output mismatch");
  run(installedCli, ["scan", sampleProject, "--format", "terminal", "--fail-on", "critical"]);
  run(installedCli, ["hunt", sampleProject, "--no-profile", "--no-explore"], { allowedExitCodes: [0, 1] });
}

function start(mode) {
  if (!TARGETS.has(target)) fail(`unsupported candidate test platform: ${target}`);
  if (!fs.existsSync(sampleProject) || !fs.statSync(sampleProject).isDirectory()) fail(`sample project missing: ${sampleProject}`);
  clean();
  fs.mkdirSync(homeRoot, { recursive: true });
  fs.writeFileSync(userConfig, "registry=https://registry.npmjs.org\n", "utf8");
  if (mode === "private") {
    let candidateDirectory = process.env.DEVSECCODE_NPM_CANDIDATE_DIR;
    let sourceCommit = process.env.DEVSECCODE_NPM_SOURCE_COMMIT;
    if (!candidateDirectory) ({ candidateDirectory, sourceCommit } = downloadPrivateCandidate());
    const tarballs = privateTarballs(path.resolve(candidateDirectory), sourceCommit);
    run(npm, ["install", "--global", "--omit=optional", "--no-audit", "--no-fund", ...tarballs]);
  } else {
    exerciseRegistryNpx();
    resetIsolatedCoreState();
    installRegistryCandidate();
  }
  exerciseInstalledProduct();
  process.stdout.write(`\nCandidate ${VERSION} passed isolated ${target} ${mode} acceptance.\n`);
  process.stdout.write(`Installed CLI: ${cli}\n`);
  process.stdout.write(`Isolated state: ${root}\n`);
  process.stdout.write("Run the cleanup command from the repository when finished.\n");
}

const operation = process.argv[2];
if (path.resolve(process.argv[1] || "") === fileURLToPath(import.meta.url)) {
  if (operation === "start-private") start("private");
  else if (operation === "start-registry") start("registry");
  else if (operation === "cleanup") clean();
  else fail("usage: candidate-platform-test.mjs <start-private|start-registry|cleanup>");
}
