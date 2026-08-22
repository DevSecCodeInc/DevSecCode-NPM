"use strict";

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const pkg = require("../package.json");
const { ConfigError, INIT_TEMPLATE } = require("./config");
const { commandCapabilities, coreRequest, ensureCoreForCommand } = require("./core");
const { renderRuleTable, showIde, showInitResult, showQuests } = require("./renderers");
const { formatScanOutput, runCoreScan, scanExitCode, writeOutput } = require("./scanner");
const { severityLabel } = require("./severity");
const {
  buildReport,
  loadProfile,
  loadTriage,
  recordHunt,
  saveProfile,
  saveReport,
  shieldScore,
  visibleFindings,
} = require("./state");

const HELP = `Gamified local security CLI for code vulnerability hunts

Usage:
  devseccode [--version]
  devseccode scan [path] [--format terminal|json|sarif|junit]
  devseccode hunt [path]
  devseccode map [path]
  devseccode watch [path]
  devseccode list-rules
  devseccode explain <rule-id>
  devseccode init [--path dir] [--force]
  devseccode quests
  devseccode stats
  devseccode ide
`;

function takeValue(argv, index, flag) {
  if (index + 1 >= argv.length) {
    const err = new Error(`${flag} requires a value`);
    err.exitCode = 2;
    throw err;
  }
  return argv[index + 1];
}

function parseScanArgs(argv, includeFormat) {
  const args = {
    path: null,
    diff: false,
    format: "terminal",
    output: null,
    failOn: null,
    threads: 4,
    noCache: false,
    scanProfile: "balanced",
    minConfidence: 0,
    includeSuppressed: false,
    ignorePatterns: [],
    verbose: false,
    jsonLines: false,
    noProfile: false,
    noExplore: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--diff") args.diff = true;
    else if (token === "--format" && includeFormat) {
      args.format = takeValue(argv, i, token);
      i += 1;
    } else if (token === "--output" && includeFormat) {
      args.output = takeValue(argv, i, token);
      i += 1;
    } else if (token === "--fail-on") {
      args.failOn = takeValue(argv, i, token);
      i += 1;
    } else if (token === "--threads") {
      args.threads = Number.parseInt(takeValue(argv, i, token), 10);
      i += 1;
    } else if (token === "--no-cache") args.noCache = true;
    else if (token === "--scan-profile") {
      args.scanProfile = takeValue(argv, i, token);
      i += 1;
    } else if (token === "--min-confidence") {
      args.minConfidence = Number.parseFloat(takeValue(argv, i, token));
      i += 1;
    } else if (token === "--include-suppressed") args.includeSuppressed = true;
    else if (token === "--ignore") {
      args.ignorePatterns.push(takeValue(argv, i, token));
      i += 1;
    } else if (token === "--verbose" && includeFormat) args.verbose = true;
    else if (token === "--json-lines" && includeFormat) args.jsonLines = true;
    else if (token === "--no-profile") args.noProfile = true;
    else if (token === "--no-explore") args.noExplore = true;
    else if (token.startsWith("-")) {
      const err = new Error(`Unknown option: ${token}`);
      err.exitCode = 2;
      throw err;
    } else if (!args.path) {
      args.path = token;
    } else {
      const err = new Error(`Unexpected argument: ${token}`);
      err.exitCode = 2;
      throw err;
    }
  }
  if (!["terminal", "json", "sarif", "junit"].includes(args.format)) {
    const err = new Error(`Unknown format: ${args.format}`);
    err.exitCode = 2;
    throw err;
  }
  if (!Number.isInteger(args.threads) || args.threads < 1 || args.threads > 32) {
    const err = new Error("--threads must be between 1 and 32");
    err.exitCode = 2;
    throw err;
  }
  return args;
}

function printError(err) {
  process.stderr.write(`${err.message || err}\n`);
}

async function cmdScan(argv) {
  const args = parseScanArgs(argv, true);
  const context = await runCoreScan(args, { command: "scan" });
  const text = await formatScanOutput(args.format, context, args);
  writeOutput(text, args.output);
  return scanExitCode(context.result, context.failOn);
}

function renderHuntSummary(profile, record, result, gatePassed) {
  const shield = shieldScore(result.findings);
  const lines = [];
  lines.push("");
  lines.push(gatePassed ? "Hunt cleared." : "Hunt found issues above your fail threshold.");
  lines.push(`Shield score: ${shield.score} (${shield.rank})`);
  lines.push(`XP earned: ${record.xpDelta}  Level: ${record.levelAfter}`);
  if (record.newAchievements.length) {
    lines.push(`Achievements unlocked: ${record.newAchievements.join(", ")}`);
  }
  lines.push(`Profile hunts completed: ${profile.hunts_completed}`);
  lines.push("");
  return lines.join("\n");
}

async function cmdHunt(argv) {
  const args = parseScanArgs(argv, false);
  process.stderr.write("DevSecCode hunt starting...\n");
  const context = await runCoreScan(args, { command: "hunt" });
  const profile = loadProfile();
  const triage = loadTriage();
  const result = { ...context.result, findings: visibleFindings(context.result.findings, triage) };
  const gatePassed = scanExitCode(result, context.failOn) === 0;
  const record = recordHunt(profile, result.findings, context.targets[0]);
  if (!args.noProfile) {
    saveProfile(profile);
  }
  saveReport(buildReport(result, context.targets, record, gatePassed));
  process.stdout.write(formatHuntFindings(result));
  process.stdout.write(renderHuntSummary(profile, record, result, gatePassed));
  return gatePassed ? 0 : 1;
}

function formatHuntFindings(result) {
  if (!result.findings.length) return "No findings. Nice clean sweep.\n";
  const lines = [];
  for (const [index, finding] of result.findings.entries()) {
    lines.push(
      `${index + 1}. ${finding.severity.toUpperCase()} ${finding.filePath}:${finding.lineStart} ` +
        `${finding.ruleId} ${finding.message}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

async function cmdMap(argv) {
  const args = parseScanArgs(argv, false);
  const context = await runCoreScan(args, { command: "map" });
  const byFile = new Map();
  for (const finding of context.result.findings) {
    if (!byFile.has(finding.filePath)) byFile.set(finding.filePath, []);
    byFile.get(finding.filePath).push(finding);
  }
  for (const [file, findings] of byFile) {
    process.stdout.write(`${file}\n`);
    for (const finding of findings) {
      process.stdout.write(`  - ${finding.severity.toUpperCase()} ${finding.lineStart}: ${finding.ruleId} ${finding.message}\n`);
    }
  }
  if (!byFile.size) process.stdout.write("No findings.\n");
  return scanExitCode(context.result, context.failOn);
}

async function cmdWatch(argv) {
  let interval = 3;
  const filtered = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--interval") {
      interval = Number.parseInt(takeValue(argv, i, "--interval"), 10);
      i += 1;
    } else {
      filtered.push(argv[i]);
    }
  }
  const args = { ...parseScanArgs(filtered, false), noCache: true, noExplore: true };
  const target = path.resolve(args.path || ".");
  let running = false;
  let queued = false;
  let lastSignature = "";

  async function scanOnce() {
    if (running) {
      queued = true;
      return;
    }
    running = true;
    try {
      process.stderr.write(`\n[watch] scanning ${target}\n`);
      await cmdHunt([target, "--no-explore"].concat(args.noProfile ? ["--no-profile"] : []));
    } finally {
      running = false;
      if (queued) {
        queued = false;
        setImmediate(scanOnce);
      }
    }
  }

  await scanOnce();
  process.stderr.write(`[watch] polling every ${interval}s. Press Ctrl-C to stop.\n`);
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, interval * 1000));
    const signature = directorySignature(target);
    if (signature && signature !== lastSignature) {
      lastSignature = signature;
      await scanOnce();
    } else if (!lastSignature) {
      lastSignature = signature;
    }
  }
}

function directorySignature(target) {
  try {
    const stat = fs.statSync(target);
    if (stat.isFile()) return `${target}:${stat.mtimeMs}:${stat.size}`;
    const files = [];
    const stack = [target];
    while (stack.length && files.length < 1000) {
      const dir = stack.pop();
      for (const name of fs.readdirSync(dir)) {
        if ([".git", "node_modules", "__pycache__"].includes(name)) continue;
        const child = path.join(dir, name);
        const childStat = fs.statSync(child);
        if (childStat.isDirectory()) stack.push(child);
        else files.push(`${child}:${childStat.mtimeMs}:${childStat.size}`);
      }
    }
    return files.sort().join("|");
  } catch (_) {
    return "";
  }
}

async function cmdListRules() {
  const connection = await ensureCoreForCommand(commandCapabilities("list-rules"));
  const body = await coreRequest(connection, "/v1/rules?limit=10000", {});
  const rules = Array.isArray(body.rules) ? body.rules : [];
  process.stdout.write(renderRuleTable(rules));
  return 0;
}

async function cmdExplain(argv) {
  const ruleId = argv[0];
  if (!ruleId) {
    const err = new Error("explain requires a rule id");
    err.exitCode = 2;
    throw err;
  }
  const connection = await ensureCoreForCommand(commandCapabilities("explain"));
  const body = await coreRequest(connection, "/v1/rules?limit=10000", {});
  const rules = Array.isArray(body.rules) ? body.rules : [];
  const rule = rules.find((item) => item.id === ruleId || item.ruleId === ruleId);
  if (!rule) {
    process.stderr.write(`Unknown rule id: ${ruleId}\n`);
    return 2;
  }
  process.stdout.write(`${rule.id || rule.ruleId} (${rule.cwe || ""})\n`);
  process.stdout.write(`Default severity: ${severityLabel(rule.severity)}\n`);
  if (rule.precision_tier || rule.precisionTier) {
    process.stdout.write(`Precision tier: ${rule.precision_tier || rule.precisionTier}\n`);
  }
  if (rule.confidence != null) process.stdout.write(`Confidence: ${rule.confidence}\n`);
  if (Array.isArray(rule.languages) && rule.languages.length) {
    process.stdout.write(`Languages: ${rule.languages.join(", ")}\n`);
  }
  process.stdout.write("\n");
  process.stdout.write(`${rule.message || rule.description || ""}\n`);
  return 0;
}

function cmdInit(argv) {
  let target = ".";
  let force = false;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--path") {
      target = takeValue(argv, i, "--path");
      i += 1;
    } else if (argv[i] === "--force") force = true;
    else {
      const err = new Error(`Unknown init option: ${argv[i]}`);
      err.exitCode = 2;
      throw err;
    }
  }
  const out = path.resolve(target, ".dsc.yml");
  const existed = fs.existsSync(out);
  if (existed && !force) {
    process.stdout.write(showInitResult(out, true, false));
    return 2;
  }
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, INIT_TEMPLATE, "utf8");
  process.stdout.write(showInitResult(out, existed, force));
  return 0;
}

function cmdStats() {
  const profile = loadProfile();
  process.stdout.write(`Hunter stats\n\n`);
  process.stdout.write(`Level: ${Math.floor(Number(profile.total_xp || 0) / 100)}\n`);
  process.stdout.write(`XP: ${profile.total_xp}\n`);
  process.stdout.write(`Hunts completed: ${profile.hunts_completed}\n`);
  process.stdout.write(`Current streak: ${profile.current_streak}\n`);
  process.stdout.write(`Achievements: ${(profile.achievements || []).join(", ") || "none"}\n`);
  return 0;
}

async function cmdVersion() {
  process.stdout.write(`devseccode ${pkg.version}\n`);
  try {
    const connection = await ensureCoreForCommand([]);
    const meta = connection.meta || {};
    process.stdout.write(`core ${meta.engineVersion || "unknown"} contract ${meta.contractVersion || "unknown"}\n`);
    process.stdout.write(`backend ${connection.diagnostics.owned ? "started" : "reused"} ${connection.diagnostics.backend}\n`);
  } catch (err) {
    process.stdout.write(`core unavailable (${err.message})\n`);
  }
  return 0;
}

async function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await new Promise((resolve) => rl.question(question, resolve));
  } finally {
    rl.close();
  }
}

async function runPlayMenu() {
  if (!process.stdin.isTTY) {
    process.stdout.write("DevSecCode play menu\n\n");
    process.stdout.write("Run `devseccode hunt .` to start a hunt, or `devseccode scan .` for CI-friendly output.\n");
    return 0;
  }
  process.stdout.write("DevSecCode play menu\n");
  process.stdout.write("1. Hunt current directory\n");
  process.stdout.write("2. Show quests\n");
  process.stdout.write("3. Show stats\n");
  process.stdout.write("4. Initialize config\n");
  const choice = String(await ask("> ")).trim();
  if (choice === "1") return cmdHunt(["."]);
  if (choice === "2") {
    process.stdout.write(showQuests());
    return 0;
  }
  if (choice === "3") return cmdStats();
  if (choice === "4") return cmdInit([]);
  return 0;
}

async function main(argv) {
  try {
    if (argv.length === 0) return runPlayMenu();
    const [command, ...rest] = argv;
    if (command === "--help" || command === "-h") {
      process.stdout.write(HELP);
      return 0;
    }
    if (command === "--version" || command === "-V") return cmdVersion();
    if (command === "play") return runPlayMenu();
    if (command === "scan") return cmdScan(rest);
    if (command === "hunt") return cmdHunt(rest);
    if (command === "map") return cmdMap(rest);
    if (command === "watch") return cmdWatch(rest);
    if (command === "list-rules") return cmdListRules(rest);
    if (command === "explain") return cmdExplain(rest);
    if (command === "init") return cmdInit(rest);
    if (command === "quests") {
      process.stdout.write(showQuests());
      return 0;
    }
    if (command === "stats") return cmdStats(rest);
    if (command === "ide") {
      process.stdout.write(showIde());
      return 0;
    }
    process.stderr.write(`Unknown command: ${command}\n\n${HELP}`);
    return 2;
  } catch (err) {
    printError(err);
    if (err instanceof ConfigError) return 2;
    return Number.isInteger(err.exitCode) ? err.exitCode : 1;
  }
}

module.exports = {
  main,
  parseScanArgs,
};
