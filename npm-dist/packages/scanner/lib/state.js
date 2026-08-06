"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PROFILE_VERSION = 1;
const TRIAGE_VERSION = 1;
const XP_PER_LEVEL = 100;
const XP_PER_HUNT = 10;
const XP_PER_SEVERITY = Object.freeze({
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
});

const CATEGORIES = Object.freeze([
  "secrets",
  "injection",
  "crypto",
  "transport",
  "config",
  "access",
  "other",
]);

function stateRoot() {
  return path.resolve(process.env.DEVSECCODE_HOME || path.join(os.homedir(), ".devseccode"));
}

function statePath(name) {
  return path.join(stateRoot(), name);
}

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (_) {
    return fallback;
  }
}

function atomicWriteJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.renameSync(tmp, file);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch (_) {
      // Ignore cleanup errors; preserve the original failure.
    }
    throw err;
  }
}

function defaultProfile() {
  return {
    version: PROFILE_VERSION,
    hunter_class: null,
    total_xp: 0,
    hunts_completed: 0,
    created_at: nowIso(),
    last_hunt_at: "",
    categories_defeated: Object.fromEntries(CATEGORIES.map((cat) => [cat, 0])),
    unique_rules: [],
    achievements: [],
    current_streak: 0,
    longest_streak: 0,
    last_streak_date: "",
    difficulty: "normal",
    loot: [],
    active_title: null,
    best_scores: {},
  };
}

function loadProfile() {
  const raw = readJson(statePath("profile.json"), null);
  const base = defaultProfile();
  if (!raw || typeof raw !== "object") return base;
  return {
    ...base,
    ...raw,
    categories_defeated: { ...base.categories_defeated, ...(raw.categories_defeated || {}) },
    unique_rules: Array.isArray(raw.unique_rules) ? raw.unique_rules.map(String) : [],
    achievements: Array.isArray(raw.achievements) ? raw.achievements.map(String) : [],
    loot: Array.isArray(raw.loot) ? raw.loot.map(String) : [],
    best_scores: raw.best_scores && typeof raw.best_scores === "object" ? raw.best_scores : {},
  };
}

function saveProfile(profile) {
  atomicWriteJson(statePath("profile.json"), profile);
}

function levelForXp(xp) {
  return Math.floor(xp / XP_PER_LEVEL);
}

function categoryForFinding(finding) {
  const haystack = `${finding.ruleId} ${finding.cwe} ${finding.message}`.toLowerCase();
  if (haystack.includes("secret") || haystack.includes("credential") || haystack.includes("key")) return "secrets";
  if (haystack.includes("injection") || haystack.includes("xss") || haystack.includes("traversal")) return "injection";
  if (haystack.includes("crypto") || haystack.includes("hash") || haystack.includes("cipher")) return "crypto";
  if (haystack.includes("cleartext") || haystack.includes("tls") || haystack.includes("http")) return "transport";
  if (haystack.includes("docker") || haystack.includes("kubernetes") || haystack.includes("config")) return "config";
  if (haystack.includes("auth") || haystack.includes("access") || haystack.includes("permission")) return "access";
  return "other";
}

function updateStreak(profile) {
  const today = new Date().toISOString().slice(0, 10);
  if (profile.last_streak_date === today) return 0;
  let streak = 1;
  if (profile.last_streak_date) {
    const last = new Date(`${profile.last_streak_date}T00:00:00Z`);
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    if (last.toISOString().slice(0, 10) === yesterday) {
      streak = Number(profile.current_streak || 0) + 1;
    }
  }
  profile.current_streak = streak;
  profile.longest_streak = Math.max(Number(profile.longest_streak || 0), streak);
  profile.last_streak_date = today;
  return streak;
}

function recordHunt(profile, findings, targetKey) {
  const beforeXp = Number(profile.total_xp || 0);
  const beforeLevel = levelForXp(beforeXp);
  const seenRules = new Set(profile.unique_rules || []);
  let newRules = 0;
  const byCategory = {};
  let xp = XP_PER_HUNT;

  for (const finding of findings) {
    xp += XP_PER_SEVERITY[finding.severity] || 0;
    const category = categoryForFinding(finding);
    byCategory[category] = (byCategory[category] || 0) + 1;
    profile.categories_defeated[category] = Number(profile.categories_defeated[category] || 0) + 1;
    if (finding.ruleId && !seenRules.has(finding.ruleId)) {
      seenRules.add(finding.ruleId);
      newRules += 1;
      xp += 10;
    }
  }

  const wasFirstHunt = Number(profile.hunts_completed || 0) === 0;
  if (wasFirstHunt) xp += 25;

  const streak = updateStreak(profile);
  const streakBonus = streak > 1 ? streak * 5 : 0;
  xp += streakBonus;

  profile.total_xp = beforeXp + xp;
  profile.hunts_completed = Number(profile.hunts_completed || 0) + 1;
  profile.last_hunt_at = nowIso();
  profile.unique_rules = [...seenRules].sort();

  const newAchievements = [];
  if (wasFirstHunt && !profile.achievements.includes("first-blood")) {
    profile.achievements.push("first-blood");
    newAchievements.push("first-blood");
  }
  if (findings.some((finding) => finding.severity === "critical") && !profile.achievements.includes("boss-fight")) {
    profile.achievements.push("boss-fight");
    newAchievements.push("boss-fight");
  }

  const score = shieldScore(findings).score;
  if (targetKey) {
    profile.best_scores[targetKey] = Math.max(Number(profile.best_scores[targetKey] || 0), score);
  }

  const afterLevel = levelForXp(profile.total_xp);
  return {
    xpBefore: beforeXp,
    xpAfter: profile.total_xp,
    xpDelta: xp,
    levelBefore: beforeLevel,
    levelAfter: afterLevel,
    levelUp: afterLevel > beforeLevel,
    newRules,
    findingsByCategory: byCategory,
    newAchievements,
    streak,
    streakBonus,
    newLoot: [],
    difficulty: profile.difficulty || "normal",
  };
}

function shieldScore(findings) {
  const penalty = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };
  const score = Math.max(0, 100 - findings.reduce((sum, finding) => sum + (penalty[finding.severity] || 0), 0));
  const rank = score >= 95 ? "S" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : "D";
  return { score, rank };
}

function loadTriage() {
  const raw = readJson(statePath("triage.json"), null);
  if (!raw || typeof raw !== "object") return { version: TRIAGE_VERSION, entries: {} };
  return {
    version: Number(raw.version || TRIAGE_VERSION),
    entries: raw.entries && typeof raw.entries === "object" ? raw.entries : {},
  };
}

function saveTriage(store) {
  atomicWriteJson(statePath("triage.json"), store);
}

function findingKey(finding) {
  return `${finding.filePath}::${finding.ruleId}::${finding.lineStart}`;
}

function visibleFindings(findings, triage) {
  const entries = triage && triage.entries ? triage.entries : {};
  return findings.filter((finding) => entries[findingKey(finding)] !== "ignored");
}

function saveReport(report) {
  atomicWriteJson(statePath("last_report.json"), report);
}

function buildReport(result, targets, record, gatePassed) {
  const bySeverity = {};
  for (const finding of result.findings) {
    const key = finding.severity.toUpperCase();
    bySeverity[key] = (bySeverity[key] || 0) + 1;
  }
  const shield = shieldScore(result.findings);
  return {
    timestamp: nowIso(),
    targets,
    total_findings: result.findings.length,
    findings_by_severity: bySeverity,
    findings_by_category: record.findingsByCategory || {},
    shield_score: shield.score,
    shield_rank: shield.rank,
    files_scanned: result.filesScanned,
    duration_ms: result.scanDurationMs,
    gate_passed: gatePassed,
    xp_earned: record.xpDelta || 0,
    level_after: record.levelAfter || 0,
    new_achievements: record.newAchievements || [],
    finding_details: result.findings.map((finding) => ({
      file: finding.filePath,
      line: finding.lineStart,
      rule_id: finding.ruleId,
      cwe: finding.cwe,
      severity: finding.severity.toUpperCase(),
      message: finding.message || "",
      snippet: finding.snippet || "",
      fix: finding.fixSuggestion || "",
    })),
  };
}

module.exports = {
  atomicWriteJson,
  buildReport,
  loadProfile,
  loadTriage,
  recordHunt,
  saveProfile,
  saveReport,
  saveTriage,
  shieldScore,
  statePath,
  stateRoot,
  visibleFindings,
};
