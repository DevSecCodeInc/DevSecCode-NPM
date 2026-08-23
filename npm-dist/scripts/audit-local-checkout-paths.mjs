import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PATTERNS = [
  /\/Users\/[^/\s\x00-\x1f]+\/(?:Projects|projects)\/(?:dsc|DevSecCode[^/\s\x00-\x1f]*)/g,
  /\/home\/[^/\s\x00-\x1f]+\/(?:work|Projects|projects)\/(?:dsc|DevSecCode[^/\s\x00-\x1f]*)/g,
  /[A-Za-z]:\\Users\\[^\\\s\x00-\x1f]+\\(?:Projects|projects|work)\\(?:dsc|DevSecCode[^\\\s\x00-\x1f]*)/g,
  /[A-Za-z]:\\a\\(?:dsc|DevSecCode[^\\\s\x00-\x1f]*)/g,
  /DevSecCode-Core/g,
  /DevSecCode-Scanner/g,
];

function matchesIn(value) {
  const matches = [];
  for (const pattern of PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of value.matchAll(pattern)) {
      matches.push({ offset: match.index, value: match[0] });
    }
  }
  return matches;
}

export function findLocalCheckoutPaths(root, limit = 20) {
  const absoluteRoot = path.resolve(root);
  if (!fs.statSync(absoluteRoot).isDirectory()) {
    throw new Error(`audit root is not a directory: ${absoluteRoot}`);
  }
  const findings = [];
  const pending = [absoluteRoot];
  while (pending.length && findings.length < limit) {
    const current = pending.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .sort((left, right) => right.name.localeCompare(left.name));
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(absoluteRoot, absolute) || ".";
      let value;
      if (entry.isDirectory()) {
        pending.push(absolute);
        continue;
      }
      if (entry.isSymbolicLink()) value = fs.readlinkSync(absolute);
      else if (entry.isFile()) value = fs.readFileSync(absolute).toString("latin1");
      else continue;
      for (const match of matchesIn(value)) {
        findings.push({ file: relative, ...match });
        if (findings.length === limit) break;
      }
      if (findings.length === limit) break;
    }
  }
  return findings;
}

function main() {
  const [root] = process.argv.slice(2);
  if (!root) throw new Error("usage: audit-local-checkout-paths.mjs <directory>");
  const findings = findLocalCheckoutPaths(root);
  for (const finding of findings) {
    process.stdout.write(`${finding.file}:${finding.offset}:${finding.value}\n`);
  }
  if (findings.length) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`audit-local-checkout-paths: ${error.message}\n`);
    process.exitCode = 2;
  }
}
