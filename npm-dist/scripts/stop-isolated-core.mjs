import fs from "node:fs";
import path from "node:path";

const root = process.argv[2] || process.env.DEVSECCODE_HOME;
if (!root || !fs.existsSync(root)) process.exit(0);
const pending = [root];
const pids = new Set();
while (pending.length) {
  const current = pending.pop();
  for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
    const file = path.join(current, entry.name);
    if (entry.isDirectory()) pending.push(file);
    else if (entry.name.endsWith(".json")) {
      try {
        const value = JSON.parse(fs.readFileSync(file, "utf8"));
        if (Number.isInteger(value.pid) && value.pid > 0) pids.add(value.pid);
      } catch {}
    }
  }
}
for (const pid of pids) {
  try {
    process.kill(pid, "SIGTERM");
    process.stdout.write(`stopped Core process ${pid}\n`);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}
