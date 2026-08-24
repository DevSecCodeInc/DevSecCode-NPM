"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("promotion publishes candidate code and runs acceptance from current workflow code", () => {
  const workflow = fs.readFileSync(
    path.resolve(__dirname, "../../../../.github/workflows/promote-npm.yml"),
    "utf8",
  );
  const releaseStart = workflow.indexOf("  release:\n");
  const acceptanceStart = workflow.indexOf("  acceptance:\n");
  assert.notEqual(releaseStart, -1);
  assert.notEqual(acceptanceStart, -1);
  const release = workflow.slice(releaseStart, acceptanceStart);
  const acceptance = workflow.slice(acceptanceStart);
  assert.match(release, /ref: \$\{\{ inputs\.npm_ref \}\}/);
  assert.match(release, /test "\$\(git rev-parse HEAD\)" = "\$NPM_REF"/);
  assert.doesNotMatch(release, /test "\$GITHUB_SHA" = "\$NPM_REF"/);
  assert.match(acceptance, /ref: \$\{\{ github\.sha \}\}/);
  assert.doesNotMatch(acceptance, /ref: \$\{\{ inputs\.npm_ref \}\}/);
});
