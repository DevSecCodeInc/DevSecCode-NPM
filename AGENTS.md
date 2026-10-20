# Agent instructions

Sprints: current sprints are in the shared DevSecCode workspace sprint set (dsc/docs/sprints/), not in this repository. Use the sprints skill there: check the open sprint before starting work and update it as tasks finish.

NPM is deliberately limited to the Core-produced `public-starter` artifact.
Follow `docs/DevSecCode-NPM Core Migration Plan.md` and the applicable refresh
spec. Core alone builds and signs Core artifacts; NPM consumes verified inputs.
Never package full Core or copy private scanner implementations into NPM.

You may push feature branches and open pull requests without asking. Direct
pushes to `main`, and merges, are Matt's call. Never force-push, delete remote
branches, or push tags unless Matt asks in the current conversation. Planning a release does not
authorize publishing or starting external jobs. After an authorized external job
starts, report its identifier and stop unless monitoring was separately requested.

## Commit attribution

- Do not add AI authorship attribution to commits or pull requests. Omit
  `Co-authored-by` trailers for Claude, Codex, Copilot, Cursor or other AI
  tools, and omit footers such as "Generated with Claude Code". Keep human
  coauthors.

`scripts/check-ai-attribution.sh` enforces this in CI (the `AI attribution` workflow) and in a local `commit-msg` hook. Enable the hook once per clone with `git config core.hooksPath .githooks`. Cursor and Copilot add attribution through per-user settings, so turn it off there too.
