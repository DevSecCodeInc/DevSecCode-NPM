#!/usr/bin/env bash
# Reads commit messages or a PR description on stdin and fails on AI authorship attribution.
# Used by the commit-msg hook and the "AI attribution" workflow; keep the tool list current.
set -euo pipefail
pattern='^(co-authored-by:.*(claude|codex|copilot|cursor|chatgpt|gemini|aider|devin|windsurf|noreply@(anthropic|openai|cursor)\.com)|.*generated (with|by) \[?(claude|codex|copilot|cursor|chatgpt|gemini|an? ai))'
if grep -Eino "$pattern"; then
  echo "AI attribution found. Remove the lines above." >&2
  exit 1
fi
