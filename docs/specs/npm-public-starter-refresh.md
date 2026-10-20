# NPM public/starter refresh

Status: Draft, requested by Matt on 2026-10-07. This authorizes the planning
document only; implementation and release actions are future sprint work.

## Goal and existing contract

Bring useful Core, CLI, and EXT reliability improvements into NPM while
preserving its deliberately limited public rule set, local anonymous scanning,
single-package installation, basic outputs, and gamified UX.

This spec supplements the [canonical migration plan](../DevSecCode-NPM%20Core%20Migration%20Plan.md).
The [released baseline](../npm-artifact-v2-release-closure.md) is NPM 0.5.0,
Core 0.3.6 `public-starter`, and Node launcher 0.6.0. The parent package owns
Node presentation; Core owns scanning and SARIF. Keep Node 22/24 and the four
existing targets: macOS ARM64, Linux x64/ARM64, and Windows x64.

Evidence inspected on 2026-10-07: all 43 existing NPM tests passed. Core and CLI
checked-out main branches lag newer locally available refs; select exact source
identities before implementation. No newer installed NPM runtime was qualified.

## IP boundary

Keep Core's public/starter module and rule-file allowlists as the source of truth.
Compilation is not an IP boundary. Do not add full rulepacks, proprietary
detectors, advanced reachability, compliance catalogs/evaluation, SBOM/CVE
enrichment, signed evidence, LLM validation/remediation, provider orchestration,
or model assets. OpenRouter and saved-finding LLM guidance are outside scope.
Retain command-specific capability negotiation, anonymous/offline standard
scanning, disabled LLM requests, and fail-closed signature/profile verification.

Do not change feature pricing or unlock advanced flags as an incidental upgrade.
Record currently exposed but unavailable options and give actionable errors;
an upgrade must not silently remove working public commands or outputs.

## Workstreams and acceptance

### NPM-R1: Qualified Core input

Select a Core source containing scan-scope/safe-cache fixes (`e303a74`), portable
SARIF/crash handling (`983d1d7`), detector coverage (`f07fa67`), stable identities
and validated baselines (`e4cb2f9`), and starter baseline allowance (`70cb7c3`).
These commits are evidence of behavior, not a release recommendation by version.
Core 0.3.9/0.3.10 being present in local refs does not prove public/starter release
availability. Build any missing input through Core's owned pipeline only.

Accept only an exact signed artifact-v2 candidate with source commit, version,
candidate ID, profile, target hashes, trust identity, and required launcher pin.
Inspect compiled module inventory as well as archive assets. Preserve the
curated rule-file set; deliberate public rule changes require a separate review.
Run Core-required launcher/release gates and downstream artifact smoke for any
packaging/trust change. Demonstrate scope isolation, cache invalidation, portable
SARIF paths, and scanner-crash rejection using the actual starter runtime.

### NPM-R2: Completion, failure, and runtime handling

Validate the returned scan ID before polling. Add a documented positive scan
deadline and bounded HTTP requests; handle complete, error, cancellation, and
invalid states explicitly. Ctrl-C stops polling and requests supported scan
cancellation without terminating an independently owned backend. Diagnostics
report scan ID and last status while redacting authentication tokens.

Use exit 2 for invalid configuration/arguments, exit 1 for threshold findings
or operational scan failure, and exit 0 only for a successful scan below the
threshold. Distinguish benign warnings from incomplete/error evidence according
to Core's contract; unresolved errors cannot produce a clean success. JUnit must
include an error testcase for an operational failure rather than always emitting
zero errors. Preserve machine-readable output and write progress to stderr.

Evaluate the CLI selected-runtime identity improvement (`3da2d07`) against the
Node launcher contract. Existing digest-scoped endpoints are useful but do not
alone prove process identity. Put any missing reusable launcher check in Core's
Node launcher; preserve managed-process ownership and never kill unrelated Core.

Focused checks: missing scan ID, deadline, cancelled status, failed request,
partial results, successful empty results, threshold finding, and JUnit failure.

### NPM-R3: Finding identity and result metadata

Preserve canonical findingId, fingerprint, and occurrenceId where supplied.
Use the canonical identity for local triage, with a documented fallback for
legacy responses. Keep existing profile/XP/history data readable. Legacy
path/rule/line entries must not silently suppress unrelated findings; migrate
only unambiguous matches. Verify duplicate snippets, line shifts, repeat scans,
and restart behavior. Do not regenerate Core identities in NPM.

Preserve activeDetectorCwes, phaseTimingsMs, cacheHits, and cacheMisses through
normalization and JSON summaries. Missing detector coverage remains unknown;
an empty list is explicit empty coverage. Update package schemas/documentation
for additive fields without dropping the existing public JSON contract.

### NPM-R4: Watch and validated baselines

Carry all applicable parsed scan/config options into watch executions, including
ignores, threshold, threads, profile, confidence, suppression, diff, and no-cache.
Remove the 1,000-file detection blind spot. Handle file deletion/rename, rapid
saves, symlinks, ignore files, and transient filesystem errors without concurrent
scans or an uncontrolled scan loop. Changes to relevant config/ignore files
invalidate the watch snapshot. Avoid rescanning generated cache/output state.

Consume Core's `/v1/scan/baseline` only when available and compatible; stale,
missing, or incompatible snapshots trigger a real scan. Respect no-cache and
diff semantics. Keep hashing, validation, and scanner cache ownership in Core.
Use CLI watch/baseline work (`9cc3fe1`, `60a25df`) as behavioral references,
adapting the UX to NPM. Quiet unchanged watch output and avoid duplicate XP for
an unchanged snapshot; reward policy otherwise stays unchanged.

### NPM-R5: Exact candidate packaging

Replace the hardcoded 0.3.6 acceptance gate with the newly accepted exact Core
identity. Select the NPM version using the existing release process and keep
parent/platform optional dependency versions aligned. Retain pinned launcher
integrity, profile checks, parent/platform file allowlists, compiled-payload
inspection, checkout-path audit, and rejection of private assets.

Do not rebuild Core downstream, add postinstall downloads, require Python or
a Core checkout, expand platforms, or enable full-Core endpoint fallback.
Keep the old release-closure record historical; create separate new acceptance
evidence only when the checks actually run. Update the fixed-input runbook.

### NPM-R6: Product and license alignment

Matt described NPM as open source, but README/contribution terms and bundled
license describe proprietary use. Root package metadata says ISC, and the EULA
names `@devseccode/cli`. Decide the intended rights for the Node client, public
rules, launcher, and bundled binary before changing legal terms. Public registry
access does not settle those rights.

Pending Matt's decision, retain existing terms and do not infer permission to
relicense Core. Once resolved, align root/parent/platform metadata, distributed
license copies, contribution rules, README wording, and package names. Preserve
privacy claims only if validated behavior supports them. Document supported
public options, error exit behavior, watch behavior, and additive output fields.

### NPM-R7: Integrated acceptance

Run existing NPM tests on Node 22 and 24 plus focused regressions above. Verify
exact parent/platform tarballs in isolated installs on all four supported
targets, with no developer tools, source checkout, account, or ambient entitlement.
Check scan/hunt/watch/rules/explain/local commands and terminal/JSON/JSON Lines/
SARIF/JUnit output, exit codes, failure recovery, offline startup, state
compatibility, and uninstall cleanup. Verify unrelated processes survive.

Audit the actual candidate contents and demonstrate banned routes/assets remain
unavailable. Freeze only the combination that passes. Record missing native
platform evidence as outstanding; source tests do not substitute for it.
The sprint ends with a reviewable, qualified candidate and evidence, not npm
publication. Publishing, pushes, external job dispatch, and monitoring need
their applicable explicit authorization.

## Decision record

- **PD1 — License model, open:** Matt chooses between a specifically scoped open
  source client/rules model with separately licensed binaries, or the current
  proprietary free-to-use model. No license change is approved by this draft.

## Execution record

Maintain implementation commit identities and acceptance results here as work
finishes. Planning evidence above does not mark any workstream complete.

### NPM-R1: Qualified Core input (2026-10-20)

Accepted input: Core `0.3.11`, profile
`public-starter`, from the `core-v0.3.11` GitHub Release.

| Field | Value |
| --- | --- |
| Source commit | `dc0faca57cd2e5932f520175f7a697fb23e8ddf2` |
| Candidate ID | `dc0faca57cd2e5932f520175f7a697fb23e8ddf2-run-39362422025-attempt-1` |
| Validation / publication runs | `39362422025/1` / `39364039471/1`; ledger `nextSafeAction` `none` |
| Release path | `candidates/v2/<candidate ID>/core/v0.3.11/public-starter` on the public R2 base |
| Manifest SHA-256 | `6ed8b910fa3a3796f58ff9b36f4cb3a1b91b91589241ee72dab1e60e21b98db5` |
| Manifest signature SHA-256 | `46568e5f001ed9832c0dde8207373c8e19c41e7236daac542be4528287c7e863` |
| Publication record / signature SHA-256 | `2993c24d038d91bd553c653026d4c659e5408f393c7d500b47f930af590571b8` / `a560fc6d8ac27b360c76f0334148864ccebd789cd48c9cc6659c11bbcfceafba` |
| Trust identity | Ed25519 `ed25519:a96597f65ec59252`; trust bundle SHA-256 `1ac1bf4a95a31a8179af06bc81e1a6ee2e7a0d8b50efcca7ad15ba1940620f33`; NPM's pinned PEM is unchanged and identical to Core's |
| Required launcher | `@devseccode/core-launcher@0.6.0`, `sha512-AupfY9wSRSJqC8zR4/6r77vP3cLBqTARfVcNYJUMy8lEM4OuYio7lubHxnw36ZHse3eaXc2c46KS9EUBXjAD2w==`; source identical to `launchers/node` at the tag, so the pin does not change |
| API contract | `v1` |

| Target | Archive SHA-256 | Bytes | `dsc-backend` SHA-256 |
| --- | --- | --- | --- |
| `darwin-arm64` | `922e0a3549b650bc99cfa830aea90b49fc9c2d9792c36efa073535a9ebdf029a` | 61457165 | `bc454472c38c2648e04822a2fcedde696664bb0ad1c207106e6400bed0f1348a` |
| `linux-arm64` | `6789c00821609c570debe4d3117a8ea0f118f89d953b660e5775a0ccf70d0b7d` | 82257030 | `f8e3791e2feae96077498006a933f8d993281c2b16bea6cd45673d490e00b484` |
| `linux-x64` | `fece85d17f9d9af99aa773ddb9d927f4e133a4025442067dd6c297c1a423fdfc` | 81309156 | `435772efe8775441664da0effd441c30b9f42bd1faf447bf372178166dc443b7` |
| `win32-x64` | `926535f6f33da8d0a8cb75c86ef42fa9a12b10edd575a7fc2de49a5dce10016a` | 64722566 | `386c8b44d98e05d1af934a623c97f5d0534fdabd34b4fe3740137db74cabce6d` |

All five required commits (`e303a74`, `983d1d7`, `f07fa67`, `e4cb2f9`,
`70cb7c3`) are ancestors of the source commit. Core's release gates passed:
every publication, download and qualification stage (all four public-starter
lanes) succeeded, and the tag resolves to the source commit.

Verification, all fail-closed:

- All 27 public-starter files match the Release `SHA256SUMS`.
- Core's own consumer (`fetch-and-smoke-published-artifact.mjs` at the tag)
  verified the manifest and publication signatures and every referenced byte
  for each of the four targets, then passed its runtime smoke on
  `darwin-arm64`.
- NPM's `download-public-core-candidate.mjs` and
  `validate-public-core-artifact.js` accept all four targets. Flipping one
  manifest byte or one archive byte is rejected.

Inventory: Core's `validate-backend-artifact.py` (PyInstaller 6.21.0) passes
for all four archives. Each embeds exactly the 33 first-party modules on the
public-starter allowlist and no banned prefix. The only allowlist change since
0.3.6 is `dsc_backend.scan_baseline`, from `70cb7c3`. Archives hold 143–167
members and no banned paths.

Rule set: the 11 curated rule files and 131 public rule IDs are unchanged from
Core 0.3.6, comparing the shipped archives. One rule's content changed:
`e303a74` widened the generic CWE-798 secret-assignment regex in
`cwe/cwe-798-hardcoded-secrets.yml` to also match JavaScript
`export`/`const`/`let`/`var` declarations. Matt accepted this change on
2026-10-20 after checking that it exposes nothing new. The public-starter archive
has shipped these rule files since 0.3.6. The change adds no rule, only widens one
that was already public, and the pattern is a generic secret-name match of the
kind open-source secret scanners already publish.

Runtime demonstrations: `npm-dist/scripts/qualify-core-input.mjs` downloads and
verifies the candidate, extracts the host target and runs the real starter
runtime against generated fixtures. A scanner stub selected through
`DSC_OPENGREP_BINARY` simulates crashes; the Core bytes are unchanged.

| Check | Result |
| --- | --- |
| Scope isolation | A single-file target reports only that file. A workspace scan honors an ignore pattern and never scans `.dsc_cache`, with and without the cache |
| Cache invalidation | Unchanged rescan: 2 hits, 0 misses, same findings. After swapping a vulnerable file and a clean one: 2 misses, and the findings move to the newly vulnerable file, matching a no-cache scan |
| Portable SARIF | URIs are relative to `SRCROOT` and percent-encoded (`src/web%20app%20%231.py`). The workspace path appears only in `originalUriBaseIds`. Two checkouts in different locations export identical locations |
| Crash rejection | Empty output (exit 0, or exit 2 with a fatal error), `{}` and `null` each yield an `opengrep failed` error and no findings. A valid empty report still succeeds cleanly |

These passed on `darwin-arm64` (native macOS 25.6, Node 24.18), `linux-arm64`
(container) and `linux-x64` (emulated container). `win32-x64` was not run here
because the crash stub is POSIX-only; Core's Windows 11 qualification lane
covers its install and smoke.

What this means for later workstreams: Core reports a crash as
`status: complete` with a non-empty `errors` array. NPM 0.5.0 treats any
`complete` status as success, so R2 must fail on these errors.

To rerun:

```bash
node npm-dist/scripts/qualify-core-input.mjs "$(mktemp -d)" 0.3.11 \
  dc0faca57cd2e5932f520175f7a697fb23e8ddf2 \
  dc0faca57cd2e5932f520175f7a697fb23e8ddf2-run-39362422025-attempt-1 evidence.json
```

The script needs the launcher installed as in CI (`npm install --prefix
npm-dist/packages/scanner ... --omit=optional`). It exits non-zero on any
failure, including a wrong identity.
