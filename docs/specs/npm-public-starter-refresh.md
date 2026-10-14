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
