# DevSecCode-NPM Core Migration Plan

## Summary

Migrate `@devseccode/scanner` so the NPM package remains the public gamified CLI, starter scan experience, profile, quest, output, and install UX layer, while scan execution comes from a Core-built **public/starter** backend artifact through the shared Core launcher and authenticated `/v1/*` API.

The public NPM package must not ship the full Core backend artifact. Full Core remains private/protected distribution because it contains proprietary scanner engine surface area, full rulepacks, compliance mappings, model assets, and scanner-bound model logic. NPM may only ship an explicitly approved public/starter artifact profile produced by Core.

Users should still install only:

```bash
npm install -g @devseccode/scanner
```

They should not need a separate DevSecCode-Core checkout or manual backend install. The NPM package will carry the platform-matched Core-built public/starter backend artifact through its optional platform packages and start or reuse that backend through `@devseccode/core-launcher`.

## Key Changes

- Keep this plan as the canonical planning artifact at
  `docs/DevSecCode-NPM Core Migration Plan.md`.

- Convert the parent package `npm-dist/packages/scanner` from a binary shim into the NPM CLI/router:
  - Replace `bin/dsc.js` so it resolves the installed platform package, locates its Core artifact manifest, verifies/extracts the artifact through `@devseccode/core-launcher`, starts or reuses `dsc-backend`, checks `/v1/meta`, then routes commands to Core APIs.
  - Add an exact dependency on the published Core launcher package.
  - Keep `devseccode` and `dsc` as the public bin names.

- Convert platform packages from PyInstaller-binary packages into Core-artifact packages:
  - Keep package names like `@devseccode/scanner-darwin-arm64`.
  - Replace `bin/dsc` or `bin/dsc.exe` contents with Core-built public/starter artifact payloads and manifest files from Core release output.
  - Reject full/private Core artifacts. Platform package assembly must require `artifactProfile: "public-starter"` and `publicNpm: true` metadata, plus a declared starter/public rule allowlist.
  - Reject archives containing full-Core payload markers, including `compliance_seeds`, private/premium/enterprise assets, model assets, SBOM/model bundles, or broad compliance/premium preset data.
  - Require Core's detached Ed25519 manifest signature and verify it against the vendor public key pinned in the parent NPM package before trusting any manifest field, filename, checksum, or archive.
  - Treat the compiled public-starter backend as inspectable public distribution. Compilation and packaging are not IP controls; Core's source/profile allowlist and release validator are the IP boundary.
  - Keep the Core-approved initial matrix: `darwin-arm64`, `linux-x64`, `win32-x64`.
  - Retain `linux-arm64` only as a private planned scaffold until Core publishes and validates that target.
  - Do not add `darwin-x64` until Core artifact production and release validation exist for that target.
  - Remove stale `darwin-x64` publishing/build assumptions from release scripts while this target is unsupported.

- Establish the runtime contract:
  - NPM owns command parsing, help text, local UX, gamification, quests, profile, stats, and install ergonomics.
  - Core owns scan execution, starter rulepack loading, finding normalization, and SARIF export for the public/starter NPM SKU. NPM renders terminal, JSON, JSON Lines, and JUnit presentations from Core findings.
  - Full compliance mapping, full/private rulepacks, premium scanner logic, and scanner-bound model functionality remain private Core surfaces and must not be reachable through the public NPM artifact unless a future product decision explicitly creates a public capability for them.
  - Every Core-backed command must call `/v1/meta` first and verify only the capabilities required for that command before invoking deeper routes.
  - Deterministic scanning must not be blocked by missing optional LLM or compliance capabilities.
  - The wrapper must use the endpoint descriptor token from `@devseccode/core-launcher`, send `Authorization: Bearer <token>` on `/v1/*`, never log the token, and rely on the launcher/Core endpoint file permissions.

- Preserve the NPM UX runtime explicitly:
  - The current public UX implementation lives in Python under `engine/src/dsc/gamification` and is currently shipped only because the PyInstaller CLI binary includes it.
  - Replacing platform packages with Core backend artifacts removes that runtime unless it is moved.
  - Decision: port the public NPM UX layer to Node/JS inside the parent `@devseccode/scanner` package, keeping Core interactions behind a small client adapter.
  - Users must still install only `@devseccode/scanner`; any JS libraries needed for command parsing, terminal rendering, or prompts must be normal parent-package dependencies.
  - Do not introduce a second user-installed package, postinstall download step, or manual Core/UX install path for the initial migration.
  - Update the parent package `files` allowlist so the published tarball includes all Node UX source files, templates, static text/assets, and package-local runtime data needed by `bin/dsc.js`.
  - Add every Node UX runtime dependency to the parent package manifest; do not rely on globally installed tools or source-tree-only dev dependencies.
  - Platform optional packages should contain only platform-matched public/starter Core artifacts and manifests, installed automatically through the parent package's `optionalDependencies`.
  - Do not claim parity for `hunt`, `map`, `play`, `watch`, `quests`, `stats`, `init`, or `ide` until the Node-owned UX runtime is packaged and tested from a fresh install.

- Migrate command behavior:
  - `scan`: call Core scan endpoints, render terminal, JSON, JSON Lines, and JUnit locally from `/v1/scan/{scanId}/results`, and use Core-backed SARIF export.
  - `hunt`, `map`, `play`, `watch`: keep NPM-specific gamified UX, but feed it normalized Core findings instead of local scanner internals.
  - `list-rules`: use Core rule metadata.
  - `explain`: use Core rule/finding metadata; if Core lacks the needed detail route, record that as a Core API gap before claiming parity.
  - `init`, `quests`, `stats`, `ide`: remain local NPM UX commands, updated to describe the Core-backed scanner model.
  - Bare `devseccode` or `dsc` with no subcommand must continue opening the play menu.
  - Do not add new compliance or LLM user-facing NPM commands during initial parity unless they are needed to preserve existing behavior.
  - Preserve existing user-facing scan semantics:
    - `.dsc.yml` discovery and path resolution.
    - `scan.paths`, `scan.ignore`, `scan.languages`, `detectors.enabled`, `detectors.disabled`, `detectors.severity_override`, and `fail_on`.
    - CLI flags: `--diff`, `--fail-on`, `--threads`, `--no-cache`, `--scan-profile`, `--min-confidence`, `--include-suppressed`, repeated `--ignore`, `--format`, `--output`, `--verbose`, `--json-lines`, `--no-profile`, `--no-explore`, and `watch --interval`.
    - Existing exit code behavior: configuration/user errors return `2`; scan gates return `1` only when findings meet or exceed the active fail severity; otherwise return `0`.
  - Treat unsupported Core request fields as migration blockers, not NPM-only emulation:
    - Core must accept or otherwise support `scan.languages`.
    - Core must accept or otherwise support detector include/exclude filtering for `detectors.enabled` and `detectors.disabled`.
    - If Core intentionally replaces those fields with a different contract, update this plan and the NPM config adapter before migrating scan parity.
  - Preserve current config parsing behavior:
    - Find `.dsc.yml` by walking from the target path up to the git root, or filesystem root when no git root exists.
    - Accept JSON configs and the existing dependency-free YAML subset written by `devseccode init`.
    - Preserve `DEVSECCODE_HOME` for tests and local state isolation.
    - Treat invalid config as a user/config error with exit code `2`.
  - Preserve existing local user state:
    - Continue using `~/.devseccode/` by default and `DEVSECCODE_HOME` when set.
    - Preserve the current `profile.json`, `triage.json`, and `last_report.json` schemas where possible.
    - Migrate schema changes forward without deleting XP, achievements, difficulty, hunter class, loot, triage decisions, or last-report data.
    - Use atomic writes for profile/report/triage updates so interrupted commands do not corrupt state.

- Introduce an NPM-local result adapter:
  - Add local `Finding`, `Severity`, and `ScanResult` domain types or plain JS equivalents for the gamification layer.
  - Convert Core `/v1` responses into those local types.
  - Remove product-path imports of `dsc.scanner`, `dsc.engine`, and `dsc.formatters`.
  - Preserve original Core severity and metadata; any NPM-only severity override should be presentation/gating-only and should not mutate Core findings.

- Rework release automation:
  - Replace PyInstaller/OpenGrep build steps in `.github/workflows/release-npm.yml` with public/starter Core artifact intake, checksum verification, platform package assembly, Core launcher version validation, and public artifact profile validation.
  - Publish or otherwise make `@devseccode/core-launcher` available before publishing the parent scanner package.
  - Continue publishing platform packages before the parent package so optional dependencies resolve on first install.
  - Change version checks so the NPM wrapper version and Core engine version are both reported, instead of deriving the NPM release from `engine/src/dsc/version.py`.
  - Keep exact optional dependency pins for platform packages and preserve each platform package's `os` and `cpu` metadata so npm installs only the matching artifact.
  - Update `npm-dist/README.md`, `npm-dist/TESTING.md`, and package README copy so they describe Core artifacts rather than PyInstaller binaries.
  - Add package-content guardrails:
    - `npm pack --dry-run` or equivalent must show the Node UX source, templates/assets, `bin/dsc.js`, README, license, and no source-tree-only scanner internals.
    - Fresh-install tests must run from the packed tarball, not the repo source tree, so missing `files` entries fail before publish.
  - Add a public/starter Core artifact admission gate before npm package assembly:
    - `devseccode-core-artifacts.json.sig` verifies over the exact manifest bytes with the pinned Core artifact public key.
    - `devseccode-core-artifacts.json` declares `artifactProfile: "public-starter"` and `publicNpm: true`.
    - The manifest declares a non-empty public/starter rule allowlist and rulepack file limit.
    - The manifest and archive do not declare or contain full/private Core payloads, full compliance mappings, model assets, premium scanner logic, private backend assets, or scanner-bound model bundles.
    - `devseccode-core-artifacts.json` contains `darwin-arm64`, `linux-x64`, and `win32-x64`.
    - Every referenced archive exists, matches `sha256` and `sizeBytes`, extracts safely, and contains the expected `dsc-backend` or `dsc-backend.exe`.
    - Generated Core manifests, signatures, and archives are never committed to this repository; release CI assembles them into package tarballs from an immutable signed Core handoff.
    - Each platform package tarball contains the expected Core manifest/archive layout and no old `dsc` PyInstaller CLI binary.
    - Each platform package smoke test launches the public/starter backend, reads endpoint discovery, checks `/health`, authenticates to `/v1/meta`, runs a representative starter scan, obtains SARIF from Core, and renders JUnit from the returned Core findings.

## Public NPM Artifact Boundary

The NPM package is a public starter scanner, not a distribution channel for full Core.

Allowed in public NPM:
- Gamified CLI UX, profile/quests/output, local config parsing, and starter scan presentation.
- `@devseccode/core-launcher`, which contains generic local service/artifact/client helpers and no scanner rules/models.
- Core-built `public-starter` backend artifacts with only approved public rulepacks/features.

Everything in the published tarballs, including compiled executables, must be
assumed recoverable and inspectable. The public-starter Core build may contain
only code, rules, metadata, and assets approved for public disclosure.

Forbidden in public NPM:
- Full Core backend artifacts.
- Full/private rulepacks, compliance seeds/mappings, model assets, scanner-bound model logic, premium/enterprise scanner logic, private backend assets, or internal SBOM/model bundles.
- Any artifact that lacks explicit `public-starter`/`publicNpm` metadata and a declared public rule allowlist.

This is a hard release gate. No public NPM tarball may contain full Core rulepacks, compliance seeds, model assets, premium scanner logic, or private backend artifacts. Packaging tests must enforce this before publish.

## Capability Requirements

Capability checks must be per command, not a single launcher default. The NPM
wrapper may use `@devseccode/core-launcher` helpers, but it must pass command
specific `requiredCapabilities`.

| Command or flow | Required Core capabilities | Optional/degraded capabilities |
|---|---|---|
| `scan --format terminal/json/json-lines` | `scan.workspace` | `llm.*`, `compliance.*`, `dependencies.*` |
| `scan --format sarif` | `scan.workspace`, `scan.export.sarif` | `llm.*`, `compliance.*` |
| `scan --format junit` | `scan.workspace`; NPM renders JUnit from Core findings | `llm.*`, `compliance.*` |
| `hunt`, `map`, `play`, `watch` | `scan.workspace` | `llm.*`, `compliance.*`, richer explain/fix metadata |
| `list-rules` | `rules.list` | none |
| `explain` | `rules.list` plus any future Core detail capability if added | LLM explanation only if a future command explicitly enables it |
| `init`, `quests`, `stats`, `ide` | none unless they perform a scan | Core diagnostics may be shown if available |

Do not use the Core launcher's broad default capability set for commands that
only require deterministic scanning or rule metadata.

## Migration Phases

1. **Baseline and contract inventory**
   - Capture golden outputs and exit codes for the existing package before edits.
   - Inventory every current product import from `dsc.scanner`, `dsc.engine`, and `dsc.formatters`, including gamification modules.
   - Confirm the Node/JS parent-package UX runtime scope and identify the JS libraries needed to replace the Python CLI and gamification surfaces.
   - Confirm Core supports every scan/config field required for NPM parity, especially language filtering and detector include/exclude lists.

2. **Core launcher and artifact packaging**
   - Add `@devseccode/core-launcher` as an exact dependency.
   - Add platform package artifact layout and manifest discovery.
   - Verify/extract public/starter Core artifacts and connect through the endpoint descriptor.
   - Confirm bearer-token handling without logging or persisting tokens outside the launcher/Core endpoint file.
   - Fail package assembly when any supported npm target is missing from the public/starter Core artifact manifest or fails checksum/extraction/backend-launch smoke.
   - Implement backend lifecycle ownership rules:
     - Reuse an existing endpoint only when `/health`, `/v1/meta`, contract version, Core version, and required capabilities are compatible.
     - Start the pinned packaged backend when no compatible endpoint is available.
     - Do not terminate a backend the NPM wrapper did not start.
     - If the NPM wrapper starts the backend for a foreground command, clean up only processes it owns when cleanup is appropriate; long-lived reuse must remain intentional and diagnosable.
     - Diagnostics must report whether the backend was reused or started by the current command.

3. **Command adapter migration**
   - Implement Core request mapping for `scan`, including config and all flags.
   - Implement local result/domain adapters for gamification.
   - Port NPM-owned UX code into the parent package so `hunt`, `map`, `play`, `watch`, `quests`, `stats`, `init`, and `ide` still run without the old PyInstaller scanner binary.
   - Keep NPM-only severity overrides presentation/gating-only; do not mutate Core findings.
   - Implement `watch` as a local NPM lifecycle feature:
     - Use Core scans for each rescan.
     - Allow at most one active scan per watch target.
     - If a file changes while a scan is active, queue or coalesce one follow-up scan instead of starting unbounded concurrent scans.
     - On process exit, stop the watcher cleanly; do not require a Core cancellation route for initial parity.

4. **Release automation**
   - Replace PyInstaller/OpenGrep release jobs with public/starter Core artifact intake.
   - Remove stale unsupported target assumptions, including `darwin-x64`.
   - Add guardrails that fail when product execution imports old scanner/engine/formatter internals.

5. **Retire duplicated scanner code after parity**
   - Keep old Python scanner paths only as temporary reference during migration.
   - Remove or stop shipping local scanner/rulepack/OpenGrep internals once command parity tests pass.
   - Final state must have no downstream product execution path importing scanner, rule loader, formatter, compliance, or LLM internals from the old NPM engine.

## Test Plan

- Capture current baseline behavior before edits:
  - `devseccode`
  - `dsc`
  - `devseccode --version`
  - `devseccode scan resources/sample-vulns`
  - `devseccode scan resources/sample-vulns --format json`
  - `devseccode scan resources/sample-vulns --format json --json-lines`
  - `devseccode scan resources/sample-vulns --format sarif`
  - `devseccode scan resources/sample-vulns --format junit`
  - `devseccode scan resources/sample-vulns --output /tmp/devseccode-scan.txt`
  - `devseccode scan resources/sample-vulns --diff`
  - `devseccode scan resources/sample-vulns --scan-profile precision --min-confidence 0.5`
  - `devseccode scan resources/sample-vulns --include-suppressed`
  - `devseccode scan resources/sample-vulns --ignore node_modules --ignore tests`
  - `devseccode scan resources/sample-vulns --fail-on critical`
  - `devseccode hunt resources/sample-vulns`
  - `devseccode hunt resources/sample-vulns --no-profile --no-explore`
  - `devseccode map resources/sample-vulns`
  - `devseccode play`
  - `devseccode watch resources/sample-vulns --interval 3 --no-profile`
  - `devseccode list-rules`
  - `devseccode explain <known-rule-id>`
  - `devseccode init --path <temp-dir>`
  - `devseccode quests`
  - `devseccode stats`
  - `devseccode ide`
  - a `.dsc.yml` driven scan covering configured paths, ignores, languages, detector enable/disable lists, severity overrides, and `fail_on`.
  - profile, triage, and last-report behavior using `DEVSECCODE_HOME=<temp-dir>`.

- Add unit tests for:
  - Platform package resolution.
  - Public/starter Core artifact manifest discovery and profile validation.
  - Core launcher invocation.
  - Endpoint descriptor reading, bearer auth header injection, and token redaction in diagnostics/errors.
  - Per-command `/v1/meta` capability gating.
  - Command/config/flag-to-Core request mapping.
  - Core result to NPM gamification adapter conversion.
  - Local severity override behavior that affects display/gating without mutating Core findings.
  - Exit code behavior for fail-on severity.
  - Bare `devseccode` and bare `dsc` routing to the play menu.
  - Existing local UX flows that do not require Core, including `init`, `quests`, `stats`, and `ide`.
  - JSON and JSON Lines rendering from `/v1/scan/{scanId}/results`.
  - Scan config adapter validation for Core-supported versus Core-missing fields.
  - Config discovery and parsing parity for JSON configs and the `.dsc.yml` subset written by `init`.
  - `DEVSECCODE_HOME` local state isolation.
  - Profile, triage, and last-report schema compatibility and atomic-write behavior.
  - Backend lifecycle ownership: compatible reuse, incompatible restart, and no termination of externally owned backend processes.
  - Watch rescan coalescing when file changes occur during an active scan.

- Add integration tests using a real packaged public/starter Core artifact:
  - Install packed parent and platform packages into a temp project.
  - Confirm no DevSecCode-Core source checkout is present.
  - Run bare command, scan, hunt, map, list-rules, explain, version, and init flows.
  - Confirm the launched backend responds to `/health` and `/v1/meta`.
  - Confirm terminal, JSON, JSON Lines, and JUnit output comes from normalized Core results and SARIF comes from the Core export route.
  - Start `watch` against a temp project, modify one file, observe one rescan, then terminate the process cleanly within a fixed timeout.
  - Run a fresh-install hunt with `DEVSECCODE_HOME=<temp-dir>` and confirm profile/report/triage files are created or preserved with the expected schemas.

- Update local registry tests:
  - Keep the Verdaccio flow.
  - Publish platform package tarballs first, parent package last.
  - Install from the local registry and run the same smoke commands.
  - Confirm only the host platform optional dependency installs.
  - Confirm installed package size remains in the expected one-platform range.
  - Confirm the installed parent package contains all Node UX runtime files declared in package-content guardrails.

- Add guardrail tests:
  - Fail if product code imports `dsc.scanner`, `dsc.engine`, or `dsc.formatters`.
  - Fail if packaged NPM UX code imports scanner, rule loader, formatter, compliance, SBOM, or LLM internals for product execution.
  - Fail if the parent package tarball omits required Node UX files, templates/assets, or runtime dependencies.
  - Fail if platform package tarballs contain the old PyInstaller CLI binary.
  - Fail if platform packages lack the expected public/starter Core artifact manifest and archive.
  - Fail if public/starter Core artifact checksums do not match the manifest.
  - Fail if the Core manifest signature is missing, altered, signed by an untrusted key, or does not match the pinned key ID.
  - Fail if the public/starter Core artifact manifest is missing any target listed in the parent package's `optionalDependencies`.
  - Fail if an artifact lacks `artifactProfile: "public-starter"`, lacks `publicNpm: true`, lacks a public rule allowlist, or contains banned full/private Core payload markers.
  - Fail if `--version` does not report both NPM wrapper version and Core engine/contract version.

- Cross-platform release acceptance:
  - Validate all currently supported platform packages.
  - Keep Intel Mac unsupported in this migration unless a real build and smoke path is added.
  - Validate Linux packages on glibc environments; do not claim Alpine/musl support unless a separate artifact and smoke path exist.

- Post-publish release acceptance:
  - Publish the exact candidate bytes first under the non-`latest` dist-tag `artifact-v2-candidate`.
  - From a clean environment with no npm auth, run `npx --yes @devseccode/scanner@artifact-v2-candidate --version`.
  - From a clean environment with no npm auth, run `npx --yes @devseccode/scanner@artifact-v2-candidate scan "$HOME/juice-shop" --format terminal`.
  - Run `npm install -g @devseccode/scanner@artifact-v2-candidate`, then `devseccode --version`, `devseccode hunt "$HOME/juice-shop" --no-explore`, and `devseccode scan "$HOME/juice-shop" --format sarif --output "$HOME/deva-results.sarif"`.
  - Confirm npmjs package visibility is public and no private registry or npm login is required.
  - Confirm only the matching platform optional package installed and the installed size matches a single platform artifact.
  - On macOS, verify signing/notarization expectations for the shipped Core backend artifact.
  - Promote the verified version to `latest` only after no-auth `npx`, global install, platform optional dependency, and smoke checks pass.

## Completion Criteria

- A user can install only `@devseccode/scanner` and run scans without separately installing DevSecCode-Core.
- NPM command UX remains intact, including the gamified hunt, profile, quest, achievement, streak, and score behavior.
- Public starter scanner execution and export generation flow through Core `/v1/*` routes as appropriate.
- Full compliance mapping, LLM-capable scanner behavior, private rulepacks, and premium Core functionality remain outside the public NPM artifact.
- NPM no longer vendors or imports scanner/compliance/LLM internals for product execution.
- The package reports clear diagnostics for wrapper version, Core engine version, Core contract version, backend location, and active endpoint.
- Diagnostics report whether the backend was reused or started by the current command, without exposing bearer tokens.
- Local pack/install and Verdaccio tests pass with packaged public/starter Core artifacts.
- Real npmjs canary `npx` and global install smoke tests pass without npm authentication before promotion to `latest`.
- Only the matching platform artifact package installs on supported platforms.
- Release automation no longer builds the old scanner binary with PyInstaller.
- Release documentation no longer describes PyInstaller/OpenGrep bundling as the active packaging model.
- The Node-owned NPM UX runtime is packaged in the parent `@devseccode/scanner` package, installed through the single user-facing npm install command, and exercised from fresh installs.
- Existing profile, triage, and last-report state remains readable after migration.

## Assumptions

- The migration target file is `docs/DevSecCode-NPM Core Migration Plan.md`.
- The NPM package version can remain independent from Core, but it must pin and report the Core engine and contract versions it ships.
- Initial migration is local-artifact based, not cloud-hosted scanning.
- Core Phase 1 launcher/artifact distribution is the source of the backend packaging contract.
- Existing untracked or unrelated files in the NPM repo, including `prototypes/`, should not be modified as part of writing this plan.
