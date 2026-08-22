# NPM artifact-v2 release runbook

This runbook releases the public, gamified `@devseccode/scanner` package with
only the approved Core `public-starter` profile. Merges, branch pushes, and tag
pushes never publish. The current `latest` release remains unchanged until the
final promotion step.

## Candidate acceptance commands

After Step 1 succeeds, use the same commands from the repository on macOS and
Windows. They automatically download the successful private candidate for the
current NPM commit and install its exact recorded tarballs. Node.js 22 or 24,
npm, authenticated GitHub CLI, and the repository are the only prerequisites.

macOS or Linux:

```bash
node npm-dist/scripts/candidate-platform-test.mjs start-private
node npm-dist/scripts/candidate-platform-test.mjs cleanup
```

Windows PowerShell:

```powershell
node .\npm-dist\scripts\candidate-platform-test.mjs start-private
node .\npm-dist\scripts\candidate-platform-test.mjs cleanup
```

`start-private` uses GitHub authentication only to download the private
Actions artifact. It verifies the release-record hashes, removes credentials
from the installation and product environment, uses an empty npm
configuration, installs the exact parent and platform tarballs into an
isolated global prefix, verifies the embedded Core payload, starts Core,
scans, and runs a gamified hunt. It leaves only its disposable test directory
in the OS temporary directory. `cleanup` stops its isolated Core process,
verifies uninstall behavior, and removes that directory.

The private candidate must pass macOS ARM64 and Windows x64 operator testing
before Step 2. Step 1 runs this same helper against the same bytes on native
Ubuntu 22.04 x64; that successful job is the Linux acceptance record. Nothing
has reached npm at this point.

## Fixed 0.5.0 Core inputs

- Core version: `0.3.6`
- Core source: `cb08082778d735ba560ca5e0ba461b440e9ac49d`
- Core candidate: `cb08082778d735ba560ca5e0ba461b440e9ac49d-run-31419121627-attempt-1`
- Core profile: `public-starter`
- Core launcher: `@devseccode/core-launcher@0.6.0`
- NPM version: `0.5.0`

## Prerequisites

- The NPM change is merged to `main` and PR CI passed on Node 22 and Node 24.
- Core launcher `0.6.0` exists on npm with the exact integrity produced by the
  Core launcher release workflow.
- The NPM repository `npm` environment exists.
- Repository secret `NPM_TOKEN` can publish the four `@devseccode` packages.
- Repository variable `CORE_V2_WINDOWS11_X64_RUNNER_LABEL` is
  `devseccode-win11-x64`.
- The managed Windows 11 runner group permits DevSecCode-NPM.

## 1. Build the nonpublishing candidate

```bash
cd /Users/matt/Projects/dsc/DevSecCode-NPM
git switch main
git pull --ff-only origin main
NPM_REF="$(git rev-parse HEAD)"

gh workflow run release-npm.yml \
  --repo DevSecCodeInc/DevSecCode-NPM \
  --ref main \
  -f npm_ref="$NPM_REF" \
  -f core_version=0.3.6 \
  -f core_ref=cb08082778d735ba560ca5e0ba461b440e9ac49d \
  -f core_candidate_id=cb08082778d735ba560ca5e0ba461b440e9ac49d-run-31419121627-attempt-1
```

Success means the workflow downloaded the real public R2 candidate, verified
the signed v2 manifest and public-only boundary, assembled all three platform
packages, passed the unit suite, exercised the exact private tarballs on Linux
x64, macOS ARM64, and Windows x64, and uploaded
`npm-artifact-v2-candidate`. It publishes nothing.

After that run succeeds:

```bash
CANDIDATE_RUN_ID="$(gh run list \
  --repo DevSecCodeInc/DevSecCode-NPM \
  --workflow release-npm.yml \
  --commit "$NPM_REF" \
  --event workflow_dispatch \
  --limit 20 \
  --json databaseId,conclusion \
  --jq '[.[] | select(.conclusion == "success")][0].databaseId')"
test -n "$CANDIDATE_RUN_ID"
```

## 2. Publish the exact candidate versions

This makes version `0.5.0` publicly readable under the
`artifact-v2-candidate` dist-tag. It does not change `latest`. npm versions are
immutable, so do this only after Step 1 passes.

```bash
gh workflow run promote-npm.yml \
  --repo DevSecCodeInc/DevSecCode-NPM \
  --ref main \
  -f operation=publish-candidate \
  -f candidate_run_id="$CANDIDATE_RUN_ID" \
  -f npm_ref="$NPM_REF" \
  -f npm_version=0.5.0 \
  -f core_version=0.3.6 \
  -f core_ref=cb08082778d735ba560ca5e0ba461b440e9ac49d \
  -f core_candidate_id=cb08082778d735ba560ca5e0ba461b440e9ac49d-run-31419121627-attempt-1
```

Success means all four registry versions match the candidate-record
integrities. No-auth `npx` and isolated global installs then start Core, scan,
select only the matching platform package, and uninstall cleanly on Ubuntu
22.04 x64, macOS 15 ARM64, and the managed Windows 11 x64 runner.

Do not run this step until the private macOS, Windows, and Linux acceptance
described above is complete and the operator has authorized npm publication.

After that run succeeds:

```bash
ACCEPTANCE_RUN_ID="$(gh run list \
  --repo DevSecCodeInc/DevSecCode-NPM \
  --workflow promote-npm.yml \
  --commit "$NPM_REF" \
  --event workflow_dispatch \
  --limit 20 \
  --json databaseId,conclusion \
  --jq '[.[] | select(.conclusion == "success")][0].databaseId')"
test -n "$ACCEPTANCE_RUN_ID"
```

## 3. Promote without rebuilding

```bash
gh workflow run promote-npm.yml \
  --repo DevSecCodeInc/DevSecCode-NPM \
  --ref main \
  -f operation=promote \
  -f candidate_run_id="$CANDIDATE_RUN_ID" \
  -f acceptance_run_id="$ACCEPTANCE_RUN_ID" \
  -f npm_ref="$NPM_REF" \
  -f npm_version=0.5.0 \
  -f core_version=0.3.6 \
  -f core_ref=cb08082778d735ba560ca5e0ba461b440e9ac49d \
  -f core_candidate_id=cb08082778d735ba560ca5e0ba461b440e9ac49d-run-31419121627-attempt-1
```

The workflow refuses promotion unless the candidate-publication/acceptance run
succeeded for the same NPM commit. It verifies every registry integrity again,
then moves `latest` for the three platform packages and parent package. It
does not rebuild or republish bytes.

## 4. Confirm and tag

```bash
npm view @devseccode/scanner dist-tags --json
npm view @devseccode/scanner@0.5.0 version
npm view @devseccode/scanner-darwin-arm64@0.5.0 version
npm view @devseccode/scanner-linux-x64@0.5.0 version
npm view @devseccode/scanner-win32-x64@0.5.0 version
```

After confirmation, `npm-v0.5.0` may be pushed as release metadata. The tag
does not trigger a build or publication workflow.

## Rollback boundary

Before promotion, `latest` still points to `0.4.5`; no rollback is necessary.
After promotion, rollback means moving all four `latest` dist-tags back to the
previous mutually compatible version. Published npm versions cannot be
overwritten and must not be unpublished as a routine rollback mechanism.
