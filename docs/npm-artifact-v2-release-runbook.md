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

## Fixed release inputs

- Core version: `0.3.6`
- Core profile: `public-starter`
- Core launcher: `@devseccode/core-launcher@0.6.0`
- NPM version: `0.5.0`

The Core source and candidate ID must come from the successful artifact-v2
candidate built after the public-starter module boundary was merged. The
workflow has no stale default for either value.

## Prerequisites

- The NPM change is merged to `main` and PR CI passed on Node 22 and Node 24.
- Core launcher `0.6.0` exists on npm with the exact integrity produced by the
  Core launcher release workflow.
- The NPM repository `npm` environment exists.
- Each of `@devseccode/scanner`, `@devseccode/scanner-darwin-arm64`,
  `@devseccode/scanner-linux-x64`, `@devseccode/scanner-linux-arm64`, and
  `@devseccode/scanner-win32-x64` has an
  npm Trusted Publisher for organization `DevSecCodeInc`, repository
  `DevSecCode-NPM`, workflow `promote-npm.yml`, and environment `npm`.
- The `npm` environment has no `NPM_TOKEN` requirement. Candidate publication
  uses GitHub OIDC and npm Trusted Publishing.
- Repository variable `CORE_V2_WINDOWS11_X64_RUNNER_LABEL` is
  `devseccode-win11-x64`.
- The managed Windows 11 runner group permits DevSecCode-NPM.

## 1. Build the nonpublishing candidate

```bash
cd /Users/matt/Projects/dsc/DevSecCode-NPM
git switch main
git pull --ff-only origin main
NPM_REF="$(git rev-parse HEAD)"
CORE_VERSION=0.3.6
NPM_VERSION=0.5.0
printf 'Core source commit from the accepted Core candidate: '
IFS= read -r CORE_REF
printf 'Core candidate ID from the accepted Core candidate: '
IFS= read -r CORE_CANDIDATE_ID
[[ "$CORE_REF" =~ ^[0-9a-f]{40}$ ]]
[[ "$CORE_CANDIDATE_ID" =~ ^${CORE_REF}-run-[1-9][0-9]*-attempt-[1-9][0-9]*$ ]]

gh workflow run release-npm.yml \
  --repo DevSecCodeInc/DevSecCode-NPM \
  --ref main \
  -f npm_ref="$NPM_REF" \
  -f core_version="$CORE_VERSION" \
  -f core_ref="$CORE_REF" \
  -f core_candidate_id="$CORE_CANDIDATE_ID"
```

Success means the workflow downloaded the real public R2 candidate, verified
the signed v2 manifest and public-only boundary, assembled all four platform
packages, audited the exact packed tarballs for unapproved source and payload
files, passed the unit suite, exercised the exact private tarballs on Linux
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
  -f candidate_run_id="$CANDIDATE_RUN_ID" \
  -f npm_ref="$NPM_REF" \
  -f npm_version="$NPM_VERSION" \
  -f core_version="$CORE_VERSION" \
  -f core_ref="$CORE_REF" \
  -f core_candidate_id="$CORE_CANDIDATE_ID"
```

Success means all four registry versions match the candidate-record
integrities. No-auth `npx` and isolated global installs then start Core, scan,
select only the matching platform package, and uninstall cleanly on Ubuntu
22.04 x64, macOS 15 ARM64, and the managed Windows 11 x64 runner.

Do not run this step until the private macOS, Windows, and Linux acceptance
described above is complete and the operator has authorized npm publication.

## 3. Promote without rebuilding

Trusted Publishing authenticates package publication. Moving `latest` is an
interactive npm operation because it changes only dist-tags and must not
depend on a long-lived automation token. After the publication workflow and
all four registry acceptance jobs succeed, run:

```bash
npm login
for package in \
  @devseccode/scanner-darwin-arm64 \
  @devseccode/scanner-linux-x64 \
  @devseccode/scanner-linux-arm64 \
  @devseccode/scanner-win32-x64 \
  @devseccode/scanner
do
  test "$(npm view "$package@artifact-v2-candidate" version)" = "$NPM_VERSION"
  npm dist-tag add "$package@$NPM_VERSION" latest
done
```

Complete npm's interactive authentication or one-time-password prompt if it
appears. These commands move `latest` for the four platform packages first
and the parent package last. They do not rebuild or republish bytes.

## 4. Confirm and tag

```bash
npm view @devseccode/scanner dist-tags --json
npm view @devseccode/scanner@0.5.0 version
npm view @devseccode/scanner-darwin-arm64@0.5.0 version
npm view @devseccode/scanner-linux-x64@0.5.0 version
npm view @devseccode/scanner-linux-arm64@0.5.0 version
npm view @devseccode/scanner-win32-x64@0.5.0 version
```

After confirmation, `npm-v0.5.0` may be pushed as release metadata. The tag
does not trigger a build or publication workflow.

## Rollback boundary

Before promotion, `latest` still points to `0.4.5`; no rollback is necessary.
After promotion, rollback means moving all four `latest` dist-tags back to the
previous mutually compatible version. Published npm versions cannot be
overwritten and must not be unpublished as a routine rollback mechanism.
