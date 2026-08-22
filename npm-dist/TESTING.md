# Testing the npm distribution

The release commands and gates are at the top-level runbook:
`docs/npm-artifact-v2-release-runbook.md`.

Two distinct "clean install as a new user" tests exist for this repo, one
**before** you publish and one **after**. They answer different questions
and you should run both.

| Phase | Question it answers | Script |
|---|---|---|
| Pre-publish, local tarballs | Does the parent CLI find the platform public/starter Core artifact when both packages are installed side by side? | `test-local-install.sh` |
| Pre-publish, local registry | Does `npm install @devseccode/scanner` (no tarball path) work end-to-end through a real registry? | `test-with-verdaccio.sh` |
| Post-publish, real user | Does it actually work for someone who's never touched this code, with no npm auth? | (manual, see below) |

---

## Pre-publish, fast path: `test-local-install.sh`

The 90% test. Run this every time you touch the Node CLI, public/starter Core artifact
assembly, or package metadata.

```bash
CORE_ARTIFACT_DIR="$(mktemp -d)"
printf 'Accepted hardened Core source commit: '
IFS= read -r CORE_REF
printf 'Accepted hardened Core candidate ID: '
IFS= read -r CORE_CANDIDATE_ID
node npm-dist/scripts/download-public-core-candidate.mjs \
  "$CORE_ARTIFACT_DIR" \
  0.3.6 \
  "$CORE_REF" \
  "$CORE_CANDIDATE_ID"
DSC_CORE_ARTIFACT_DIR="$CORE_ARTIFACT_DIR" \
  bash npm-dist/scripts/test-local-install.sh
```

What happens (in order):

1. Verifies the Core manifest's detached Ed25519 signature against the pinned
   vendor public key, then assembles the host platform package.
2. `npm pack` against the parent and the host-platform package.
3. `npm init -y` in a throwaway temp dir.
4. `npm install <platform.tgz> <parent.tgz>` — install both tarballs
   into that fresh `node_modules`.
5. Runs `node_modules/.bin/devseccode --version` and a scan/hunt against
   `resources/sample-vulns/`.
6. Uses isolated home/state/cache directories and stops the Core process it
   started before removing the temporary install.

Limit: this does **not** exercise registry resolution. Because both tarballs
are present at install time, npm satisfies the platform dependency from the
local `.tgz` rather than the registry. For that, use the Verdaccio test.

## Pre-publish, full path: `test-with-verdaccio.sh`

Spins up a [Verdaccio](https://verdaccio.org/) registry on
`localhost:4873`, publishes everything to it, then installs from it with
no tarball paths — exactly the command a customer will run.

```bash
CORE_ARTIFACT_DIR="$(mktemp -d)"
printf 'Accepted hardened Core source commit: '
IFS= read -r CORE_REF
printf 'Accepted hardened Core candidate ID: '
IFS= read -r CORE_CANDIDATE_ID
node npm-dist/scripts/download-public-core-candidate.mjs \
  "$CORE_ARTIFACT_DIR" \
  0.3.6 \
  "$CORE_REF" \
  "$CORE_CANDIDATE_ID"
DSC_CORE_ARTIFACT_DIR="$CORE_ARTIFACT_DIR" \
  bash npm-dist/scripts/test-with-verdaccio.sh
```

What happens:

1. Assembles the host-platform public/starter Core artifact package if missing.
2. Stamps the parent `package.json` so the `optionalDependencies` pins
   match the version we're about to publish.
3. Boots Verdaccio in the background via `npx verdaccio@5`. First run
   downloads ~30 MB; subsequent runs are instant.
4. Publishes the platform package to Verdaccio first, then the parent
   second — same ordering `publish-all.sh` enforces against real npm.
5. In a fresh temp dir, runs the actual customer-facing command:
   `npm install --registry http://127.0.0.1:4873/ @devseccode/scanner`.
6. Verifies the dep resolved to the correct platform sibling, then runs
   `devseccode --version` and a hunt.

If this passes, you've validated everything except npmjs.com's public
registry path.

Differences from real publish:

- Verdaccio is local, so it does not prove npmjs.com propagation or package
  visibility.
- No macOS Gatekeeper / notarization round trip.

## Post-publish: actual new-user test

After the candidate-publication workflow passes, run the repository helper.
It creates an isolated npm prefix, home, configuration, and DevSecCode state;
removes npm and GitHub credentials from the child environment; exercises both
`npx` and a global installation; verifies the exact platform package; starts
Core; scans; and runs a hunt.

macOS or Linux:

```bash
node npm-dist/scripts/candidate-platform-test.mjs start-registry
node npm-dist/scripts/candidate-platform-test.mjs cleanup
```

Windows PowerShell:

```powershell
node .\npm-dist\scripts\candidate-platform-test.mjs start-registry
node .\npm-dist\scripts\candidate-platform-test.mjs cleanup
```

Success reports `Candidate 0.5.0 passed isolated` followed by exactly one of
`darwin-arm64`, `linux-x64`, or `win32-x64`. The installed scope contains the
parent scanner, Core launcher, and exactly one matching scanner platform
package. The cleanup command verifies npm uninstall behavior before removing
the isolated test directory.

Failure signals that map to common bugs:

| Symptom | Likely cause |
|---|---|
| `npm install` fails with 403 | The package is not public on npm or the registry is pointed at a private mirror. Check npm package visibility and `.npmrc`. |
| `devseccode: command not found` after global install | npm's global executable directory is not on `PATH`; inspect it with `npm prefix -g`. |
| `devseccode --version` says "no Core artifact package for ..." | The customer's platform/arch pair isn't in `optionalDependencies` or its public/starter sub-package wasn't published. |
| `devseccode: cannot be opened because the developer cannot be verified` (macOS) | The Core backend artifact was not signed/notarized before npm assembly. |
| Install size is much larger than one platform artifact | All platform artifacts got installed instead of just one. Check that each platform `package.json` has the correct `os` / `cpu` fields. |

## Cleaning up between runs

```bash
# Generated artifact payloads are ignored and replaced by the assembly script.
git status --short
```

## Continuous integration

The release workflow should run artifact admission checks before publish:
manifest target coverage, checksum/size validation, safe extraction,
Ed25519 signature verification, backend launch, `/health`, authenticated `/v1/meta`, a representative scan,
Core-backed SARIF export, and local JUnit rendering from Core findings. Publish
the exact migrated npm candidate under `artifact-v2-candidate`, then promote
the same bytes only after no-auth `npx` and global-install smokes pass.
