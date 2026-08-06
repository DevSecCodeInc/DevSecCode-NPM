# Testing the npm distribution

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
DSC_CORE_ARTIFACT_DIR=/path/to/core-public-starter-artifacts \
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
DSC_CORE_ARTIFACT_DIR=/path/to/core-public-starter-artifacts \
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

After `git push origin npm-vX.Y.Z` succeeds and the release workflow shows
green, do this on a machine where you have **never** authenticated to npm --
ideally a fresh VM, a clean Docker container, or at minimum a different user
account on your laptop. The public package should install without login.

```bash
# In a brand new directory, with no ~/.npmrc:
mkdir /tmp/dsc-realworld && cd /tmp/dsc-realworld

# 1. Try npx -- the canonical first-time invocation.
npx --yes @devseccode/scanner@core-migration-canary --version
npx --yes @devseccode/scanner@core-migration-canary scan . --format terminal

# 2. And the global install path.
npm install -g @devseccode/scanner@core-migration-canary
devseccode --version
devseccode hunt /path/to/a/real/project
devseccode scan /path/to/a/real/project --format terminal

# 3. (macOS only) Verify the packaged Core backend is signed by the right entity.
CORE_BACKEND="$(find "$(npm root -g)/@devseccode/scanner-darwin-arm64" -path '*/dsc-backend' -type f | head -n1)"
codesign -dvvv "$CORE_BACKEND" 2>&1 | grep -E 'Authority|TeamIdentifier'
# Expect:
#   Authority=Developer ID Application: Summit Wanderlust, LLC (S4X2KJ3UYL)
#   Authority=Developer ID Certification Authority
#   Authority=Apple Root CA
#   TeamIdentifier=S4X2KJ3UYL
#
# Notarization is recorded for the Core backend artifact before npm assembly.

# 4. Check install size on disk.
du -sh "$(npm root -g)/@devseccode/"
# Expect: one parent package plus one platform artifact package.

# 6. Confirm only the right platform package was installed.
ls "$(npm root -g)/@devseccode/"
# Expect: scanner, scanner-<your-platform>  (and nothing else)
```

Failure signals that map to common bugs:

| Symptom | Likely cause |
|---|---|
| `npm install` fails with 403 | The package is not public on npm or the registry is pointed at a private mirror. Check npm package visibility and `.npmrc`. |
| `devseccode: command not found` after global install | npm `bin` directory not on `PATH`. Run `npm prefix -g` and add `<that>/bin` to `PATH`. |
| `devseccode --version` says "no Core artifact package for ..." | The customer's platform/arch pair isn't in `optionalDependencies` or its public/starter sub-package wasn't published. |
| `devseccode: cannot be opened because the developer cannot be verified` (macOS) | The Core backend artifact was not signed/notarized before npm assembly. |
| Install size is much larger than one platform artifact | All platform artifacts got installed instead of just one. Check that each platform `package.json` has the correct `os` / `cpu` fields. |

## Cleaning up between runs

```bash
# Delete assembled artifacts for one platform so the next test reassembles:
rm -rf npm-dist/packages/scanner-darwin-arm64/artifacts/*      # adjust target
```

## Continuous integration

The release workflow should run artifact admission checks before publish:
manifest target coverage, checksum/size validation, safe extraction,
Ed25519 signature verification, backend launch, `/health`, authenticated `/v1/meta`, a representative scan,
and SARIF/JUnit export. Publish the migrated npm release under a canary
dist-tag first, then promote only after no-auth `npx` and global-install
smokes pass.
