# npm distribution -- `@devseccode/scanner`

Release operators start with
[`docs/npm-artifact-v2-release-runbook.md`](../docs/npm-artifact-v2-release-runbook.md).

This directory holds the npm side of the public DevSecCode CLI. Users install
one package (`@devseccode/scanner`), run `devseccode hunt .`, and npm
auto-resolves the right platform-specific public/starter Core artifact from a
sibling `optionalDependencies` entry.

The package is public on npm for frictionless `npx @devseccode/scanner hunt .`.
It remains proprietary under the EULA included in each package.

```
npm-dist/
├── packages/
│   ├── scanner/                    ← @devseccode/scanner (Node CLI/UX)
│   ├── scanner-darwin-arm64/       ← public/starter Core artifact package
│   ├── scanner-linux-x64/
│   ├── scanner-linux-arm64/        ← private scaffold for planned support
│   └── scanner-win32-x64/
└── scripts/
    ├── version.sh              ← echoes parent npm wrapper version
    ├── assemble-platform-pkg.sh← verifies/copies public/starter artifacts
    ├── stamp-parent-version.sh ← stamps parent + optionalDependencies pins
    ├── sign-and-notarize-macos.sh
    ├── publish-all.sh          ← platform packages first, then parent
    ├── test-local-install.sh   ← pre-publish: pack + install + run, all local
    └── test-with-verdaccio.sh  ← pre-publish: full registry simulation
```

## How a Release Flows

1. Build and publish the matching DevSecCode-Core public/starter artifacts and
   `@devseccode/core-launcher`.
2. Assemble each npm platform package from Core's public/starter
   `devseccode-core-artifacts.json`.
3. Pack/test the parent package from `npm-dist/packages/scanner`.
4. Publish a canary/non-`latest` dist-tag first, then run no-auth `npx` and
   global-install smokes before promoting to `latest`.
5. `publish-all.sh` publishes platform packages first, parent last. Order
   matters because the parent depends on the platform packages via
   `optionalDependencies`.

Platform packages are assembled only from a Core `public-starter` manifest
whose detached Ed25519 signature verifies against the vendor key pinned in the
parent package. Generated Core archives are CI inputs and are never committed
to this repository. Because npm payloads and compiled executables are publicly
inspectable, the Core public-starter profile—not compilation—is the IP boundary.

## Intended artifact-v2 contract

NPM's migration target is Core's
[`artifact-v2 downstream product contract`](https://github.com/DevSecCodeInc/DevSecCode-Core/blob/main/docs/distribution/artifact-v2-downstream-contract.md).
The `0.5.0` candidate implementation uses this contract. Production remains on
`0.4.5` until the candidate and three-platform registry acceptance gates pass.

NPM consumes only a signed `devseccode-core-artifacts/v2` `public-starter`
matrix through `@devseccode/core-launcher` and the shared validator. Each
platform optional package contains the exact verified Core archive for its
target. The parent package and all platform packages in one candidate bind the
same Core manifest, source commit, trust bundle, and immutable Core input.

`full-core`, private assets, private rulepacks, compliance seeds, model assets,
and premium scanner logic must never enter an npm tarball. Installation is
package extraction only: there is no postinstall downloader, Core rebuild,
Python environment, OpenGrep installation, compiler, or container-runtime
requirement. NPM owns command parsing, terminal presentation, JavaScript APIs,
profiles, quests, achievements, publishing order, canary validation, and
promotion. Scanner evidence comes from public-starter Core through `/v1`.

## Reproducing the candidate locally

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

## Things to Know

- **No separate Core install.** The parent package depends on
  `@devseccode/core-launcher`; platform optional dependencies carry the
  public/starter Core backend artifact.
- **NPM owns UX.** Command parsing, local output rendering, profile state,
  quests, and the gamified hunt layer live in the parent package.
- **Core owns public starter scanning.** Workspace scans, public rule metadata,
  and SARIF export flow through authenticated `/v1/*` routes. JUnit is a local
  NPM presentation of Core findings. Full
  Core rulepacks, compliance mappings, model assets, and premium scanner logic
  are not shipped in public npm packages.
- **No postinstall.** Install is file extraction only. No download step, shell
  hook, or node-gyp.
- **Alpine / musl Linux is not supported.** Use a glibc image such as Debian
  or Ubuntu in CI.
- **Linux arm64 is planned, not published.** The private package scaffold is
  retained so it can be activated only after Core adds a signed, accepted
  `public-starter` target.

See [`DevSecCode-NPM Core Migration Plan.md`](../docs/DevSecCode-NPM%20Core%20Migration%20Plan.md)
for the migration contract and release gates.
