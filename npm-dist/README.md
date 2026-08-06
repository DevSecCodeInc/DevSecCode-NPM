# npm distribution -- `@devseccode/scanner`

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

## Building Locally

```bash
CORE_ARTIFACT_DIR=/path/to/core-release-artifacts
bash npm-dist/scripts/assemble-platform-pkg.sh darwin-arm64 "$CORE_ARTIFACT_DIR"
bash npm-dist/scripts/assemble-platform-pkg.sh linux-x64 "$CORE_ARTIFACT_DIR"
bash npm-dist/scripts/assemble-platform-pkg.sh win32-x64 "$CORE_ARTIFACT_DIR"
DSC_CORE_ARTIFACT_DIR="$CORE_ARTIFACT_DIR" bash npm-dist/scripts/test-local-install.sh
```

## Things to Know

- **No separate Core install.** The parent package depends on
  `@devseccode/core-launcher`; platform optional dependencies carry the
  public/starter Core backend artifact.
- **NPM owns UX.** Command parsing, local output rendering, profile state,
  quests, and the gamified hunt layer live in the parent package.
- **Core owns public starter scanning.** Workspace scans, public rule metadata,
  and SARIF/JUnit exports flow through authenticated `/v1/*` routes. Full
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
