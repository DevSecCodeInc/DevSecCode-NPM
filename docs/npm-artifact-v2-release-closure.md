# NPM artifact-v2 release closure

- Status: Complete
- Released: 2026-08-23
- Product version: `0.5.0`
- Product source commit: `9c7b36c9105b8d0d767983b515c59e2f90bf6f68`
- Release tag: `npm-v0.5.0`
- Core version: `0.3.6`
- Core profile: `public-starter`
- Core source commit: `fee62b7b18dd943649e12b31d7db7f224ee2db30`
- Core candidate ID: `fee62b7b18dd943649e12b31d7db7f224ee2db30-run-32615829775-attempt-1`
- Core launcher: `@devseccode/core-launcher@0.6.0`

## Released packages

The following public packages were published at version `0.5.0` and promoted
to npm's `latest` dist-tag:

- `@devseccode/scanner`
- `@devseccode/scanner-darwin-arm64`
- `@devseccode/scanner-linux-x64`
- `@devseccode/scanner-linux-arm64`
- `@devseccode/scanner-win32-x64`

The parent package selects the target package through optional dependencies.
Each target package contains the exact signed Core `public-starter` artifact
accepted for that target. Installation does not download or build Core and
does not require Python, OpenGrep, a compiler, or a container runtime.

## Acceptance evidence

- Candidate build and package validation:
  [run 32675379976](https://github.com/DevSecCodeInc/DevSecCode-NPM/actions/runs/32675379976)
- Exact-candidate publication and installed-product acceptance:
  [run 32679720341](https://github.com/DevSecCodeInc/DevSecCode-NPM/actions/runs/32679720341)

The final release passed registry installation and execution acceptance on:

- macOS 15 ARM64
- Ubuntu Linux x64
- Ubuntu Linux ARM64
- Windows 11 x64

An unauthenticated clean-user smoke also passed with
`npx @devseccode/scanner@latest --version`, reporting NPM `0.5.0` and bundled
Core `0.3.6`.

## Public package boundary

Only the deliberately limited `public-starter` Core profile is present in the
public npm packages. The final package-content and behavior gates verified that
private Core payloads, private rulepacks, compliance seeds, model assets, and
premium scanner logic were absent. Compilation is not treated as an IP
boundary.

## Contract version clarification

NPM `0.5.0` uses the artifact-v2 distribution contract: signed immutable Core
artifacts, shared trust and extraction policy, and the official Node launcher.
The bundled Core process currently exposes runtime API `/v1`. Artifact format
versioning and runtime API versioning are independent; the `/v1` label does not
mean the product is using artifact-v1.

## Phase 4 disposition

The NPM artifact-v2 integration, four-target acceptance, publication, and
promotion are complete. Together with EXT `0.2.6`, this satisfies the Phase 4
exit gate. IDE and MCP remain deferred.
