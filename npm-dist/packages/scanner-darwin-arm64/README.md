# @devseccode/scanner-darwin-arm64

> **Do not install this package directly.** Install
> [`@devseccode/scanner`](https://www.npmjs.com/package/@devseccode/scanner)
> instead; npm auto-resolves this platform package for Apple Silicon macOS.

This package carries the packaged DevSecCode public/starter Core backend artifact for
`darwin-arm64`. It is listed as an `optionalDependency` of
`@devseccode/scanner`, so npm installs only the variant that matches your OS
and CPU.

## What's Inside

- `artifacts/devseccode-core-artifacts.json`
- the matching public/starter Core backend archive referenced by that manifest

The parent package owns the public `devseccode` and `dsc` commands, verifies
and extracts this artifact through `@devseccode/core-launcher`, then talks to
Core through authenticated `/v1/*` routes.

## License

Proprietary. See the `LICENSE` file shipped in this tarball.
