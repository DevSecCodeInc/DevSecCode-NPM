# @devseccode/scanner-linux-arm64

> **Do not install this package directly.** Install
> [`@devseccode/scanner`](https://www.npmjs.com/package/@devseccode/scanner)
> instead; npm auto-resolves this platform package for ARM64 Linux.

This package carries the packaged DevSecCode public/starter Core backend
artifact for `linux-arm64` glibc environments. It is listed as an
`optionalDependency` of `@devseccode/scanner`, so npm installs only the variant
that matches the user's OS and CPU.

## What's Inside

- `artifacts/devseccode-core-artifacts.json`
- the matching public/starter Core backend archive referenced by that manifest

The parent package verifies and extracts this artifact through
`@devseccode/core-launcher` and talks to Core through authenticated `/v1/*`
routes.

## License

Proprietary. See the `LICENSE` file shipped in this tarball.
