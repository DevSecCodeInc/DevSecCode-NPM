# @devseccode/scanner-linux-arm64 (planned)

> **Private scaffold. Do not publish or install this package.**

This directory is reserved for a future signed DevSecCode public/starter Core
artifact for `linux-arm64` glibc environments. It is not an
`optionalDependency`, is not published, and is not part of the supported
matrix. It may be activated only after Core promotes and clean-host validates
the target.

## Future contents

- `artifacts/devseccode-core-artifacts.json`
- the matching public/starter Core backend archive referenced by that manifest

When the target is approved, the parent package will verify and extract the
artifact through `@devseccode/core-launcher` and talk to Core through
authenticated `/v1/*` routes.

## License

Proprietary. See the `LICENSE` file shipped in this tarball.
