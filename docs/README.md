# Documentation assets

## Planning and releases

- [NPM sprint history](sprints/README.md); current sprints are in the shared DevSecCode workspace sprint set (dsc/docs/sprints/), not in this repository.
- [Public/starter refresh spec](specs/npm-public-starter-refresh.md)
- [Core migration plan](DevSecCode-NPM%20Core%20Migration%20Plan.md)
- [Artifact-v2 release runbook](npm-artifact-v2-release-runbook.md)
- [NPM 0.5.0 release closure](npm-artifact-v2-release-closure.md)

Assets referenced from the top-level README live here.

## Required: `demo.gif`

The top-level README references `docs/demo.gif`. Until that file exists,
the image shows up as broken on the GitHub repo home page. **This is the
single highest-leverage thing to add before promoting the project**, so
priority-fix it before any Show HN / social push.

### What to record

A 15-30 second scan of the bundled sample-vulns directory, starting from
a clean terminal:

```bash
npx @devseccode/scanner hunt resources/sample-vulns/
```

Frame to capture:

1. The boot banner and the gamified intro.
2. The scan map / progress as findings come in.
3. An encounter card for one finding (any of the sample-vulns will trip
   the public rulepack).
4. The summary screen at the end.

### Tooling options

- [**vhs**](https://github.com/charmbracelet/vhs) (recommended) — declarative
  `.tape` files, deterministic output, easy to re-record when the UI
  changes. Output is a `.gif` directly.
- [**asciinema**](https://asciinema.org/) + [**agg**](https://github.com/asciinema/agg)
  — record once interactively, then `agg cast.cast demo.gif`. Slightly
  more cinematic feel.
- [**terminalizer**](https://github.com/faressoft/terminalizer) — older,
  Node-based, still works.

### Size budget

Keep `demo.gif` under ~3 MB so the README loads quickly. Tradeoffs:

- 30 fps → 10-15 fps if file size is too big.
- 1200px wide is enough; the GitHub README column is narrower.
- Drop or shorten the intro animation if needed.

If the GIF is unavoidably large, host it on a CDN or as a GitHub release
asset and inline it via raw.githubusercontent URL rather than committing
a fat binary to git.
