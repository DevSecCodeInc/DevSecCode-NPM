# Prototypes

Throwaway, **non-wired** experiments. Nothing here ships or is imported by the
engine or the npm package — it exists to look at and react to.

## `hunt-arena-3d.html`

A clickable prototype of an **optional 3D "Hunt Arena"** — the gamified `dsc hunt`
experience rendered in the browser with Three.js instead of the terminal TUI.

Open it directly:

```bash
open prototypes/hunt-arena-3d.html      # macOS
```

### The game: find the vulnerabilities yourself
The vulnerabilities are **not shown**. You navigate a codebase of files (the 3D
map), open each file to read its **real source code**, and click the lines you
believe are vulnerable. When ready you **run the scanner** — which holds the
engine's ground-truth findings — and it grades you:

- **caught** — you flagged a line the scanner also flags (a real vuln)
- **missed** — a real vuln you never flagged (it escapes as its monster)
- **false alarm** — you flagged a clean line

Score = found / total, false alarms, accuracy %, and an S–D grade. Two of the
eight files are clean, so flagging everything tanks your accuracy. "Review files"
after scoring shows the answer key inline; switch hunters with the dropdown.

### Faithful to the engine
Pulled from `engine/src/dsc/gamification/`:

- Monsters + CWE mapping — `encounter.py` (`_CWE_TO_ENEMY`, `_CATEGORY_FALLBACK`)
- HP bars + severity tags (FATAL/GRAVE/…) — `encounter.py` (`_SEVERITY_HP_BARS`)
- 5 defense families + glyphs (`* + # @ ~`) — `categories.py`
- The scanner's answer key = real `Finding` records (`file_path` + `line_start`) — `scanner/models.py`
- XP `25/15/8/3/1` by severity, level = xp // 100, First Blood + Veteran — `profile.py`, `achievements.py`
- Deva orb + voice, hunter roster — `deva.py`, `characters.py`

### Mocked (prototype only)
- Sample findings, not a real scan
- Procedural primitive monsters, not bespoke art
- Three.js + Tabler icons load from CDN — a shipped build must **vendor** these
  to keep the offline / "source never leaves the machine" guarantee
- Difficulty modes and daily-streak XP are not surfaced; XP shown is the
  per-finding severity value only (the real `record_hunt` also adds per-hunt /
  new-rule / first-hunt bonuses)
- The eight files and their source are sample data. In a real build the file map
  comes from the scan target (laid out via the `ImportGraph`), the code shown is
  the user's actual source, and the answer key is the engine's real findings
  (`file_path` + `line_start`) — already what `ScanResult.to_json()` emits

### Path to a real `dsc hunt --3d`
Because triage must persist (write `triage.json` + award XP in `profile.json`),
the shipping version needs an ephemeral **loopback server**, not a static file:

```
dsc hunt . --3d
  → same scan engine → ScanResult
  → serialize findings + profile + bestiary  (reuse to_json() + the maps above)
  → start 127.0.0.1:PORT  (loopback only, no egress)
  → webbrowser.open()  → the 3D arena
       POST /triage  → TriageStore.set_status + profile.record_hunt
       GET  /        → vendored Three.js bundle + injected scan data
```
