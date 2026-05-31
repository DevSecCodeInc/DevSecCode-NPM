from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from typing import Iterable

from dsc.config import ConfigError, load_config
from dsc.engine.rulepack_loader import LoadedRule, RulepackLoader
from dsc.formatters.json_fmt import format_json
from dsc.formatters.junit import format_junit
from dsc.formatters.sarif import format_sarif
from dsc.formatters.terminal import format_terminal
from dsc.scanner.engine import DEFAULT_RULEPACK, ScanEngine
from dsc.scanner.models import Finding, ScanResult, Severity
from dsc.version import __version__


UPGRADE_MESSAGE = (
    "DevSecCode public CLI is the starter campaign: local security hunts, "
    "focused rules, and CI-friendly reports. DevSecCode IDE unlocks the full "
    "campaign with the complete rule library, compliance mapping, SBOM, audit "
    "evidence, POA&M, git-history analysis, and guided remediation workflows."
)

QUESTS: list[tuple[str, str, str]] = [
    (
        "First Blood",
        "Hardcoded secrets",
        "Find committed credentials before attackers do.",
    ),
    (
        "Injection Hunter",
        "SQLi, XSS, command injection, path traversal",
        "Clear the classic web-app traps.",
    ),
    (
        "Crypto Clean-up",
        "Weak crypto and cleartext transport",
        "Retire risky primitives and unsafe channels.",
    ),
    (
        "Container Guard",
        "Dockerfile and Kubernetes checks",
        "Harden deployment config before it ships.",
    ),
    ("Boss Fight", "SARIF in CI", "Make the build fail on high-severity findings."),
]


def _print_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(col.ljust(widths[i]) for i, col in enumerate(r)) for r in rows) + "\n"


def _write_output(text: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        sys.stdout.flush()


def _resolve_scan_targets(
    path_arg: str | None,
    cfg: dict[str, object],
    cfg_path: Path | None,
) -> list[Path]:
    if path_arg:
        return [Path(path_arg).resolve()]

    scan_cfg = cfg.get("scan")
    paths_cfg = scan_cfg.get("paths") if isinstance(scan_cfg, dict) else None
    if not isinstance(paths_cfg, list):
        return [Path.cwd().resolve()]

    base_dir = cfg_path.parent if cfg_path is not None else Path.cwd().resolve()
    targets: list[Path] = []
    seen: set[str] = set()
    for raw in paths_cfg:
        txt = str(raw).strip()
        if not txt:
            continue
        p = Path(txt)
        resolved = p.resolve() if p.is_absolute() else (base_dir / p).resolve()
        key = str(resolved)
        if key not in seen:
            targets.append(resolved)
            seen.add(key)
    return targets or [Path.cwd().resolve()]


def _parse_severity_overrides(raw: object) -> dict[str, Severity]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("detectors.severity_override must be a mapping of rule->severity.")

    overrides: dict[str, Severity] = {}
    for key, value in raw.items():
        try:
            overrides[str(key).upper()] = Severity.from_str(str(value))
        except ValueError as exc:
            raise ConfigError(f"Invalid severity override for {key!r}: {value!r}") from exc
    return overrides


def _apply_severity_overrides(
    findings: Iterable[Finding],
    overrides: dict[str, Severity],
) -> list[Finding]:
    if not overrides:
        return list(findings)
    adjusted: list[Finding] = []
    for finding in findings:
        override = overrides.get(finding.rule_id.upper()) or overrides.get(finding.cwe.upper())
        adjusted.append(replace(finding, severity=override) if override is not None else finding)
    return adjusted


def _merge_scan_results(results: list[ScanResult]) -> ScanResult:
    if not results:
        return ScanResult(scanner_version=__version__)
    if len(results) == 1:
        return results[0]

    findings: list[Finding] = []
    files_scanned = 0
    scan_duration_ms = 0
    errors: list[str] = []
    detector_timings_ms: dict[str, int] = {}
    active_detector_cwes: set[str] = set()
    for result in results:
        findings.extend(result.findings)
        files_scanned += result.files_scanned
        scan_duration_ms += result.scan_duration_ms
        errors.extend(result.errors)
        active_detector_cwes.update(result.active_detector_cwes)
        for detector_id, elapsed in result.detector_timings_ms.items():
            detector_timings_ms[detector_id] = detector_timings_ms.get(detector_id, 0) + elapsed

    findings.sort(key=lambda f: (-int(f.severity), f.file_path, f.line_start, f.rule_id))
    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        scan_duration_ms=scan_duration_ms,
        scanner_version=__version__,
        errors=errors,
        detector_timings_ms=detector_timings_ms,
        active_detector_cwes=sorted(active_detector_cwes),
    )


def _load_rulepack() -> list[LoadedRule]:
    loader = RulepackLoader(
        _public_rulepack_dir(),
        known_post_processors=(),
        strict=False,
    )
    return list(loader.load().rules)


def _public_rulepack_dir() -> Path:
    # Source-tree runs should use the same curated subset that PyInstaller
    # mounts as runtime rulepacks/ in the npm binary.
    source_subset = Path(__file__).resolve().parents[2] / "public_rulepacks" / "_expanded"
    return source_subset if source_subset.exists() else DEFAULT_RULEPACK


def _pick_extra_files(
    targets: list[Path],
    *,
    findings: list[str],
    cap: int,
) -> list[str]:
    """Pick a manageable set of source files in the targets to render
    as map nodes alongside the findings files.

    Always includes the findings files. Fills the rest up to `cap`
    with other source files in the target tree (excluding the usual
    cruft via walk_target_files). Files that share a directory with
    a findings file are prioritized so the local neighborhood reads
    coherently before unrelated parts of the tree.
    """
    from dsc.gamification.imports import walk_target_files

    findings_set = set(findings)
    all_files = walk_target_files(targets)

    findings_dirs = {str(Path(f).parent) for f in findings_set}

    in_findings_dirs: list[str] = []
    elsewhere: list[str] = []
    for f in all_files:
        if f in findings_set:
            continue
        if str(Path(f).parent) in findings_dirs:
            in_findings_dirs.append(f)
        else:
            elsewhere.append(f)

    picked = list(findings_set)
    for bucket in (in_findings_dirs, elsewhere):
        for f in bucket:
            if len(picked) >= cap:
                break
            picked.append(f)
        if len(picked) >= cap:
            break
    return sorted(picked)


def _run_scan(
    *,
    args: argparse.Namespace,
    on_targets_resolved=None,
) -> tuple[ScanResult, Severity, list[Path]]:
    """Shared scan setup used by both `hunt` and `scan`.

    Returns (merged_result, fail_on_severity, targets). Severity overrides
    are applied to result.findings before return so downstream rendering
    only sees the final severities.

    `on_targets_resolved(targets)` fires after the config has been read
    and the target list is known, but before the scanner does any work.
    Lets `cmd_hunt` print the hunt banner before the engine's phase logs
    so the banner reads as a prelude rather than a postscript.
    """
    config_target = Path(args.path).resolve() if args.path else Path.cwd().resolve()
    if not config_target.exists():
        raise FileNotFoundError(f"Target path does not exist: {config_target}")

    cfg, cfg_path = load_config(config_target)

    fail_on = args.fail_on or cfg.get("fail_on") or "high"
    try:
        fail_sev = Severity.from_str(str(fail_on))
    except ValueError as exc:
        raise ValueError(f"Invalid --fail-on severity: {fail_on} ({exc})") from exc

    cfg_detectors = cfg.get("detectors") or {}
    enabled_cfg = cfg_detectors.get("enabled", "all")
    if isinstance(enabled_cfg, str) and enabled_cfg.lower() == "all":
        enabled_ids = None
    elif isinstance(enabled_cfg, list):
        enabled_ids = [str(x) for x in enabled_cfg]
    elif isinstance(enabled_cfg, str):
        enabled_ids = [enabled_cfg]
    else:
        enabled_ids = None

    disabled_ids = [str(x) for x in (cfg_detectors.get("disabled") or [])]
    languages = [str(x) for x in ((cfg.get("scan") or {}).get("languages") or [])]
    ignore_patterns = [str(x) for x in ((cfg.get("scan") or {}).get("ignore") or [])]
    for raw in getattr(args, "ignore_patterns", None) or []:
        pattern = str(raw).strip()
        if pattern and pattern not in ignore_patterns:
            ignore_patterns.append(pattern)

    severity_overrides = _parse_severity_overrides(cfg_detectors.get("severity_override"))

    engine = ScanEngine(rulepack_dir=_public_rulepack_dir(), known_post_processors=())
    targets = _resolve_scan_targets(args.path, cfg, cfg_path)

    if on_targets_resolved is not None:
        on_targets_resolved(targets)

    results = [
        engine.scan(
            target,
            diff_only=bool(args.diff),
            extra_ignore_patterns=ignore_patterns,
            enabled_ids=enabled_ids,
            disabled_ids=disabled_ids,
            languages=languages,
            threads=int(args.threads),
            use_cache=not bool(args.no_cache),
            scan_profile=args.scan_profile,
            min_confidence=float(args.min_confidence),
            include_suppressed=bool(args.include_suppressed),
        )
        for target in targets
    ]
    result = _merge_scan_results(results)
    result = replace(
        result,
        findings=_apply_severity_overrides(result.findings, severity_overrides),
    )
    return result, fail_sev, targets


def cmd_init(args: argparse.Namespace) -> int:
    from dsc.gamification import screens

    out = Path(args.path).resolve() / ".dsc.yml"
    already_existed = out.exists()
    if already_existed and not args.force:
        screens.show_init_result(
            target_path=str(out),
            already_existed=True,
            force=False,
        )
        return 2

    template = """# DevSecCode public CLI configuration
version: 1

scan:
  paths:
    - "."
  ignore:
    - "tests/"
    - "migrations/"
    - "node_modules/"
  languages:
    - "python"
    - "javascript"
    - "typescript"
    - "go"
    - "java"
    - "ruby"
    - "rust"
    - "php"
    - "csharp"
    - "dockerfile"
    - "yaml"
    - "json"

detectors:
  enabled: all
  disabled: []
  severity_override: {}

fail_on: high
"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(template, encoding="utf-8")
    screens.show_init_result(
        target_path=str(out),
        already_existed=already_existed,
        force=bool(args.force),
    )
    return 0


def cmd_list_rules(_args: argparse.Namespace) -> int:
    rows: list[list[str]] = [["ID", "CWE", "Severity", "Languages", "Tier", "Confidence"]]
    for rule in sorted(_load_rulepack(), key=lambda r: r.id):
        rows.append(
            [
                rule.id,
                rule.cwe,
                rule.severity.name,
                ",".join(rule.languages),
                rule.precision_tier,
                f"{rule.confidence:.2f}",
            ]
        )
    sys.stdout.write(_print_table(rows))
    return 0


def cmd_quests(_args: argparse.Namespace) -> int:
    from dsc.gamification import screens
    screens.show_quests()
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    rule = {r.id: r for r in _load_rulepack()}.get(args.rule_id)
    if rule is None:
        sys.stderr.write(f"Unknown rule id: {args.rule_id}\n")
        return 2
    sys.stdout.write(f"{rule.id} ({rule.cwe})\n")
    sys.stdout.write(f"Default severity: {rule.severity.name}\n")
    sys.stdout.write(f"Precision tier: {rule.precision_tier}\n")
    sys.stdout.write(f"Confidence: {rule.confidence:.2f}\n")
    if rule.languages:
        sys.stdout.write(f"Languages: {', '.join(rule.languages)}\n")
    sys.stdout.write("\n")
    sys.stdout.write(rule.message.strip() + "\n")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    """Gamified scan with exploratory drill-down.

    Flow in a TTY:
        banner → scan → HUNT MAP (interactive tree of findings) → user
        drills into files at will → HUNT REPORT summary card with XP,
        achievements, defense bars.

    Flow in CI / non-TTY (or with --no-explore):
        banner → scan → linear encounter cards → summary card.

    Always uses the terminal renderer — there's no --format flag for hunt
    because the gamified UX is the entire point. Use `scan` for SARIF/JSON/CI.
    """
    # Import lazily so `scan` / `list-rules` don't pay the Rich-init cost
    # when they're piped into other tools.
    from dsc.gamification import banner, encounter, explore, summary
    from dsc.gamification.achievements import evaluate_achievements, get_achievement
    from dsc.gamification.animations import (
        render_achievement_unlock,
        render_boss_encounter,
        render_damage_number,
        render_defeat,
        render_defense_bars_fill,
        render_encounter_intro,
        render_level_up,
        render_loot_drop,
        render_scan_progress,
        render_shield_countup,
        render_streak_fire,
        render_victory,
        render_xp_gain,
    )
    from dsc.gamification.characters import get_character
    from dsc.gamification.profile import DIFFICULTY_FAIL_ON, load_profile, record_hunt, save_profile

    profile = load_profile()
    char = get_character(profile.hunter_class)

    def _before_scan(targets: list[Path]) -> None:
        banner.render_hunt_banner(targets, profile)
        # Animated scan progress (TTY only).
        if explore._is_interactive():
            render_scan_progress(accent_color=char.accent_color)

    try:
        result, fail_sev, targets = _run_scan(
            args=args,
            on_targets_resolved=_before_scan,
        )
    except (FileNotFoundError, ValueError, ConfigError) as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2

    # Override fail_on based on difficulty if not explicitly set.
    if not args.fail_on and profile.difficulty in DIFFICULTY_FAIL_ON:
        fail_sev = DIFFICULTY_FAIL_ON[profile.difficulty]

    # Boss encounter animation for CRITICAL findings (TTY only).
    _is_tty = explore._is_interactive()
    if _is_tty and result.findings:
        from dsc.gamification.encounter import _enemy_name
        from dsc.gamification.categories import classify_finding
        _SEVERITY_PENALTY = {Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}
        _SEV_COLOR = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "blue", Severity.INFO: "dim"}
        for f in result.findings:
            if f.severity == Severity.CRITICAL:
                cat = classify_finding(f)
                enemy = _enemy_name(f, cat)
                render_boss_encounter(enemy, accent_color="bold red")
                break  # Only one boss intro per hunt.

    if _is_tty and result.findings:
        # Animated encounter intros + damage numbers for each finding.
        from dsc.gamification.encounter import _enemy_name
        from dsc.gamification.categories import classify_finding as _classify
        _SEV_PENALTY_MAP = {Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}
        _SEV_CLR = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "blue", Severity.INFO: "dim"}
        for idx, f in enumerate(result.findings, 1):
            cat = _classify(f)
            enemy = _enemy_name(f, cat)
            sev_clr = _SEV_CLR.get(f.severity, "white")
            render_encounter_intro(
                enemy, f.severity.name,
                index=idx, total=len(result.findings),
                severity_color=sev_clr,
            )
            penalty = _SEV_PENALTY_MAP.get(f.severity, 0)
            if penalty > 0:
                render_damage_number(penalty, f.severity.name, accent_color=sev_clr)
        encounter.render_all_encounters(result.findings)
    elif not _is_tty:
        encounter.render_all_encounters(result.findings)

    gate_passed = not any(f.severity >= fail_sev for f in result.findings)
    target_key = str(targets[0]) if targets else None
    record = record_hunt(
        profile,
        result.findings,
        achievements_evaluator=evaluate_achievements,
        target_key=target_key,
    )
    if not bool(getattr(args, "no_profile", False)):
        try:
            save_profile(profile)
        except OSError as exc:
            sys.stderr.write(f"(warning) couldn't persist hunter profile: {exc}\n")

    # ── Pre-summary animations (TTY only) ──
    if _is_tty:
        # Victory / defeat splash.
        if gate_passed:
            render_victory(accent_color=char.accent_color)
        elif result.findings:
            render_defeat()

        # Shield score count-up.
        from dsc.gamification.summary import shield_score as _shield_score
        _score, _letter, _stars = _shield_score(result.findings)
        render_shield_countup(_score, _letter, _stars, accent_color=char.accent_color)

        # Defense bars animated fill.
        from dsc.gamification.categories import ALL_CATEGORIES as _ALL_CATS, classify_finding as _clf
        _sev_pen = {Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}
        _defense_data = []
        for cat in _ALL_CATS:
            cat_findings = [f for f in result.findings if _clf(f).key == cat.key]
            pen = sum(_sev_pen.get(f.severity, 0) for f in cat_findings)
            pct = max(0, 100 - pen)
            if pct >= 95:
                clr = "bright_green"
            elif pct >= 80:
                clr = "green"
            elif pct >= 60:
                clr = "yellow"
            elif pct >= 30:
                clr = "red"
            else:
                clr = "bold red"
            _defense_data.append((cat.label.upper(), pct, clr))
        render_defense_bars_fill(_defense_data, accent_color=char.accent_color)

        # XP gain ticker.
        from dsc.gamification.profile import XP_PER_LEVEL
        render_xp_gain(
            xp_before=record.xp_after - record.xp_delta,
            xp_after=record.xp_after,
            xp_delta=record.xp_delta,
            level_before=record.level_before,
            level_after=record.level_after,
            xp_per_level=XP_PER_LEVEL,
            accent_color=char.accent_color,
        )

        # Streak fire animation (7+ days).
        if record.streak >= 7:
            render_streak_fire(record.streak, accent_color=char.accent_color)

        # Level-up animation.
        if record.level_up:
            render_level_up(
                old_level=record.level_before,
                new_level=record.level_after,
                accent_color=char.accent_color,
            )

        # Achievement unlock animations.
        if record.new_achievements:
            for ach_key in record.new_achievements:
                ach = get_achievement(ach_key)
                if ach:
                    render_achievement_unlock(ach.title, ach.description, ach.glyph)

        # Loot chest animation.
        if record.new_loot:
            from dsc.gamification.profile import get_loot_info
            for loot_key in record.new_loot:
                info = get_loot_info(loot_key)
                if info:
                    render_loot_drop(info[0], info[1], accent_color="bright_cyan")

    summary.render_summary(
        profile=profile,
        record=record,
        findings=result.findings,
        gate_passed=gate_passed,
        duration_ms=result.scan_duration_ms,
        files_scanned=result.files_scanned,
    )

    # Persist the report so View/Save Report can access it later.
    try:
        from dsc.gamification.report_store import build_report, save_report
        stored = build_report(
            findings=list(result.findings),
            targets=targets,
            files_scanned=result.files_scanned,
            duration_ms=result.scan_duration_ms,
            gate_passed=gate_passed,
            xp_earned=record.xp_delta,
            level_after=record.level_after,
            new_achievements=record.new_achievements,
            findings_by_category=record.findings_by_category,
        )
        save_report(stored)
    except OSError:
        pass  # Non-critical — don't break the hunt over report storage.

    return 0 if gate_passed else 1


def cmd_scan(args: argparse.Namespace) -> int:
    """Scriptable scan. No banner, no profile write, no gamification.

    Output formats: terminal, json, sarif, junit. Exit code respects
    --fail-on. This is the surface CI pipelines should call.
    """
    try:
        result, fail_sev, _ = _run_scan(args=args)
    except (FileNotFoundError, ValueError, ConfigError) as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2

    if args.format == "terminal":
        text = format_terminal(result, verbose=bool(args.verbose))
    elif args.format == "json":
        text = format_json(result, json_lines=bool(args.json_lines))
    elif args.format == "sarif":
        text = format_sarif(result)
    elif args.format == "junit":
        text = format_junit(result)
    else:
        sys.stderr.write(f"Unknown format: {args.format}\n")
        return 2

    _write_output(text, args.output)
    return 1 if any(f.severity >= fail_sev for f in result.findings) else 0


def cmd_stats(_args: argparse.Namespace) -> int:
    """Show the hunter's persistent profile + achievements."""
    from dsc.gamification import screens
    from dsc.gamification.profile import load_profile

    profile = load_profile()
    screens.show_stats(profile)
    return 0


def cmd_map(args: argparse.Namespace) -> int:
    """Preview a target's findings as an interactive map (no XP, no profile write).

    Same scan engine and same severity gating as `hunt`, but skips the
    XP / achievement bookkeeping and the post-hunt summary card. Useful
    for poking at a codebase without "committing" to a hunt run.
    """
    from dsc.gamification import banner, explore
    from dsc.gamification.imports import build_graph
    from dsc.gamification.profile import load_profile
    from dsc.gamification.triage import load_triage

    profile = load_profile()

    def _before_scan(targets: list[Path]) -> None:
        banner.render_hunt_banner(targets, profile)

    try:
        result, fail_sev, targets = _run_scan(
            args=args,
            on_targets_resolved=_before_scan,
        )
    except (FileNotFoundError, ValueError, ConfigError) as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2

    if not result.findings:
        from dsc.gamification.deva import ACCENT_COLOR, VOICE
        from rich.console import Console
        from rich.text import Text
        console = Console(file=sys.stderr, highlight=False)
        text = Text()
        text.append("Deva: ", style="dim")
        text.append(VOICE.scan_done_clean, style=f"italic {ACCENT_COLOR}")
        console.print()
        console.print(text)
        return 0

    if explore._is_interactive():
        from dsc.gamification import tui
        files_with_findings = sorted({f.file_path for f in result.findings})
        extra_files = _pick_extra_files(targets, findings=files_with_findings, cap=80)
        all_nodes = sorted(set(files_with_findings) | set(extra_files))
        import_graph = build_graph(all_nodes, target_roots=targets)
        triage = load_triage()
        tui.run_map_session(
            result.findings,
            targets,
            import_graph=import_graph,
            triage=triage,
            extra_files=extra_files,
            hunter_class=profile.hunter_class,
        )
    else:
        explore.render_map(result.findings, targets)

    return 1 if any(f.severity >= fail_sev for f in result.findings) else 0


def cmd_play(_args: argparse.Namespace) -> int:
    """Explicit alias for the interactive play menu."""
    return _run_play_menu()


def cmd_watch(args: argparse.Namespace) -> int:
    """Watch a target for file changes and auto-rescan."""
    from dsc.gamification.profile import load_profile
    from dsc.gamification.watch import run_watch

    profile = load_profile()
    target = args.path or "."

    def _hunt_callback(t: str) -> int:
        ns = argparse.Namespace(
            path=t,
            diff=False,
            fail_on=None,
            threads=4,
            no_cache=True,   # Always fresh scan in watch mode.
            scan_profile="balanced",
            min_confidence=0.0,
            include_suppressed=False,
            ignore_patterns=None,
            no_profile=getattr(args, "no_profile", False),
            no_explore=True,  # Non-interactive in watch mode.
        )
        return cmd_hunt(ns)

    return run_watch(
        target,
        run_hunt_fn=_hunt_callback,
        poll_interval=int(getattr(args, "interval", 3)),
        hunter_class=profile.hunter_class,
    )


def cmd_ide(_args: argparse.Namespace) -> int:
    from dsc.gamification import screens
    screens.show_ide()
    return 0


def _run_play_menu() -> int:
    from dsc.gamification.menu import run_play_menu

    def _hunt_callback(target: str) -> int:
        ns = argparse.Namespace(
            path=target,
            diff=False,
            fail_on=None,
            threads=4,
            no_cache=False,
            scan_profile="balanced",
            min_confidence=0.0,
            include_suppressed=False,
            ignore_patterns=None,
            no_profile=False,
            no_explore=False,
        )
        return cmd_hunt(ns)

    def _init_callback() -> int:
        ns = argparse.Namespace(path=".", force=False)
        return cmd_init(ns)

    def _quests_callback() -> int:
        return cmd_quests(argparse.Namespace())

    def _ide_callback() -> int:
        return cmd_ide(argparse.Namespace())

    def _watch_callback(target: str) -> int:
        ns = argparse.Namespace(path=target, interval=3, no_profile=False)
        return cmd_watch(ns)

    return run_play_menu(
        run_hunt=_hunt_callback,
        run_init=_init_callback,
        show_quests=_quests_callback,
        run_ide=_ide_callback,
        run_watch=_watch_callback,
    )


def add_scan_arguments(parser: argparse.ArgumentParser, *, include_format: bool) -> None:
    parser.add_argument("path", nargs="?", default=None)
    parser.add_argument("--diff", action="store_true", help="Scan only changed files")
    if include_format:
        parser.add_argument(
            "--format",
            default="terminal",
            choices=["terminal", "json", "sarif", "junit"],
            help="Output format",
        )
        parser.add_argument("--output", help="Write output to a file")
    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        help="Exit 1 if any finding is at/above this severity",
    )
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--scan-profile",
        dest="scan_profile",
        default="balanced",
        choices=["precision", "balanced", "coverage", "deep"],
        help="Scan quality profile (default: balanced)",
    )
    parser.add_argument(
        "--min-confidence",
        dest="min_confidence",
        type=float,
        default=0.0,
        help="Minimum confidence threshold (0.0-1.0)",
    )
    parser.add_argument(
        "--include-suppressed",
        dest="include_suppressed",
        action="store_true",
        help="Include suppressed findings in output",
    )
    parser.add_argument(
        "--ignore",
        dest="ignore_patterns",
        action="append",
        default=None,
        metavar="PATTERN",
        help="Additional path pattern to exclude. May be repeated.",
    )
    if include_format:
        parser.add_argument("--verbose", action="store_true")
        parser.add_argument(
            "--json-lines",
            action="store_true",
            help="JSON Lines output (format=json)",
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="devseccode",
        description="Gamified local security CLI for code vulnerability hunts",
        epilog=UPGRADE_MESSAGE,
    )
    p.add_argument("--version", action="version", version=f"devseccode {__version__}")

    sub = p.add_subparsers(dest="command", required=False)

    play = sub.add_parser("play", help="Open the interactive play menu (default)")
    play.set_defaults(func=cmd_play)

    hunt = sub.add_parser("hunt", help="Start a gamified security hunt")
    add_scan_arguments(hunt, include_format=False)
    hunt.add_argument(
        "--no-profile",
        action="store_true",
        help="Skip writing XP/achievements to ~/.devseccode/profile.json",
    )
    hunt.add_argument(
        "--no-explore",
        action="store_true",
        help="Skip the interactive map; render findings linearly (CI-friendly)",
    )
    hunt.set_defaults(func=cmd_hunt)

    map_cmd = sub.add_parser(
        "map",
        help="Scan a target and explore findings on the hunt map (no XP)",
    )
    add_scan_arguments(map_cmd, include_format=False)
    map_cmd.set_defaults(func=cmd_map)

    scan = sub.add_parser("scan", help="Run a scriptable security scan")
    add_scan_arguments(scan, include_format=True)
    scan.set_defaults(func=cmd_scan)

    stats = sub.add_parser("stats", help="Show your hunter profile")
    stats.set_defaults(func=cmd_stats)

    init = sub.add_parser("init", help="Create a .dsc.yml config file")
    init.add_argument("--path", default=".")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    lr = sub.add_parser("list-rules", help="List public rules")
    lr.set_defaults(func=cmd_list_rules)

    quests = sub.add_parser("quests", help="Show the public security quest map")
    quests.set_defaults(func=cmd_quests)

    ex = sub.add_parser("explain", help="Explain a public rule")
    ex.add_argument("rule_id")
    ex.set_defaults(func=cmd_explain)

    watch = sub.add_parser("watch", help="Watch a target and auto-rescan on changes")
    watch.add_argument("path", nargs="?", default=".")
    watch.add_argument(
        "--interval",
        type=int,
        default=3,
        help="Poll interval in seconds (default: 3)",
    )
    watch.add_argument(
        "--no-profile",
        action="store_true",
        help="Skip writing XP/achievements during watch scans",
    )
    watch.set_defaults(func=cmd_watch)

    ide = sub.add_parser("ide", help="Show what DevSecCode IDE adds")
    ide.set_defaults(func=cmd_ide)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # `devseccode` with no subcommand → play menu (Flamebird-style).
        return _run_play_menu()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
