"""Thin scan orchestrator.

Per scanner-rearchitecture-spec.md Section 5.3.1.2: this module
shrinks from 623 lines (with timeout pool, detector-source-fingerprint
cache, per-detector phase markers, threat-intel inline loops) to a
thin orchestrator that:

1. Enumerates source files via ``scanner.parser.parse_directory``
2. Invokes the new engine module (OpenGrep or realtime fast-path)
3. Maps results to ``Finding`` via the result mapper (post-processors inline)
4. Runs the existing quality layer for dedup / suppression / gating
5. Enriches findings with compliance and threat-intel data
6. Returns a ``ScanResult`` matching the legacy public shape

The legacy detector loop, the 2-worker timeout pool, the per-detector
fingerprint cache, and tree-sitter parsing are gone. Public ScanEngine
API is preserved so the CLI, backend, and IDE keep working without
changes.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from dsc._paths import rulepacks_expanded_dir
from dsc.engine import (
    OpenGrepError,
    OpenGrepRunner,
    RealtimeMatcher,
    ResultMapper,
    RulepackLoader,
)
from dsc.engine.rulepack_loader import LoadedRulepack
from dsc.postprocessors.base import PostProcessorRegistry, ScanContext
from dsc.scanner.models import Finding, ScanResult, Severity
from dsc.scanner.parser import (
    DEFAULT_BUNDLED_PATTERNS,
    DEFAULT_IGNORE_DIRS,
    CodeFile,
    find_git_root,
    parse_directory,
)
from dsc.scanner.quality import (
    REALTIME_STRICT,
    apply_quality_layer,
    load_suppressions,
    policy_for_profile,
)
from dsc.scanner.reachability import enrich_reachability
from dsc.version import __version__

logger = logging.getLogger(__name__)

# Cache-format version. Bumped whenever the cache schema or the way
# the new engine drives the cache key changes in a way that requires
# a cold rebuild.
CACHE_VERSION = 3

DEFAULT_RULEPACK = rulepacks_expanded_dir()

# Above this number of files we hand OpenGrep the workspace directory plus
# a fixed exclude list rather than every path as a CLI arg. Keeps us well
# clear of ARG_MAX (1 MB on macOS, 2 MB on Linux) for huge monorepos.
_FILE_LIST_ARG_LIMIT = 4000

# Default cap on OpenGrep parallelism. The IDE flow runs on developer
# laptops, not CI boxes; saturating every core fights the user's editor,
# compiler, and (worse) any local Ollama process. We leave at least 2
# cores of headroom and cap at 8 even on bigger boxes -- OpenGrep's
# returns on parallelism flatten quickly past that.
_OPENGREP_JOBS_HEADROOM = 2
_OPENGREP_JOBS_CAP = 8


def _resolve_opengrep_jobs(*, threads: int = 0) -> int:
    """Pick a sane ``--jobs`` value for OpenGrep.

    Priority:
      1. ``DSC_OPENGREP_JOBS`` env -- explicit override for CI / power
         users. Honored verbatim if positive.
      2. Caller-supplied ``threads`` -- the legacy CLI ``--threads`` arg.
         Honored verbatim if positive (lets power users say "I want
         exactly N").
      3. Auto: ``max(1, cpu_count - _OPENGREP_JOBS_HEADROOM)`` capped at
         ``_OPENGREP_JOBS_CAP``.
    """
    import os as _os

    raw = _os.environ.get("DSC_OPENGREP_JOBS")
    if raw and raw.isdigit():
        v = int(raw)
        if v > 0:
            return v

    if threads and threads > 0:
        return threads

    cpu = _os.cpu_count() or 4
    return max(1, min(cpu - _OPENGREP_JOBS_HEADROOM, _OPENGREP_JOBS_CAP))


def _opengrep_excludes() -> tuple[str, ...]:
    """Fixed exclude set for OpenGrep when scanning a whole directory.

    Mirrors parser.DEFAULT_IGNORE_DIRS and DEFAULT_BUNDLED_PATTERNS so a
    workspace-mode scan doesn't walk node_modules / .venv / build / dist
    / minified bundles. ``parse_directory`` already filters these out of
    the per-file pipeline; this teaches OpenGrep to skip them too on the
    directory-scan path.
    """
    dirs = tuple(f"{d}/" for d in sorted(DEFAULT_IGNORE_DIRS))
    return dirs + tuple(DEFAULT_BUNDLED_PATTERNS)


def _emit_timing_digest(
    timing: dict,
    phase: "callable[[str], None]",
) -> None:
    """Emit OpenGrep --time data as phase markers + a per-rule digest.

    The benchmark harness greps these out of stderr; humans can read them
    inline when DSC_OPENGREP_RECORD_TIMING=1. We summarize aggressively
    instead of dumping the full payload (a 9k-file scan produces thousands
    of per-target rows).
    """
    pt = timing.get("profiling_times") or {}
    cfg_s = float(pt.get("config_time") or 0)
    core_s = float(pt.get("core_time") or 0)
    total_s = float(pt.get("total_time") or 0)
    rules_parse_s = float(timing.get("rules_parse_time") or 0)
    max_mem = timing.get("max_memory_bytes")
    total_bytes = timing.get("total_bytes")

    phase(
        "opengrep-timing "
        f"total_s={total_s:.2f} config_s={cfg_s:.2f} core_s={core_s:.2f} "
        f"rules_parse_s={rules_parse_s:.2f} "
        f"max_mem={max_mem or 0} total_bytes={total_bytes or 0}"
    )

    # Per-rule time aggregation: time.targets[i].match_times is a parallel
    # array to time.rules. Sum match_times across targets to get a per-rule
    # cost, then surface the top N.
    rules = timing.get("rules") or []
    targets = timing.get("targets") or []
    per_rule_total = [0.0] * len(rules)
    for t in targets:
        mts = t.get("match_times") or []
        for i, dt in enumerate(mts):
            if i >= len(per_rule_total):
                break
            try:
                per_rule_total[i] += float(dt)
            except (TypeError, ValueError):
                pass

    ranked = sorted(
        ((per_rule_total[i], rules[i]) for i in range(len(rules))),
        reverse=True,
    )[:10]
    for rank, (dt, rule_id) in enumerate(ranked, start=1):
        phase(f"opengrep-rule-cost rank={rank} time_s={dt:.3f} rule={rule_id}")

    # Top-N slowest targets by run_time.
    target_costs = []
    for t in targets:
        path = t.get("path") or ""
        run_time = float(t.get("run_time") or 0)
        target_costs.append((run_time, path, t.get("num_bytes") or 0))
    target_costs.sort(reverse=True)
    for rank, (dt, path, num_bytes) in enumerate(target_costs[:10], start=1):
        phase(
            f"opengrep-target-cost rank={rank} time_s={dt:.3f} "
            f"bytes={num_bytes} path={path}"
        )


def _rulepack_fingerprint(rulepack: LoadedRulepack) -> str:
    """Stable hash over the loaded rule set.

    Replaces the legacy detector-source fingerprint. Driven by the
    rulepack hash (computed by RulepackLoader over file contents) plus
    the engine cache version so any rule edit invalidates the cache.
    """
    return f"v{CACHE_VERSION}:{rulepack.rulepack_hash}"


class ScanCache:
    """File-level scan-result cache.

    Keyed by the rulepack fingerprint plus per-file SHA. A change in
    any rule, in the OpenGrep version, or in the file content forces
    a cold scan for that file.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_file = cache_dir / "cache.json"
        self._data: dict = {}

    def load(self) -> None:
        if not self.cache_file.exists():
            self._data = {}
            return
        try:
            self._data = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except Exception:
            self._data = {}

    def is_compatible(self, *, rulepack_fingerprint: str) -> bool:
        if not self._data:
            return True
        return (
            self._data.get("cache_version") == CACHE_VERSION
            and self._data.get("scanner_version") == __version__
            and self._data.get("rulepack_fingerprint") == rulepack_fingerprint
        )

    def get(self, file: CodeFile) -> list[Finding] | None:
        entry = (self._data.get("entries") or {}).get(file.path)
        if not entry:
            return None
        if entry.get("sha256") != file.sha256():
            return None
        try:
            return [Finding.from_dict(d) for d in (entry.get("findings") or [])]
        except Exception:
            return None

    def put(self, file: CodeFile, findings: list[Finding]) -> None:
        self._data.setdefault("entries", {})
        self._data["entries"][file.path] = {
            "sha256": file.sha256(),
            "findings": [f.to_dict() for f in findings],
        }

    def save(self, *, rulepack_fingerprint: str) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "cache_version": CACHE_VERSION,
            "scanner_version": __version__,
            "rulepack_fingerprint": rulepack_fingerprint,
            "entries": self._data.get("entries") or {},
        }
        self.cache_file.write_text(
            json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
        )


@dataclass(frozen=True, slots=True)
class _RulepackHandle:
    rulepack: LoadedRulepack
    runner: OpenGrepRunner
    mapper: ResultMapper
    realtime: RealtimeMatcher


class ScanEngine:
    """Thin orchestrator wrapping the new engine module.

    Public API kept compatible with the pre-rearchitecture ScanEngine so
    the CLI, FastAPI backend, and IDE workbench bridge keep working.
    """

    def __init__(
        self,
        *,
        rulepack_dir: Path | None = None,
        known_post_processors: Iterable[str] | None = None,
    ) -> None:
        self.rulepack_dir = Path(rulepack_dir) if rulepack_dir else DEFAULT_RULEPACK
        self.known_post_processors = known_post_processors
        self._suppressions: dict = {}
        self._handle: _RulepackHandle | None = None

    # -- public interface -------------------------------------------------

    def scan_code_file(
        self,
        file: CodeFile,
        *,
        languages: Iterable[str] | None = None,
        enabled_ids: Iterable[str] | None = None,
        disabled_ids: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        realtime: bool = False,
        workspace_root: str | None = None,
        preset_name: str | None = None,
        scan_profile: str = "precision",
        min_confidence: float = 0.0,
        include_suppressed: bool = False,
    ) -> tuple[list[Finding], list[str]]:
        """Scan a single CodeFile through the unified pipeline.

        When *realtime* is True the in-process Layer 1 matcher runs
        (eligible-rule subset only). Otherwise OpenGrep runs against
        the file's path.
        """
        handle = self._ensure_handle()
        errors: list[str] = []
        findings: list[Finding] = []
        path = Path(file.path)

        if realtime:
            # Use the in-memory buffer that the API caller passed in
            # CodeFile.content. The previous implementation re-read
            # from disk here, which silently scanned stale content
            # while the user typed in an unsaved buffer -- the very
            # case realtime is for. CodeFile.content defaults to ""
            # so callers that don't pass buffer text will see an empty
            # scan; the disk-read fallback was masking that gap.
            findings = handle.realtime.scan_file(path, file.content)
        else:
            try:
                grep_result = handle.runner.scan(path, config=self.rulepack_dir)
            except OpenGrepError as exc:
                return [], [f"opengrep failed for {file.path}: {exc}"]
            context = ScanContext(
                workspace_root=str(workspace_root or path.parent),
                scanner_version=__version__,
                rulepack_hash=handle.rulepack.rulepack_hash,
            )
            findings = handle.mapper.map_results(
                list(grep_result.raw_results), context
            )

        findings = self._apply_quality(
            findings,
            workspace_root=workspace_root,
            single_file=True,
            realtime=realtime,
            scan_profile=scan_profile,
            min_confidence=min_confidence,
            include_suppressed=include_suppressed,
        )
        findings = self._enrich_reachability(
            findings,
            workspace_root=workspace_root or str(path.parent),
            file_contents={str(path): file.content} if file.content else None,
        )
        return findings, errors

    def scan(
        self,
        target: Path,
        *,
        diff_only: bool = False,
        extra_ignore_patterns: list[str] | None = None,
        enabled_ids: Iterable[str] | None = None,
        disabled_ids: Iterable[str] | None = None,
        languages: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        threads: int = 4,
        use_cache: bool = True,
        preset_name: str | None = None,
        scan_profile: str = "balanced",
        min_confidence: float = 0.0,
        include_suppressed: bool = False,
        enable_llm_bridge: bool = False,
    ) -> ScanResult:
        """Scan a directory or file. Public surface preserved from legacy."""
        start = time.perf_counter()

        def _phase(msg: str) -> None:
            sys.stderr.write(
                f"[dsc-phase t={time.perf_counter()-start:.1f}s] {msg}\n"
            )
            sys.stderr.flush()

        _phase("scan-begin")
        resolved_target = target.resolve()
        workspace_root = (
            find_git_root(target)
            or (resolved_target if resolved_target.is_dir() else resolved_target.parent)
        )

        errors: list[str] = []
        _phase("parse-begin")
        code_files = parse_directory(
            target,
            diff_only=diff_only,
            extra_ignore_patterns=extra_ignore_patterns,
        )
        _phase(f"parse-end files={len(code_files)}")

        handle = self._ensure_handle()
        rulepack_fp = _rulepack_fingerprint(handle.rulepack)

        cache: ScanCache | None = None
        if use_cache:
            cache = ScanCache(workspace_root / ".dsc_cache")
            cache.load()
            if not cache.is_compatible(rulepack_fingerprint=rulepack_fp):
                cache = ScanCache(workspace_root / ".dsc_cache")

        # Split files into cache-hit and miss buckets. Cache hits short-
        # circuit; misses go through OpenGrep in a single batched run.
        cached_findings: list[Finding] = []
        files_to_scan: list[CodeFile] = []
        if cache is not None:
            for cf in code_files:
                got = cache.get(cf)
                if got is None:
                    files_to_scan.append(cf)
                else:
                    cached_findings.extend(got)
        else:
            files_to_scan = list(code_files)

        _phase(
            f"opengrep-begin scan_files={len(files_to_scan)} "
            f"cached_files={len(code_files) - len(files_to_scan)}"
        )

        scanned_findings: list[Finding] = []
        if files_to_scan:
            try:
                # Prefer passing the explicit file list parse_directory
                # already filtered. OpenGrep then skips its own walk --
                # crucial because we run with --no-git-ignore, which
                # disables OpenGrep's gitignore filtering, so a bare
                # directory scan would re-walk node_modules / .venv /
                # build / dist / vendor and cancel out the work
                # parse_directory just did.
                #
                # For huge workspaces (>_FILE_LIST_ARG_LIMIT files) we
                # fall back to scanning the directory with an explicit
                # --exclude list so the OS argv limit can't truncate
                # the command line.
                scan_targets: Path | list[Path]
                excludes: tuple[str, ...] = ()
                if len(files_to_scan) <= _FILE_LIST_ARG_LIMIT:
                    scan_targets = [Path(cf.path) for cf in files_to_scan]
                else:
                    scan_targets = (
                        target if target.is_dir() else target.parent
                    )
                    excludes = _opengrep_excludes()
                # OpenGrep parallelism. Its default is `cpu_count`,
                # which on a developer laptop means the scan grabs
                # *every* core -- VS Code, the user's compiler, the
                # browser, the LLM-via-Ollama process all fight for
                # what's left. Multiply that by even one stacked scan
                # and the machine starts swapping. We default to
                # ``max(1, cpu_count - 2)`` capped at 8, leaving the
                # user at least 2 cores of headroom regardless of
                # box size. DSC_OPENGREP_JOBS overrides for CI / power
                # users who want a different policy.
                _jobs = _resolve_opengrep_jobs(threads=threads)
                grep_result = handle.runner.scan(
                    scan_targets,
                    config=self.rulepack_dir,
                    excludes=excludes,
                    jobs=_jobs,
                )
                context = ScanContext(
                    workspace_root=str(workspace_root),
                    scanner_version=__version__,
                    rulepack_hash=handle.rulepack.rulepack_hash,
                )
                scanned_findings = handle.mapper.map_results(
                    list(grep_result.raw_results), context
                )
                if grep_result.timing is not None:
                    _emit_timing_digest(grep_result.timing, _phase)
                # Bucket per-file for cache.
                if cache is not None:
                    by_path: dict[str, list[Finding]] = {}
                    for f in scanned_findings:
                        by_path.setdefault(f.file_path, []).append(f)
                    for cf in files_to_scan:
                        cache.put(cf, by_path.get(cf.path, []))
            except OpenGrepError as exc:
                errors.append(f"opengrep failed: {exc}")
                _phase(f"opengrep-error {exc}")

        all_findings = cached_findings + scanned_findings
        _phase(f"scan-end findings={len(all_findings)}")

        all_findings = self._apply_quality(
            all_findings,
            workspace_root=str(workspace_root),
            single_file=False,
            realtime=False,
            scan_profile=scan_profile,
            min_confidence=min_confidence,
            include_suppressed=include_suppressed,
        )
        _phase(f"quality-end findings={len(all_findings)}")

        all_findings = self._enrich_reachability(
            all_findings,
            workspace_root=str(workspace_root),
        )
        _phase("reachability-end")

        active_cwes = sorted(
            {r.cwe for r in handle.rulepack.rules if r.cwe}
        )

        if cache is not None:
            cache.save(rulepack_fingerprint=rulepack_fp)

        duration_ms = int((time.perf_counter() - start) * 1000)
        _phase(
            f"scan-complete duration={duration_ms}ms "
            f"findings={len(all_findings)}"
        )
        return ScanResult(
            findings=all_findings,
            files_scanned=len(code_files),
            scan_duration_ms=duration_ms,
            scanner_version=__version__,
            preset=preset_name,
            errors=errors,
            detector_timings_ms={},
            active_detector_cwes=active_cwes,
        )

    # -- private helpers --------------------------------------------------

    def _ensure_handle(self) -> _RulepackHandle:
        if self._handle is not None:
            return self._handle
        if not self.rulepack_dir.exists():
            raise OpenGrepError(
                f"rulepack directory not found at {self.rulepack_dir}. "
                f"Run scripts/expand_rulepacks.py first."
            )
        # The public scanner doesn't register any postprocessors; callers
        # always pass an explicit list (often empty). The proprietary
        # IDE's engine copy threads its own REGISTRY in here.
        known_post_processors = self.known_post_processors or ()
        post_processor_registry = PostProcessorRegistry()

        loader = RulepackLoader(
            self.rulepack_dir,
            known_post_processors=known_post_processors,
        )
        rulepack = loader.load()
        runner = OpenGrepRunner()
        mapper = ResultMapper(rulepack, post_processors=post_processor_registry)
        realtime = RealtimeMatcher(rulepack)
        self._handle = _RulepackHandle(
            rulepack=rulepack,
            runner=runner,
            mapper=mapper,
            realtime=realtime,
        )
        return self._handle

    def _apply_quality(
        self,
        findings: list[Finding],
        *,
        workspace_root: str | None,
        single_file: bool,
        realtime: bool,
        scan_profile: str,
        min_confidence: float,
        include_suppressed: bool,
    ) -> list[Finding]:
        if not findings:
            return findings
        target_root = workspace_root or str(Path.cwd())
        if not single_file:
            self._suppressions = load_suppressions(Path(target_root))
        policy = (
            REALTIME_STRICT
            if realtime
            else policy_for_profile(
                scan_profile,
                min_confidence=min_confidence,
                include_suppressed=include_suppressed,
            )
        )
        # The new engine populates rule metadata directly on each
        # Finding via result_mapper; quality.py's `detectors` arg is
        # used only as fallback for missing fields. Pass {} so the
        # fallback defaults kick in when needed.
        return apply_quality_layer(
            findings,
            {},
            target_root=target_root,
            policy=policy,
            suppressions=self._suppressions,
        )

    @staticmethod
    def _enrich_reachability(
        findings: list[Finding],
        *,
        workspace_root: str | None,
        file_contents: dict[str, str] | None = None,
    ) -> list[Finding]:
        return enrich_reachability(
            findings,
            workspace_root=workspace_root,
            file_contents=file_contents,
        )


def max_severity(findings: Iterable[Finding]) -> Severity | None:
    max_s: Severity | None = None
    for f in findings:
        if max_s is None or f.severity > max_s:
            max_s = f.severity
    return max_s
