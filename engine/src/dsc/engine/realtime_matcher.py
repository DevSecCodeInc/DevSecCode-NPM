"""In-process realtime matcher (Layer 1 of the layered UX).

Per scanner-rearchitecture-spec.md Section 3.6: a small fast-path
matcher that runs the realtime-eligible subset of rules against a
single file's content in microseconds-to-milliseconds. No subprocess.

Only ``mode: search`` rules with no post-processor and no
framework/language source references are eligible (the rulepack loader
enforces this). The matcher implements a subset of OpenGrep pattern
semantics sufficient for the eligible cases:

- ``pattern: <literal>`` — substring match on the source content
- ``pattern: <regex>`` — full Python re.search match (when
  ``metadata.deva.realtime_pattern_kind: regex`` is set)
- ``pattern-either: [list]`` — any of the listed patterns matches

This is intentionally narrower than OpenGrep itself. Rules that need
real AST matching are not realtime-eligible; they fire on save (Layer 2)
when full OpenGrep runs.

If `metadata.deva.realtime_token_gates` is set, the matcher requires
each token to appear in the source content before running any pattern
checks. This is the cheap pre-filter that keeps irrelevant files at
microsecond cost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from dsc.scanner.models import Finding

from .rulepack_loader import LoadedRule, LoadedRulepack


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    rule: LoadedRule
    token_gates: tuple[str, ...]
    patterns: tuple[re.Pattern[str] | str, ...]
    pattern_kind: str  # "literal" or "regex"


class RealtimeMatcher:
    """Layer-1 in-process matcher for the realtime-eligible rule subset."""

    def __init__(self, rulepack: LoadedRulepack) -> None:
        self._compiled: tuple[_CompiledRule, ...] = tuple(
            self._compile(r)
            for r in rulepack.realtime_subset()
            if self._has_compilable_pattern(r)
        )

    @staticmethod
    def _has_compilable_pattern(rule: LoadedRule) -> bool:
        # The schema validator already enforces pattern presence for
        # search-mode rules; here we just confirm the pattern is in a
        # form the matcher can consume.
        deva = rule.metadata.get("deva", {}) or {}
        kind = deva.get("realtime_pattern_kind", "literal")
        return kind in {"literal", "regex"}

    @staticmethod
    def _compile(rule: LoadedRule) -> _CompiledRule:
        deva = rule.metadata.get("deva", {}) or {}
        kind = str(deva.get("realtime_pattern_kind", "literal"))
        token_gates = tuple(deva.get("realtime_token_gates", []) or ())
        patterns = tuple(_extract_patterns(rule, kind))
        return _CompiledRule(
            rule=rule,
            token_gates=token_gates,
            patterns=patterns,
            pattern_kind=kind,
        )

    def scan_file(self, path: Path, content: str) -> list[Finding]:
        out: list[Finding] = []
        for compiled in self._compiled:
            if compiled.token_gates and not all(
                g in content for g in compiled.token_gates
            ):
                continue
            if compiled.rule.languages and not _language_match(
                path, compiled.rule.languages
            ):
                continue
            for hit in self._find_hits(content, compiled):
                out.append(_make_finding(path, content, hit, compiled.rule))
        return out

    def _find_hits(
        self, content: str, compiled: _CompiledRule
    ) -> list[tuple[int, int]]:
        hits: list[tuple[int, int]] = []
        if compiled.pattern_kind == "literal":
            for pat in compiled.patterns:
                start = 0
                needle = str(pat)
                while True:
                    idx = content.find(needle, start)
                    if idx < 0:
                        break
                    hits.append((idx, idx + len(needle)))
                    start = idx + max(len(needle), 1)
        else:  # regex
            for pat in compiled.patterns:
                if not isinstance(pat, re.Pattern):
                    continue
                for m in pat.finditer(content):
                    hits.append((m.start(), m.end()))
        return hits


_LANG_EXT = {
    "python": (".py",),
    "javascript": (".js", ".cjs", ".mjs", ".jsx"),
    "typescript": (".ts", ".tsx"),
    "java": (".java",),
    "go": (".go",),
    "ruby": (".rb",),
    "php": (".php",),
    "json": (".json",),
    "yaml": (".yml", ".yaml"),
    "rust": (".rs",),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".hpp", ".cc", ".cxx"),
    "csharp": (".cs",),
    "kotlin": (".kt", ".kts"),
    "swift": (".swift",),
    "scala": (".scala",),
    "generic": (),
}


def _language_match(path: Path, languages: tuple[str, ...]) -> bool:
    suffix = path.suffix.lower()
    for lang in languages:
        if lang == "generic":
            return True
        for ext in _LANG_EXT.get(lang, ()):
            if suffix == ext:
                return True
    return False


def _extract_patterns(
    rule: LoadedRule, kind: str
) -> list[re.Pattern[str] | str]:
    raw_meta = rule.metadata.get("deva", {}) or {}
    inline = raw_meta.get("realtime_patterns")
    if inline:
        if kind == "regex":
            return [re.compile(p, re.MULTILINE) for p in inline]
        return [str(p) for p in inline]
    return []


def _make_finding(
    path: Path,
    content: str,
    hit: tuple[int, int],
    rule: LoadedRule,
) -> Finding:
    start_off, end_off = hit
    line_start = content.count("\n", 0, start_off) + 1
    line_end = content.count("\n", 0, end_off) + 1
    last_nl = content.rfind("\n", 0, start_off)
    column = (start_off - last_nl) if last_nl >= 0 else (start_off + 1)
    snippet_line_start = max(0, content.rfind("\n", 0, start_off) + 1)
    snippet_line_end = content.find("\n", end_off)
    if snippet_line_end < 0:
        snippet_line_end = len(content)
    snippet = content[snippet_line_start:snippet_line_end]
    return Finding(
        rule_id=rule.id,
        cwe=rule.cwe,
        severity=rule.severity,
        file_path=str(path),
        line_start=line_start,
        line_end=line_end,
        column=column,
        message=rule.message,
        snippet=snippet,
        metadata={
            "precision_tier": rule.precision_tier,
            "realtime_eligible": True,
            "engine": "realtime",
            "confidence": rule.confidence,
            "family": "realtime",
        },
    )
