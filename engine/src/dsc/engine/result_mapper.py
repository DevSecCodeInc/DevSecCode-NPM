"""SARIF/JSON match -> Finding mapping with inline post-processor stage.

This is the single point where OpenGrep matches become Findings. If a
rule declares a post-processor, the mapper invokes it inline with the
match; the processor returns 0..N Findings. Whether or not a rule has
a post-processor is invisible downstream.
"""

from __future__ import annotations

from typing import Any

from dsc.postprocessors.base import PostProcessorRegistry, SarifMatch, ScanContext
from dsc.scanner.models import Finding

from .rulepack_loader import LoadedRule, LoadedRulepack


class ResultMapper:
    """Maps OpenGrep match dicts to Finding objects."""

    def __init__(
        self,
        rulepack: LoadedRulepack,
        *,
        post_processors: PostProcessorRegistry | None = None,
    ) -> None:
        self._by_id = rulepack.by_id()
        if post_processors is None:
            post_processors = PostProcessorRegistry()
        self._registry = post_processors

    def map_results(
        self,
        raw_results: list[dict[str, Any]],
        context: ScanContext,
    ) -> list[Finding]:
        out: list[Finding] = []
        for raw in raw_results:
            for finding in self.map_one(raw, context):
                out.append(finding)
        return out

    def map_one(
        self,
        raw: dict[str, Any],
        context: ScanContext,
    ) -> list[Finding]:
        check_id = str(raw.get("check_id") or "")
        rule = self._resolve_rule(check_id)
        match = self._build_sarif_match(raw, rule)

        if rule and rule.post_processor:
            try:
                processor = self._registry.get(rule.post_processor)
            except KeyError:
                # Rulepack loader should reject this; defensive only.
                return []
            return list(
                processor.process(
                    match,
                    rule_metadata=rule.metadata,
                    args=rule.post_processor_args,
                    context=context,
                )
            )

        return [self._direct_finding(match, rule)]

    def _resolve_rule(self, check_id: str) -> LoadedRule | None:
        if check_id in self._by_id:
            return self._by_id[check_id]
        # OpenGrep can prefix the rule id with the config file path
        # (e.g. "rulepacks.cwe.deva.cwe-79.servlet"); peel until we
        # find a known id.
        if "." in check_id:
            tail = check_id
            while "." in tail:
                tail = tail.split(".", 1)[1]
                if tail in self._by_id:
                    return self._by_id[tail]
        return None

    def _build_sarif_match(
        self,
        raw: dict[str, Any],
        rule: LoadedRule | None,
    ) -> SarifMatch:
        start = raw.get("start") or {}
        end = raw.get("end") or {}
        extra = raw.get("extra") or {}
        metavars: dict[str, str] = {}
        for k, v in (extra.get("metavars") or {}).items():
            if isinstance(v, dict) and "abstract_content" in v:
                metavars[k] = v["abstract_content"]

        return SarifMatch(
            rule_id=rule.id if rule else str(raw.get("check_id") or ""),
            file_path=str(raw.get("path") or ""),
            line_start=int(start.get("line") or 0),
            line_end=int(end.get("line") or 0),
            column=int(start.get("col") or 0),
            message=str(extra.get("message") or (rule.message if rule else "")),
            severity=str(extra.get("severity") or "WARNING"),
            metavars=metavars,
            raw_lines=str(extra.get("lines") or ""),
        )

    def _direct_finding(
        self,
        match: SarifMatch,
        rule: LoadedRule | None,
    ) -> Finding:
        if rule is None:
            from dsc.scanner.models import Severity
            return Finding(
                rule_id=match.rule_id,
                cwe="",
                severity=Severity.MEDIUM,
                file_path=match.file_path,
                line_start=match.line_start,
                line_end=match.line_end,
                column=match.column,
                message=match.message,
                snippet=match.raw_lines or None,
                metadata={"unresolved_rule": True},
            )
        return Finding(
            rule_id=rule.id,
            cwe=rule.cwe,
            severity=rule.severity,
            file_path=match.file_path,
            line_start=match.line_start,
            line_end=match.line_end,
            column=match.column,
            message=match.message or rule.message,
            snippet=match.raw_lines or None,
            metadata={
                "precision_tier": rule.precision_tier,
                "confidence": rule.confidence,
                "realtime_eligible": rule.realtime_eligible,
                **({"deva_compliance": rule.metadata.get("deva", {}).get("compliance")}
                   if rule.metadata.get("deva", {}).get("compliance") else {}),
                **({"triage_hint": rule.metadata.get("deva", {}).get("triage_hint")}
                   if rule.metadata.get("deva", {}).get("triage_hint") else {}),
            },
        )
