"""Rulepack loader.

Discovers YAML rule files under a rulepack root, validates each rule
against the Deva schema, resolves metadata (CWE, post-processor, tier,
realtime eligibility), and returns a ``LoadedRulepack`` ready for the
OpenGrep runner and result mapper to consume.

The loader does NOT do framework-source expansion. That is the
responsibility of ``scripts/expand_rulepacks.py``, which writes its
output to ``rulepacks/_expanded/``. The loader points at whichever
directory the caller chooses; the production path uses ``_expanded/``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from dsc.scanner.models import Severity

from .schema import RuleSchemaError, validate_rule_dict


class RulepackValidationError(ValueError):
    """Raised when one or more rules in a pack fail validation."""


@dataclass(frozen=True, slots=True)
class LoadedRule:
    id: str
    cwe: str
    languages: tuple[str, ...]
    severity: Severity
    message: str
    mode: str
    precision_tier: str
    confidence: float
    realtime_eligible: bool
    post_processor: str | None
    post_processor_args: dict[str, Any]
    metadata: dict[str, Any]
    source_path: Path


@dataclass(frozen=True, slots=True)
class LoadedRulepack:
    rules: tuple[LoadedRule, ...]
    config_dir: Path
    rulepack_hash: str
    errors: tuple[str, ...] = field(default_factory=tuple)

    def by_id(self) -> dict[str, LoadedRule]:
        return {r.id: r for r in self.rules}

    def realtime_subset(self) -> tuple[LoadedRule, ...]:
        return tuple(r for r in self.rules if r.realtime_eligible)


_SARIF_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_DEFAULT_CONFIDENCE_BY_TIER = {
    "A": 0.90,
    "B": 0.75,
    "C": 0.55,
}


class RulepackLoader:
    """Discovers and validates YAML rule files under a directory tree."""

    def __init__(
        self,
        config_dir: Path,
        *,
        known_post_processors: Iterable[str] | None = None,
        strict: bool = True,
    ) -> None:
        self.config_dir = Path(config_dir)
        self._known_post_processors = (
            set(known_post_processors) if known_post_processors is not None else None
        )
        self._strict = strict

    def load(self) -> LoadedRulepack:
        if not self.config_dir.exists():
            raise FileNotFoundError(f"rulepack dir not found: {self.config_dir}")

        rules: list[LoadedRule] = []
        errors: list[str] = []
        hasher = hashlib.sha256()

        for path in sorted(self.config_dir.rglob("*.yml")):
            if "_expanded" in path.parts and self.config_dir.name != "_expanded":
                # Skip generated output unless we were explicitly pointed at it.
                continue
            try:
                with path.open("rb") as fh:
                    contents = fh.read()
                hasher.update(path.relative_to(self.config_dir).as_posix().encode())
                hasher.update(b"\0")
                hasher.update(contents)
                doc = yaml.safe_load(contents)
            except (yaml.YAMLError, OSError) as exc:
                msg = f"{path}: failed to parse: {exc}"
                if self._strict:
                    errors.append(msg)
                continue

            for rule, _rule_dict in self._extract_rules(doc, path, errors):
                rules.append(rule)

        if errors and self._strict:
            joined = "\n  ".join(errors)
            raise RulepackValidationError(
                f"{len(errors)} rule(s) failed validation:\n  {joined}"
            )

        return LoadedRulepack(
            rules=tuple(rules),
            config_dir=self.config_dir,
            rulepack_hash=hasher.hexdigest(),
            errors=tuple(errors),
        )

    def _extract_rules(
        self,
        doc: Any,
        path: Path,
        errors: list[str],
    ) -> Iterable[tuple[LoadedRule, dict]]:
        if not isinstance(doc, dict):
            return ()
        rules = doc.get("rules")
        if not isinstance(rules, list):
            return ()
        out: list[tuple[LoadedRule, dict]] = []
        for idx, rule_dict in enumerate(rules):
            source = f"{path}#{idx}"
            try:
                validate_rule_dict(rule_dict, source=source)
                out.append((self._build_loaded_rule(rule_dict, path), rule_dict))
            except RuleSchemaError as exc:
                errors.append(str(exc))
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"{source}: unexpected error: {exc}")
        return out

    def _build_loaded_rule(
        self,
        rule_dict: dict[str, Any],
        path: Path,
    ) -> LoadedRule:
        metadata = dict(rule_dict.get("metadata") or {})
        deva = dict(metadata.get("deva") or {})

        post_processor = deva.get("post_processor")
        if post_processor is not None and self._known_post_processors is not None:
            if post_processor not in self._known_post_processors:
                raise RuleSchemaError(
                    f"{path}: rule '{rule_dict['id']}' references "
                    f"unknown post_processor '{post_processor}'. "
                    f"Known: {sorted(self._known_post_processors)}"
                )

        tier = deva.get("precision_tier", "B")
        realtime_default = (
            tier == "A"
            and rule_dict.get("mode", "search") == "search"
            and not post_processor
            and not rule_dict.get("framework_sources")
            and not rule_dict.get("language_sources")
        )
        realtime_eligible = bool(
            deva.get("realtime_eligible", realtime_default)
        )
        confidence_raw = deva.get("confidence")
        if isinstance(confidence_raw, (int, float)) and not isinstance(confidence_raw, bool):
            confidence = float(confidence_raw)
        else:
            confidence = _DEFAULT_CONFIDENCE_BY_TIER.get(tier, 0.75)
            if realtime_eligible:
                confidence = max(confidence, 0.95)
        # The schema validator already enforced the cross-checks for
        # realtime_eligible: true; here we just trust the boolean.

        severity_str = rule_dict.get("severity", "WARNING")
        severity = _SARIF_SEVERITY.get(severity_str, Severity.MEDIUM)
        # OpenGrep's native severity surface tops out at ERROR (which
        # we map to HIGH). For findings that warrant a hard stop --
        # production secrets in source, RCE primitives in clear code,
        # known-exploited CVE references -- rules can opt in to
        # CRITICAL via `metadata.deva.severity_override`. The schema
        # validator restricts the allowed values.
        override = deva.get("severity_override")
        if isinstance(override, str):
            try:
                severity = Severity.from_str(override)
            except ValueError:
                # Schema validator should prevent this; fall through
                # to the SARIF-derived severity if it slips through.
                pass

        return LoadedRule(
            id=rule_dict["id"],
            cwe=str(metadata.get("cwe") or ""),
            languages=tuple(rule_dict.get("languages") or ()),
            severity=severity,
            message=rule_dict.get("message", ""),
            mode=rule_dict.get("mode", "search"),
            precision_tier=tier,
            confidence=confidence,
            realtime_eligible=realtime_eligible,
            post_processor=post_processor,
            post_processor_args=dict(deva.get("post_processor_args") or {}),
            metadata=metadata,
            source_path=path,
        )
