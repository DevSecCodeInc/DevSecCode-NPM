"""Rule schema validation.

Validates a single rule dict (as parsed from YAML) against the Deva
rule format described in scanner-rearchitecture-spec.md Section 4.2.
The schema is lightweight on purpose: full Semgrep syntax validation
is delegated to OpenGrep itself via ``opengrep validate``. This layer
only enforces the Deva-specific extensions (precision tier, post-processor
name, framework_sources references, etc.) that OpenGrep does not know
about.
"""

from __future__ import annotations

import re
from typing import Any

_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]*$")
_VALID_SEVERITIES = {"ERROR", "WARNING", "INFO"}
_VALID_TIERS = {"A", "B", "C"}
_VALID_MODES = {"search", "taint", "extract"}
# Phase 6 follow-up: rules can declare metadata.deva.severity_override
# to lift past OpenGrep's ERROR ceiling. The Severity enum uppercases
# its names; we accept both upper and lower case in the YAML for
# author convenience.
_VALID_SEVERITY_OVERRIDES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class RuleSchemaError(ValueError):
    """Raised when a rule dict fails schema validation."""


def validate_rule_dict(rule: dict[str, Any], *, source: str = "<rule>") -> None:
    """Validate a single rule. Raises RuleSchemaError on first failure."""

    def fail(msg: str) -> None:
        raise RuleSchemaError(f"{source}: {msg}")

    if not isinstance(rule, dict):
        fail("rule must be a mapping")

    rid = rule.get("id")
    if not isinstance(rid, str) or not _RULE_ID_RE.match(rid):
        fail(
            "rule.id must be a kebab/dot-cased string "
            "(letters, digits, '_', '.', '-')"
        )

    languages = rule.get("languages")
    if not isinstance(languages, list) or not languages:
        fail("rule.languages must be a non-empty list")
    for lang in languages:
        if not isinstance(lang, str) or not lang:
            fail("each rule.languages entry must be a non-empty string")

    severity = rule.get("severity")
    if severity not in _VALID_SEVERITIES:
        fail(f"rule.severity must be one of {sorted(_VALID_SEVERITIES)}")

    if not isinstance(rule.get("message"), str) or not rule["message"].strip():
        fail("rule.message must be a non-empty string")

    mode = rule.get("mode", "search")
    if mode not in _VALID_MODES:
        fail(f"rule.mode must be one of {sorted(_VALID_MODES)}")

    metadata = rule.get("metadata") or {}
    if not isinstance(metadata, dict):
        fail("rule.metadata must be a mapping")

    cwe = metadata.get("cwe")
    if cwe is not None and not isinstance(cwe, str):
        fail("rule.metadata.cwe must be a string if present")

    deva = metadata.get("deva") or {}
    if not isinstance(deva, dict):
        fail("rule.metadata.deva must be a mapping")

    tier = deva.get("precision_tier", "B")
    if tier not in _VALID_TIERS:
        fail(f"rule.metadata.deva.precision_tier must be one of {sorted(_VALID_TIERS)}")

    confidence = deva.get("confidence")
    if confidence is not None:
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            fail("rule.metadata.deva.confidence must be a number between 0.0 and 1.0")
        if confidence < 0.0 or confidence > 1.0:
            fail("rule.metadata.deva.confidence must be between 0.0 and 1.0")

    realtime_eligible = deva.get("realtime_eligible")
    if realtime_eligible is not None and not isinstance(realtime_eligible, bool):
        fail("rule.metadata.deva.realtime_eligible must be a boolean")

    pp = deva.get("post_processor")
    if pp is not None:
        if not isinstance(pp, str) or not pp:
            fail("rule.metadata.deva.post_processor must be a non-empty string")
        # registry membership is checked at load time, not in schema

    pp_args = deva.get("post_processor_args")
    if pp_args is not None and not isinstance(pp_args, dict):
        fail("rule.metadata.deva.post_processor_args must be a mapping")

    # Severity override (Phase 6 follow-up). OpenGrep's native severity
    # tops out at ERROR which the loader maps to HIGH. Rules whose
    # impact warrants a hard stop (live production secrets, KEV-class
    # RCE primitives) can opt up to CRITICAL via this override. Down-
    # mapping is also allowed for low-impact ERROR cases.
    severity_override = deva.get("severity_override")
    if severity_override is not None:
        if not isinstance(severity_override, str):
            fail("rule.metadata.deva.severity_override must be a string if present")
        if severity_override.upper() not in _VALID_SEVERITY_OVERRIDES:
            fail(
                "rule.metadata.deva.severity_override must be one of "
                f"{sorted(_VALID_SEVERITY_OVERRIDES)}"
            )

    # AI triage hint (Phase 6 / spec section 5.8). Free-form prose
    # passed to the LLM during the triage pass to give it domain
    # context: "this rule typically fires on test fixtures, look for
    # `Test` in the surrounding class name", or "the false-positive
    # rate spikes on framework-internal code; check for vendored
    # paths". Optional. No length cap is enforced here -- rule-pack
    # CI lints overly verbose hints separately.
    triage_hint = deva.get("triage_hint")
    if triage_hint is not None and not isinstance(triage_hint, str):
        fail("rule.metadata.deva.triage_hint must be a string if present")

    # Compliance metadata (Phase 6). Populates per-framework evidence
    # packages. Keys are framework identifiers (hipaa, pci, soc2,
    # iso27001, fedramp, owasp_asvs, nist_csf), values are the
    # control identifiers covered.
    compliance = deva.get("compliance")
    if compliance is not None:
        if not isinstance(compliance, dict):
            fail("rule.metadata.deva.compliance must be a mapping")
        for framework, controls in compliance.items():
            if not isinstance(framework, str) or not framework:
                fail("rule.metadata.deva.compliance keys must be non-empty strings")
            if not isinstance(controls, list):
                fail(
                    f"rule.metadata.deva.compliance.{framework} "
                    "must be a list of control identifiers"
                )
            for ctrl in controls:
                if not isinstance(ctrl, str) or not ctrl:
                    fail(
                        f"rule.metadata.deva.compliance.{framework} "
                        "entries must be non-empty strings"
                    )

    fs = rule.get("framework_sources")
    if fs is not None:
        if not isinstance(fs, list) or not all(isinstance(x, str) for x in fs):
            fail("rule.framework_sources must be a list of strings")

    ls = rule.get("language_sources")
    if ls is not None:
        if not isinstance(ls, list) or not all(isinstance(x, str) for x in ls):
            fail("rule.language_sources must be a list of strings")

    # Mode-specific checks
    if mode == "search":
        has_pattern = any(
            k in rule
            for k in (
                "pattern",
                "patterns",
                "pattern-either",
                "pattern-regex",
            )
        )
        if not has_pattern:
            fail(
                "search-mode rule must define one of pattern / patterns / "
                "pattern-either / pattern-regex"
            )
    elif mode == "taint":
        if not rule.get("pattern-sources"):
            fail("taint-mode rule must define pattern-sources")
        if not rule.get("pattern-sinks"):
            fail("taint-mode rule must define pattern-sinks")

    # Realtime eligibility cross-check (Section 3.6)
    effective_realtime_eligible = (
        realtime_eligible
        if realtime_eligible is not None
        else tier == "A" and mode == "search" and not pp and not fs and not ls
    )
    if effective_realtime_eligible is True:
        if confidence is not None and confidence < 0.90:
            fail(
                "realtime_eligible: true requires metadata.deva.confidence "
                ">= 0.90 so inline findings survive REALTIME_STRICT gating"
            )
        if mode != "search":
            fail(
                "realtime_eligible: true requires mode: search "
                "(taint mode is too expensive for inline UX)"
            )
        if pp:
            fail(
                "realtime_eligible: true is incompatible with post_processor "
                "(post-processors run in Layer 2, not inline)"
            )
        if fs or ls:
            fail(
                "realtime_eligible: true is incompatible with "
                "framework_sources / language_sources references"
            )
