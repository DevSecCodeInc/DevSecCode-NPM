from __future__ import annotations

import json
import re
from collections import OrderedDict

from dsc.scanner.models import ScanResult, Severity

_CWE_DIGITS = re.compile(r"\d+")


def _sarif_level(sev: Severity) -> str:
    if sev in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def _cwe_tag(finding) -> str | None:
    for source in (finding.cwe, finding.rule_id):
        m = _CWE_DIGITS.search(str(source or ""))
        if m:
            return f"CWE-{m.group(0)}"
    return None


def _finding_properties(f) -> dict:
    props: dict = {"cwe": f.cwe, "severity": f.severity.name}
    if f.metadata:
        for key in (
            "precision_tier",
            "confidence",
            "realtime_eligible",
            "advisory",
            "suppressed",
        ):
            if key in f.metadata:
                props[key] = f.metadata[key]
    if getattr(f, "reachability", "unknown") != "unknown":
        props["reachability"] = f.reachability
    if getattr(f, "entry_points", None):
        props["entry_points"] = list(f.entry_points)
    compliance_controls = f.metadata.get("compliance_controls") if f.metadata else None
    if compliance_controls:
        props["compliance_controls"] = compliance_controls
    # Phase 6: surface AI-triage classification on each result so SARIF
    # consumers (GitHub code-scanning, third-party SARIF viewers, the
    # Deva HUD) can tier findings by confidence without parsing
    # rule-specific metadata.
    if f.triage_label and f.triage_label != "untriaged":
        props["triage_label"] = f.triage_label
        props["triage_confidence"] = f.triage_confidence
        if f.triage_reasoning:
            props["triage_reasoning"] = f.triage_reasoning
    # Surface the per-rule compliance map so downstream graders can
    # group findings by framework / control without re-loading the
    # rulepack.
    deva_compliance = f.metadata.get("deva_compliance") if f.metadata else None
    if deva_compliance:
        props["deva_compliance"] = deva_compliance
    return props


def format_sarif(result: ScanResult) -> str:
    rules_map: dict[str, dict] = OrderedDict()
    for f in result.findings:
        if f.rule_id not in rules_map:
            tags = ["security"]
            cwe_tag = _cwe_tag(f)
            if cwe_tag:
                tags.insert(0, cwe_tag)
            short_description = f.message.splitlines()[0] if f.message else f.rule_id
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": short_description},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
                "properties": {
                    "cwe": f.cwe,
                    "severity": f.severity.name,
                    "tags": tags,
                },
            }

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Deva Scanner",
                        "informationUri": "https://github.com/devseccode/DevSecCode-IDE",
                        "version": result.scanner_version,
                        "rules": list(rules_map.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": _sarif_level(f.severity),
                        "message": {"text": f.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file_path},
                                    "region": {
                                        "startLine": max(f.line_start, 1),
                                        "startColumn": max(f.column, 1),
                                        "endLine": max(f.line_end, f.line_start, 1),
                                    },
                                }
                            }
                        ],
                        "properties": _finding_properties(f),
                    }
                    for f in result.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"
