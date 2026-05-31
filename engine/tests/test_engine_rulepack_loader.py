from __future__ import annotations

from pathlib import Path

import yaml

from dsc.engine.result_mapper import ResultMapper
from dsc.engine.rulepack_loader import RulepackLoader
from dsc.postprocessors.base import ScanContext
from dsc.scanner.models import Severity


def _write_rule(path: Path, **fields) -> Path:
    base = {
        "id": "deva.cwe-79.example",
        "languages": ["python"],
        "severity": "WARNING",
        "message": "example",
        "mode": "search",
        "pattern": "$X.dangerous(...)",
        "metadata": {"cwe": "CWE-79", "deva": {"precision_tier": "B"}},
    }
    base.update(fields)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"rules": [base]}), encoding="utf-8")
    return path


def test_loads_default_confidence(tmp_path: Path) -> None:
    _write_rule(tmp_path / "cwe" / "rule.yml")

    rule = RulepackLoader(tmp_path).load().rules[0]

    assert rule.id == "deva.cwe-79.example"
    assert rule.cwe == "CWE-79"
    assert rule.languages == ("python",)
    assert rule.severity == Severity.MEDIUM
    assert rule.precision_tier == "B"
    assert rule.confidence == 0.75


def test_loads_explicit_confidence(tmp_path: Path) -> None:
    _write_rule(
        tmp_path / "cwe" / "rule.yml",
        metadata={
            "cwe": "CWE-79",
            "deva": {"precision_tier": "B", "confidence": 0.82},
        },
    )

    rule = RulepackLoader(tmp_path).load().rules[0]

    assert rule.confidence == 0.82


def test_tier_defaults_confidence(tmp_path: Path) -> None:
    _write_rule(
        tmp_path / "cwe" / "tier_a.yml",
        metadata={
            "cwe": "CWE-79",
            "deva": {"precision_tier": "A", "realtime_eligible": False},
        },
    )
    _write_rule(
        tmp_path / "cwe" / "tier_c.yml",
        id="deva.cwe-79.tier-c",
        metadata={"cwe": "CWE-79", "deva": {"precision_tier": "C"}},
    )

    by_id = RulepackLoader(tmp_path).load().by_id()

    assert by_id["deva.cwe-79.example"].confidence == 0.90
    assert by_id["deva.cwe-79.tier-c"].confidence == 0.55


def test_realtime_default_confidence_preserves_inline_gate(tmp_path: Path) -> None:
    _write_rule(
        tmp_path / "cwe" / "realtime_b.yml",
        metadata={
            "cwe": "CWE-79",
            "deva": {"precision_tier": "B", "realtime_eligible": True},
        },
    )

    rule = RulepackLoader(tmp_path).load().rules[0]

    assert rule.confidence == 0.95


def test_maps_rule_confidence_to_finding_metadata(tmp_path: Path) -> None:
    _write_rule(
        tmp_path / "cwe" / "rule.yml",
        metadata={
            "cwe": "CWE-79",
            "deva": {"precision_tier": "B", "confidence": 0.82},
        },
    )
    pack = RulepackLoader(tmp_path).load()
    mapper = ResultMapper(pack)

    findings = mapper.map_results(
        [
            {
                "check_id": "deva.cwe-79.example",
                "path": "src/app.py",
                "start": {"line": 4, "col": 3},
                "end": {"line": 4, "col": 18},
                "extra": {
                    "message": "example",
                    "severity": "WARNING",
                    "lines": "dangerous(user_input)",
                },
            }
        ],
        ScanContext(
            workspace_root=str(tmp_path),
            scanner_version="test",
            rulepack_hash=pack.rulepack_hash,
        ),
    )

    assert findings[0].metadata["precision_tier"] == "B"
    assert findings[0].metadata["confidence"] == 0.82
