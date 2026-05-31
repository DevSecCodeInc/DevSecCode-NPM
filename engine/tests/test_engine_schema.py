from __future__ import annotations

import pytest

from dsc.engine.schema import RuleSchemaError, validate_rule_dict


def _rule() -> dict:
    return {
        "id": "deva.cwe-79.example",
        "languages": ["python"],
        "severity": "WARNING",
        "message": "example",
        "mode": "search",
        "pattern": "$X.dangerous(...)",
        "metadata": {"cwe": "CWE-79", "deva": {"precision_tier": "B"}},
    }


@pytest.mark.parametrize("confidence", [0.0, 0.55, 0.9, 1.0])
def test_accepts_valid_confidence(confidence: float) -> None:
    rule = _rule()
    rule["metadata"]["deva"]["confidence"] = confidence

    validate_rule_dict(rule)


@pytest.mark.parametrize("confidence", [-0.1, 1.1, "high", True])
def test_rejects_invalid_confidence(confidence: object) -> None:
    rule = _rule()
    rule["metadata"]["deva"]["confidence"] = confidence

    with pytest.raises(RuleSchemaError, match="confidence"):
        validate_rule_dict(rule)


def test_realtime_requires_high_confidence() -> None:
    rule = _rule()
    rule["metadata"]["deva"]["realtime_eligible"] = True
    rule["metadata"]["deva"]["confidence"] = 0.75

    with pytest.raises(RuleSchemaError, match="confidence"):
        validate_rule_dict(rule)


def test_tier_a_default_realtime_requires_high_confidence() -> None:
    rule = _rule()
    rule["metadata"]["deva"]["precision_tier"] = "A"
    rule["metadata"]["deva"]["confidence"] = 0.75

    with pytest.raises(RuleSchemaError, match="confidence"):
        validate_rule_dict(rule)


def test_tier_a_can_lower_confidence_when_realtime_disabled() -> None:
    rule = _rule()
    rule["metadata"]["deva"]["precision_tier"] = "A"
    rule["metadata"]["deva"]["realtime_eligible"] = False
    rule["metadata"]["deva"]["confidence"] = 0.75

    validate_rule_dict(rule)
