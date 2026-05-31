from __future__ import annotations

from dsc.scanner.models import Finding, ReachabilityLabel, ScanResult, Severity


def _finding(**fields) -> Finding:
    base = {
        "rule_id": "deva.cwe-79.example",
        "cwe": "CWE-79",
        "severity": Severity.HIGH,
        "file_path": "src/app.py",
        "line_start": 3,
        "line_end": 3,
        "column": 1,
        "message": "example",
        "metadata": {"precision_tier": "A", "confidence": 0.95},
    }
    base.update(fields)
    return Finding(**base)


def test_finding_roundtrip_preserves_reachability_fields() -> None:
    finding = _finding(
        reachability=ReachabilityLabel.REACHABLE,
        entry_points=["routes.create_user"],
    )

    roundtrip = Finding.from_dict(finding.to_dict())

    assert roundtrip.reachability == ReachabilityLabel.REACHABLE
    assert roundtrip.entry_points == ["routes.create_user"]


def test_scan_result_includes_metadata_summary_counts() -> None:
    result = ScanResult(
        findings=[
            _finding(metadata={"precision_tier": "A", "confidence": 0.95}),
            _finding(
                rule_id="deva.cwe-89.example",
                cwe="CWE-89",
                severity=Severity.MEDIUM,
                metadata={
                    "precision_tier": "C",
                    "confidence": 0.55,
                    "advisory": True,
                    "suppressed": True,
                },
            ),
        ]
    )

    data = result.to_dict()

    assert data["counts_by_severity"]["HIGH"] == 1
    assert data["counts_by_severity"]["MEDIUM"] == 1
    assert data["counts_by_precision_tier"] == {"A": 1, "C": 1}
    assert data["advisory_count"] == 1
    assert data["suppressed_count"] == 1
