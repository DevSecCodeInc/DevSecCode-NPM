from __future__ import annotations

from pathlib import Path

from dsc.scanner.models import Finding, ReachabilityLabel, Severity
from dsc.scanner.reachability import enrich_reachability


def _finding(path: Path, line: int, **fields) -> Finding:
    base = {
        "rule_id": "deva.cwe-78.example",
        "cwe": "CWE-78",
        "severity": Severity.HIGH,
        "file_path": str(path),
        "line_start": line,
        "line_end": line,
        "column": 1,
        "message": "example",
        "metadata": {"precision_tier": "A", "confidence": 0.95},
    }
    base.update(fields)
    return Finding(**base)


def test_marks_python_route_finding_reachable(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                "@router.post('/users')",
                "def create_user(user):",
                "    dangerous(user.name)",
            ]
        ),
        encoding="utf-8",
    )

    result = enrich_reachability([_finding(app, 6)], workspace_root=tmp_path)

    assert result[0].reachability == ReachabilityLabel.REACHABLE
    assert result[0].entry_points == ["app.py:create_user via @router.post('/users')"]
    assert result[0].metadata["reachability_method"] == "local_entrypoint_heuristic"


def test_marks_express_route_finding_reachable(tmp_path: Path) -> None:
    app = tmp_path / "server.ts"
    app.write_text(
        "\n".join(
            [
                "import express from 'express';",
                "const app = express();",
                "app.post('/run', (req, res) => {",
                "  dangerous(req.body.command);",
                "});",
            ]
        ),
        encoding="utf-8",
    )

    result = enrich_reachability([_finding(app, 4)], workspace_root=tmp_path)

    assert result[0].reachability == ReachabilityLabel.REACHABLE
    assert result[0].entry_points == ["server.ts:POST route /run"]


def test_leaves_non_route_finding_unknown(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    helper.write_text("def helper(value):\n    dangerous(value)\n", encoding="utf-8")

    result = enrich_reachability([_finding(helper, 2)], workspace_root=tmp_path)

    assert result[0].reachability == ReachabilityLabel.UNKNOWN
    assert result[0].entry_points == []
    assert "reachability_method" not in result[0].metadata


def test_preserves_existing_reachability(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("dangerous(value)\n", encoding="utf-8")
    finding = _finding(
        app,
        1,
        reachability=ReachabilityLabel.UNREACHABLE,
        entry_points=["external analyzer"],
    )

    result = enrich_reachability([finding], workspace_root=tmp_path)

    assert result[0].reachability == ReachabilityLabel.UNREACHABLE
    assert result[0].entry_points == ["external analyzer"]
