from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:  # pragma: no cover
            raise ValueError(f"Unknown severity: {value!r}") from exc

    def to_str(self) -> str:
        return self.name.lower()


class TriageLabel:
    """Phase 6 AI-triage classification (spec section 5.8).

    The LLM bridge tags each finding with one of these buckets so
    downstream surfaces (HUD, Magic Wand, AI chat, SARIF consumers)
    can tier by confidence. Stored as plain strings rather than an
    Enum so they round-trip cleanly through JSON / SARIF without
    casting.
    """

    DEFINITE = "definite_vulnerability"
    LIKELY = "likely_vulnerability"
    PROBABLY_FP = "probably_false_positive"
    UNTRIAGED = "untriaged"

    ALL = (DEFINITE, LIKELY, PROBABLY_FP, UNTRIAGED)


class ReachabilityLabel:
    """Exploitability reachability classification.

    Defaults to UNKNOWN until a reachability analyzer can prove whether a
    finding is reachable from an entry point. Stored as plain strings so
    findings remain JSON / SARIF friendly.
    """

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"

    ALL = (REACHABLE, UNREACHABLE, UNKNOWN)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    cwe: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    column: int
    message: str
    fix_suggestion: str | None = None
    snippet: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    # Phase 6 fields. Default to UNTRIAGED + 0.0 so deterministic-only
    # scans (no LLM bridge enabled) still produce well-formed Findings.
    triage_label: str = "untriaged"
    triage_confidence: float = 0.0
    triage_reasoning: str | None = None
    reachability: str = "unknown"
    entry_points: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity.name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column": self.column,
            "message": self.message,
            "fix_suggestion": self.fix_suggestion,
            "snippet": self.snippet,
            "metadata": self.metadata,
            "triage_label": self.triage_label,
            "triage_confidence": self.triage_confidence,
            "triage_reasoning": self.triage_reasoning,
            "reachability": self.reachability,
            "entry_points": list(self.entry_points),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            rule_id=str(data["rule_id"]),
            cwe=str(data["cwe"]),
            severity=Severity.from_str(str(data["severity"])),
            file_path=str(data["file_path"]),
            line_start=int(data["line_start"]),
            line_end=int(data["line_end"]),
            column=int(data["column"]),
            message=str(data["message"]),
            fix_suggestion=data.get("fix_suggestion"),
            snippet=data.get("snippet"),
            metadata=dict(data.get("metadata") or {}),
            triage_label=str(data.get("triage_label") or "untriaged"),
            triage_confidence=float(data.get("triage_confidence") or 0.0),
            triage_reasoning=data.get("triage_reasoning"),
            reachability=str(data.get("reachability") or "unknown"),
            entry_points=[str(e) for e in (data.get("entry_points") or [])],
        )


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: int = 0
    scanner_version: str = "0.0.0"
    preset: str | None = None
    errors: list[str] = field(default_factory=list)
    detector_timings_ms: dict[str, int] = field(default_factory=dict)
    active_detector_cwes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "scan_duration_ms": self.scan_duration_ms,
            "scanner_version": self.scanner_version,
            "preset": self.preset,
            "errors": list(self.errors),
            "detector_timings_ms": dict(self.detector_timings_ms),
            "active_detector_cwes": list(self.active_detector_cwes),
            "counts_by_severity": {
                severity.name: count for severity, count in self.counts_by_severity().items()
            },
            "counts_by_precision_tier": self.counts_by_precision_tier(),
            "advisory_count": self.advisory_count(),
            "suppressed_count": self.suppressed_count(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            findings=[Finding.from_dict(f) for f in (data.get("findings") or [])],
            files_scanned=int(data.get("files_scanned") or 0),
            scan_duration_ms=int(data.get("scan_duration_ms") or 0),
            scanner_version=str(data.get("scanner_version") or "0.0.0"),
            preset=data.get("preset"),
            errors=[str(e) for e in (data.get("errors") or [])],
            detector_timings_ms={
                str(k): int(v) for k, v in (data.get("detector_timings_ms") or {}).items()
            },
            active_detector_cwes=[
                str(cwe) for cwe in (data.get("active_detector_cwes") or [])
            ],
        )

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def counts_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def counts_by_precision_tier(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            tier = finding.metadata.get("precision_tier")
            key = str(tier) if tier else "unknown"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    def advisory_count(self) -> int:
        return sum(1 for finding in self.findings if finding.metadata.get("advisory"))

    def suppressed_count(self) -> int:
        return sum(1 for finding in self.findings if finding.metadata.get("suppressed"))


@dataclass(frozen=True, slots=True)
class DetectorMetadata:
    id: str
    name: str
    cwe: str
    description: str
    severity_default: Severity
    tags: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    vulnerable_example: str | None = None
    secure_example: str | None = None
    fix_suggestion: str | None = None
    references: list[str] = field(default_factory=list)
    supports_realtime: bool = True
    family: str = ""
    precision_tier: str = ""
    default_confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "cwe": self.cwe,
            "description": self.description,
            "severity_default": self.severity_default.name,
            "tags": list(self.tags),
            "languages": list(self.languages),
            "vulnerable_example": self.vulnerable_example,
            "secure_example": self.secure_example,
            "fix_suggestion": self.fix_suggestion,
            "references": list(self.references),
            "supports_realtime": self.supports_realtime,
            "family": self.family,
            "precision_tier": self.precision_tier,
            "default_confidence": self.default_confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DetectorMetadata":
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            cwe=str(data["cwe"]),
            description=str(data["description"]),
            severity_default=Severity.from_str(str(data["severity_default"])),
            tags=[str(t) for t in (data.get("tags") or [])],
            languages=[str(lang) for lang in (data.get("languages") or [])],
            vulnerable_example=data.get("vulnerable_example"),
            secure_example=data.get("secure_example"),
            fix_suggestion=data.get("fix_suggestion"),
            references=[str(r) for r in (data.get("references") or [])],
            supports_realtime=bool(data.get("supports_realtime", True)),
            family=str(data.get("family") or ""),
            precision_tier=str(data.get("precision_tier") or ""),
            default_confidence=float(data.get("default_confidence") or 0.0),
        )
