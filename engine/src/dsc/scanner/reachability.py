"""Conservative reachability enrichment for scanner findings.

This module does not try to prove whole-program data flow. It annotates
findings as reachable only when there is local, same-file entry-point
evidence around the vulnerable line. Unknown remains the default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from dsc.scanner.models import Finding, ReachabilityLabel


_PY_SCOPE_RE = re.compile(
    r"^(?P<indent>\s*)(?:(?:async\s+)?def|class)\s+(?P<name>[A-Za-z_][\w]*)"
)
_PY_ROUTE_DECORATOR_RE = re.compile(
    r"^\s*@(?:(?:[\w_]+\.)+)?(?:route|get|post|put|patch|delete|api_view)\b",
    re.IGNORECASE,
)
_PY_DJANGO_URL_RE = re.compile(r"\b(?:path|re_path|url)\s*\(")

_JS_ROUTE_RE = re.compile(
    r"\b(?:app|router|server)\.(?:get|post|put|patch|delete|all|use)\s*\(",
    re.IGNORECASE,
)
_JS_ROUTE_METHOD_RE = re.compile(
    r"\b(?:app|router|server)\.(?P<method>get|post|put|patch|delete|all|use)\s*\(",
    re.IGNORECASE,
)
_NEST_ROUTE_DECORATOR_RE = re.compile(
    r"^\s*@(?:Get|Post|Put|Patch|Delete|All)\s*\(",
)
_NEST_CONTROLLER_RE = re.compile(r"^\s*@Controller\s*\(")
_NEXT_HTTP_EXPORT_RE = re.compile(
    r"^\s*export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"
)


@dataclass(frozen=True, slots=True)
class ReachabilityEvidence:
    entry_points: list[str]
    reason: str


def enrich_reachability(
    findings: list[Finding],
    *,
    workspace_root: str | Path | None = None,
    file_contents: dict[str, str] | None = None,
) -> list[Finding]:
    """Populate reachability fields when local entry-point evidence exists."""
    if not findings:
        return findings

    root = Path(workspace_root).resolve() if workspace_root else None
    content_by_path = file_contents or {}
    lines_cache: dict[str, list[str] | None] = {}
    out: list[Finding] = []

    for finding in findings:
        if finding.reachability != ReachabilityLabel.UNKNOWN or finding.entry_points:
            out.append(finding)
            continue

        lines = _lines_for_finding(finding, content_by_path, lines_cache)
        if not lines:
            out.append(finding)
            continue

        evidence = _analyze_finding(finding, lines, root)
        if evidence is None:
            out.append(finding)
            continue

        metadata = dict(finding.metadata)
        metadata.setdefault("reachability_method", "local_entrypoint_heuristic")
        metadata.setdefault("reachability_reason", evidence.reason)
        out.append(
            replace(
                finding,
                metadata=metadata,
                reachability=ReachabilityLabel.REACHABLE,
                entry_points=evidence.entry_points,
            )
        )

    return out


def _lines_for_finding(
    finding: Finding,
    content_by_path: dict[str, str],
    lines_cache: dict[str, list[str] | None],
) -> list[str] | None:
    content = content_by_path.get(finding.file_path)
    if content is None:
        content = content_by_path.get(str(Path(finding.file_path)))
    if content is not None:
        return content.splitlines()

    path_key = finding.file_path
    if path_key in lines_cache:
        return lines_cache[path_key]

    try:
        lines = Path(finding.file_path).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        lines = None
    lines_cache[path_key] = lines
    return lines


def _analyze_finding(
    finding: Finding,
    lines: list[str],
    workspace_root: Path | None,
) -> ReachabilityEvidence | None:
    line_idx = max(0, min(len(lines) - 1, finding.line_start - 1))
    path = Path(finding.file_path)
    suffix = path.suffix.lower()
    display_path = _display_path(path, workspace_root)

    if suffix == ".py":
        return _python_evidence(lines, line_idx, display_path)
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return _javascript_evidence(lines, line_idx, display_path)
    if suffix == ".php":
        return ReachabilityEvidence(
            entry_points=[f"{display_path}:public PHP entry"],
            reason="PHP file can be directly routed by common web server setups",
        )
    return None


def _python_evidence(
    lines: list[str],
    line_idx: int,
    display_path: str,
) -> ReachabilityEvidence | None:
    scope = _enclosing_python_scope(lines, line_idx)
    if scope is not None:
        scope_line, scope_name = scope
        decorator = _route_decorator_above(lines, scope_line)
        if decorator:
            return ReachabilityEvidence(
                entry_points=[f"{display_path}:{scope_name} via {decorator}"],
                reason="finding is inside a decorated Python web route",
            )

    for i in range(max(0, line_idx - 8), min(len(lines), line_idx + 9)):
        if _PY_DJANGO_URL_RE.search(lines[i]):
            return ReachabilityEvidence(
                entry_points=[f"{display_path}:django url pattern"],
                reason="finding is near a Django URL pattern",
            )
    return None


def _javascript_evidence(
    lines: list[str],
    line_idx: int,
    display_path: str,
) -> ReachabilityEvidence | None:
    if _is_next_route_file(display_path):
        export_name = _nearest_next_http_export(lines, line_idx)
        if export_name:
            return ReachabilityEvidence(
                entry_points=[f"{display_path}:{export_name}"],
                reason="finding is inside a Next.js route handler file",
            )
        return ReachabilityEvidence(
            entry_points=[f"{display_path}:nextjs route file"],
            reason="finding is inside a Next.js route handler file",
        )

    route_line = _nearest_js_route_call(lines, line_idx)
    if route_line is not None:
        route = _format_js_route(lines[route_line])
        return ReachabilityEvidence(
            entry_points=[f"{display_path}:{route}"],
            reason="finding is inside or near an Express-style route handler",
        )

    nest_method = _nearest_nest_route(lines, line_idx)
    if nest_method:
        return ReachabilityEvidence(
            entry_points=[f"{display_path}:{nest_method}"],
            reason="finding is inside a NestJS route handler",
        )

    return None


def _enclosing_python_scope(lines: list[str], line_idx: int) -> tuple[int, str] | None:
    for i in range(line_idx, -1, -1):
        match = _PY_SCOPE_RE.match(lines[i])
        if not match:
            continue
        scope_indent = len(match.group("indent").replace("\t", "    "))
        if _line_is_within_indented_scope(lines, line_idx, i, scope_indent):
            return i, match.group("name")
    return None


def _line_is_within_indented_scope(
    lines: list[str],
    line_idx: int,
    scope_line: int,
    scope_indent: int,
) -> bool:
    if line_idx == scope_line:
        return True
    for i in range(scope_line + 1, line_idx + 1):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(lines[i]) - len(lines[i].lstrip(" \t"))
        if indent <= scope_indent:
            return False
    return True


def _route_decorator_above(lines: list[str], scope_line: int) -> str | None:
    i = scope_line - 1
    decorators: list[str] = []
    while i >= 0:
        stripped = lines[i].strip()
        if not stripped:
            i -= 1
            continue
        if not stripped.startswith("@"):
            break
        decorators.append(stripped)
        i -= 1
    for decorator in decorators:
        if _PY_ROUTE_DECORATOR_RE.match(decorator):
            return decorator
    return None


def _nearest_js_route_call(lines: list[str], line_idx: int) -> int | None:
    lower_bound = max(0, line_idx - 80)
    for i in range(line_idx, lower_bound - 1, -1):
        if _JS_ROUTE_RE.search(lines[i]):
            return i
        if i != line_idx and _looks_like_top_level_boundary(lines[i]):
            return None
    return None


def _format_js_route(line: str) -> str:
    match = _JS_ROUTE_METHOD_RE.search(line)
    if not match:
        return "route handler"
    method = match.group("method").lower()
    route_match = re.search(r"['\"]([^'\"]+)['\"]", line[match.end():])
    route = f" {route_match.group(1)}" if route_match else ""
    return f"{method.upper()} route{route}"


def _nearest_nest_route(lines: list[str], line_idx: int) -> str | None:
    has_controller = any(_NEST_CONTROLLER_RE.match(line) for line in lines[: line_idx + 1])
    if not has_controller:
        return None
    for i in range(line_idx, max(0, line_idx - 40) - 1, -1):
        if _NEST_ROUTE_DECORATOR_RE.match(lines[i]):
            return lines[i].strip()
        if i != line_idx and _looks_like_top_level_boundary(lines[i]):
            return None
    return None


def _nearest_next_http_export(lines: list[str], line_idx: int) -> str | None:
    for i in range(line_idx, max(0, line_idx - 80) - 1, -1):
        match = _NEXT_HTTP_EXPORT_RE.match(lines[i])
        if match:
            return lines[i].strip().removesuffix("{").strip()
    return None


def _is_next_route_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return (
        ("/app/api/" in normalized or normalized.startswith("app/api/"))
        and normalized.endswith(("/route.ts", "/route.tsx", "/route.js", "/route.jsx"))
    ) or "/pages/api/" in normalized or normalized.startswith("pages/api/")


def _looks_like_top_level_boundary(line: str) -> bool:
    return bool(
        re.match(
            r"^(?:export\s+)?(?:async\s+)?(?:function|class)\s+"
            r"|^(?:const|let|var)\s+\w+\s*=",
            line,
        )
    )


def _display_path(path: Path, workspace_root: Path | None) -> str:
    if workspace_root is not None:
        try:
            return path.resolve().relative_to(workspace_root).as_posix()
        except (OSError, ValueError):
            pass
    return path.as_posix()
