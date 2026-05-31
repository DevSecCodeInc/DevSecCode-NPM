from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath

from dsc.config import load_config
from dsc.scanner.models import DetectorMetadata, Finding

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScanPolicy:
	name: str
	allowed_tiers: frozenset[str]
	min_confidence: float
	realtime_only: bool
	include_advisory: bool
	include_suppressed: bool


@dataclass(frozen=True, slots=True)
class SuppressionEntry:
	reason: str
	author: str
	expires_on: str | None = None


REALTIME_STRICT = ScanPolicy(
	name="realtime_strict",
	min_confidence=0.90,
	allowed_tiers=frozenset({"A", "B"}),
	realtime_only=True,
	include_advisory=False,
	include_suppressed=False,
)

FULL_PRECISION = ScanPolicy(
	name="full_precision",
	min_confidence=0.75,
	allowed_tiers=frozenset({"A", "B"}),
	realtime_only=False,
	include_advisory=False,
	include_suppressed=False,
)

FULL_BALANCED = ScanPolicy(
	name="full_balanced",
	min_confidence=0.50,
	allowed_tiers=frozenset({"A", "B", "C"}),
	realtime_only=False,
	include_advisory=True,
	include_suppressed=False,
)

FULL_COVERAGE = ScanPolicy(
	name="full_coverage",
	min_confidence=0.0,
	allowed_tiers=frozenset({"A", "B", "C"}),
	realtime_only=False,
	include_advisory=True,
	include_suppressed=False,
)

_PROFILE_POLICIES: dict[str, ScanPolicy] = {
	"precision": FULL_PRECISION,
	"balanced": FULL_BALANCED,
	"coverage": FULL_COVERAGE,
	"deep": FULL_COVERAGE,
}

_WHITESPACE_RUN = re.compile(r"\s+")


def _normalize_snippet(snippet: str | None) -> str:
	if not snippet:
		return ""
	return _WHITESPACE_RUN.sub(" ", snippet.strip())


def _relative_path(file_path: str, workspace_root: str) -> str:
	try:
		return str(PurePosixPath(file_path).relative_to(workspace_root))
	except ValueError:
		return file_path


def compute_fingerprint(finding: Finding, *, workspace_root: str) -> str:
	normalized = _normalize_snippet(finding.snippet)
	rel_path = _relative_path(finding.file_path, workspace_root)
	payload = finding.rule_id + "\0" + normalized + "\0" + rel_path
	return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_occurrence_id(finding: Finding, *, workspace_root: str) -> str:
	normalized = _normalize_snippet(finding.snippet)
	rel_path = _relative_path(finding.file_path, workspace_root)
	payload = (
		finding.rule_id
		+ "\0"
		+ rel_path
		+ "\0"
		+ str(finding.line_start)
		+ "\0"
		+ str(finding.line_end)
		+ "\0"
		+ str(finding.column)
		+ "\0"
		+ normalized
	)
	return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def policy_for_profile(
	profile: str,
	*,
	min_confidence: float = 0.0,
	include_suppressed: bool = False,
) -> ScanPolicy:
	base = _PROFILE_POLICIES.get(profile, FULL_PRECISION)
	effective_confidence = min_confidence if min_confidence > 0.0 else base.min_confidence
	return ScanPolicy(
		name=base.name,
		allowed_tiers=base.allowed_tiers,
		min_confidence=effective_confidence,
		realtime_only=base.realtime_only,
		include_advisory=base.include_advisory,
		include_suppressed=include_suppressed,
	)


def load_suppressions(workspace_root: Path) -> dict[str, SuppressionEntry]:
	cfg, _ = load_config(workspace_root)
	raw = cfg.get("suppressions")
	if not raw or not isinstance(raw, dict):
		return {}
	result: dict[str, SuppressionEntry] = {}
	for fingerprint, entry_data in raw.items():
		if not isinstance(entry_data, dict):
			continue
		reason = str(entry_data.get("reason", ""))
		author = str(entry_data.get("author", ""))
		expires_on = entry_data.get("expires_on")
		if expires_on is not None:
			expires_on = str(expires_on)
		result[str(fingerprint)] = SuppressionEntry(
			reason=reason,
			author=author,
			expires_on=expires_on,
		)
	return result


_TIER_RANK = {"A": 3, "B": 2, "C": 1}


# Inline allowlist comment markers honored at the quality layer. When
# any of these appears on a finding's line (or, for snippet-only
# matching, anywhere in the matched span), the finding is dropped
# silently with no entry in the result.
#
# These are industry conventions shared across many tools. We accept
# them all so a codebase that already annotates secrets for one tool
# (detect-secrets, bandit, etc.) doesn't have to re-annotate for ours.
#
# The match is intentionally loose -- variations in whitespace, casing,
# and surrounding punctuation all pass. The risk of accidentally
# silencing a real finding by writing "allowlist secret" in regular
# code is acceptable: someone typing that string is signaling intent.
_ALLOWLIST_MARKERS = re.compile(
	r"(?:"
	r"pragma\s*:\s*allowlist\s+secret"  # detect-secrets convention (Yelp)
	r"|nosec(?:\b|[(:])"                  # bandit short form
	r"|noqa\s*:\s*(?:bandit|s\d+)"       # bandit via noqa
	r"|lgtm\s*\[(?:py/|js/)"             # LGTM / Semmle
	r"|deva-ignore(?:\b|:)"               # our forward-compatible convention
	r"|nosemgrep|nosem(?:\b|:)"           # semgrep / opengrep (defensive duplication)
	r")",
	re.IGNORECASE,
)


def _inline_allowlist_disabled() -> bool:
	"""Allow users to opt out of the inline-marker filter for audit runs.

	Off-by-default is the right call: respecting these markers matches
	what every other security tool does, and ignoring them is the
	unusual ask.
	"""
	return os.environ.get("DSC_DISABLE_INLINE_ALLOWLIST", "").strip().lower() in (
		"1", "true", "yes", "on",
	)


def _has_inline_allowlist_marker(finding: Finding, *, target_root: str) -> bool:
	"""Return True if the finding's line carries an inline allowlist marker.

	Two-stage check:
	  1. Fast path: scan the snippet OpenGrep already returned. For most
	     findings the trailing comment is in the snippet, so we never
	     touch the disk.
	  2. Fallback: open the file and read the line range. Cheap because
	     OpenGrep has already paid for the directory walk, and we read
	     only the lines we need.
	"""
	if finding.snippet and _ALLOWLIST_MARKERS.search(finding.snippet):
		return True

	# Fall back to reading the file directly. Findings are stamped with
	# absolute paths by the engine; if it's relative, resolve against the
	# scan's workspace root.
	try:
		path = Path(finding.file_path)
		if not path.is_absolute():
			path = Path(target_root) / path
		if not path.is_file():
			return False
		lo = max(1, finding.line_start)
		hi = max(lo, finding.line_end or lo)
		with path.open("r", encoding="utf-8", errors="replace") as fh:
			for i, line in enumerate(fh, start=1):
				if i < lo:
					continue
				if i > hi:
					break
				if _ALLOWLIST_MARKERS.search(line):
					return True
	except OSError:
		# Can't read the file; treat as "not allowlisted" rather than
		# crash the scan. The snippet check above is best-effort anyway.
		return False
	return False


# Path patterns that mark a file as test/spec code. Findings under these
# paths are dropped at the quality layer by default -- test fixtures
# routinely contain deliberately-bad-looking content (fake keys, fake
# emails, sample payloads) that's noise in a security report. Override
# globally via DSC_INCLUDE_TEST_FINDINGS=1; override per-rule via
# `metadata.deva.apply_to_tests: true` on the rule definition.
#
# The patterns target the common test conventions across major
# ecosystems: jest / mocha / vitest (*.test.*, *.spec.*, __tests__/),
# pytest (test_*.py, tests/), Go (*_test.go, testdata/), Java
# (*Test.java, src/test/), Ruby (spec/, *_spec.rb), Rust (#[cfg(test)]
# blocks inside src/, plus tests/), C# (*.Tests.cs), Cypress / Playwright
# (cypress/, e2e/, playwright/), and various __mocks__ / fixtures /
# stubs directories.
_TEST_PATH_FILE_RE = re.compile(
	r"(?:^|[/\\])"  # path segment boundary
	r"(?:"
	r"test_[^/\\]+\.(?:py|rb|cs|php)"        # pytest / xUnit / phpunit
	r"|[^/\\]+_test\.(?:go|rs|exs?|ex)"      # Go / Rust / Elixir
	r"|[^/\\]+_spec\.(?:rb|ts|js)"           # RSpec / Jasmine
	r"|[^/\\]+\.(?:test|spec)\."             # Jest / Vitest / Mocha
	r"|[^/\\]+Tests?\.(?:cs|java|kt|swift)"  # xUnit-family naming
	r")",
	re.IGNORECASE,
)

_TEST_PATH_DIR_RE = re.compile(
	r"(?:^|[/\\])"
	r"(?:"
	r"tests?"               # tests/ test/
	r"|__tests__"           # jest
	r"|__mocks__"           # jest mock fixtures
	r"|spec|specs"          # rspec / jasmine
	r"|cypress|e2e"         # cypress / playwright
	r"|playwright"
	r"|fixtures?"           # test fixtures
	r"|testdata"            # Go convention
	r"|test-fixtures"
	r"|test-utils"
	r")"
	r"(?:[/\\]|$)",
	re.IGNORECASE,
)


def is_test_path(file_path: str) -> bool:
	"""Return True if the path looks like test / spec code.

	Public so the engine and tests can probe it directly. Pure path
	check -- doesn't touch disk.
	"""
	# Normalize Windows separators so the same regex handles both.
	norm = file_path.replace("\\", "/")
	if _TEST_PATH_FILE_RE.search(norm):
		return True
	if _TEST_PATH_DIR_RE.search(norm):
		return True
	return False


def _test_filter_disabled() -> bool:
	"""Allow users to opt back into seeing test-file findings.

	Off by default for the same reason the inline-allowlist filter is:
	the noise is overwhelming and the signal is rare. Audit runs and
	test-harness security reviews can set DSC_INCLUDE_TEST_FINDINGS=1.
	"""
	return os.environ.get("DSC_INCLUDE_TEST_FINDINGS", "").strip().lower() in (
		"1", "true", "yes", "on",
	)


def _rule_applies_to_tests(finding: Finding) -> bool:
	"""Per-rule opt-in: a rule can declare it still wants test-file hits.

	Reads ``metadata.deva.apply_to_tests`` off the rule definition (the
	result mapper threads rule metadata onto the Finding). No rule in
	the bundled pack opts in today; the hook exists so a future
	"test-fixture leaked prod credentials" rule can survive the filter.
	"""
	md = finding.metadata or {}
	# Direct boolean on the finding's own metadata.
	if md.get("apply_to_tests") is True:
		return True
	# Or nested under a 'deva' subdict that some rules use for their
	# private fields. The result mapper hoists most of these, but be
	# defensive.
	deva = md.get("deva") if isinstance(md.get("deva"), dict) else None
	if deva and deva.get("apply_to_tests") is True:
		return True
	return False


# Path patterns for "data files" -- machine-generated or machine-
# maintained content where rules looking for prose-like signals (PII,
# secret-shaped strings, password assignments) reliably misfire.
#
# Concrete examples this catches in the openclaw scan:
#   - .secrets.baseline: detect-secrets snapshot of 40-hex hashes
#     that the PII rule reads as identifiers
#   - pnpm-lock.yaml / package-lock.json: package integrity hashes
#   - docs/.i18n/zh-CN.tm.jsonl: translation-memory cache
#   - .detect-secrets.cfg: pattern config file
#   - .mailmap: contributor email mapping (matches PII rules)
#   - *.md: documentation containing example URLs / IPs
#
# Notably NOT in the list (these stay scannable):
#   - Dockerfile, *.yml/yaml, *.tf: infrastructure code with real rules
#   - .env, .env.*: real credential leak surface
#   - *.json (without a lockfile suffix): could be config or data;
#     too broad to filter blanket
_DATA_PATH_RE = re.compile(
	r"(?:^|[/\\])"
	r"(?:"
	# Documentation / prose
	r"[^/\\]+\.(?:md|mdx|rst|adoc|markdown)"
	# Lockfiles -- machine-generated dependency graphs
	r"|package-lock\.json"
	r"|npm-shrinkwrap\.json"
	r"|pnpm-lock\.yaml"
	r"|yarn\.lock"
	r"|pipfile\.lock"
	r"|poetry\.lock"
	r"|gemfile\.lock"
	r"|cargo\.lock"
	r"|composer\.lock"
	r"|go\.sum"
	r"|flake\.lock"
	# Generated outputs by naming convention
	r"|[^/\\]+\.generated\.[^/\\]+"
	r"|[^/\\]+\.gen\.[^/\\]+"
	r"|[^/\\]+-generated\.[^/\\]+"
	r"|[^/\\]+\.pb\.(?:go|ts|py|java|cs)"
	r"|[^/\\]+\.codegen\.[^/\\]+"
	# Jest / Vitest snapshots
	r"|[^/\\]+\.snap"
	# Git / project metadata
	r"|\.gitignore"
	r"|\.gitattributes"
	r"|\.mailmap"
	r"|\.editorconfig"
	r"|CODEOWNERS"
	# Security-tool baselines (their entire purpose is to record
	# fake-looking patterns we shouldn't re-flag)
	r"|\.secrets\.baseline"
	r"|\.detect-secrets\.cfg"
	r"|\.semgrepignore"
	# Bulk data dumps
	r"|[^/\\]+\.(?:jsonl|ndjson|csv|tsv)"
	# i18n translation files
	r"|[^/\\]+\.(?:po|pot|mo)"
	r")$",
	re.IGNORECASE,
)

# Directory patterns for data-heavy trees.
_DATA_DIR_RE = re.compile(
	r"(?:^|[/\\])"
	r"(?:"
	r"docs?"                 # docs/ doc/
	r"|documentation"
	r"|__snapshots__"        # jest snapshot tree
	r"|i18n|locales?"        # translation trees
	r")"
	r"(?:[/\\]|$)",
	re.IGNORECASE,
)


def is_data_path(file_path: str) -> bool:
	"""Return True if the path is a documentation, generated, or
	machine-maintained data file (not a source code or IaC file).

	Used by the quality layer to drop findings from rules that don't
	make sense outside production / IaC source: PII detectors that
	match content hashes, secret-shape detectors that match example
	strings in docs, etc.

	Public so the engine and tests can probe it directly. Pure path
	check -- doesn't touch disk.
	"""
	norm = file_path.replace("\\", "/")
	if _DATA_PATH_RE.search(norm):
		return True
	if _DATA_DIR_RE.search(norm):
		return True
	return False


def _data_filter_disabled() -> bool:
	"""Allow users to opt back into scanning docs / lockfiles / data.

	Off by default for the same reason as the test-file filter: the
	noise is overwhelming and the signal is rare. Set
	DSC_INCLUDE_DATA_FINDINGS=1 to keep them.
	"""
	return os.environ.get("DSC_INCLUDE_DATA_FINDINGS", "").strip().lower() in (
		"1", "true", "yes", "on",
	)


def _rule_applies_to_data_files(finding: Finding) -> bool:
	"""Per-rule opt-in: a rule can declare it still wants data-file hits.

	Reads ``metadata.apply_to_data_files`` (or nested under ``deva``).
	No bundled rule sets this today; the hook is here for rules like
	"production secret committed in a *.md changelog" that we may
	want to keep flagging.
	"""
	md = finding.metadata or {}
	if md.get("apply_to_data_files") is True:
		return True
	deva = md.get("deva") if isinstance(md.get("deva"), dict) else None
	if deva and deva.get("apply_to_data_files") is True:
		return True
	return False


def _is_suppression_active(entry: SuppressionEntry) -> bool:
	if entry.expires_on is None:
		return True
	try:
		expiry = date.fromisoformat(entry.expires_on)
		return date.today() <= expiry
	except ValueError:
		return True


def _rebuild_finding(f: Finding, md: dict) -> Finding:
	"""Create a new Finding with updated metadata (Finding is frozen)."""
	return Finding(
		rule_id=f.rule_id,
		cwe=f.cwe,
		severity=f.severity,
		file_path=f.file_path,
		line_start=f.line_start,
		line_end=f.line_end,
		column=f.column,
		message=f.message,
		fix_suggestion=f.fix_suggestion,
		snippet=f.snippet,
		metadata=md,
		triage_label=f.triage_label,
		triage_confidence=f.triage_confidence,
		triage_reasoning=f.triage_reasoning,
		reachability=f.reachability,
		entry_points=list(f.entry_points),
	)


def apply_quality_layer(
	findings: list[Finding],
	detectors: dict[str, DetectorMetadata],
	*,
	target_root: str,
	policy: ScanPolicy,
	suppressions: dict[str, SuppressionEntry],
) -> list[Finding]:
	"""Annotate, deduplicate, suppress, and gate findings in two passes.

	Pass 1: Annotate each finding with fingerprint, occurrence_id, and
	detector metadata, then deduplicate by occurrence_id (keep highest
	quality).

	Pass 2: Apply suppressions and policy gating on the deduplicated set.
	"""
	# --- Pass 0: Filter out findings on lines carrying an inline
	# allowlist marker (`pragma: allowlist secret`, `nosec`, etc.),
	# and findings under test / spec / fixture paths. Both filters
	# are developer opt-outs we read as "this is intentional"; no
	# point fingerprinting and gating findings we're about to drop.
	allowlist_disabled = _inline_allowlist_disabled()
	test_filter_disabled = _test_filter_disabled()
	data_filter_disabled = _data_filter_disabled()
	allowlist_dropped = 0
	test_dropped = 0
	data_dropped = 0
	pre_filter: list[Finding] = []
	for f in findings:
		if not allowlist_disabled and _has_inline_allowlist_marker(
			f, target_root=target_root
		):
			allowlist_dropped += 1
			continue
		if (
			not test_filter_disabled
			and is_test_path(f.file_path)
			and not _rule_applies_to_tests(f)
		):
			test_dropped += 1
			continue
		if (
			not data_filter_disabled
			and is_data_path(f.file_path)
			and not _rule_applies_to_data_files(f)
		):
			data_dropped += 1
			continue
		pre_filter.append(f)

	if allowlist_dropped or test_dropped or data_dropped:
		import sys as _sys

		if allowlist_dropped:
			_log.info(
				"inline-allowlist filter dropped %d finding(s) "
				"(pragma: allowlist secret / nosec / etc.)",
				allowlist_dropped,
			)
			# Also surface as a phase marker on stderr so the benchmark
			# harness (and humans reading the scan log) can see how
			# aggressive the filter was without configuring Python
			# logging.
			_sys.stderr.write(
				f"[dsc-quality] inline-allowlist-dropped={allowlist_dropped}\n"
			)
		if test_dropped:
			_log.info(
				"test-file filter dropped %d finding(s) under test / spec / "
				"fixture paths (set DSC_INCLUDE_TEST_FINDINGS=1 to keep them)",
				test_dropped,
			)
			_sys.stderr.write(
				f"[dsc-quality] test-file-dropped={test_dropped}\n"
			)
		if data_dropped:
			_log.info(
				"data-file filter dropped %d finding(s) under doc / "
				"lockfile / generated / metadata paths "
				"(set DSC_INCLUDE_DATA_FINDINGS=1 to keep them)",
				data_dropped,
			)
			_sys.stderr.write(
				f"[dsc-quality] data-file-dropped={data_dropped}\n"
			)
		_sys.stderr.flush()

	# --- Pass 1: Annotate + Deduplicate ---
	best: dict[str, Finding] = {}
	best_quality: dict[str, tuple[int, float]] = {}

	for f in pre_filter:
		md = dict(f.metadata)

		# Annotate: fingerprint + occurrence ID
		fp = md.get("fingerprint")
		if not isinstance(fp, str) or not fp:
			fp = compute_fingerprint(f, workspace_root=target_root)
		md["fingerprint"] = fp

		occurrence_id = md.get("occurrence_id")
		if not isinstance(occurrence_id, str) or not occurrence_id:
			occurrence_id = compute_occurrence_id(f, workspace_root=target_root)
		md["occurrence_id"] = occurrence_id

		# Annotate: detector metadata
		det = detectors.get(f.rule_id)
		if det is not None:
			md.setdefault("family", det.family or "unknown")
			md.setdefault("precision_tier", det.precision_tier or "B")
			md.setdefault("confidence", det.default_confidence or 0.75)
		else:
			md.setdefault("family", "unknown")
			md.setdefault("precision_tier", "B")
			md.setdefault("confidence", 0.75)

		annotated = _rebuild_finding(f, md)

		# Deduplicate: keep highest (tier_rank, confidence) per occurrence_id
		tier_rank = _TIER_RANK.get(md.get("precision_tier", "B"), 2)
		confidence = md.get("confidence", 0.75)
		if not isinstance(confidence, (int, float)):
			confidence = 0.75
		quality = (tier_rank, float(confidence))
		existing_quality = best_quality.get(occurrence_id)
		if existing_quality is None or quality > existing_quality:
			best[occurrence_id] = annotated
			best_quality[occurrence_id] = quality

	# --- Pass 2: Suppress + Gate ---
	result: list[Finding] = []
	for f in best.values():
		md = f.metadata
		fp = md["fingerprint"]
		tier = md.get("precision_tier", "B")
		raw_confidence = md.get("confidence", 0.0)
		# Confidence is normally a float; defensively coerce strings
		# (e.g., legacy "high"/"medium"/"low" tags) so the gate below
		# still works rather than raising TypeError.
		if isinstance(raw_confidence, str):
			confidence = {"high": 0.9, "medium": 0.7, "low": 0.5}.get(
				raw_confidence.lower(), 0.0
			)
		else:
			try:
				confidence = float(raw_confidence)
			except (TypeError, ValueError):
				confidence = 0.0

		# Check suppression
		entry = suppressions.get(fp)
		if entry is not None and _is_suppression_active(entry):
			if not policy.include_suppressed:
				continue
			md = dict(md)
			md["suppressed"] = True
			md["suppression_reason"] = entry.reason
			f = _rebuild_finding(f, md)

		# Gate by tier
		if tier not in policy.allowed_tiers:
			if policy.include_advisory:
				md = dict(md)
				md["advisory"] = True
				result.append(_rebuild_finding(f, md))
			continue

		# Gate by confidence
		if confidence < policy.min_confidence:
			if policy.include_advisory:
				md = dict(md)
				md["advisory"] = True
				result.append(_rebuild_finding(f, md))
			continue

		result.append(f)

	return result
