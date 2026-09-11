#!/usr/bin/env python3
"""Standard-library-only validator for a security review report JSON.

Checks the shape and enums against references/report-schema.json and the
business rules (R-01..R-09) documented there and in
references/severity-and-score.md. This script never fixes content itself -
the Skill runtime is responsible for retrying with the analysis step (see
the original brief, section 29: at most 2 retries before reportStatus
becomes "invalid").

Deliberately does not depend on a third-party JSON Schema library (stdlib
only, per CLAUDE.md); report-schema.json is the human/AI-facing reference,
this file is its executable counterpart and both are meant to stay in sync
(see tests/test_validate_report.py for a drift check).

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from preprocess import CATEGORIES, ModesConfigError, load_modes_config  # noqa: E402
from score import compute_id, compute_stable_key, score_band  # noqa: E402

EXIT_OK = 0
EXIT_FAILED = 1

SC_CATEGORIES = ["SC%02d" % n for n in range(1, 11)]
VALID_CATEGORIES = set(CATEGORIES.keys())
VALID_COMPLETENESS = {"complete", "partial", "failed"}
VALID_COVERAGE_STATUS = {"DETECTED", "NOT_DETECTED", "NOT_ASSESSED"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
VALID_CONFIDENCES = {"high", "medium", "low"}
VALID_FINDING_STATUSES = {"suspected", "confirmed", "informational"}
VALID_BANDS = {"LOW", "MODERATE", "HIGH", "CRITICAL"}
VALID_GAS_IMPACT = {"low", "medium", "high"}

TOP_LEVEL_REQUIRED = [
    "generatedBy",
    "skillVersion",
    "analysisEngineVersion",
    "checklistVersion",
    "scoreVersion",
    "mode",
    "compilerVersion",
    "scriptsAvailable",
    "inputHash",
    "scope",
    "categoryCoverage",
    "findings",
    "limitations",
    "riskIndicator",
    "scoreStatus",
]
TOP_LEVEL_OPTIONAL = {"language", "gasSuggestions", "executiveSummary", "architectureNotes"}
TOP_LEVEL_ALLOWED = set(TOP_LEVEL_REQUIRED) | TOP_LEVEL_OPTIONAL

FINDING_REQUIRED = [
    "id", "stableKey", "category", "severity", "confidence", "status",
    "locations", "evidence", "description", "recommendation", "patch",
]
FINDING_OPTIONAL = {"signature", "mergedCount"}
FINDING_ALLOWED = set(FINDING_REQUIRED) | FINDING_OPTIONAL

INPUT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINDING_ID_RE = re.compile(r"^F-[0-9a-f]{8}$")


class ReportValidationError(Exception):
    """Raised when the input cannot even be checked (not JSON, not an object)."""


class ErrorCollector:
    def __init__(self) -> None:
        self.errors: List[str] = []

    def add(self, message: str) -> None:
        self.errors.append(message)

    def require(self, condition: bool, message: str) -> bool:
        if not condition:
            self.add(message)
        return condition


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _validate_location(loc: Any, path: str, errors: ErrorCollector) -> None:
    if not errors.require(isinstance(loc, dict), "%s must be an object" % path):
        return
    errors.require(_is_str(loc.get("file")) and loc.get("file"), "%s.file must be a non-empty string" % path)
    for key in ("lineStart", "lineEnd"):
        if key in loc and loc[key] is not None:
            errors.require(isinstance(loc[key], int), "%s.%s must be an integer or null" % (path, key))
    for key in ("contract", "function"):
        if key in loc and loc[key] is not None:
            errors.require(_is_str(loc[key]), "%s.%s must be a string or null" % (path, key))
    unknown = set(loc.keys()) - {"file", "lineStart", "lineEnd", "contract", "function"}
    errors.require(not unknown, "%s has unknown fields: %s" % (path, sorted(unknown)))


def _validate_patch(patch: Any, path: str, errors: ErrorCollector) -> None:
    if patch is None:
        return
    if not errors.require(isinstance(patch, dict), "%s must be null or an object" % path):
        return
    errors.require(patch.get("format") == "unified-diff", "%s.format must be 'unified-diff'" % path)
    errors.require(_is_str(patch.get("diff")) and patch.get("diff"), "%s.diff must be a non-empty string" % path)
    unknown = set(patch.keys()) - {"format", "diff"}
    errors.require(not unknown, "%s has unknown fields: %s" % (path, sorted(unknown)))


def _validate_finding(finding: Any, index: int, errors: ErrorCollector) -> Optional[Dict[str, Any]]:
    path = "findings[%d]" % index
    if not errors.require(isinstance(finding, dict), "%s must be an object" % path):
        return None

    unknown = set(finding.keys()) - FINDING_ALLOWED
    errors.require(not unknown, "%s has unknown fields: %s" % (path, sorted(unknown)))
    for key in FINDING_REQUIRED:
        errors.require(key in finding, "%s missing required field %r" % (path, key))

    category = finding.get("category")
    errors.require(category in VALID_CATEGORIES, "%s.category must be one of the checklist categories" % path)

    severity = finding.get("severity")
    errors.require(severity in VALID_SEVERITIES, "%s.severity must be one of %s" % (path, sorted(VALID_SEVERITIES)))

    confidence = finding.get("confidence")
    errors.require(confidence in VALID_CONFIDENCES, "%s.confidence must be one of %s" % (path, sorted(VALID_CONFIDENCES)))

    status = finding.get("status")
    errors.require(status in VALID_FINDING_STATUSES, "%s.status must be one of %s" % (path, sorted(VALID_FINDING_STATUSES)))
    if status == "informational":
        errors.require(severity == "INFORMATIONAL", "%s: status 'informational' requires severity 'INFORMATIONAL' (rule R-07)" % path)

    locations = finding.get("locations")
    if errors.require(isinstance(locations, list), "%s.locations must be an array" % path):
        errors.require(
            len(locations) >= 1,
            "%s.locations must have at least one entry (an empty array makes stableKey's primary-location "
            "component degenerate and lets unrelated findings collapse into one - see D-022)" % path,
        )
        for loc_index, loc in enumerate(locations):
            _validate_location(loc, "%s.locations[%d]" % (path, loc_index), errors)

    evidence = finding.get("evidence")
    if errors.require(isinstance(evidence, list), "%s.evidence must be an array" % path):
        errors.require(len(evidence) <= 5, "%s.evidence must have at most 5 lines" % path)
        errors.require(all(_is_str(line) for line in evidence), "%s.evidence entries must be strings" % path)

    errors.require(_is_str(finding.get("description")), "%s.description must be a string" % path)
    errors.require(_is_str(finding.get("recommendation")), "%s.recommendation must be a string" % path)

    _validate_patch(finding.get("patch"), "%s.patch" % path, errors)

    finding_id = finding.get("id")
    errors.require(_is_str(finding_id) and bool(FINDING_ID_RE.match(finding_id or "")), "%s.id must match ^F-[0-9a-f]{8}$" % path)

    stable_key = finding.get("stableKey")
    errors.require(_is_str(stable_key) and bool(INPUT_HASH_RE.match(stable_key or "")), "%s.stableKey must match ^sha256:[0-9a-f]{64}$" % path)

    if category in VALID_CATEGORIES and isinstance(locations, list) and _is_str(status):
        try:
            expected_key = compute_stable_key(finding)
            expected_id = compute_id(expected_key)
        except Exception:  # pragma: no cover - defensive, inputs already validated above
            expected_key = None
            expected_id = None
        if expected_key is not None:
            errors.require(
                stable_key == expected_key,
                "%s.stableKey does not match a fresh recomputation from category+locations+signature "
                "(rule R-02: score.py must own this, it is never trusted from AI input)" % path,
            )
            errors.require(finding_id == expected_id, "%s.id does not match its stableKey (rule R-02)" % path)

    if "mergedCount" in finding:
        errors.require(isinstance(finding["mergedCount"], int) and finding["mergedCount"] >= 1, "%s.mergedCount must be an integer >= 1" % path)

    return finding if not errors.errors else None


def _validate_category_coverage(coverage: Any, errors: ErrorCollector) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not errors.require(isinstance(coverage, list), "categoryCoverage must be an array"):
        return result
    errors.require(len(coverage) == 10, "categoryCoverage must have exactly 10 entries (SC01-SC10), got %d" % len(coverage))
    seen: List[str] = []
    for index, entry in enumerate(coverage):
        path = "categoryCoverage[%d]" % index
        if not errors.require(isinstance(entry, dict), "%s must be an object" % path):
            continue
        unknown = set(entry.keys()) - {"category", "status", "note"}
        errors.require(not unknown, "%s has unknown fields: %s" % (path, sorted(unknown)))
        category = entry.get("category")
        errors.require(category in SC_CATEGORIES, "%s.category must be one of %s" % (path, SC_CATEGORIES))
        status = entry.get("status")
        errors.require(status in VALID_COVERAGE_STATUS, "%s.status must be one of %s" % (path, sorted(VALID_COVERAGE_STATUS)))
        if "note" in entry and entry["note"] is not None:
            errors.require(_is_str(entry["note"]), "%s.note must be a string" % path)
        if category in SC_CATEGORIES:
            if category in seen:
                errors.add("categoryCoverage has a duplicate entry for %s" % category)
            seen.append(category)
            if status in VALID_COVERAGE_STATUS:
                result[category] = status
    missing = [c for c in SC_CATEGORIES if c not in seen]
    if missing:
        errors.add("categoryCoverage is missing entries for: %s" % missing)
    return result


def _validate_scope(scope: Any, errors: ErrorCollector) -> str:
    if not errors.require(isinstance(scope, dict), "scope must be an object"):
        return ""
    unknown = set(scope.keys()) - {"completeness", "reasons"}
    errors.require(not unknown, "scope has unknown fields: %s" % sorted(unknown))
    completeness = scope.get("completeness")
    errors.require(completeness in VALID_COMPLETENESS, "scope.completeness must be one of %s" % sorted(VALID_COMPLETENESS))
    if "reasons" in scope:
        reasons = scope["reasons"]
        if errors.require(isinstance(reasons, list), "scope.reasons must be an array"):
            for index, reason in enumerate(reasons):
                path = "scope.reasons[%d]" % index
                if errors.require(isinstance(reason, dict), "%s must be an object" % path):
                    errors.require(_is_str(reason.get("code")), "%s.code must be a string" % path)
                    errors.require(_is_str(reason.get("detail")), "%s.detail must be a string" % path)
    return completeness if completeness in VALID_COMPLETENESS else ""


def _validate_risk_indicator(indicator: Any, top_level_score_status: Any, errors: ErrorCollector) -> None:
    if not errors.require(isinstance(indicator, dict), "riskIndicator must be an object"):
        return
    unknown = set(indicator.keys()) - {"scoreStatus", "score", "band", "explanation", "scopeNote", "message", "lowBandNote"}
    errors.require(not unknown, "riskIndicator has unknown fields: %s" % sorted(unknown))

    status = indicator.get("scoreStatus")
    errors.require(status in {"computed", "not_computed"}, "riskIndicator.scoreStatus must be 'computed' or 'not_computed'")
    errors.require(status == top_level_score_status, "top-level scoreStatus and riskIndicator.scoreStatus must agree (rule R-08)")

    score = indicator.get("score")
    band = indicator.get("band")
    if status == "computed":
        if errors.require(isinstance(score, int) and not isinstance(score, bool), "riskIndicator.score must be an integer when scoreStatus is 'computed'"):
            errors.require(0 <= score <= 100, "riskIndicator.score must be between 0 and 100")
            errors.require(band == score_band(score), "riskIndicator.band must match the score table for score=%r (rule R-08)" % score)
        errors.require(band in VALID_BANDS, "riskIndicator.band must be one of %s when computed" % sorted(VALID_BANDS))
    elif status == "not_computed":
        errors.require(score is None, "riskIndicator.score must be null when scoreStatus is 'not_computed'")
        errors.require(band is None, "riskIndicator.band must be null when scoreStatus is 'not_computed'")
        errors.require(_is_str(indicator.get("message")) and indicator.get("message"), "riskIndicator.message is required when scoreStatus is 'not_computed'")


def _validate_gas_suggestions(gas_suggestions: Any, errors: ErrorCollector) -> None:
    if not errors.require(isinstance(gas_suggestions, list), "gasSuggestions must be an array"):
        return
    for index, item in enumerate(gas_suggestions):
        path = "gasSuggestions[%d]" % index
        if not errors.require(isinstance(item, dict), "%s must be an object" % path):
            continue
        errors.require(_is_str(item.get("technique")) and item.get("technique"), "%s.technique must be a non-empty string" % path)
        _validate_location(item.get("location"), "%s.location" % path, errors)
        errors.require(_is_str(item.get("explanation")), "%s.explanation must be a string" % path)
        errors.require(item.get("impact") in VALID_GAS_IMPACT, "%s.impact must be one of %s" % (path, sorted(VALID_GAS_IMPACT)))


def _validate_architecture_notes(notes: Any, errors: ErrorCollector) -> None:
    if not errors.require(isinstance(notes, list), "architectureNotes must be an array"):
        return
    for index, item in enumerate(notes):
        path = "architectureNotes[%d]" % index
        if not errors.require(isinstance(item, dict), "%s must be an object" % path):
            continue
        errors.require(_is_str(item.get("title")) and item.get("title"), "%s.title must be a non-empty string" % path)
        errors.require(_is_str(item.get("description")) and item.get("description"), "%s.description must be a non-empty string" % path)
        unknown = set(item.keys()) - {"title", "description"}
        errors.require(not unknown, "%s has unknown fields: %s" % (path, sorted(unknown)))


def validate_report(report: Any) -> List[str]:
    if not isinstance(report, dict):
        raise ReportValidationError("report must be a JSON object")

    # No silent fallback: a missing or malformed config/modes.json must stop
    # validation rather than let it proceed against invented mode rules.
    modes_config = load_modes_config()
    valid_modes = set(modes_config["modes"].keys())

    errors = ErrorCollector()

    unknown = set(report.keys()) - TOP_LEVEL_ALLOWED
    errors.require(not unknown, "report has unknown top-level fields: %s" % sorted(unknown))
    for key in TOP_LEVEL_REQUIRED:
        errors.require(key in report, "report missing required field %r" % key)

    errors.require(report.get("generatedBy") == "ai", "generatedBy must be 'ai'")
    for key in ("skillVersion", "analysisEngineVersion", "checklistVersion", "scoreVersion", "compilerVersion"):
        if key in report:
            errors.require(_is_str(report[key]) and report[key], "%s must be a non-empty string" % key)
    errors.require(report.get("mode") in valid_modes, "mode must be one of %s" % sorted(valid_modes))
    errors.require(isinstance(report.get("scriptsAvailable"), bool), "scriptsAvailable must be a boolean")
    input_hash = report.get("inputHash")
    errors.require(_is_str(input_hash) and bool(INPUT_HASH_RE.match(input_hash or "")), "inputHash must match ^sha256:[0-9a-f]{64}$")
    if "language" in report and report["language"] is not None:
        errors.require(_is_str(report["language"]), "language must be a string")

    completeness = _validate_scope(report.get("scope"), errors)

    coverage_by_category = _validate_category_coverage(report.get("categoryCoverage"), errors)

    findings = report.get("findings")
    valid_findings: List[Dict[str, Any]] = []
    if errors.require(isinstance(findings, list), "findings must be an array"):
        for index, finding in enumerate(findings):
            validated = _validate_finding(finding, index, errors)
            if validated is not None:
                valid_findings.append(validated)

    seen_ids = set()
    for finding in valid_findings:
        finding_id = finding.get("id")
        if finding_id in seen_ids:
            errors.add("duplicate finding id after validation: %s (deduplication should have merged these)" % finding_id)
        seen_ids.add(finding_id)

    referenced_categories = {
        f["category"] for f in valid_findings
        if f.get("status") != "informational" and f.get("category") in SC_CATEGORIES
    }
    for category in referenced_categories:
        status = coverage_by_category.get(category)
        if status is not None and status != "DETECTED":
            errors.add(
                "categoryCoverage[%s].status is %r but a non-informational finding references this category "
                "(rule R-04: it must be 'DETECTED')" % (category, status)
            )

    if completeness in ("partial", "failed"):
        if coverage_by_category and "NOT_ASSESSED" not in coverage_by_category.values():
            errors.add(
                "scope.completeness is %r but no categoryCoverage entry is 'NOT_ASSESSED' "
                "(rule R-05: a partial analysis must never look complete)" % completeness
            )

    mode = report.get("mode")
    mode_rules = modes_config["modes"].get(mode)
    if mode_rules is not None:
        if not mode_rules["allowPatch"]:
            for finding in valid_findings:
                if finding.get("patch") is not None:
                    errors.add(
                        "mode %r forbids a non-null patch (rule R-06; config/modes.json: allowPatch is false), "
                        "found on finding %s" % (mode, finding.get("id"))
                    )
        if not mode_rules["allowGasSuggestions"] and report.get("gasSuggestions"):
            errors.add("mode %r forbids gasSuggestions (rule R-06; config/modes.json: allowGasSuggestions is false)" % mode)
        if not mode_rules["allowExecutiveSummary"] and report.get("executiveSummary"):
            errors.add("mode %r forbids executiveSummary (rule R-09; config/modes.json: allowExecutiveSummary is false)" % mode)
        if not mode_rules["allowArchitectureChecks"] and report.get("architectureNotes"):
            errors.add("mode %r forbids architectureNotes (rule R-09; config/modes.json: allowArchitectureChecks is false)" % mode)

    if "gasSuggestions" in report and report["gasSuggestions"] is not None:
        _validate_gas_suggestions(report["gasSuggestions"], errors)

    if "executiveSummary" in report and report["executiveSummary"] is not None:
        errors.require(_is_str(report["executiveSummary"]), "executiveSummary must be a string")

    if "architectureNotes" in report and report["architectureNotes"] is not None:
        _validate_architecture_notes(report["architectureNotes"], errors)

    limitations = report.get("limitations")
    if errors.require(isinstance(limitations, list), "limitations must be an array"):
        errors.require(all(_is_str(item) for item in limitations), "limitations entries must be strings")

    _validate_risk_indicator(report.get("riskIndicator"), report.get("scoreStatus"), errors)
    errors.require(report.get("scoreStatus") in {"computed", "not_computed"}, "scoreStatus must be 'computed' or 'not_computed'")

    return errors.errors


def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _read_input(path: Optional[str]) -> Any:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportValidationError("input is not valid JSON: %s" % exc) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validate_report.py",
        description="Validate a security review report JSON against report-schema.json and its business rules.",
    )
    parser.add_argument("path", nargs="?", default=None, help="Report JSON file. Reads stdin if omitted.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        report = _read_input(args.path)
        errors = validate_report(report)
    except (ReportValidationError, ModesConfigError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    payload = {
        "ok": True,
        "reportStatus": "valid" if not errors else "invalid",
        "errors": errors,
    }
    indent = args.indent if args.indent > 0 else None
    print(json.dumps(payload, ensure_ascii=False, indent=indent, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
