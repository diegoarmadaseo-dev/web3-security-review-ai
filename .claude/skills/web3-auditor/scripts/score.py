#!/usr/bin/env python3
"""Deterministic deduplication and scoring for a draft security review report.

Reads a report JSON (see references/report-schema.json), recomputes each
finding's id/stableKey from its category, locations and signature (never
trusting those fields from the input), merges findings that share a root
cause, computes the deterministic score/band, and writes the updated report
JSON back out.

This script never authors a finding and never calls a model. If it runs at
all, scoreStatus is always "computed" - "not_computed" is written directly by
the Skill runtime when this script cannot be invoked in the first place (see
references/severity-and-score.md, section 5).

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional

SCORE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_ORDER = ["low", "medium", "high"]
VALID_SEVERITIES = set(SEVERITY_ORDER)
VALID_CONFIDENCES = set(CONFIDENCE_ORDER)
VALID_STATUSES = {"suspected", "confirmed", "informational"}

SEVERITY_PENALTY = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3,
    "INFORMATIONAL": 0,
}
CONFIDENCE_WEIGHT = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
}

RISK_EXPLANATION = (
    "This indicator reflects findings detected within the analyzed scope. "
    "It is not a measure of overall protocol security."
)
RISK_SCOPE_NOTE = "according to the analyzed scope"
RISK_LOW_BAND_NOTE = "A LOW automated risk indicator does not mean that deployment is safe."


class ScoreError(Exception):
    """Raised when the input report is too malformed to score."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ScoreError(message)


def normalized_location_key(locations: Any) -> str:
    """Identity is anchored on the finding's *primary* (first) location only.

    Deliberately not the union of every location: a single draft finding's
    own `locations[]` may already legitimately list several affected sites
    for one root cause (see references/severity-and-score.md, section 2).
    Keying on the full set instead of the primary site would make two
    draft findings for the same root cause fail to match the moment their
    location lists were not byte-identical - defeating deduplication.
    """
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return ""
    loc = locations[0]
    file_ = str(loc.get("file") or "")
    contract = str(loc.get("contract") or "")
    function = str(loc.get("function") or "")
    return "%s#%s#%s" % (file_, contract, function)


def compute_stable_key(finding: Dict[str, Any]) -> str:
    category = str(finding.get("category") or "")
    signature = str(finding.get("signature") or "")
    location_key = normalized_location_key(finding.get("locations"))
    raw = "%s|%s|%s" % (category, location_key, signature)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return "sha256:" + digest


def compute_id(stable_key: str) -> str:
    digest = stable_key.split(":", 1)[1] if ":" in stable_key else stable_key
    return "F-" + digest[:8]


def _validate_finding_shape(finding: Any, index: int) -> None:
    _require(isinstance(finding, dict), "findings[%d] must be an object" % index)
    category = finding.get("category")
    _require(isinstance(category, str) and category, "findings[%d].category must be a non-empty string" % index)
    severity = finding.get("severity")
    _require(severity in VALID_SEVERITIES, "findings[%d].severity must be one of %s" % (index, sorted(VALID_SEVERITIES)))
    confidence = finding.get("confidence")
    _require(confidence in VALID_CONFIDENCES, "findings[%d].confidence must be one of %s" % (index, sorted(VALID_CONFIDENCES)))
    status = finding.get("status", "suspected")
    _require(status in VALID_STATUSES, "findings[%d].status must be one of %s" % (index, sorted(VALID_STATUSES)))
    if status == "informational":
        _require(severity == "INFORMATIONAL", "findings[%d]: status 'informational' requires severity 'INFORMATIONAL'" % index)
    locations = finding.get("locations", [])
    _require(isinstance(locations, list), "findings[%d].locations must be an array" % index)
    evidence = finding.get("evidence", [])
    _require(isinstance(evidence, list), "findings[%d].evidence must be an array" % index)


def merge_group(stable_key: str, group: List[Dict[str, Any]]) -> Dict[str, Any]:
    primary = dict(group[0])

    best_severity = max(group, key=lambda f: SEVERITY_ORDER.index(f["severity"]))["severity"]
    best_confidence = max(group, key=lambda f: CONFIDENCE_ORDER.index(f["confidence"]))["confidence"]

    merged_locations: List[Dict[str, Any]] = []
    seen_locations = set()
    for finding in group:
        for loc in finding.get("locations", []) or []:
            if not isinstance(loc, dict):
                continue
            key = (loc.get("file"), loc.get("lineStart"), loc.get("lineEnd"), loc.get("contract"), loc.get("function"))
            if key in seen_locations:
                continue
            seen_locations.add(key)
            merged_locations.append(loc)

    merged_evidence: List[str] = []
    for finding in group:
        for line in finding.get("evidence", []) or []:
            if line not in merged_evidence:
                merged_evidence.append(line)
    merged_evidence = merged_evidence[:5]

    primary["stableKey"] = stable_key
    primary["id"] = compute_id(stable_key)
    primary["severity"] = best_severity
    primary["confidence"] = best_confidence
    primary["locations"] = merged_locations
    primary["evidence"] = merged_evidence
    primary["mergedCount"] = len(group)
    return primary


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: "Dict[str, List[Dict[str, Any]]]" = {}
    order: List[str] = []
    for finding in findings:
        key = compute_stable_key(finding)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)
    return [merge_group(key, groups[key]) for key in order]


def score_band(score: int) -> str:
    if score >= 85:
        return "LOW"
    if score >= 60:
        return "MODERATE"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"


def compute_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_penalty = 0.0
    has_high_confidence_critical = False
    for finding in findings:
        if finding.get("status") == "informational":
            continue
        severity = finding["severity"]
        confidence = finding["confidence"]
        total_penalty += SEVERITY_PENALTY[severity] * CONFIDENCE_WEIGHT[confidence]
        if severity == "CRITICAL" and confidence == "high":
            has_high_confidence_critical = True

    score = 100.0 - total_penalty
    score = max(score, 0.0)
    if has_high_confidence_critical:
        score = min(score, 40.0)
    score_int = int(round(score))

    band = score_band(score_int)
    return {
        "scoreStatus": "computed",
        "score": score_int,
        "band": band,
        "explanation": RISK_EXPLANATION,
        "scopeNote": RISK_SCOPE_NOTE,
        **({"lowBandNote": RISK_LOW_BAND_NOTE} if band == "LOW" else {}),
    }


def score_report(report: Dict[str, Any]) -> Dict[str, Any]:
    _require(isinstance(report, dict), "report must be a JSON object")
    findings = report.get("findings", [])
    _require(isinstance(findings, list), "report.findings must be an array")
    for index, finding in enumerate(findings):
        _validate_finding_shape(finding, index)

    deduped = deduplicate_findings(findings)
    deduped.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f["category"], f["id"]))
    risk_indicator = compute_score(deduped)

    updated = dict(report)
    updated["findings"] = deduped
    updated["riskIndicator"] = risk_indicator
    updated["scoreStatus"] = risk_indicator["scoreStatus"]
    updated["scoreVersion"] = SCORE_VERSION
    return updated


def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _read_input(path: Optional[str]) -> Dict[str, Any]:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ScoreError("input is not valid JSON: %s" % exc) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="score.py",
        description="Deterministically deduplicate findings and compute the Automated Risk Indicator for a draft report.",
    )
    parser.add_argument("path", nargs="?", default=None, help="Draft report JSON file. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the updated report to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        report = _read_input(args.path)
        updated = score_report(report)
    except ScoreError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(updated, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
