#!/usr/bin/env python3
"""Deterministic evidence-locality check (V3 Block 2, R3, docs/decisiones.md
D-069).

Checks whether each finding's `evidence[]` lines are textually REAL - do
they actually appear, together, at or near ONE of the source locations the
finding itself claims (`locations[]` - every declared location is checked,
not only the first)? This never re-judges
whether a finding is a correct security judgment (that stays Step 6's own
call, and no code path here adds, removes, or reclassifies a finding by
itself) - it only checks whether the CITED PROOF for that judgment is real,
deterministically, against the actual source text.

Intended use (SKILL.md Step 6, before Step 7 scoring): the AI runs this on
its own draft findings against the same source it just analyzed. Per the
result:
  - "verified": every evidence line was found within (or very near) the
    SAME one declared location - no action needed. A finding with several
    locations verifies as soon as any one of them accounts for all of its
    evidence; evidence does not need to cluster near every location.
  - "location_mismatch": every evidence line exists SOMEWHERE in the
    finding's referenced file(s), but no single declared location's window
    contains all of it - the location is probably wrong or incomplete. The
    finding must be corrected (fix the location) or, if the
    right location can't be determined, DOWNGRADED - never left as-is with
    a misleading location, and never "fixed" by inventing a new location
    that wasn't independently verified.
  - "fabricated": at least one evidence line does not appear ANYWHERE in
    the claimed file at all. The finding must be REMOVED or downgraded to
    low confidence pending re-examination - never kept as HIGH/CRITICAL on
    unverifiable proof, and the evidence must never be rewritten/replaced
    with a different quote to make it pass; that would be inventing data
    exactly like a fabricated finding would be.
  - "unverifiable": no locations, or the caller did not provide source text
    for any of them. Never treated as passing (a missing check is not a
    passing check) and never treated as an automatic rejection either
    (the caller may not have had the file available) - the caller decides,
    same posture as ingest_onchain.py's own verified/unverified distinction.

This module makes NO judgment about severity/category/confidence itself
and adds no new detector - it is a text-presence check over data the
pipeline already has (the finding's own evidence[] and locations[], plus
the source text the analysis step already read). Standard library only.
No network access, no LLM calls. Python 3.8+.
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

EVIDENCE_LOCALITY_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

DEFAULT_TOLERANCE_LINES = 3  # a claimed lineStart/lineEnd off by a few lines is still "near" it.

_WHITESPACE_RE = re.compile(r"\s+")


class EvidenceLocalityError(Exception):
    """Raised only for malformed input (not a JSON object/array, wrong
    types) - never for a finding whose evidence simply fails to verify;
    that is a normal, expected result value, not an error."""


def _normalize(text: str) -> str:
    """Collapses whitespace runs to a single space and strips ends, so
    Solidity's own indentation/formatting can never cause a false
    mismatch - this never changes any other character, so a genuinely
    different token/expression still fails to match."""
    return _WHITESPACE_RE.sub(" ", text).strip()


def _line_window(lines: List[str], line_start: Optional[int], line_end: Optional[int], tolerance: int) -> str:
    if not isinstance(line_start, int) or not isinstance(line_end, int):
        return ""
    start = max(1, line_start - tolerance)
    end = min(len(lines), line_end + tolerance)
    if start > end:
        return ""
    return "\n".join(lines[start - 1:end])


def verify_finding_evidence(
    finding: Dict[str, Any], source_files: Dict[str, str], tolerance_lines: int = DEFAULT_TOLERANCE_LINES
) -> Dict[str, Any]:
    """Checks ONE finding's evidence[] against ALL of its declared
    locations[] (not only the first) in already-provided source text(s).
    Pure function; raises nothing - an unverifiable input is a result value
    ("unverifiable"), never an exception, since a caller iterating many
    findings must never have one malformed entry abort the whole check
    (matching ingest_onchain.py/build_bundle()'s own per-item-never-aborts
    convention). Verification is per-location: a finding verifies as soon
    as ONE declared location's window contains every evidence line - this
    is deliberately not a line-by-line OR across scattered locations, so a
    finding whose evidence genuinely spans two unrelated places still
    surfaces as location_mismatch (a real signal that locations[] should be
    tightened), not a false "verified"."""
    evidence = finding.get("evidence")
    locations = finding.get("locations")
    signature = finding.get("signature") if isinstance(finding.get("signature"), str) else None

    if not isinstance(evidence, list) or not evidence:
        return {"status": "unverifiable", "signature": signature, "reason": "finding has no evidence to check"}
    if not isinstance(locations, list) or not locations:
        return {"status": "unverifiable", "signature": signature, "reason": "finding has no locations to check against"}

    valid_locations = [loc for loc in locations if isinstance(loc, dict)]
    if not valid_locations:
        return {"status": "unverifiable", "signature": signature, "reason": "finding has no locations to check against"}

    checkable_locations = [loc for loc in valid_locations if isinstance(loc.get("file"), str) and loc.get("file") in source_files]
    if not checkable_locations:
        return {"status": "unverifiable", "signature": signature, "reason": "source text for the finding's location file(s) was not provided"}

    clean_evidence = [line for line in evidence if isinstance(line, str) and line.strip()]

    normalized_file_text: Dict[str, str] = {}
    for loc in checkable_locations:
        file_path = loc["file"]
        if file_path not in normalized_file_text:
            normalized_file_text[file_path] = _normalize(source_files[file_path])

    missing_everywhere = [
        line for line in clean_evidence
        if not any(_normalize(line) in text for text in normalized_file_text.values())
    ]
    if missing_everywhere:
        return {
            "status": "fabricated",
            "signature": signature,
            "reason": "evidence line(s) do not appear anywhere in the finding's referenced file(s): %r" % missing_everywhere,
        }

    for loc in checkable_locations:
        source_lines = source_files[loc["file"]].splitlines()
        window_text = _normalize(_line_window(source_lines, loc.get("lineStart"), loc.get("lineEnd"), tolerance_lines))
        if all(_normalize(line) in window_text for line in clean_evidence):
            return {"status": "verified", "signature": signature, "reason": None}

    return {
        "status": "location_mismatch",
        "signature": signature,
        "reason": "evidence exists in the finding's referenced file(s) but no single declared location's window "
        "(+/- %d lines) contains all of it" % tolerance_lines,
    }


def verify_report_evidence(
    findings: Any, source_files: Any, tolerance_lines: int = DEFAULT_TOLERANCE_LINES
) -> List[Dict[str, Any]]:
    """G-equivalent entry point: one result per finding, same order, never
    fewer/more than len(findings) - a caller can zip() this 1:1 against
    the original findings list."""
    if not isinstance(findings, list):
        raise EvidenceLocalityError("findings must be an array")
    if not isinstance(source_files, dict) or not all(isinstance(v, str) for v in source_files.values()):
        raise EvidenceLocalityError("sourceFiles must be an object mapping file path -> source text")
    return [
        verify_finding_evidence(f, source_files, tolerance_lines) if isinstance(f, dict)
        else {"status": "unverifiable", "signature": None, "reason": "finding entry is not an object"}
        for f in findings
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _read_json_file(path: Optional[str]) -> Any:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvidenceLocalityError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence_locality.py",
        description=(
            "Checks whether each finding's evidence[] is textually real at its claimed location. "
            "Never judges whether a finding is correct - only whether its cited proof is real."
        ),
    )
    parser.add_argument(
        "input", nargs="?", default=None,
        help="Path to a JSON file: {\"findings\": [...], \"sourceFiles\": {\"path\": \"text\", ...}}. Reads stdin if omitted.",
    )
    parser.add_argument("--tolerance-lines", type=int, default=DEFAULT_TOLERANCE_LINES, help="Line-window slack around lineStart/lineEnd (default: %d)." % DEFAULT_TOLERANCE_LINES)
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = _read_json_file(args.input)
        if not isinstance(payload, dict):
            raise EvidenceLocalityError("%s must contain a JSON object" % (args.input or "stdin"))
        results = verify_report_evidence(payload.get("findings"), payload.get("sourceFiles"), args.tolerance_lines)
    except (EvidenceLocalityError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    result = {
        "evidenceLocalityVersion": EVIDENCE_LOCALITY_VERSION,
        "results": results,
        "verifiedCount": sum(1 for r in results if r["status"] == "verified"),
        "flaggedCount": sum(1 for r in results if r["status"] in ("fabricated", "location_mismatch")),
    }
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
