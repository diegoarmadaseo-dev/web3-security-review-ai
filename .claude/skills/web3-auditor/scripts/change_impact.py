#!/usr/bin/env python3
"""Deterministic change-impact classification over an already-computed
diff_reports.py `preprocess`-mode structural diff (V3 Block 3, B4,
docs/decisiones.md D-071).

Consumes ONLY the output of `diff_reports.py preprocess` (never raw
preprocess.py artifacts, never re-diffs anything - diff_functions/
diff_state_variables/diff_system_graph in diff_reports.py are reused
UNCHANGED and are this module's only input) and classifies each matched
contract, and the change overall, as one of:

  - "NO_CHANGE": nothing differs for that contract.
  - "SAFE": every difference is a pure addition (new function, new state
    variable, new contract) - nothing existing was removed, narrowed, or
    retyped.
  - "REVIEW_RECOMMENDED": at least one structural fact suggests the public
    surface or storage shape may have narrowed or shifted - a function or
    state variable removed, a function's visibility WIDENED, a modifier
    REMOVED from a function, a state variable's type changed, or (when
    `systemGraphDelta.status == "computed"`, pro mode only) an `inherits`
    edge removed.

This is a purely STRUCTURAL classification, independent of `findings[]` -
its entire point is to surface a change worth a second look even when no
detector/AI finding fired on it at all (docs/decisiones.md D-071). It is
a deterministic fact/classification, never itself a finding, never a
severity on any finding, and never feeds `score.py` (this module does not
touch reports/findings/score.py in any way - it only reads a diff object
and returns a new, separate classification object).

Visibility "widened" ranking, narrowest to broadest: private < internal <
external ~ public (external/public are treated as equally broad here -
both are externally callable, which is the property that matters for this
classification; the ABI-level distinction between them is out of scope).

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

CHANGE_IMPACT_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_VISIBILITY_RANK = {"private": 0, "internal": 1, "external": 2, "public": 2}


class ChangeImpactError(Exception):
    """Raised only for malformed input (not a diff_reports.py `preprocess`
    -mode output) - never for "no risky change found", a normal result."""


def _visibility_widened(from_vis: Any, to_vis: Any) -> bool:
    a, b = _VISIBILITY_RANK.get(from_vis), _VISIBILITY_RANK.get(to_vis)
    if a is None or b is None:
        return False  # unrecognized value: never guess, never flag from a guess.
    return b > a


def _classify_contract(entry: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []

    if entry.get("functionsRemoved"):
        reasons.append("function(s) removed: %s" % sorted(entry["functionsRemoved"]))
    if entry.get("stateVariablesRemoved"):
        reasons.append("state variable(s) removed: %s" % sorted(entry["stateVariablesRemoved"]))

    for changed in entry.get("functionsChanged") or []:
        changes = changed.get("changes") or {}
        vis = changes.get("visibility")
        if vis and _visibility_widened(vis.get("from"), vis.get("to")):
            reasons.append("%s: visibility widened %s -> %s" % (changed.get("identity"), vis.get("from"), vis.get("to")))
        if changes.get("modifiersRemoved"):
            reasons.append("%s: modifier(s) removed: %s" % (changed.get("identity"), sorted(changes["modifiersRemoved"])))

    for changed in entry.get("stateVariablesChanged") or []:
        changes = changed.get("changes") or {}
        if "type" in changes:
            reasons.append("%s: type changed %s -> %s" % (changed.get("name"), changes["type"].get("from"), changes["type"].get("to")))

    has_additions = bool(entry.get("functionsAdded") or entry.get("stateVariablesAdded"))
    has_any_change = has_additions or bool(reasons) or bool(entry.get("functionsChanged") or entry.get("stateVariablesChanged"))

    if reasons:
        classification = "REVIEW_RECOMMENDED"
    elif has_any_change:
        classification = "SAFE"
    else:
        classification = "NO_CHANGE"

    return {"classification": classification, "reasons": reasons}


def compute_change_impact(diff: Any) -> Dict[str, Any]:
    """Pure function over one diff_reports.py `preprocess`-mode output."""
    if not isinstance(diff, dict):
        raise ChangeImpactError("input must be a JSON object (diff_reports.py 'preprocess'-mode output)")
    if diff.get("mode") != "preprocess" or not isinstance(diff.get("functionSurfaceDelta"), dict):
        raise ChangeImpactError("input must be diff_reports.py 'preprocess'-mode output (mode=='preprocess' with a functionSurfaceDelta object)")

    per_contract = {key: _classify_contract(entry) for key, entry in diff["functionSurfaceDelta"].items()}

    reasons: List[str] = []
    if diff.get("contractsRemoved"):
        reasons.append("contract(s) removed: %s" % sorted(diff["contractsRemoved"]))
    system_graph_delta = diff.get("systemGraphDelta") or {}
    if system_graph_delta.get("status") == "computed":
        removed_inherits = [e for e in system_graph_delta.get("edgesRemoved") or [] if e.get("kind") == "inherits"]
        if removed_inherits:
            reasons.append("inheritance edge(s) removed: %s" % [(e.get("from"), e.get("to")) for e in removed_inherits])

    classifications = {v["classification"] for v in per_contract.values()} | ({"REVIEW_RECOMMENDED"} if reasons else set())
    if "REVIEW_RECOMMENDED" in classifications or reasons:
        overall = "REVIEW_RECOMMENDED"
    elif "SAFE" in classifications or diff.get("contractsAdded"):
        overall = "SAFE"
    else:
        overall = "NO_CHANGE"

    return {
        "changeImpactVersion": CHANGE_IMPACT_VERSION,
        "overall": overall,
        "overallReasons": reasons,
        "perContract": per_contract,
        "note": "Purely structural classification, independent of findings[] - never itself a finding, never affects score.py.",
    }


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
        raise ChangeImpactError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="change_impact.py",
        description=(
            "Deterministic change-impact classification over a diff_reports.py 'preprocess'-mode "
            "structural diff - flags a regression even when no finding fired on it."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a diff_reports.py 'preprocess'-mode output JSON. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        diff = _read_json_file(args.input)
        result = compute_change_impact(diff)
    except (ChangeImpactError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
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
