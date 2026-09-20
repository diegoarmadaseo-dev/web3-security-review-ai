#!/usr/bin/env python3
"""Deterministic pass/fail gate over a bundle of already-computed advisory
outputs (V3 Block 8, G2, docs/decisiones.md D-076).

Reads the SAME bundle shape render_advisory_summary.py (E3) already
consumes - {sectionKey: toolOutputJSON}, one already-computed advisory
tool's own JSON output per key - and reduces EACH tool's own EXISTING
signal to one of three outcomes, via an EXPLICIT, per-tool table below,
never a guess: OK (nothing to flag), FLAG (the tool's own output already
says so), or NOT_ASSESSED (this tool's status/signal for this run is one
this module does not recognize, or the tool was not run/not computed) -
an unrecognized or missing signal NEVER becomes OK.

MOST tools expose a single top-level `status` string with an unambiguous
OK/FLAG vocabulary (e.g. constructor_zero_address.py's "clean"/"flagged").
A few do not, and are handled by their OWN small function below, each
reading whichever field ACTUALLY carries that tool's signal - verified
against each tool's own real source before being encoded here, never
assumed from a field name alone (D-054):
  - privilegePath (B2) and bytecodeAdvisory (B3): `status` is always
    "computed" regardless of findings; the real signal is whether `paths`/
    `advisories` is non-empty.
  - changeImpact (B4): has no `status` field at all; its signal is the
    `overall` field (NO_CHANGE/SAFE/REVIEW_RECOMMENDED).
  - upgradeGap (C3): has no top-level `status`; its signal is whether
    `contractsFlagged` is non-empty.
  - bytecodeCompilerBugs (D3): its own `status` only reports whether a
    solc version could be EXTRACTED from bytecode, never whether a bug
    matched - the real signal is the NESTED `compilerBugReport.status`,
    evaluated by reusing compilerBugs (C2)'s own rule unchanged.
  - proxyFingerprint (C1): "matched"/"no_match" are both purely
    DESCRIPTIVE (finding a known proxy pattern is not itself a problem) -
    this tool never contributes a FLAG.
A bundle key this module does not recognize at all (a future tool, or a
typo) is NOT_ASSESSED, the same as a recognized tool reporting a signal
value outside its own known vocabulary.

NO NEW JUDGMENT: every outcome above is read directly off a field the
named tool already computed - this module adds no severity, no new
detection, and never inspects raw source/bytecode itself. Never mutates
the input bundle, and never modifies any tool's own output in place (E3
remains the place to see a tool's full result rendered).

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

ADVISORY_GATE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_GATE_FAILED = 2  # only returned when --strict-exit is passed and overall != "PASS" (same opt-in convention as pr_gate.py's --strict-exit, D-068).

_OK = "OK"
_FLAG = "FLAG"
_NOT_ASSESSED = "NOT_ASSESSED"

# Tools whose signal is a single top-level `status` string with an
# unambiguous OK/FLAG vocabulary. Any status value NOT listed here for
# that tool is NOT_ASSESSED, never guessed as OK.
_SIMPLE_STATUS_MAP: Dict[str, Dict[str, str]] = {
    "storageLayout": {"unchanged": _OK, "safe_append": _OK, "collision_risk": _FLAG},
    "proxyFingerprint": {"matched": _OK, "no_match": _OK},
    "compilerBugs": {"not_affected": _OK, "affected": _FLAG},
    "initializerSafety": {"unchanged": _OK, "flagged": _FLAG},
    "bytecodeSize": {"within_limit": _OK, "exceeds_limit": _FLAG},
    "delegatecallCycle": {"no_cycle": _OK, "cycle_found": _FLAG, "not_computed": _NOT_ASSESSED},
    "constructorZeroAddress": {"clean": _OK, "no_constructor": _OK, "flagged": _FLAG},
    "upgradeAuthorityGuard": {"clean": _OK, "flagged": _FLAG},
    "bytecodeMetamorphicSignal": {"no_signal": _OK, "signal_present": _FLAG},
    "implementationConstructorSignal": {"clean": _OK, "flagged": _FLAG, "not_computed": _NOT_ASSESSED},
}


class AdvisoryGateError(Exception):
    """Raised only for a malformed top-level bundle - never for an empty
    bundle or a tool section this module cannot assess, both handled as
    NOT_ASSESSED for that one tool, never a hard failure of the whole gate."""


def _simple(section: Dict[str, Any], status_map: Dict[str, str]) -> Tuple[str, Any]:
    raw = section.get("status")
    if not isinstance(raw, str):
        return _NOT_ASSESSED, raw  # non-string status (list/dict/null/number/bool) is never a dict-key lookup - would raise TypeError on an unhashable value.
    return status_map.get(raw, _NOT_ASSESSED), raw


def _evaluate_privilege_path(section: Dict[str, Any]) -> Tuple[str, Any]:
    raw = section.get("status")
    if raw != "computed":
        return _NOT_ASSESSED, raw
    paths = section.get("paths")
    if not isinstance(paths, list):
        return _NOT_ASSESSED, raw
    return (_FLAG if paths else _OK), raw


def _evaluate_bytecode_advisory(section: Dict[str, Any]) -> Tuple[str, Any]:
    raw = section.get("status")
    if raw != "computed":
        return _NOT_ASSESSED, raw
    advisories = section.get("advisories")
    if not isinstance(advisories, list):
        return _NOT_ASSESSED, raw
    return (_FLAG if advisories else _OK), raw


def _evaluate_change_impact(section: Dict[str, Any]) -> Tuple[str, Any]:
    raw = section.get("overall")
    if not isinstance(raw, str):
        return _NOT_ASSESSED, raw  # same non-hashable-status guard as _simple() above.
    mapping = {"NO_CHANGE": _OK, "SAFE": _OK, "REVIEW_RECOMMENDED": _FLAG}
    return mapping.get(raw, _NOT_ASSESSED), raw


def _evaluate_upgrade_gap(section: Dict[str, Any]) -> Tuple[str, Any]:
    flagged = section.get("contractsFlagged")
    if not isinstance(flagged, list):
        return _NOT_ASSESSED, None
    return (_FLAG if flagged else _OK), flagged


def _evaluate_bytecode_compiler_bugs(section: Dict[str, Any]) -> Tuple[str, Any]:
    raw = section.get("status")
    if raw != "version_extracted":
        return _NOT_ASSESSED, raw
    nested = section.get("compilerBugReport")
    if not isinstance(nested, dict):
        return _NOT_ASSESSED, raw
    outcome, _nested_raw = _simple(nested, _SIMPLE_STATUS_MAP["compilerBugs"])
    return outcome, raw


_SPECIAL_EVALUATORS = {
    "privilegePath": _evaluate_privilege_path,
    "bytecodeAdvisory": _evaluate_bytecode_advisory,
    "changeImpact": _evaluate_change_impact,
    "upgradeGap": _evaluate_upgrade_gap,
    "bytecodeCompilerBugs": _evaluate_bytecode_compiler_bugs,
}


def _evaluate_tool(key: str, section: Any) -> Tuple[str, Any]:
    if not isinstance(section, dict):
        return _NOT_ASSESSED, None
    if key in _SPECIAL_EVALUATORS:
        return _SPECIAL_EVALUATORS[key](section)
    if key in _SIMPLE_STATUS_MAP:
        return _simple(section, _SIMPLE_STATUS_MAP[key])
    return _NOT_ASSESSED, section.get("status")


def compute_advisory_gate(bundle: Any) -> Dict[str, Any]:
    """Pure function; never mutates `bundle`."""
    if not isinstance(bundle, dict):
        raise AdvisoryGateError("bundle must be a JSON object mapping known section keys to tool outputs")

    tools: Dict[str, Dict[str, Any]] = {}
    ok_count = flag_count = not_assessed_count = 0
    for key in sorted(bundle):
        outcome, raw = _evaluate_tool(key, bundle[key])
        tools[key] = {"outcome": outcome, "rawSignal": raw}
        if outcome == _OK:
            ok_count += 1
        elif outcome == _FLAG:
            flag_count += 1
        else:
            not_assessed_count += 1

    if flag_count > 0:
        overall = "FAIL"
    elif not_assessed_count > 0 or ok_count == 0:
        overall = "INCOMPLETE"
    else:
        overall = "PASS"

    return {
        "advisoryGateVersion": ADVISORY_GATE_VERSION,
        "overall": overall,
        "okCount": ok_count,
        "flagCount": flag_count,
        "notAssessedCount": not_assessed_count,
        "tools": tools,
        "note": "Aggregates each tool's own already-computed signal only - no new severity or judgment; an unrecognized or missing per-tool signal is NOT_ASSESSED, never PASS.",
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
        raise AdvisoryGateError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="advisory_gate.py",
        description=(
            "Deterministic pass/fail gate aggregating already-computed advisory tool outputs "
            "(same bundle shape as render-advisory-summary). No new judgment or severity."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file mapping known section keys to tool outputs. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    parser.add_argument("--strict-exit", action="store_true", help="Exit with EXIT_GATE_FAILED (2) when overall != 'PASS', instead of the default EXIT_OK (0).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        bundle = _read_json_file(args.input)
        result = compute_advisory_gate(bundle)
    except (AdvisoryGateError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    if args.strict_exit and result["overall"] != "PASS":
        return EXIT_GATE_FAILED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
