#!/usr/bin/env python3
"""Deterministic check for OpenZeppelin-style reserved storage-gap arrays
across an upgrade (V3 Block 4, C3, docs/decisiones.md D-072).

STRUCTURAL ONLY - this module reports WHAT CHANGED about a `__gap`-named
reserved array between two versions of the same contract; it never judges
whether a given shrink amount is correctly compensated by newly-added real
variables elsewhere (shrinking `__gap` by exactly as much as new state was
added is the INTENDED, safe way to use this convention - a bare "shrunk"
result is not itself a defect, it is a fact a reviewer must cross-check
against what else changed, e.g. via storage_layout.py/B1). This module
NEVER replaces B1 (`storage_layout.py`): B1 answers "did the declared
variables move", this one answers only "what happened to the named
reserved-gap slot(s)", a narrower, convention-specific question B1 does
not ask (B1 has no concept of `__gap` at all).

Convention detected: a state variable whose name matches `__gap`/`__gapN`
(the OpenZeppelin pattern for a base contract with more than one reserved
gap in a multi-inheritance chain) and whose type is a FIXED-SIZE array
(`T[N]`, literal N) - the gap's own element type is intentionally never
required to match between versions (only used by convention, e.g.
`uint256[50]`), only the SIZE N is tracked here.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

UPGRADE_GAP_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_GAP_NAME_RE = re.compile(r"^__gap[0-9]*$")
_FIXED_ARRAY_SIZE_RE = re.compile(r"\[\s*(\d+)\s*\]\s*$")


class UpgradeGapError(Exception):
    """Raised only for malformed input - never for "no gap present" or
    "gap unchanged", both normal, expected result values."""


def _gap_sizes(contract: Dict[str, Any]) -> Dict[str, int]:
    """name -> declared array size, for every state variable matching the
    __gap naming convention with a literal fixed-size array type. A
    __gap-named variable whose type is NOT a parseable fixed-size array
    (e.g. a mapping, or a malformed type string) is skipped, never guessed."""
    sizes: Dict[str, int] = {}
    for v in contract.get("stateVariables") or []:
        if not isinstance(v, dict):
            continue
        name = v.get("name")
        type_text = v.get("type")
        if not isinstance(name, str) or not _GAP_NAME_RE.match(name):
            continue
        if not isinstance(type_text, str):
            continue
        match = _FIXED_ARRAY_SIZE_RE.search(type_text)
        if not match:
            continue
        sizes[name] = int(match.group(1))
    return sizes


def diff_upgrade_gap(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
    """Pure function: compares __gap-convention arrays of two contract
    dicts. Never mutates either input."""
    v1_gaps = _gap_sizes(c1)
    v2_gaps = _gap_sizes(c2)
    names = sorted(set(v1_gaps) | set(v2_gaps))

    gaps: Dict[str, Dict[str, Any]] = {}
    for name in names:
        before = v1_gaps.get(name)
        after = v2_gaps.get(name)
        if before is None:
            status = "added"
        elif after is None:
            status = "removed"
        elif after == before:
            status = "unchanged"
        elif after > before:
            status = "expanded"
        else:
            status = "shrunk"
        gaps[name] = {"status": status, "sizeBefore": before, "sizeAfter": after}

    if not names:
        overall = "not_present"
    elif any(g["status"] == "removed" for g in gaps.values()):
        overall = "removed"
    elif any(g["status"] == "shrunk" for g in gaps.values()):
        overall = "shrunk"
    elif any(g["status"] in ("expanded", "added") for g in gaps.values()):
        overall = "expanded"
    else:
        overall = "unchanged"

    return {"overall": overall, "gaps": gaps}


def compute_upgrade_gap_report(v1: Any, v2: Any) -> Dict[str, Any]:
    if not isinstance(v1, dict) or not isinstance(v1.get("contracts"), list):
        raise UpgradeGapError("v1 must be a preprocess.py output (JSON object with a contracts array)")
    if not isinstance(v2, dict) or not isinstance(v2.get("contracts"), list):
        raise UpgradeGapError("v2 must be a preprocess.py output (JSON object with a contracts array)")

    v1_by_key = {c["key"]: c for c in v1["contracts"] if isinstance(c, dict) and c.get("key")}
    v2_by_key = {c["key"]: c for c in v2["contracts"] if isinstance(c, dict) and c.get("key")}
    matched = sorted(set(v1_by_key) & set(v2_by_key))

    results = {key: diff_upgrade_gap(v1_by_key[key], v2_by_key[key]) for key in matched}
    flagged = sorted(key for key, r in results.items() if r["overall"] in ("removed", "shrunk"))

    return {
        "upgradeGapVersion": UPGRADE_GAP_VERSION,
        "contractsCompared": matched,
        "contractsFlagged": flagged,
        "results": results,
        "note": "Structural only - a 'shrunk' gap is the INTENDED way to consume reserved slots for new state, not itself a defect; never replaces storage_layout.py (B1).",
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


def _read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UpgradeGapError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="upgrade_gap.py",
        description="Deterministic OpenZeppelin-style __gap reserved-array check between two preprocess.py runs. Structural only, never replaces storage_layout.py.",
    )
    parser.add_argument("v1", help="Path to the V1 (baseline) preprocess.py output JSON.")
    parser.add_argument("v2", help="Path to the V2 (candidate upgrade) preprocess.py output JSON.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        v1 = _read_json_file(args.v1)
        v2 = _read_json_file(args.v2)
        result = compute_upgrade_gap_report(v1, v2)
    except (UpgradeGapError, OSError) as exc:
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
