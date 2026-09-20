#!/usr/bin/env python3
"""Deterministic storage-layout compatibility check between two versions of
the same contract (V3 Block 3, B1, docs/decisiones.md D-071).

Compares each matched contract's OWN declared `stateVariables` (as already
parsed by preprocess.py - name/type/order, never re-parsed here) between a
V1 (baseline, e.g. currently deployed) and V2 (candidate upgrade) run of
preprocess.py, and classifies the result as a purely POSITIONAL fact:

  - "unchanged": both sides have the exact same (name, type) list.
  - "safe_append": V1's list is an exact, untouched prefix of V2's list -
    every variable V1 already had keeps its name, type AND position, and
    V2 only ADDS new variables after them. This is the one shape that is
    always storage-layout-safe regardless of packing details, because
    nothing before the append point moves.
  - "collision_risk": V1's list is NOT a prefix of V2's list - something
    was removed, reordered, renamed, or retyped at or before the point
    where the two lists diverge. Every variable at or after that point is
    now at risk of reading/writing the wrong storage slot.

SCOPE, STATED EXPLICITLY: this compares only variables DECLARED DIRECTLY in
this contract (preprocess.py's per-contract `stateVariables`, never the
inherited base contracts' own variables, which occupy earlier slots in a
real deployment) and reasons about DECLARATION ORDER, never computed byte
offsets/packing (preprocess.py has no slot/packing computation - see
docs/decisiones.md D-071). `constant`/`immutable` variables are EXCLUDED
from the comparison entirely: neither occupies a real storage slot (a
`constant` is inlined at compile time, an `immutable` lives in the
contract's own bytecode, never in storage) - including them positionally
would flag a brand-new `constant` inserted before a real variable as a
"collision" even though nothing about the actual storage layout moved. A real Solidity compiler can pack multiple small
variables into one 32-byte slot; two positionally-identical (name, type)
lists are always packing-identical (the compiler is a pure function of
that), so "safe_append"/"unchanged" are sound conclusions. A "collision_risk"
result does NOT itself prove an actual on-chain collision (e.g. a type
change between two types of the same byte width, in isolation, might still
pack identically) - it is a conservative, deterministic FLAG that something
moved, never a full byte-level packing simulation. Never a finding by
itself and never auto-severity - purely advisory input for further review.

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

STORAGE_LAYOUT_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1


class StorageLayoutError(Exception):
    """Raised only for malformed input (not a JSON object, missing
    `contracts` array) - never for a contract that simply has a layout
    change, which is a normal, expected result value."""


def _own_state_vars(contract: Dict[str, Any]) -> List[Tuple[str, str]]:
    out = []
    for v in contract.get("stateVariables") or []:
        if not isinstance(v, dict) or not isinstance(v.get("name"), str):
            continue
        if v.get("constant") or v.get("immutable"):
            continue  # never occupies a real storage slot - see module docstring.
        out.append((v["name"], v.get("type") if isinstance(v.get("type"), str) else None))
    return out


def diff_storage_layout(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
    """Pure function: compares two contract dicts' own stateVariables[].
    Never mutates either input."""
    v1 = _own_state_vars(c1)
    v2 = _own_state_vars(c2)

    common = 0
    while common < len(v1) and common < len(v2) and v1[common] == v2[common]:
        common += 1

    if common == len(v1):
        status = "unchanged" if len(v2) == len(v1) else "safe_append"
        first_divergence_index = None
        collisions: List[Dict[str, Any]] = []
    else:
        status = "collision_risk"
        first_divergence_index = common
        collisions = [
            {
                "index": i,
                "v1": {"name": v1[i][0], "type": v1[i][1]} if i < len(v1) else None,
                "v2": {"name": v2[i][0], "type": v2[i][1]} if i < len(v2) else None,
            }
            for i in range(common, max(len(v1), len(v2)))
        ]

    return {
        "status": status,
        "v1Count": len(v1),
        "v2Count": len(v2),
        "firstDivergenceIndex": first_divergence_index,
        "collisions": collisions,
    }


def compute_storage_layout_report(v1: Any, v2: Any) -> Dict[str, Any]:
    """G-equivalent entry point over two full preprocess.py artifacts.
    Raises StorageLayoutError only for malformed top-level input."""
    if not isinstance(v1, dict) or not isinstance(v1.get("contracts"), list):
        raise StorageLayoutError("v1 must be a preprocess.py output (JSON object with a contracts array)")
    if not isinstance(v2, dict) or not isinstance(v2.get("contracts"), list):
        raise StorageLayoutError("v2 must be a preprocess.py output (JSON object with a contracts array)")

    v1_by_key = {c["key"]: c for c in v1["contracts"] if isinstance(c, dict) and c.get("key")}
    v2_by_key = {c["key"]: c for c in v2["contracts"] if isinstance(c, dict) and c.get("key")}
    matched = sorted(set(v1_by_key) & set(v2_by_key))

    results = {key: diff_storage_layout(v1_by_key[key], v2_by_key[key]) for key in matched}
    at_risk = sorted(key for key, r in results.items() if r["status"] == "collision_risk")

    return {
        "storageLayoutVersion": STORAGE_LAYOUT_VERSION,
        "contractsCompared": matched,
        "contractsAtRisk": at_risk,
        "results": results,
        "scopeNote": (
            "Compares each contract's OWN declared stateVariables only (never inherited base "
            "contracts' variables) by declaration order, never computed byte-level packing."
        ),
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
        raise StorageLayoutError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="storage_layout.py",
        description=(
            "Deterministic storage-layout compatibility check between two preprocess.py runs of the "
            "same contract(s) - flags any positional change to declared state variables."
        ),
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
        result = compute_storage_layout_report(v1, v2)
    except (StorageLayoutError, OSError) as exc:
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
