#!/usr/bin/env python3
"""Deterministic delegatecall-cycle detection over an already-computed
preprocess.py `systemGraph` (V3 Block 6, E1, docs/decisiones.md D-074).

Walks ONLY `systemGraph.edges` where `kind == "delegatesTo"` (`pro` mode,
already computed - never re-derived here, same data B2's `privilege_path.py`
already consumes) looking for a cycle: a proxy whose delegate chain
eventually loops back to itself (A delegatesTo B delegatesTo A, or a longer
loop). A real cycle would cause infinite recursion / an out-of-gas revert
at runtime - this module reports the CYCLE ITSELF as a deterministic graph
fact, advisory only, and never claims a specific exploit or that the cycle
is definitely reachable at runtime (a `delegatesTo` edge here means B2's
own definition already applies: a resolved, statically-detected delegatecall
target, not a claim about which code path actually executes it).

Distinct from privilege_path.py (B2): B2 asks whether an UNGUARDED entry
point can reach an unguarded MUTATOR in another contract; this module asks
only whether the delegate graph itself contains a LOOP, independent of any
notion of "guarded"/"exposed" - a cycle is a fact about graph shape, not
about access control.

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

DELEGATECALL_CYCLE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

MAX_CYCLE_SEARCH_DEPTH = 25  # defensive bound only - real delegatesTo graphs are tiny.


class DelegatecallCycleError(Exception):
    """Raised only for malformed input (top-level or a nested edge entry) -
    never for "no cycle found", a normal, expected result value."""


def _canonical_cycle(cycle: List[str]) -> tuple:
    core = cycle[:-1]  # drop the repeated closing node.
    min_idx = core.index(min(core))
    return tuple(core[min_idx:] + core[:min_idx])


def find_delegatecall_cycles(system_graph: Dict[str, Any]) -> List[List[str]]:
    """Pure function; never mutates `system_graph`. Returns one entry per
    DISTINCT cycle (deduplicated across which node it was first found
    from), each a list of contract keys ending back at its own start."""
    if not isinstance(system_graph, dict):
        raise DelegatecallCycleError("systemGraph must be a JSON object")
    edges = system_graph.get("edges")
    if edges is None:
        edges = []
    if not isinstance(edges, list):
        raise DelegatecallCycleError("systemGraph.edges must be an array")

    adjacency: Dict[str, List[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            raise DelegatecallCycleError("each systemGraph.edges entry must be a JSON object")
        if edge.get("kind") == "delegatesTo" and edge.get("from") and edge.get("to"):
            adjacency.setdefault(edge["from"], []).append(edge["to"])

    cycles: List[List[str]] = []
    seen: set = set()

    def dfs(node: str, stack: List[str], stack_set: set) -> None:
        if len(stack) > MAX_CYCLE_SEARCH_DEPTH:
            return
        for neighbor in adjacency.get(node, []):
            if neighbor in stack_set:
                idx = stack.index(neighbor)
                cycle = stack[idx:] + [neighbor]
                canonical = _canonical_cycle(cycle)
                if canonical not in seen:
                    seen.add(canonical)
                    cycles.append(cycle)
                continue
            dfs(neighbor, stack + [neighbor], stack_set | {neighbor})

    for start in sorted(adjacency):
        dfs(start, [start], {start})

    cycles.sort(key=lambda c: (len(c), c))
    return cycles


def compute_delegatecall_cycle_report(artifact: Any) -> Dict[str, Any]:
    if not isinstance(artifact, dict):
        raise DelegatecallCycleError("artifact must be a JSON object (a preprocess.py output)")
    if not isinstance(artifact.get("contracts"), list):
        raise DelegatecallCycleError("artifact.contracts must be an array (is this a preprocess.py output?)")
    system_graph = artifact.get("systemGraph") or {}
    if not isinstance(system_graph, dict):
        raise DelegatecallCycleError("artifact.systemGraph must be a JSON object")

    if system_graph.get("status") != "computed":
        return {
            "delegatecallCycleVersion": DELEGATECALL_CYCLE_VERSION,
            "status": "not_computed",
            "message": "systemGraph.status != 'computed' (requires pro mode, config/modes.json allowSystemGraph).",
            "cycles": [],
        }

    cycles = find_delegatecall_cycles(system_graph)
    return {
        "delegatecallCycleVersion": DELEGATECALL_CYCLE_VERSION,
        "status": "cycle_found" if cycles else "no_cycle",
        "cycles": [{"path": cycle, "confidence": "low"} for cycle in cycles],
        "note": "Advisory graph fact only - never a claim that a specific runtime path actually reaches this cycle.",
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
        raise DelegatecallCycleError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="delegatecall_cycle.py",
        description="Deterministic delegatecall-cycle detection over an already-computed preprocess.py systemGraph (pro mode). Advisory only.",
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a preprocess.py output JSON. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        artifact = _read_json_file(args.input)
        result = compute_delegatecall_cycle_report(artifact)
    except (DelegatecallCycleError, OSError) as exc:
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
