#!/usr/bin/env python3
"""Deterministic cross-contract privilege-path detection (V3 Block 3, B2,
docs/decisiones.md D-071).

Consumes a SINGLE, already-computed preprocess.py artifact's `systemGraph`
(`pro` mode only - never computed here, never re-derived) and each
contract's already-parsed `functions[]`, and walks `calls`/`delegatesTo`
edges to answer one narrow, mechanical question: starting from a function
that is itself reachable by anyone and unguarded, can you reach an
UNGUARDED, STATE-MUTATING function in a DIFFERENT contract?

Vocabulary used throughout:
  - "exposed" function: visibility in (external, public), mutability in
    (nonpayable, payable), and an EMPTY modifiers list. Any modifier at all
    - regardless of what it actually checks - is treated as guarded; this
      module never inspects a modifier's body, so it can only be
      conservative in one direction (a real no-op modifier could still
      make this over-report, never under-report a genuinely bare function).
  - a path only ever CONTINUES through further unguarded, resolved calls;
    the moment a call reaches a function that itself has a modifier, that
    branch stops there (guarded is exactly the outcome this module exists
    to distinguish from unguarded, so it must never be treated as a
    pass-through).
  - OVERLOADS: functions are indexed by (contract, name, paramSignature),
    never by (contract, name) alone - two same-named functions with
    different guard status each keep their own entry. `systemGraph`'s own
    `calls`/`delegatesTo` edges carry only a bare method NAME (never
    argument types), so resolving an edge's target can only ever narrow
    down to "every overload sharing this name" - never one specific
    overload. Given that ambiguity, every check below is deliberately the
    most INCLUSIVE reading (ANY matching overload exposed -> flag it, ANY
    matching overload unguarded -> keep walking through it): the one
    outcome this module must never produce is a false negative from a
    same-named sibling silently hiding a genuinely exposed function. A
    flagged path whose target name resolves to more than one overload
    carries `ambiguousOverload: true` and lists every exposed overload's
    signature in `matchedOverloads`, instead of guessing which one applies.

THIS IS ADVISORY ONLY. It never assigns a severity, never becomes a
finding by itself, and a path's mere existence is never proof of a real
vulnerability - plenty of intentional protocol designs call an unguarded
view-safe accessor, or the target may be guarded by a modifier this module
correctly stops at. `confidence` is always "low", fixed, never computed
from path length/shape - the AI (Step 6) is the only place that judges
whether a specific reported path is actually meaningful; this module only
ever narrows down which paths exist mechanically.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

PRIVILEGE_PATH_VERSION = "2026.1"
MAX_HOPS = 4  # bounds BFS depth on a real, if unusual, call graph - never unbounded.

EXIT_OK = 0
EXIT_FAILED = 1

_MUTATING = ("nonpayable", "payable")
_PUBLIC_FACING = ("external", "public")


class PrivilegePathError(Exception):
    """Raised only for malformed top-level input - never for "no paths
    found" or "systemGraph not computed", which are normal result values."""


def _param_signature(fn: Dict[str, Any]) -> str:
    """A per-run overload key, not a cross-version identity (diff_reports.py's
    own _function_identity/_canonical_param_type solve a harder, DIFFERENT
    problem - matching the same function ACROSS two separate runs, including
    renamed/rewritten types - and is private to that module by convention;
    re-derived independently here, never imported, same rationale diff_reports.py
    itself already documents for its own independent re-derivations). This only
    needs to distinguish two overloads seen in the SAME artifact, so raw
    declared param types (never canonicalized) are sufficient."""
    params = fn.get("params") or []
    types = [p.get("type") if isinstance(p, dict) and isinstance(p.get("type"), str) else "?" for p in params]
    return "(%s)" % ",".join(types)


def _function_index(contracts: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """Keyed by (contract_key, name, paramSignature) - NEVER (contract_key,
    name) alone, so two overloaded functions sharing a name but differing in
    guard status/visibility/mutability each keep their OWN entry instead of
    one silently overwriting the other."""
    index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for c in contracts:
        key = c.get("key")
        if not key:
            continue
        for fn in c.get("functions") or []:
            name = fn.get("name")
            if not isinstance(name, str):
                continue
            modifiers = [m.get("name") for m in (fn.get("modifiers") or []) if isinstance(m, dict) and m.get("name")]
            index[(key, name, _param_signature(fn))] = {
                "visibility": fn.get("visibility"),
                "mutability": fn.get("mutability"),
                "guarded": bool(modifiers),
            }
    return index


def _by_name_index(fn_index: Dict[Tuple[str, str, str], Dict[str, Any]]) -> Dict[Tuple[str, str], List[Tuple[str, Dict[str, Any]]]]:
    """Groups the signature-keyed index by (contract_key, name) only -
    systemGraph's own 'calls' edges carry just a bare method NAME, never a
    signature (preprocess.py does not resolve call-site argument types), so
    resolving an edge's target can only ever narrow down to "every overload
    sharing this name", never one specific overload. Each value is a list of
    (paramSignature, meta) pairs, never collapsed to one."""
    by_name: Dict[Tuple[str, str], List[Tuple[str, Dict[str, Any]]]] = {}
    for (key, name, sig), meta in fn_index.items():
        by_name.setdefault((key, name), []).append((sig, meta))
    return by_name


def _is_exposed(entry: Optional[Dict[str, Any]]) -> bool:
    if not entry:
        return False
    return entry["visibility"] in _PUBLIC_FACING and entry["mutability"] in _MUTATING and not entry["guarded"]


def _exposed_signatures(candidates: List[Tuple[str, Dict[str, Any]]]) -> List[str]:
    return [sig for sig, meta in candidates if _is_exposed(meta)]


def _any_unguarded(candidates: List[Tuple[str, Dict[str, Any]]]) -> bool:
    """Deliberately ANY, not ALL: since a bare edge name cannot say which
    overload is really invoked, treating the walk as blocked only when
    EVERY overload happens to be guarded is the only choice that can never
    produce a false negative - if even one overload is unguarded, that one
    might be the one actually called, so the walk must be allowed through."""
    return any(not meta["guarded"] for _sig, meta in candidates)


def compute_privilege_paths(artifact: Any) -> Dict[str, Any]:
    """Pure function over one preprocess.py artifact. Never mutates it."""
    if not isinstance(artifact, dict):
        raise PrivilegePathError("artifact must be a JSON object (a preprocess.py output)")
    contracts = artifact.get("contracts")
    if not isinstance(contracts, list):
        raise PrivilegePathError("artifact.contracts must be an array (is this a preprocess.py output?)")
    system_graph = artifact.get("systemGraph") or {}

    if system_graph.get("status") != "computed":
        return {
            "privilegePathVersion": PRIVILEGE_PATH_VERSION,
            "status": "not_computed",
            "message": "systemGraph.status != 'computed' (requires pro mode, config/modes.json allowSystemGraph).",
            "paths": [],
        }

    fn_index = _function_index(contracts)
    by_name = _by_name_index(fn_index)

    # (from_key, calling_function_name) -> [(to_key, target_function_name_or_None)]
    calls_by_caller: Dict[Tuple[str, str], List[Tuple[str, Optional[str]]]] = {}
    delegates: Dict[str, List[str]] = {}
    for edge in system_graph.get("edges") or []:
        kind = edge.get("kind")
        if kind == "calls":
            caller = (edge.get("from"), edge.get("function"))
            if caller[0] and caller[1]:
                calls_by_caller.setdefault(caller, []).append((edge.get("to"), edge.get("method")))
        elif kind == "delegatesTo":
            frm, to = edge.get("from"), edge.get("to")
            if frm and to:
                delegates.setdefault(frm, []).append(to)

    paths: List[Dict[str, Any]] = []
    entries = sorted(
        (key, name) for (key, name), candidates in by_name.items() if _exposed_signatures(candidates)
    )
    for entry_key, entry_name in entries:
        visited: Set[Tuple[str, str]] = {(entry_key, entry_name)}
        # BFS frontier holds (contract_key, function_name, hop_path_so_far)
        frontier: List[Tuple[str, str, List[Dict[str, str]]]] = [(entry_key, entry_name, [])]
        depth = 0
        while frontier and depth < MAX_HOPS:
            depth += 1
            next_frontier: List[Tuple[str, str, List[Dict[str, str]]]] = []
            for from_key, from_name, hops in frontier:
                for to_key, method in calls_by_caller.get((from_key, from_name), []):
                    if method is None or (to_key, method) in visited:
                        continue  # unresolved target method: never guess a match (D-054 precedent).
                    visited.add((to_key, method))
                    hop = {"from": from_key, "fromFunction": from_name, "to": to_key, "toFunction": method}
                    # A bare edge name can match several overloads at once (see
                    # _by_name_index) - "ANY exposed" / "ANY unguarded" below are
                    # both deliberately the most INCLUSIVE reading, so a genuinely
                    # exposed overload can never be hidden by a same-named sibling.
                    candidates = by_name.get((to_key, method), [])
                    exposed_sigs = _exposed_signatures(candidates)
                    if to_key != entry_key and exposed_sigs:
                        paths.append({
                            "entry": {"contract": entry_key, "function": entry_name},
                            "target": {"contract": to_key, "function": method},
                            "matchedOverloads": exposed_sigs,
                            "ambiguousOverload": len(candidates) > 1,
                            "hops": hops + [hop],
                            "confidence": "low",
                        })
                        continue  # an exposed target is where this branch's story ends, never a pass-through.
                    if _any_unguarded(candidates):
                        next_frontier.append((to_key, method, hops + [hop]))
                    # every known overload guarded (or the name is unknown) stops this branch here.
            frontier = next_frontier

        for to_key in delegates.get(entry_key, []):
            for (fkey, fname), candidates in by_name.items():
                exposed_sigs = _exposed_signatures(candidates)
                if fkey == to_key and to_key != entry_key and exposed_sigs:
                    hop = {"from": entry_key, "fromFunction": entry_name, "to": to_key, "toFunction": "<delegatecall fallback>"}
                    paths.append({
                        "entry": {"contract": entry_key, "function": entry_name},
                        "target": {"contract": to_key, "function": fname},
                        "matchedOverloads": exposed_sigs,
                        "ambiguousOverload": len(candidates) > 1,
                        "hops": [hop],
                        "confidence": "low",
                    })

    paths.sort(key=lambda p: (p["entry"]["contract"], p["entry"]["function"], p["target"]["contract"], p["target"]["function"]))
    return {
        "privilegePathVersion": PRIVILEGE_PATH_VERSION,
        "status": "computed",
        "paths": paths,
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
        raise PrivilegePathError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privilege_path.py",
        description=(
            "Deterministic cross-contract privilege-path detection over an already-computed "
            "preprocess.py systemGraph (pro mode). Advisory only - never a finding, never a severity."
        ),
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
        result = compute_privilege_paths(artifact)
    except (PrivilegePathError, OSError) as exc:
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
