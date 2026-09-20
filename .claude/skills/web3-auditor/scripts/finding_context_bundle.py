#!/usr/bin/env python3
"""Deterministic context assembler for a specific contract (and, optionally,
one of its functions) out of an already-computed preprocess.py artifact
(V3 Block 8, G1, docs/decisiones.md D-076).

PURE DATA ASSEMBLY ONLY: gathers the target contract's own already-parsed
data (verbatim, never reshaped or renamed) and, if systemGraph is
available (pro mode), the already-computed `edges[]` that touch this
contract (and, if a function was named, the narrower subset that touch
that function specifically, via the SAME `edge.function`/`edge.method`
convention B2/E1/F3 already consume - `edge.function` is the CALLING
function, `edge.method` is the CALLED function, confirmed live against a
real 2-contract bundle in V3 Block 3/D-071). This module introduces no new
judgment, no new parsing, and never invents a field: every value in its
output is copied unchanged from preprocess.py's own output. The point is
purely to save a caller (a human reviewer or the AI at Step 6) from having
to re-scan an entire artifact to gather everything already known about one
finding's location.

TARGET RESOLUTION, NEVER GUESSED (D-054): `contractKey` must match exactly
one `artifact.contracts[].key`, or this raises cleanly - contract keys are
unique by construction in preprocess.py's own output, so only "not found"
applies there. An optional `function` matches by exact NAME against that
contract's `functions[]`; a contract can legitimately have more than one
function sharing a name (overloads, the same situation F1 had to handle
exactly) - if `function` matches more than one entry, this raises cleanly
rather than guessing which overload was meant, exactly like F1 never
guesses which upgrade-authority overload is "the" one.

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

FINDING_CONTEXT_BUNDLE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1


class FindingContextBundleError(Exception):
    """Raised only for malformed input or an unresolvable target (a
    contractKey not found, or a function name that is missing or
    ambiguous) - never for a target that resolves but has an empty
    function/base/edge list, all normal, expected results."""


def compute_finding_context_bundle(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise FindingContextBundleError("input must be a JSON object with artifact/contractKey fields")
    artifact = payload.get("artifact")
    contract_key = payload.get("contractKey")
    function_name = payload.get("function")

    if not isinstance(artifact, dict) or not isinstance(artifact.get("contracts"), list):
        raise FindingContextBundleError("artifact must be a preprocess.py output (JSON object with a contracts array)")
    if not isinstance(contract_key, str) or not contract_key:
        raise FindingContextBundleError("contractKey must be a non-empty string matching one of artifact.contracts[].key")
    if function_name is not None and (not isinstance(function_name, str) or not function_name):
        raise FindingContextBundleError("function, if provided, must be a non-empty string")

    contract = next((c for c in artifact["contracts"] if isinstance(c, dict) and c.get("key") == contract_key), None)
    if contract is None:
        raise FindingContextBundleError("contractKey %r was not found in artifact.contracts" % contract_key)

    matched_function = None
    if function_name is not None:
        candidates = [fn for fn in contract.get("functions") or [] if isinstance(fn, dict) and fn.get("name") == function_name]
        if not candidates:
            raise FindingContextBundleError("function %r was not found in contract %r" % (function_name, contract_key))
        if len(candidates) > 1:
            raise FindingContextBundleError(
                "function %r is ambiguous in contract %r (%d overloads) - matches by name only, never guesses which overload"
                % (function_name, contract_key, len(candidates))
            )
        matched_function = candidates[0]

    system_graph = artifact.get("systemGraph") or {}
    if not isinstance(system_graph, dict):
        raise FindingContextBundleError("artifact.systemGraph must be a JSON object")

    if system_graph.get("status") != "computed":
        graph_section: Dict[str, Any] = {
            "status": "not_computed",
            "contractEdges": [],
            "functionEdges": ([] if function_name is not None else None),
        }
    else:
        edges = system_graph.get("edges")
        if edges is None:
            edges = []
        if not isinstance(edges, list):
            raise FindingContextBundleError("systemGraph.edges must be an array")
        contract_edges = [e for e in edges if isinstance(e, dict) and (e.get("from") == contract_key or e.get("to") == contract_key)]
        function_edges = None
        if function_name is not None:
            function_edges = [e for e in contract_edges if e.get("function") == function_name or e.get("method") == function_name]
        graph_section = {"status": "computed", "contractEdges": contract_edges, "functionEdges": function_edges}

    return {
        "findingContextBundleVersion": FINDING_CONTEXT_BUNDLE_VERSION,
        "contractKey": contract_key,
        "function": function_name,
        "contract": contract,
        "matchedFunction": matched_function,
        "systemGraph": graph_section,
        "note": "Pure data assembly only - no new judgment, severity, or finding is introduced; every field is copied unchanged from preprocess.py's own already-computed output.",
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
        raise FindingContextBundleError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finding_context_bundle.py",
        description=(
            "Assembles already-computed data (contract, optional function, related systemGraph edges) "
            "for one target out of a preprocess.py artifact. Pure data assembly only."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file: {\"artifact\":..., \"contractKey\":..., \"function\":...(optional)}. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = _read_json_file(args.input)
        result = compute_finding_context_bundle(payload)
    except (FindingContextBundleError, OSError) as exc:
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
