#!/usr/bin/env python3
"""Deterministic constructor-safety signal for a proxy's IMPLEMENTATION
contract (V3 Block 7, F3, docs/decisiones.md D-075).

Walks ONLY `systemGraph.proxies[]` entries already RESOLVED by
`compute_system_graph` (pro mode, the exact same already-computed pairing
B2/E1/compute_selector_clash_signals (C1-era) all consume unchanged -
never re-derives which contract is a proxy's implementation) and, for each
resolved implementation contract, looks up its constructor (the same
`kind == "constructor"` lookup E2/constructor_zero_address.py already
uses) and flags one fact: the constructor accepts one or more parameters.

WHY THIS MATTERS: a contract meant to be used only behind a proxy
(delegatecall) never runs its OWN constructor in the proxy's storage
context - constructor-time writes to a regular (non-`immutable`) storage
variable are dead code, executed once against the IMPLEMENTATION's own
storage, which the proxy never reads. A constructor that accepts real
configuration arguments is often a sign this was written as if it were an
ordinary, non-proxied contract.

SCOPE, STATED EXPLICITLY, AND THE RESULTING FALSE-POSITIVE CLASS: this
module uses ONLY the constructor `params[]` array preprocess.py already
exposes (the same field E2 already consumes) - it never adds a source/
body parser, so it CANNOT tell whether a given parameter is used to set an
`immutable` variable (which IS safely baked into the deployed bytecode
itself, not proxy-invisible storage, and is a common, legitimate pattern
for upgradeable implementations - e.g. `constructor(address registry) {
REGISTRY = registry; _disableInitializers(); }`) versus a genuinely
proxy-unsafe regular storage write. Any constructor with 1+ params is
flagged the same way; a caller must treat this as a prompt to check by
hand, never as a confirmed defect - the direct, disclosed cost of not
adding a new parser (same D-058/D-073 precedent: reuse existing data or
narrow scope, never guess).

Advisory only: `confidence` is always the fixed string "low", never a
severity.

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

IMPLEMENTATION_CONSTRUCTOR_SIGNAL_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1


class ImplementationConstructorSignalError(Exception):
    """Raised only for malformed input - never for "nothing flagged", a
    normal, expected result value."""


def _constructor_param_count(contract: Dict[str, Any]) -> int:
    constructor = next(
        (fn for fn in contract.get("functions") or [] if isinstance(fn, dict) and fn.get("kind") == "constructor"),
        None,
    )
    if constructor is None:
        return 0
    params = constructor.get("params")
    return len(params) if isinstance(params, list) else 0


def compute_implementation_constructor_signal_report(artifact: Any) -> Dict[str, Any]:
    if not isinstance(artifact, dict) or not isinstance(artifact.get("contracts"), list):
        raise ImplementationConstructorSignalError("artifact must be a preprocess.py output (JSON object with a contracts array)")
    system_graph = artifact.get("systemGraph") or {}
    if not isinstance(system_graph, dict):
        raise ImplementationConstructorSignalError("artifact.systemGraph must be a JSON object")

    if system_graph.get("status") != "computed":
        return {
            "implementationConstructorSignalVersion": IMPLEMENTATION_CONSTRUCTOR_SIGNAL_VERSION,
            "status": "not_computed",
            "message": "systemGraph.status != 'computed' (requires pro mode, config/modes.json allowSystemGraph).",
            "flagged": [],
        }

    proxies = system_graph.get("proxies")
    if proxies is None:
        proxies = []
    if not isinstance(proxies, list):
        raise ImplementationConstructorSignalError("systemGraph.proxies must be an array")

    contracts_by_key = {c["key"]: c for c in artifact["contracts"] if isinstance(c, dict) and c.get("key")}

    flagged: List[Dict[str, Any]] = []
    for entry in proxies:
        if not isinstance(entry, dict) or entry.get("status") != "resolved":
            continue
        if not entry.get("implementation") or not entry.get("proxy"):
            continue  # malformed entry (missing/null proxy or implementation key) - skipped, never emitted as a null-keyed result.
        impl = contracts_by_key.get(entry["implementation"])
        if not impl:
            continue
        param_count = _constructor_param_count(impl)
        if param_count == 0:
            continue
        flagged.append({
            "proxyKey": entry["proxy"],
            "implementationKey": entry["implementation"],
            "constructorParamCount": param_count,
            "confidence": "low",
        })

    return {
        "implementationConstructorSignalVersion": IMPLEMENTATION_CONSTRUCTOR_SIGNAL_VERSION,
        "status": "flagged" if flagged else "clean",
        "flagged": flagged,
        "note": "Structural signal only (constructor params[] presence) - cannot distinguish a safe immutable-only constructor from a proxy-unsafe one without body parsing (out of scope, see module docstring); never a severity, never a confirmed defect.",
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
        raise ImplementationConstructorSignalError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="implementation_constructor_signal.py",
        description=(
            "Deterministic constructor-safety signal for a proxy's already-resolved implementation contract "
            "(constructor params[] presence). Advisory only."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a preprocess.py output JSON (pro mode). Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        artifact = _read_json_file(args.input)
        result = compute_implementation_constructor_signal_report(artifact)
    except (ImplementationConstructorSignalError, OSError) as exc:
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
