#!/usr/bin/env python3
"""Deterministic constructor zero-address sanity check (V3 Block 6, E2,
docs/decisiones.md D-074).

Given ONE preprocess.py artifact's already-parsed constructor `params[]`
(each already carrying `isAddress: bool` - preprocess.py's own
classification, reused unchanged, never re-derived by a new type-string
matcher here) and a caller-supplied list of PLANNED constructor argument
values (never fetched from a live chain - this is pre-deployment input the
caller already has in hand, e.g. a deploy script's own argument list),
flags any address-typed argument whose value is the literal zero address.

This is a SANITY SIGNAL ONLY: the zero address is a completely ordinary,
sometimes-deliberate value (e.g. "no admin yet, set later" or "disable this
optional integration"). This module never claims the value is wrong, never
assigns a severity, and never guesses which non-zero addresses might also
be mistaken - only the one, unambiguous, literal zero-address fact.

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

CONSTRUCTOR_ZERO_ADDRESS_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1


class ConstructorZeroAddressError(Exception):
    """Raised only for malformed input - never for "no zero address
    found" or "contract has no constructor", both normal results."""


def _is_zero_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text:
        return False
    try:
        return int(text, 16) == 0
    except ValueError:
        return False


def find_constructor_zero_addresses(contract: Dict[str, Any], constructor_args: List[Any]) -> Dict[str, Any]:
    """Pure function; never mutates `contract` or `constructor_args`."""
    constructor = next(
        (fn for fn in contract.get("functions") or [] if isinstance(fn, dict) and fn.get("kind") == "constructor"),
        None,
    )
    if constructor is None:
        return {"status": "no_constructor", "flagged": []}

    params = constructor.get("params") or []
    flagged: List[Dict[str, Any]] = []
    for index, param in enumerate(params):
        if not isinstance(param, dict) or not param.get("isAddress"):
            continue
        if index >= len(constructor_args):
            continue  # fewer args supplied than params: an arity mismatch is not this module's concern.
        if _is_zero_address(constructor_args[index]):
            flagged.append({"paramName": param.get("name"), "paramIndex": index})

    return {"status": "flagged" if flagged else "clean", "flagged": flagged}


def compute_constructor_zero_address_report(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ConstructorZeroAddressError("input must be a JSON object with artifact/contractKey/constructorArgs fields")
    artifact = payload.get("artifact")
    contract_key = payload.get("contractKey")
    constructor_args = payload.get("constructorArgs")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("contracts"), list):
        raise ConstructorZeroAddressError("artifact must be a preprocess.py output (JSON object with a contracts array)")
    if not isinstance(contract_key, str):
        raise ConstructorZeroAddressError("contractKey must be a string matching one of artifact.contracts[].key")
    if not isinstance(constructor_args, list):
        raise ConstructorZeroAddressError("constructorArgs must be an array, positionally matching the constructor's params")

    contract = next((c for c in artifact["contracts"] if isinstance(c, dict) and c.get("key") == contract_key), None)
    if contract is None:
        raise ConstructorZeroAddressError("contractKey %r was not found in artifact.contracts" % contract_key)

    result = find_constructor_zero_addresses(contract, constructor_args)
    return {
        "constructorZeroAddressVersion": CONSTRUCTOR_ZERO_ADDRESS_VERSION,
        "contractKey": contract_key,
        "status": result["status"],
        "flagged": result["flagged"],
        "note": "Sanity signal only - the zero address may be intentional; never a severity, never a claim of wrongness.",
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
        raise ConstructorZeroAddressError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="constructor_zero_address.py",
        description=(
            "Deterministic constructor zero-address sanity check against planned deployment arguments. "
            "Sanity signal only - the zero address may be intentional."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file: {\"artifact\":..., \"contractKey\":..., \"constructorArgs\":[...]}. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = _read_json_file(args.input)
        result = compute_constructor_zero_address_report(payload)
    except (ConstructorZeroAddressError, OSError) as exc:
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
