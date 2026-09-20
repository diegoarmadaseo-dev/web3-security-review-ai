#!/usr/bin/env python3
"""Deterministic bytecode-only "metamorphic contract" co-occurrence signal
(V3 Block 7, F2, docs/decisiones.md D-075).

Reuses compare_bytecode.py's own opcode walker/decoders UNCHANGED
(normalize_hex, strip_cbor_metadata, _walk_opcodes), exactly like B3
(bytecode_advisory.py) - this module adds no new bytecode parser. Unlike
B3, which reports each advisory opcode's PRESENCE independently, this
module reports one signal only when BOTH CREATE2 and SELFDESTRUCT are
present in the SAME bytecode - the well-known "metamorphic contract"
pattern (deploy, selfdestruct, then redeploy DIFFERENT code at the exact
same address via CREATE2's deterministic, input-derived addressing) that
lets a code review performed at one point in time silently stop applying
after a later redeploy at that same address.

Neither opcode alone is unusual or noteworthy on its own: CREATE2 is an
extremely common, entirely legitimate factory-pattern opcode, and
SELFDESTRUCT alone is already covered independently by B3
(bytecode_advisory.py) - so this module exists specifically for their
CO-OCCURRENCE, a much rarer and more specific signal than either flag
individually, deliberately chosen to keep false-positive risk low.

`_walk_opcodes` already treats PUSH-data bytes as data, never as
instructions (compare_bytecode.py, reused unchanged here) - so an opcode
byte value that only ever appears as the operand of a PUSH is correctly
NEVER counted as "present". That existing correctness is this module's own
primary defense against the most obvious false-positive class, same as B3.

Advisory only: a co-occurrence SIGNAL, never a claim that this contract
actually is, or ever will be, redeployed - opcode presence alone does not
show whether the CREATE2/SELFDESTRUCT paths are reachable, by whom, or
under what guard.

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

import compare_bytecode as _compare_bytecode  # noqa: E402 - reused unchanged, never duplicated.

BYTECODE_METAMORPHIC_SIGNAL_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_OPCODE_CREATE2 = 0xF5
_OPCODE_SELFDESTRUCT = 0xFF


class BytecodeMetamorphicSignalError(Exception):
    """Raised only for malformed input (missing/non-hex runtimeBytecode) -
    never for "no signal", a normal, expected result value."""


def compute_bytecode_metamorphic_signal(payload: Any) -> Dict[str, Any]:
    """Pure function; raises only for malformed top-level input."""
    if not isinstance(payload, dict):
        raise BytecodeMetamorphicSignalError("input must be a JSON object with a runtimeBytecode field")
    raw = payload.get("runtimeBytecode")
    if not isinstance(raw, str) or not raw.strip():
        raise BytecodeMetamorphicSignalError("runtimeBytecode must be a non-empty hex string")

    normalized, err = _compare_bytecode.normalize_hex(raw, "runtimeBytecode")
    if err:
        raise BytecodeMetamorphicSignalError(err)

    data = bytes.fromhex(normalized)
    stripped, cbor_present, _reason = _compare_bytecode.strip_cbor_metadata(data)
    used_opcodes = _compare_bytecode._walk_opcodes(stripped)  # reused unchanged, not re-implemented.

    has_create2 = _OPCODE_CREATE2 in used_opcodes
    has_selfdestruct = _OPCODE_SELFDESTRUCT in used_opcodes
    co_occurs = has_create2 and has_selfdestruct

    return {
        "bytecodeMetamorphicSignalVersion": BYTECODE_METAMORPHIC_SIGNAL_VERSION,
        "status": "signal_present" if co_occurs else "no_signal",
        "cborMetadataStripped": cbor_present,
        "hasCreate2": has_create2,
        "hasSelfdestruct": has_selfdestruct,
        "confidence": "low",
        "note": "Co-occurrence signal only, no source available - never a claim of exploitability or that a redeploy has occurred or will occur.",
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
        raise BytecodeMetamorphicSignalError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bytecode_metamorphic_signal.py",
        description=(
            "Deterministic bytecode-only CREATE2+SELFDESTRUCT co-occurrence signal (metamorphic-contract "
            "redeploy pattern), for contracts with no available source. Advisory only."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file: {\"runtimeBytecode\": \"0x...\"}. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = _read_json_file(args.input)
        result = compute_bytecode_metamorphic_signal(payload)
    except (BytecodeMetamorphicSignalError, OSError, ValueError) as exc:
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
