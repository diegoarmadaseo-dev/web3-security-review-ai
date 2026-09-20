#!/usr/bin/env python3
"""Deterministic bytecode-only advisory scan for contracts with NO available
source (V3 Block 3, B3, docs/decisiones.md D-071).

Reuses compare_bytecode.py's own opcode walker/decoders UNCHANGED
(normalize_hex, strip_cbor_metadata, _walk_opcodes) - this module adds no
new bytecode parser. It only checks PRESENCE of a small, fixed set of
opcodes that are meaningful on their own even with zero semantic context:
DELEGATECALL, CALLCODE, SELFDESTRUCT. Each present opcode becomes one
ADVISORY entry, `confidence` always "low", never a severity, never a
finding by itself - this is deliberately the lowest-information-density
check in the whole Skill (no function names, no variable names, no
control-flow reasoning), offered only because a huge share of real deployed
contracts are never verified and therefore have no source-level checks
available to them at all. A caller must never present this output as
equivalent to a source-level review.

`_walk_opcodes` already treats PUSH-data bytes as data, never as
instructions (compare_bytecode.py, reused unchanged here) - so an opcode
byte value that only ever appears as the operand of a PUSH is correctly
NEVER flagged as "present". That existing correctness is this module's own
primary defense against the most obvious false-positive class.

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

BYTECODE_ADVISORY_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_OPCODE_CALLCODE = 0xF2
_OPCODE_DELEGATECALL = 0xF4
_OPCODE_SELFDESTRUCT = 0xFF

_ADVISORY_OPCODES = (
    (
        _OPCODE_DELEGATECALL,
        "DELEGATECALL",
        "This bytecode contains DELEGATECALL, which executes another contract's code in THIS contract's own "
        "storage/msg.sender context - the pattern behind proxies, but also a path for a malicious or "
        "compromised target to overwrite arbitrary storage here. Opcode presence alone does not show who "
        "controls the target address or whether it is fixed/upgradeable - verify that separately.",
    ),
    (
        _OPCODE_CALLCODE,
        "CALLCODE",
        "This bytecode contains the deprecated CALLCODE opcode, which shares DELEGATECALL's "
        "foreign-code-in-this-storage-context risk and is rarely emitted by modern compilers for "
        "intentional reasons - worth confirming this wasn't hand-written or emitted by an old toolchain "
        "for a purpose that has since been superseded.",
    ),
    (
        _OPCODE_SELFDESTRUCT,
        "SELFDESTRUCT",
        "This bytecode contains SELFDESTRUCT, which can permanently remove this contract's code and forward "
        "its balance. Opcode presence alone does not show what gates reaching it - verify who can trigger "
        "this path before relying on this contract's continued existence.",
    ),
)


class BytecodeAdvisoryError(Exception):
    """Raised only for malformed input (missing/non-hex runtimeBytecode) -
    never for "no advisory opcodes found", a normal result value."""


def compute_bytecode_advisories(payload: Any) -> Dict[str, Any]:
    """Pure function; raises only for malformed top-level input."""
    if not isinstance(payload, dict):
        raise BytecodeAdvisoryError("input must be a JSON object with a runtimeBytecode field")
    raw = payload.get("runtimeBytecode")
    if not isinstance(raw, str) or not raw.strip():
        raise BytecodeAdvisoryError("runtimeBytecode must be a non-empty hex string")

    normalized, err = _compare_bytecode.normalize_hex(raw, "runtimeBytecode")
    if err:
        raise BytecodeAdvisoryError(err)

    data = bytes.fromhex(normalized)
    stripped, cbor_present, _reason = _compare_bytecode.strip_cbor_metadata(data)
    used_opcodes = _compare_bytecode._walk_opcodes(stripped)  # reused unchanged, not re-implemented.

    advisories = [
        {"opcode": label, "opcodeHex": "0x%02x" % opcode, "confidence": "low", "note": note}
        for opcode, label, note in _ADVISORY_OPCODES
        if opcode in used_opcodes
    ]

    return {
        "bytecodeAdvisoryVersion": BYTECODE_ADVISORY_VERSION,
        "status": "computed",
        "cborMetadataStripped": cbor_present,
        "advisories": advisories,
        "advisoryCount": len(advisories),
        "note": "Opcode-presence heuristic only, no source available - never equivalent to a source-level review.",
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
        raise BytecodeAdvisoryError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bytecode_advisory.py",
        description=(
            "Deterministic opcode-presence advisory scan for contracts with no available source. "
            "Low-confidence, advisory only - never a finding, never a severity."
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
        result = compute_bytecode_advisories(payload)
    except (BytecodeAdvisoryError, OSError, ValueError) as exc:
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
