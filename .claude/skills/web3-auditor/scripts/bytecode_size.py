#!/usr/bin/env python3
"""Deterministic EIP-170 runtime-bytecode size check (V3 Block 5, D2,
docs/decisiones.md D-073).

EIP-170 caps deployed CONTRACT CODE at 24576 bytes (0x6000) - a contract
whose compiled runtime bytecode exceeds this literally CANNOT be deployed
on mainnet or any EIP-170-enforcing chain, regardless of any other
property of the code. This is a single, exact byte-length comparison
against `runtimeBytecode` as already normalized by compare_bytecode.py's
own `normalize_hex` (reused unchanged, never re-parsed) - advisory only,
never a severity, never a finding by itself.

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

BYTECODE_SIZE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

EIP170_MAX_RUNTIME_BYTES = 24576  # 0x6000, EIP-170


class BytecodeSizeError(Exception):
    """Raised only for malformed input - never for "exceeds the limit",
    a normal, expected result value."""


def compute_bytecode_size_report(payload: Any) -> Dict[str, Any]:
    """Pure function; raises only for malformed top-level input."""
    if not isinstance(payload, dict):
        raise BytecodeSizeError("input must be a JSON object with a runtimeBytecode field")
    raw = payload.get("runtimeBytecode")
    if not isinstance(raw, str) or not raw.strip():
        raise BytecodeSizeError("runtimeBytecode must be a non-empty hex string")

    normalized, err = _compare_bytecode.normalize_hex(raw, "runtimeBytecode")
    if err:
        raise BytecodeSizeError(err)

    size_bytes = len(normalized) // 2
    within_limit = size_bytes <= EIP170_MAX_RUNTIME_BYTES

    return {
        "bytecodeSizeVersion": BYTECODE_SIZE_VERSION,
        "status": "within_limit" if within_limit else "exceeds_limit",
        "sizeBytes": size_bytes,
        "limitBytes": EIP170_MAX_RUNTIME_BYTES,
        "bytesOverLimit": 0 if within_limit else size_bytes - EIP170_MAX_RUNTIME_BYTES,
        "note": "EIP-170 runtime code size only - a contract over this limit cannot be deployed, independent of any other property of the code.",
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
        raise BytecodeSizeError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bytecode_size.py",
        description="Deterministic EIP-170 runtime-bytecode size check - exact byte-length comparison, advisory only.",
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
        result = compute_bytecode_size_report(payload)
    except (BytecodeSizeError, OSError) as exc:
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
