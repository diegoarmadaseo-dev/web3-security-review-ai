#!/usr/bin/env python3
"""Deterministic bridge: extract the solc compiler version embedded in a
contract's own CBOR metadata trailer, then feed it straight into
compiler_bugs.py's existing exact-version matcher (V3 Block 5, D3,
docs/decisiones.md D-073).

Reuses compare_bytecode.py's normalize_hex/strip_cbor_metadata/
_decode_cbor_solc_metadata/_solc_version_from_metadata and
compiler_bugs.py's check_compiler_version/load_known_bugs_dataset - ALL
UNCHANGED. This module adds no new CBOR parser and no new version-matching
logic; it only slices out the CBOR body strip_cbor_metadata already
located (never re-implements CBOR boundary detection) and hands the
decoded version string to the already-existing, already-tested matcher.
Exists specifically for the bytecode-only case: a caller with runtime
bytecode but no separately-known compiler version.

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

import compare_bytecode as _compare_bytecode  # noqa: E402 - reused unchanged, never duplicated.
import compiler_bugs as _compiler_bugs  # noqa: E402 - reused unchanged, never duplicated.

BYTECODE_COMPILER_BUGS_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1


class BytecodeCompilerBugsError(Exception):
    """Raised only for malformed input - never for "no version found" or
    "not affected", both normal, expected result values."""


def extract_solc_version_from_bytecode(runtime_bytecode_hex: Any) -> Tuple[Optional[str], str]:
    """Returns (version_or_None, detail). Never raises for a bytecode that
    simply has no (decodable) CBOR metadata - that is a normal outcome for
    contracts compiled without metadata emission or already stripped."""
    normalized, err = _compare_bytecode.normalize_hex(runtime_bytecode_hex, "runtimeBytecode")
    if err:
        return None, err
    data = bytes.fromhex(normalized)
    stripped, was_stripped, strip_detail = _compare_bytecode.strip_cbor_metadata(data)
    if not was_stripped:
        return None, "no CBOR metadata found: %s" % strip_detail
    # strip_cbor_metadata already located the CBOR region; slice it out from
    # the ORIGINAL data using its own reported boundary (data = stripped +
    # cbor_body + 2-byte length word) instead of re-deriving the boundary.
    cbor_body = data[len(stripped):len(data) - 2]
    meta, decode_detail = _compare_bytecode._decode_cbor_solc_metadata(cbor_body)
    if meta is None:
        return None, "CBOR metadata present but could not be decoded: %s" % decode_detail
    version = _compare_bytecode._solc_version_from_metadata(meta)
    if version is None:
        return None, "CBOR metadata decoded but contains no recognizable solc version field"
    return version, "decoded from CBOR metadata trailer"


def compute_bytecode_compiler_bug_report(payload: Any, dataset: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise BytecodeCompilerBugsError("input must be a JSON object with a runtimeBytecode field")
    if "runtimeBytecode" not in payload:
        raise BytecodeCompilerBugsError("input must have a runtimeBytecode field")

    version, detail = extract_solc_version_from_bytecode(payload["runtimeBytecode"])
    if version is None:
        return {
            "bytecodeCompilerBugsVersion": BYTECODE_COMPILER_BUGS_VERSION,
            "status": "version_not_found",
            "extractionDetail": detail,
            "extractedVersion": None,
            "compilerBugReport": None,
        }

    bug_report = _compiler_bugs.compute_compiler_bug_report({"compilerVersion": version}, dataset)
    return {
        "bytecodeCompilerBugsVersion": BYTECODE_COMPILER_BUGS_VERSION,
        "status": "version_extracted",
        "extractionDetail": detail,
        "extractedVersion": version,
        "compilerBugReport": bug_report,
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
        raise BytecodeCompilerBugsError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bytecode_compiler_bugs.py",
        description=(
            "Extracts the solc version from a contract's own CBOR metadata trailer and cross-references "
            "it against compiler_bugs.py's bundled dataset - for callers with bytecode but no separately-known compiler version."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file: {\"runtimeBytecode\": \"0x...\"}. Reads stdin if omitted.")
    parser.add_argument("--dataset", default=None, help="Path to an alternate compiler-bugs dataset JSON (default: config/solc-known-bugs.json).")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = _read_json_file(args.input)
        dataset = _compiler_bugs.load_known_bugs_dataset(args.dataset) if args.dataset else None
        result = compute_bytecode_compiler_bug_report(payload, dataset)
    except (BytecodeCompilerBugsError, _compiler_bugs.CompilerBugsError, OSError) as exc:
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
