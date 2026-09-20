#!/usr/bin/env python3
"""Deterministic bytecode-only proxy-pattern fingerprinting against a small
number of EXACT, near-fixed public standards (V3 Block 4, C1,
docs/decisiones.md D-072).

Reuses compare_bytecode.py's normalize_hex/strip_cbor_metadata UNCHANGED -
this module adds no new hex/bytecode parser, only two exact-byte checks:

  - EIP-1167 "minimal proxy": the runtime bytecode is a FIXED 45-byte
    template with only the 20-byte implementation address varying
    (`_EIP1167_PREFIX + <address> + _EIP1167_SUFFIX`, exactly - published
    verbatim in EIP-1167 and reproduced identically by OpenZeppelin's
    Clones.sol). A match requires ALL 45 bytes outside the address to be
    byte-for-byte identical - never a fuzzy/partial match - so the
    extracted `implementation` address is READ directly from the bytecode
    itself, never guessed: this is the one case where reporting a target
    address is sound, because the standard's whole design embeds it in
    the code, unlike EIP-1967 below.
  - EIP-1967 "storage-slot convention": `PROXIABLE_IMPLEMENTATION_SLOT`
    below is the well-known `bytes32(uint256(keccak256('eip1967.proxy.
    implementation')) - 1)` constant every EIP-1967-compliant proxy
    (transparent OR UUPS - both reuse the same slot, the standard does
    not let bytecode alone distinguish which) must reference as a PUSH32
    literal to read/write its implementation slot. Detecting this literal
    only reports "this bytecode follows the EIP-1967 slot convention" -
    it NEVER extracts an implementation address (that value lives in
    contract STORAGE at that slot, never in the bytecode itself, and
    reading storage needs a live RPC call this Skill's core deliberately
    never makes) and NEVER claims to distinguish transparent from UUPS.

**PROVENANCE / VERIFICATION STATUS**: `PROXIABLE_IMPLEMENTATION_SLOT` is
`preprocess.EIP1967_IMPLEMENTATION_SLOT_HEX` (imported, never a second copy -
D-058 single-source-of-truth discipline). That constant was ALREADY committed
V1/V2-era in `preprocess.py`'s `KNOWN_PUBLIC_SLOTS` (used by its secrets
scanner to recognize this slot as a known-public, non-secret hex64 value),
predating this module. An earlier draft of this module independently
retyped the same value from training knowledge and disagreed with the
existing constant at its very last hex character - reusing the existing
one here removes that drift risk entirely, but the underlying VALUE itself
still traces back to training knowledge with no live re-verification this
session (this Skill's core has no network access to re-derive or
cross-check it against the EIP-1967 text) - spot-check it against the
published EIP-1967 spec before relying on it in production; flagged here
exactly like this project already flags `[CAPAFY-VERIFY]`-class facts
elsewhere. `_EIP1167_PREFIX`/`_EIP1167_SUFFIX` are the same 20-years-stable,
extremely widely reproduced EIP-1167 template bytes, unaffected by any of
this.

Advisory only, no severity, never invents a match - a bytecode that
doesn't fit either exact shape returns "no_match", never a guess.

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
import preprocess as _preprocess  # noqa: E402 - single source of truth for the EIP-1967 slot, see PROVENANCE note above.

PROXY_FINGERPRINT_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
_EIP1167_TOTAL_LEN = len(_EIP1167_PREFIX) + 20 + len(_EIP1167_SUFFIX)  # 45

PROXIABLE_IMPLEMENTATION_SLOT = bytes.fromhex(_preprocess.EIP1967_IMPLEMENTATION_SLOT_HEX)


class ProxyFingerprintError(Exception):
    """Raised only for malformed input - never for "no proxy pattern
    matched", a normal, expected result value."""


def _detect_eip1167(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) != _EIP1167_TOTAL_LEN:
        return None
    prefix_len = len(_EIP1167_PREFIX)
    if data[:prefix_len] != _EIP1167_PREFIX:
        return None
    if data[prefix_len + 20:] != _EIP1167_SUFFIX:
        return None
    address_bytes = data[prefix_len:prefix_len + 20]
    return {
        "pattern": "EIP-1167",
        "name": "Minimal proxy (EIP-1167)",
        "implementation": "0x" + address_bytes.hex(),
        "confidence": "low",
        "note": "Exact 45-byte template match; the implementation address is read directly from the bytecode, not guessed.",
    }


def _detect_eip1967_slot(data: bytes) -> Optional[Dict[str, Any]]:
    if PROXIABLE_IMPLEMENTATION_SLOT not in data:
        return None
    return {
        "pattern": "EIP-1967",
        "name": "EIP-1967 storage-slot convention (transparent or UUPS - bytecode alone cannot distinguish)",
        "implementation": None,
        "confidence": "low",
        "note": "The literal EIP-1967 implementation-slot constant is present; the implementation address itself lives in contract STORAGE, never in bytecode, and is not extracted here.",
    }


def compute_proxy_fingerprint(payload: Any) -> Dict[str, Any]:
    """Pure function; raises only for malformed top-level input."""
    if not isinstance(payload, dict):
        raise ProxyFingerprintError("input must be a JSON object with a runtimeBytecode field")
    raw = payload.get("runtimeBytecode")
    if not isinstance(raw, str) or not raw.strip():
        raise ProxyFingerprintError("runtimeBytecode must be a non-empty hex string")

    normalized, err = _compare_bytecode.normalize_hex(raw, "runtimeBytecode")
    if err:
        raise ProxyFingerprintError(err)

    data = bytes.fromhex(normalized)
    stripped, cbor_present, _reason = _compare_bytecode.strip_cbor_metadata(data)

    matches: List[Dict[str, Any]] = []
    eip1167 = _detect_eip1167(stripped)
    if eip1167:
        matches.append(eip1167)
    eip1967 = _detect_eip1967_slot(stripped)
    if eip1967:
        matches.append(eip1967)

    return {
        "proxyFingerprintVersion": PROXY_FINGERPRINT_VERSION,
        "status": "matched" if matches else "no_match",
        "cborMetadataStripped": cbor_present,
        "matches": matches,
        "note": "Exact/near-fixed standard templates only, never a fuzzy or heuristic match - no target is ever guessed.",
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
        raise ProxyFingerprintError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy_fingerprint.py",
        description=(
            "Deterministic bytecode-only proxy-pattern fingerprinting against EIP-1167/EIP-1967 only - "
            "exact/near-fixed standard templates, never a guessed target."
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
        result = compute_proxy_fingerprint(payload)
    except (ProxyFingerprintError, OSError, ValueError) as exc:
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
