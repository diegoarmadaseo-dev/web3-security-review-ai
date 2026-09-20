#!/usr/bin/env python3
"""Deterministic check for an unprotected upgrade-authority function (V3
Block 7, F1, docs/decisiones.md D-075).

Flags a function that EXACTLY matches one of three well-known, fixed
UUPS/EIP-1822 upgrade-authority signatures - `_authorizeUpgrade(address)`
(OpenZeppelin UUPSUpgradeable's own override point, always `internal`),
`upgradeTo(address)`, `upgradeToAndCall(address,bytes)` (the public/
external entry points that call it) - and carries ZERO modifiers. This is
one of the single most catastrophic upgradeable-contract mistakes: if the
function that authorizes an upgrade has no access control at all, anyone
can replace the implementation.

MATCHING METHOD, STATED EXPLICITLY: this module NEVER computes a 4-byte
selector. Computing one correctly requires Keccak-256, which is NOT the
same digest as the NIST-standardized SHA3-256 that Python's own
standard-library `hashlib.sha3_256` implements (a well-known, easy-to-miss
substitution that would silently produce a WRONG selector for every
function, matching nothing and never warning) - and this Skill's core has
no dependency that provides a correct Keccak-256 implementation. Instead,
this module reuses preprocess.py's OWN existing, already-tested
canonical-signature TEXT matching (`_canonical_signature`/
`_canonical_param_type` - the exact helpers `compute_selector_clash_signals`
already uses for its own proxy/implementation signature-collision check,
imported here UNCHANGED, never re-derived or duplicated): a function's
identity is matched by its canonical `name(type1,type2)` TEXT form, never
by a computed hash. The three target signatures below are well-known,
stable, publicly documented standard names - never guessed (D-054) and
never derived from anything requiring Keccak.

Deliberately does NOT reuse `_external_function_signatures` (also in
preprocess.py): that helper only considers `public`/`external` functions,
which would silently exclude `_authorizeUpgrade` itself - the actual
override point in UUPS, always declared `internal`.

Advisory only: `confidence` is always the fixed string "low", never a
severity, never a claim that this exact function is reachable without
going through some other unmodeled guard (e.g. a modifier on a base
contract outside an incomplete bundle) - and never a claim that a
same-named, same-typed function in an unrelated, non-UUPS contract is
actually an upgrade path at all (a disclosed, low-probability false-
positive class of exact name+signature matching).

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

import preprocess as _preprocess  # noqa: E402 - reused unchanged: _canonical_signature (never a second copy).

UPGRADE_AUTHORITY_GUARD_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

# Well-known, fixed UUPS/EIP-1822 upgrade-authority canonical signatures -
# TEXT form, matching exactly what preprocess._canonical_signature produces
# (name + "(" + comma-joined canonical ABI param types + ")"). Never a
# computed hash - see module docstring.
_UPGRADE_AUTHORITY_SIGNATURES = frozenset({
    "_authorizeUpgrade(address)",
    "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)",
})


class UpgradeAuthorityGuardError(Exception):
    """Raised only for malformed input - never for "nothing flagged", a
    normal, expected result value."""


def find_unprotected_upgrade_authority(contract: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pure function; never mutates `contract`."""
    flagged: List[Dict[str, Any]] = []
    for fn in contract.get("functions") or []:
        if not isinstance(fn, dict) or fn.get("kind") != "function":
            continue
        if not isinstance(fn.get("name"), str):
            continue
        signature = _preprocess._canonical_signature(fn)
        if signature not in _UPGRADE_AUTHORITY_SIGNATURES:
            continue
        if fn.get("modifiers"):
            continue
        flagged.append({"function": fn["name"], "signature": signature, "confidence": "low"})
    return flagged


def compute_upgrade_authority_guard_report(artifact: Any) -> Dict[str, Any]:
    if not isinstance(artifact, dict) or not isinstance(artifact.get("contracts"), list):
        raise UpgradeAuthorityGuardError("artifact must be a preprocess.py output (JSON object with a contracts array)")

    flagged: List[Dict[str, Any]] = []
    for contract in artifact["contracts"]:
        if not isinstance(contract, dict) or not contract.get("key"):
            continue
        for entry in find_unprotected_upgrade_authority(contract):
            flagged.append({"contractKey": contract["key"], **entry})

    return {
        "upgradeAuthorityGuardVersion": UPGRADE_AUTHORITY_GUARD_VERSION,
        "status": "flagged" if flagged else "clean",
        "flagged": flagged,
        "note": "Advisory signal only - matches by canonical signature text, never a computed selector; never a claim that no other guard exists elsewhere in an incomplete bundle.",
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
        raise UpgradeAuthorityGuardError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="upgrade_authority_guard.py",
        description=(
            "Deterministic check for an unprotected UUPS/EIP-1822 upgrade-authority function "
            "(_authorizeUpgrade/upgradeTo/upgradeToAndCall with zero modifiers). Advisory only."
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
        result = compute_upgrade_authority_guard_report(artifact)
    except (UpgradeAuthorityGuardError, OSError) as exc:
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
