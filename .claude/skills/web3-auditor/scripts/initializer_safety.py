#!/usr/bin/env python3
"""Deterministic upgrade initializer-safety check between two versions of
the same contract (V3 Block 5, D1, docs/decisiones.md D-073).

Compares only the OpenZeppelin-convention initializer-family MODIFIERS
already parsed by preprocess.py (`initializer`/`reinitializer(N)`/
`onlyInitializing` - each function's own `modifiers[]`, including each
modifier's own `args` string when present, e.g. `reinitializer(2)` ->
`{"name": "reinitializer", "args": "2"}`) between a V1 (baseline) and V2
(candidate upgrade) run of preprocess.py. Reports two purely STRUCTURAL/
VERSION facts, never a severity and never a claim of exploitability:

  - "guard_removed": a function that carried an initializer-family
    modifier in V1 still exists in V2 (same name) but no longer carries
    ANY initializer-family modifier - a fact about what changed, not a
    claim that re-initialization is actually reachable (that depends on
    the function's new visibility/logic, which this module does not
    judge).
  - "reinitializer_version_reused": a NEWLY ADDED function in V2 uses
    `reinitializer(N)` where N was ALREADY used by another
    reinitializer-guarded function (in V1, or by another new function in
    V2) - a fact about a version-number collision in the convention's own
    counter, never a claim about what that collision would actually do at
    runtime.

SCOPE, STATED EXPLICITLY: this does NOT detect a missing
`_disableInitializers()` call in a constructor (preprocess.py's `calls[]`
array only tracks object-method-style calls like `x.foo()`, confirmed live
against a real probe contract - a bare internal call like
`_disableInitializers()` is not recorded there at all, and adding a new
body-text parser to find it would duplicate work rather than reuse it, so
this module does not attempt it - see docs/decisiones.md D-073). Only the
two facts above are reported.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

INITIALIZER_SAFETY_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_INITIALIZER_MODIFIER_RE = re.compile(r"^(initializer|reinitializer|onlyInitializing)$")


class InitializerSafetyError(Exception):
    """Raised only for malformed input - never for "no change", a normal,
    expected result value."""


def _initializer_functions(contract: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """function name -> {"modifier": name, "version": int_or_None}, one
    entry per function that carries an initializer-family modifier. A
    function with more than one such modifier (unusual, but not itself
    malformed) keeps the LAST one encountered - the same convention
    preprocess.py's own functions[] list order already reflects."""
    result: Dict[str, Dict[str, Any]] = {}
    for fn in contract.get("functions") or []:
        name = fn.get("name")
        if not isinstance(name, str):
            continue
        for m in fn.get("modifiers") or []:
            if not isinstance(m, dict):
                continue
            mod_name = m.get("name")
            if not isinstance(mod_name, str) or not _INITIALIZER_MODIFIER_RE.match(mod_name):
                continue
            version = None
            if mod_name == "reinitializer":
                args = m.get("args")
                if isinstance(args, str) and args.strip().isdigit():
                    version = int(args.strip())
            result[name] = {"modifier": mod_name, "version": version}
    return result


def diff_initializer_safety(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
    """Pure function: compares two contract dicts' initializer-family
    modifier usage. Never mutates either input."""
    v1_init = _initializer_functions(c1)
    v2_init = _initializer_functions(c2)
    v2_names = {fn.get("name") for fn in (c2.get("functions") or []) if isinstance(fn, dict) and isinstance(fn.get("name"), str)}

    findings: List[Dict[str, Any]] = []

    for name in sorted(v1_init):
        if name in v2_names and name not in v2_init:
            findings.append({
                "type": "guard_removed",
                "function": name,
                "modifierBefore": v1_init[name]["modifier"],
            })

    v1_versions = {info["version"] for info in v1_init.values() if info["version"] is not None}
    newly_added = sorted(set(v2_init) - set(v1_init))
    seen_new_versions: Dict[int, str] = {}
    for name in newly_added:
        info = v2_init[name]
        if info["modifier"] != "reinitializer" or info["version"] is None:
            continue
        version = info["version"]
        if version in v1_versions or version in seen_new_versions:
            findings.append({
                "type": "reinitializer_version_reused",
                "function": name,
                "version": version,
            })
        else:
            seen_new_versions[version] = name

    return {"status": "flagged" if findings else "unchanged", "findings": findings}


def compute_initializer_safety_report(v1: Any, v2: Any) -> Dict[str, Any]:
    if not isinstance(v1, dict) or not isinstance(v1.get("contracts"), list):
        raise InitializerSafetyError("v1 must be a preprocess.py output (JSON object with a contracts array)")
    if not isinstance(v2, dict) or not isinstance(v2.get("contracts"), list):
        raise InitializerSafetyError("v2 must be a preprocess.py output (JSON object with a contracts array)")

    v1_by_key = {c["key"]: c for c in v1["contracts"] if isinstance(c, dict) and c.get("key")}
    v2_by_key = {c["key"]: c for c in v2["contracts"] if isinstance(c, dict) and c.get("key")}
    matched = sorted(set(v1_by_key) & set(v2_by_key))

    results = {key: diff_initializer_safety(v1_by_key[key], v2_by_key[key]) for key in matched}
    flagged = sorted(key for key, r in results.items() if r["status"] == "flagged")

    return {
        "initializerSafetyVersion": INITIALIZER_SAFETY_VERSION,
        "contractsCompared": matched,
        "contractsFlagged": flagged,
        "results": results,
        "note": "Structural/version facts only - never a severity, never a claim of exploitability. Does not detect a missing _disableInitializers() call (see module docstring).",
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


def _read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InitializerSafetyError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="initializer_safety.py",
        description="Deterministic upgrade initializer-safety check between two preprocess.py runs. Structural/version facts only, never a severity.",
    )
    parser.add_argument("v1", help="Path to the V1 (baseline) preprocess.py output JSON.")
    parser.add_argument("v2", help="Path to the V2 (candidate upgrade) preprocess.py output JSON.")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        v1 = _read_json_file(args.v1)
        v2 = _read_json_file(args.v2)
        result = compute_initializer_safety_report(v1, v2)
    except (InitializerSafetyError, OSError) as exc:
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
