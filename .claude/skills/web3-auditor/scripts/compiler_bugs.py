#!/usr/bin/env python3
"""Deterministic Solidity known-compiler-bug cross-reference against a
bundled, versioned, offline dataset (V3 Block 4, C2, docs/decisiones.md
D-072).

Loads `config/solc-known-bugs.json` (same directory/loading pattern as
`preprocess.py`'s `load_modes_config()` for `config/modes.json` - a single
bundled file, never a second copy of its own schema) and checks a single
`compilerVersion` string for EXACT semantic-version membership in
`[introducedVersion, fixedVersion)` for each bug entry - never a fuzzy or
range-guessed match; a version that cannot be parsed as `X.Y.Z` is reported
as "unparseable_version", never silently skipped or silently assumed safe.

**DATASET PROVENANCE, STATED EXPLICITLY**: `config/solc-known-bugs.json` is
a STUB seeded from training knowledge, NOT independently re-verified this
session against Solidity's own published bug list (this analyzer's core is
network-free by design and has no way to fetch it live) - the dataset's own
`provenance` field says so, and every entry currently carries
`"verified": false`. This module's OUTPUT always echoes back each matched
entry's `verified` flag and the dataset's own `datasetVersion`/`sourceUrl`,
so a caller can never mistake a stub-data hit for a confirmed one.

No network access, no live feed - the dataset is loaded from disk exactly
once, as a static file. No network access, no LLM calls. Python 3.8+.
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

CONFIG_DIR = os.path.join(SCRIPT_DIR, "..", "config")
DATASET_PATH = os.path.join(CONFIG_DIR, "solc-known-bugs.json")

COMPILER_BUGS_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1


class CompilerBugsError(Exception):
    """Raised only for malformed input or an unreadable/malformed bundled
    dataset - never for "this version is not affected", a normal result."""


def _parse_semver(text: Any) -> Optional[Tuple[int, int, int]]:
    if not isinstance(text, str):
        return None
    parts = text.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def load_known_bugs_dataset(path: str = DATASET_PATH) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        try:
            dataset = json.load(handle)
        except json.JSONDecodeError as exc:
            raise CompilerBugsError("%s is not valid JSON: %s" % (path, exc)) from exc
    if not isinstance(dataset, dict) or not isinstance(dataset.get("bugs"), list):
        raise CompilerBugsError("%s must be a JSON object with a bugs array" % path)
    return dataset


def check_compiler_version(compiler_version: Any, dataset: Dict[str, Any]) -> Dict[str, Any]:
    """Pure function; raises only if `dataset` itself is malformed. Never
    mutates `dataset`."""
    if not isinstance(dataset.get("bugs"), list):
        raise CompilerBugsError("dataset must be a JSON object with a bugs array")

    parsed = _parse_semver(compiler_version)
    if parsed is None:
        return {
            "status": "unparseable_version",
            "compilerVersion": compiler_version,
            "matches": [],
        }

    matches: List[Dict[str, Any]] = []
    for bug in dataset["bugs"]:
        if not isinstance(bug, dict):
            continue
        introduced = _parse_semver(bug.get("introducedVersion"))
        fixed = _parse_semver(bug.get("fixedVersion"))
        if introduced is None or fixed is None:
            continue  # malformed dataset entry: never guessed as a match.
        if introduced <= parsed < fixed:
            matches.append({
                "uid": bug.get("uid"),
                "name": bug.get("name"),
                "severity": bug.get("severity"),
                "summary": bug.get("summary"),
                "verified": bool(bug.get("verified", False)),
            })

    return {
        "status": "affected" if matches else "not_affected",
        "compilerVersion": compiler_version,
        "matches": matches,
    }


def compute_compiler_bug_report(payload: Any, dataset: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise CompilerBugsError("input must be a JSON object with a compilerVersion field")
    if "compilerVersion" not in payload:
        raise CompilerBugsError("input must have a compilerVersion field")

    if dataset is None:
        dataset = load_known_bugs_dataset()

    result = check_compiler_version(payload["compilerVersion"], dataset)
    return {
        "compilerBugsVersion": COMPILER_BUGS_VERSION,
        "datasetVersion": dataset.get("datasetVersion"),
        "datasetSourceUrl": dataset.get("sourceUrl"),
        "datasetProvenance": dataset.get("provenance"),
        **result,
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
        raise CompilerBugsError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compiler_bugs.py",
        description=(
            "Deterministic known-Solidity-compiler-bug cross-reference against a bundled, offline dataset. "
            "Exact semantic-version matching only, dataset provenance always echoed back."
        ),
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file: {\"compilerVersion\": \"0.8.13\"}. Reads stdin if omitted.")
    parser.add_argument("--dataset", default=None, help="Path to an alternate dataset JSON (default: config/solc-known-bugs.json).")
    parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = _read_json_file(args.input)
        dataset = load_known_bugs_dataset(args.dataset) if args.dataset else None
        result = compute_compiler_bug_report(payload, dataset)
    except (CompilerBugsError, OSError) as exc:
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
