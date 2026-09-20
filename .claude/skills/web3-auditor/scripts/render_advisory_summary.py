#!/usr/bin/env python3
"""Human-readable Markdown rendering of the advisory scripts' JSON outputs
(V3 Block 6, E3, docs/decisiones.md D-074).

Every advisory script since V3 Block 3 (storage_layout.py/privilege_path.py/
bytecode_advisory.py/change_impact.py/proxy_fingerprint.py/compiler_bugs.py/
upgrade_gap.py/initializer_safety.py/bytecode_size.py/
bytecode_compiler_bugs.py/delegatecall_cycle.py/constructor_zero_address.py)
outputs JSON only - unlike the core pipeline, which has had human-readable
rendering since render_report.py's own introduction. This module closes
that gap for a BUNDLE of already-computed outputs the caller supplies
under known keys (see `_SECTION_TITLES`).

FORMATTING ONLY - reuses render_report.py's own rendering CONVENTION
(build a `lines: List[str]`, join with "\n" - matched here deliberately).
This module introduces NO new judgment: it walks whatever JSON each
section already contains and prints it as nested bullets, generically,
never selecting or computing which fields "matter" for a specific tool. A
tool the caller didn't run is simply absent from the bundle and skipped -
never a placeholder claiming that tool found nothing.

TWO SAFETY PROPERTIES, both added after an adversarial audit found real
gaps (docs/decisiones.md D-074): (1) every piece of text this module
renders - a section heading (known OR caller-supplied/unknown), a nested
dict key, or a scalar value - has every C0 control character and DEL
stripped via `_sanitize_text` before it reaches the output, so a NUL byte,
an ANSI escape sequence, or an embedded newline can never inject a fake
Markdown heading or a raw control byte into the rendered text; unlike
render_report.py's own values (always from a fixed vocabulary), an unknown
section's KEY is directly caller-supplied and was the actual gap found.
(2) `_render_value`'s recursion is bounded by `_MAX_RENDER_DEPTH` (40,
comfortably below Python's default recursion limit) - a pathologically
deep input raises `RenderAdvisorySummaryError` (a clean, caught error),
never an uncaught `RecursionError`/traceback.

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

RENDER_ADVISORY_SUMMARY_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_MAX_LIST_ITEMS = 20  # defensive cap only - avoids a runaway render on a pathological input.
_MAX_RENDER_DEPTH = 40  # comfortably below Python's default recursion limit; real tool outputs are a handful of levels deep.

# Every C0 control character (NUL, ESC, newline/CR/tab, ...), every C1
# control character (\x80-\x9f - e.g. NEL \x85, and CSI \x9b, the 8-bit
# equivalent of ESC[ that a C0-only filter still let through, found by a
# follow-up audit), and DEL - stripped from EVERY piece of text this
# module renders (section keys used as headings, nested dict keys, and
# scalar values alike), not only "known-dangerous" ones. Ordinary
# printable text - ASCII or any other Unicode letter/symbol outside these
# two 32-code-point control ranges - is never touched. A heading is
# inherently single-line, so removing a newline from one is correct, not
# a data loss; for an ordinary multi-line value it trades exact
# whitespace for the guarantee that no control byte ever reaches the
# rendered text - see docs/decisiones.md D-074.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _sanitize_text(text: str) -> str:
    return _CONTROL_CHAR_RE.sub(" ", text)

# Bundle key -> display title. Order here is DISPLAY order only, never a
# judgment about importance.
_SECTION_TITLES = {
    "storageLayout": "Storage Layout (B1)",
    "privilegePath": "Cross-Contract Privilege Paths (B2)",
    "bytecodeAdvisory": "Bytecode Opcode Advisories (B3)",
    "changeImpact": "Change Impact (B4)",
    "proxyFingerprint": "Proxy Pattern Fingerprint (C1)",
    "compilerBugs": "Compiler Bug Cross-Reference (C2)",
    "upgradeGap": "Upgrade Storage Gap (C3)",
    "initializerSafety": "Initializer Safety (D1)",
    "bytecodeSize": "Bytecode Size (D2)",
    "bytecodeCompilerBugs": "Bytecode Compiler Bug Bridge (D3)",
    "delegatecallCycle": "Delegatecall Cycle Detection (E1)",
    "constructorZeroAddress": "Constructor Zero-Address Check (E2)",
}


class RenderAdvisorySummaryError(Exception):
    """Raised only for malformed top-level input - never for an empty
    bundle or a section with no findings, both normal results."""


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return _sanitize_text(str(value))


def _render_value(value: Any, indent: int) -> List[str]:
    if indent > _MAX_RENDER_DEPTH:
        raise RenderAdvisorySummaryError(
            "nesting depth exceeds the maximum of %d levels - refusing to render (malformed or pathological input)" % _MAX_RENDER_DEPTH
        )
    prefix = "  " * indent
    if isinstance(value, dict):
        lines: List[str] = []
        for key in sorted(value):
            child = value[key]
            safe_key = _sanitize_text(str(key))
            if isinstance(child, (dict, list)) and child:
                lines.append("%s- **%s:**" % (prefix, safe_key))
                lines.extend(_render_value(child, indent + 1))
            else:
                lines.append("%s- **%s:** %s" % (prefix, safe_key, _scalar(child)))
        return lines or ["%s(empty)" % prefix]
    if isinstance(value, list):
        if not value:
            return ["%s(none)" % prefix]
        lines = []
        for item in value[:_MAX_LIST_ITEMS]:
            if isinstance(item, (dict, list)):
                lines.append("%s-" % prefix)
                lines.extend(_render_value(item, indent + 1))
            else:
                lines.append("%s- %s" % (prefix, _scalar(item)))
        if len(value) > _MAX_LIST_ITEMS:
            lines.append("%s- ... (%d more)" % (prefix, len(value) - _MAX_LIST_ITEMS))
        return lines
    return ["%s%s" % (prefix, _scalar(value))]


def render_markdown(bundle: Any) -> str:
    """Pure function; never mutates `bundle`."""
    if not isinstance(bundle, dict):
        raise RenderAdvisorySummaryError("bundle must be a JSON object mapping known section keys to tool outputs")

    lines: List[str] = [
        "# Advisory Checks Summary",
        "",
        "Rendering only - no new judgment, severity, or computation is introduced here; each section is exactly what its own tool already produced.",
        "",
    ]
    # Known keys first (in the documented display order), then any
    # unrecognized key the caller supplied anyway, in sorted order - an
    # unknown section is rendered generically under its own name, never
    # silently dropped (dropping it would itself be a judgment call).
    known_present = [key for key in _SECTION_TITLES if key in bundle]
    unknown_present = sorted(key for key in bundle if key not in _SECTION_TITLES)
    present = known_present + unknown_present
    if not present:
        lines.append("_No advisory tool outputs were provided._")
        return "\n".join(lines)

    for key in present:
        lines.append("## %s" % _sanitize_text(_SECTION_TITLES.get(key, key)))
        lines.append("")
        data = bundle[key]
        if not isinstance(data, dict):
            lines.append("_(malformed entry for this section - expected an object, got %s)_" % type(data).__name__)
        else:
            lines.extend(_render_value(data, 0))
        lines.append("")

    return "\n".join(lines)


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
        raise RenderAdvisorySummaryError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="render_advisory_summary.py",
        description="Renders a bundle of already-computed advisory-script outputs as one human-readable Markdown summary. Formatting only.",
    )
    parser.add_argument("input", nargs="?", default=None, help="Path to a JSON file mapping known section keys to tool outputs. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the Markdown to this file instead of stdout.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        bundle = _read_json_file(args.input)
        text = render_markdown(bundle)
    except (RenderAdvisorySummaryError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
