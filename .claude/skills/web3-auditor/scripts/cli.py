#!/usr/bin/env python3
"""Unified CLI dispatcher over this Skill's deterministic scripts (V2.11,
docs/decisiones.md D-066, capability A-01).

PURE DISPATCH ONLY: each command below forwards its remaining arguments
UNCHANGED to that script's own, already-existing main(argv) - see that
script's own --help for its actual arguments. This module adds no new
argument parsing, no new validation, and no new output shape of its own; it
exists only so a caller can invoke `cli.py <command> ...` instead of needing
to know which of the 9 underlying script files to invoke directly.

Backward compatibility: every script's own CLI (`python pr_gate.py ...`,
`python preprocess.py ...`, etc.) is UNCHANGED and keeps working exactly as
before. This dispatcher is a pure ADDITION, never a replacement.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from typing import List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

CLI_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

# command name -> (module name, module's own main(argv) function name).
# Order here is the order shown in the usage listing.
COMMANDS = {
    "preprocess": "preprocess",
    "score": "score",
    "validate": "validate_report",
    "render": "render_report",
    "ingest": "ingest_onchain",
    "compare": "compare_bytecode",
    "diff": "diff_reports",
    "monitor": "monitor_diff",
    "pr-gate": "pr_gate",
    "analyze-pipeline": "analyze_pipeline",
}


def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _usage_text() -> str:
    lines = ["usage: cli.py <command> [args...]", "", "commands:"]
    for name, module_name in COMMANDS.items():
        lines.append("  %-18s -> %s.py (see: python %s.py --help)" % (name, module_name, module_name))
    lines.append("")
    lines.append("Every command forwards its remaining arguments UNCHANGED to that script's own CLI.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if not argv:
        print(_usage_text())
        return EXIT_FAILED
    if argv[0] in ("-h", "--help"):
        print(_usage_text())
        return EXIT_OK
    command, rest = argv[0], argv[1:]
    module_name = COMMANDS.get(command)
    if module_name is None:
        print(json.dumps(
            {"ok": False, "error": "unknown command %r (choices: %s)" % (command, sorted(COMMANDS))},
            ensure_ascii=False,
        ))
        return EXIT_FAILED
    module = importlib.import_module(module_name)
    return module.main(rest)


if __name__ == "__main__":
    sys.exit(main())
