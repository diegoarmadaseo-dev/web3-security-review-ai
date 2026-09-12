# -*- coding: utf-8 -*-
"""File-level checks (phase="file"): run once per file, before any per-scope
detector. Moved verbatim from the pre-V2.1 detect_solidity_signals monolith.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from text_utils import version_tuple


def detect_pragma_missing(ctx: Dict[str, Any]) -> None:
    pragma = ctx["structure"]["pragma"]
    if pragma["present"]:
        return
    pragma_line = pragma.get("line") or 1
    pragma_offset = ctx["line_index"].offset_of_line(pragma_line)
    ctx["collector"].add("pragma-missing.general", pragma_offset, None, {}, {"language": "solidity"}, line=1)


def detect_floating_pragma(ctx: Dict[str, Any]) -> None:
    pragma = ctx["structure"]["pragma"]
    if not pragma["present"] or not pragma["floating"]:
        return
    pragma_line = pragma.get("line") or 1
    pragma_offset = ctx["line_index"].offset_of_line(pragma_line)
    ctx["collector"].add("floating-pragma.general", pragma_offset, None, {}, {"expression": pragma["expression"], "minVersion": pragma["minVersion"]}, line=pragma_line)


def detect_obsolete_compiler(ctx: Dict[str, Any]) -> None:
    pragma = ctx["structure"]["pragma"]
    if not pragma["present"]:
        return
    min_version = version_tuple(pragma["minVersion"])
    if min_version is None or min_version >= (0, 8, 0):
        return
    pragma_line = pragma.get("line") or 1
    pragma_offset = ctx["line_index"].offset_of_line(pragma_line)
    ctx["collector"].add("obsolete-compiler.general", pragma_offset, None, {}, {"expression": pragma["expression"], "minVersion": pragma["minVersion"], "checkedArithmetic": False}, line=pragma_line)


def detect_legacy_arithmetic(ctx: Dict[str, Any]) -> None:
    pragma = ctx["structure"]["pragma"]
    if not pragma["present"]:
        return
    min_version = version_tuple(pragma["minVersion"])
    if min_version is None or min_version >= (0, 8, 0):
        return
    masked = ctx["masked"]
    uses_safemath = bool(re.search(r"\bSafeMath\b", masked))
    if uses_safemath or not re.search(r"[\w\)\]]\s*[+\-*]\s*[\w\(]", masked):
        return
    pragma_line = pragma.get("line") or 1
    pragma_offset = ctx["line_index"].offset_of_line(pragma_line)
    ctx["collector"].add("legacy-arithmetic.general", pragma_offset, None, {}, {"minVersion": pragma["minVersion"], "safeMathDetected": False}, line=pragma_line)


CHECKS = [
    ("pragma-missing.general", detect_pragma_missing),
    ("floating-pragma.general", detect_floating_pragma),
    ("obsolete-compiler.general", detect_obsolete_compiler),
    ("legacy-arithmetic.general", detect_legacy_arithmetic),
]
