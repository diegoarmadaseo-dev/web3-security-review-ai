# -*- coding: utf-8 -*-
"""Generic, stdlib-only text/offset helpers shared by preprocess.py's structural
parser, its secret/injection scanners, and every detector in detectors/.

Extracted out of preprocess.py (V2.1, docs/decisiones.md) so scripts/detectors/
can depend on these without importing preprocess.py itself (preprocess.py
imports the detector registry, not the other way around). No behavior change:
every function/class here is moved verbatim from preprocess.py.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
ELEMENTARY_TYPES = re.compile(r"^(u?int\d*|address(\s+payable)?|bool|bytes\d*|string|mapping|function|fixed\d*x?\d*|ufixed\d*x?\d*)$")


def version_tuple(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if not version:
        return None
    match = VERSION_RE.match(version)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def truncate(text: str, limit: int) -> Tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[: limit - 1] + "…", True


def matching_paren(masked: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(masked)):
        char = masked[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def split_top_level(text: str, separator: str = ",") -> List[str]:
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if "".join(current).strip():
        parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


class LineIndex:
    """Maps character offsets to 1-based line numbers and 0-based columns."""

    def __init__(self, text: str) -> None:
        self.starts: List[int] = [0]
        for idx, char in enumerate(text):
            if char == "\n":
                self.starts.append(idx + 1)
        self.lines = text.split("\n")

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def col_of(self, offset: int) -> int:
        return offset - self.starts[self.line_of(offset) - 1]

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def offset_of_line(self, line: int) -> int:
        return self.starts[line - 1]

    @property
    def count(self) -> int:
        return len(self.lines)
