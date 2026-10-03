#!/usr/bin/env python3
"""Effective LOC of a job submission, measured exactly as the analysis
worker will measure it (docs/decisiones.md D-107).

The worker writes the submitted `source` text to /scratch/contract.sol and
runs scripts/preprocess.py on that one path (backend/worker_entrypoint.py):
preprocess.collect_inputs() splits it into files when it is a
"=== FILE: ... ===" bundle, otherwise treats it as one file named
contract.sol, and the artifact's totalEffectiveLoc is the sum of
line_metrics()["effective"] over the Solidity/Vyper source entries. This
module replays exactly that path with preprocess.py's OWN functions
(normalize_text, looks_like_bundle, parse_bundle, detect_language,
mask_solidity/mask_vyper, line_metrics) - never a second, approximate
counter - so the commercial limit a customer is charged against is the
same number the engine reports. tests/test_backend_commercial.py checks
the equality against preprocess.run() itself.

Only lexing happens here: no structure parsing, no detectors, no LLM, no
subprocess. Measured at the 2 MiB submission ceiling: 0.1-0.4 s. The web
process therefore imports the Skill's scripts package (copied into the
web image by backend/docker/Dockerfile.web); before D-107 it only read
config/modes.json.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".claude", "skills", "web3-auditor", "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import preprocess as _pp  # noqa: E402

WORKER_SOURCE_NAME = "contract.sol"   # basename of backend/worker_entrypoint.py's SOURCE_PATH

# preprocess.py's own file policy and bundle markers, re-exported (never
# copied) for backend/submission_input.py (D-109), so the multi-file/ZIP
# validation and the engine can never disagree on what a source file or a
# bundle marker is.
SOURCE_EXTENSIONS = _pp.SOURCE_EXTENSIONS
DOCUMENT_EXTENSIONS = _pp.DOCUMENT_EXTENSIONS
DOCUMENT_BASENAMES = _pp.DOCUMENT_BASENAMES
BUNDLE_START_RE = _pp.BUNDLE_START_RE
BUNDLE_END_RE = _pp.BUNDLE_END_RE
detect_language = _pp.detect_language


def entry_effective_loc(path: str, text: Optional[str]) -> int:
    """Effective LOC of ONE file as the engine counts it (0 for anything
    that is not Solidity/Vyper source)."""
    if text is None or not text.strip():
        return 0
    language = _pp.detect_language(path, text)
    if language not in ("solidity", "vyper"):
        return 0
    masked = _pp.mask_solidity(text) if language == "solidity" else _pp.mask_vyper(text)
    return _pp.line_metrics(text, masked["masked"])["effective"]


def submission_effective_loc(source: str) -> int:
    """Total effective LOC the worker's preprocess run will report for
    this exact `source` string (a single file or a bundle - D-109's
    multi-file/ZIP submissions arrive here as the bundle they built)."""
    data = source.encode("utf-8")
    text, _, _ = _pp.normalize_text(data)
    if text is not None and _pp.looks_like_bundle(text):
        entries = [{"path": item["path"], "text": item["text"]} for item in _pp.parse_bundle(text, WORKER_SOURCE_NAME)]
    else:
        entries = [{"path": WORKER_SOURCE_NAME, "text": text}]
    return sum(entry_effective_loc(entry["path"], entry["text"]) for entry in entries)
