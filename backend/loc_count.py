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

_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".claude", "skills", "web3-auditor", "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import preprocess as _pp  # noqa: E402

WORKER_SOURCE_NAME = "contract.sol"   # basename of backend/worker_entrypoint.py's SOURCE_PATH


def submission_effective_loc(source: str) -> int:
    """Total effective LOC the worker's preprocess run will report for
    this exact `source` string."""
    data = source.encode("utf-8")
    text, _, _ = _pp.normalize_text(data)
    if text is not None and _pp.looks_like_bundle(text):
        entries = [{"path": item["path"], "text": item["text"]} for item in _pp.parse_bundle(text, WORKER_SOURCE_NAME)]
    else:
        entries = [{"path": WORKER_SOURCE_NAME, "text": text}]
    total = 0
    for entry in entries:
        body = entry["text"]
        if body is None or not body.strip():
            continue
        language = _pp.detect_language(entry["path"], body)
        if language not in ("solidity", "vyper"):
            continue
        masked = _pp.mask_solidity(body) if language == "solidity" else _pp.mask_vyper(body)
        total += _pp.line_metrics(body, masked["masked"])["effective"]
    return total
