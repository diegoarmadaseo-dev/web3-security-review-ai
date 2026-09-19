#!/usr/bin/env python3
"""Thin, provider-agnostic Python API facade over this Skill's deterministic
scripts (V2.11, docs/decisiones.md D-066, capability A-02).

RE-EXPORTS ONLY - every name below is imported, unchanged, from the script
that already owns it; this module contains zero logic of its own beyond the
import statements themselves. It exists so an external Python caller (a CI
script, another internal tool) has ONE stable, documented import path
instead of needing to know this Skill's internal file layout - the exact
same "PUBLIC functions imported at module level" convention this project
already uses for cross-script reuse (see e.g. pr_gate.py importing
ingest_onchain.build_bundle), now exposed as a single flat surface.

Only each script's own established public capability entrypoint(s), its own
exception class, and functions ALREADY proven to be cross-script reuse
points (build_bundle, diff_reports/DiffError, compute_stable_key,
byte_divergence_profile, chains.py's resolve_chain/load_chains_config/
get_chain_capabilities) are re-exported here - internal building blocks
(e.g. preprocess.py's mask_solidity/parse_pragma, or any detectors/*.py
detect_* function) are deliberately NOT part of this surface: they are
preprocessing/detector internals, not a stable capability contract.

Architecture boundary (unchanged from every prior version - D-055, D-063 M4,
D-065's G-boundary): every function re-exported here is a stateless, pure
function of its arguments. This module makes no network/API calls, holds no
credentials, opens no files, and starts no server - so API authentication,
secrets/input isolation beyond what each function's own docstring already
guarantees, and timeouts/resource limits are NOT concerns of this module and
are NOT implemented here: there is no credential to hold, no shared/multi-
tenant state to isolate, and no unbounded operation (network wait, retry
loop, recursion) to bound. If this facade is ever wrapped by a hosted
service, that wrapper owns authentication, request isolation, and resource
governance entirely - exactly the same "network stays outside the Skill"
boundary already established for RPC calls, never re-litigated here.

Backward compatibility: this module is a pure ADDITION. Every script's own
existing CLI (invoked directly, e.g. `python pr_gate.py ...`) is unchanged
and keeps working exactly as before - see cli.py (A-01) for a unified
command-line entrypoint over the same set of scripts.

Standard library only (via the modules it re-exports). No network access,
no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

API_VERSION = "2026.1"

# Step 3 - deterministic preprocessing (never Step 6 AI judgment).
from preprocess import run as preprocess_run, PreprocessError, ModesConfigError, load_modes_config  # noqa: E402,F401

# On-chain, already-fetched-data ingestion (never a network call itself).
from ingest_onchain import (  # noqa: E402,F401
    ingest as ingest_onchain_record,
    build_bundle,
    find_contradictory_duplicate_identities,
    check_network_identity_consistency,
    IngestError,
)

# Source-vs-deployed / cross-chain bytecode comparison.
from compare_bytecode import (  # noqa: E402,F401
    compare as compare_bytecode,
    byte_divergence_profile,
    normalize_hex,
    strip_cbor_metadata,
    CompareError,
)

# Deterministic version/security diff.
from diff_reports import (  # noqa: E402,F401
    diff_reports,
    diff_preprocess,
    DiffError,
)

# Step 7 - deterministic scoring (never a judgment call).
from score import score_report, compute_stable_key, ScoreError  # noqa: E402,F401

# Step 8 - deterministic validation.
from validate_report import validate_report, ReportValidationError  # noqa: E402,F401

# Step 9 - deterministic rendering.
from render_report import render_markdown, render_html, ReportRenderError  # noqa: E402,F401

# Continuous monitoring / history (never storage, never alerts, never a clock).
from monitor_diff import (  # noqa: E402,F401
    monitor_snapshot_pair,
    compute_temporal_snapshot_drift,
    compute_finding_lifecycle,
    compute_snapshot_coverage_status,
    compute_snapshot_content_hash,
    snapshots_are_identical,
    MonitorDiffError,
)

# Provider-agnostic PR/CI security gate (never a Git-hosting client).
from pr_gate import (  # noqa: E402,F401
    ingest_pr_changed_files,
    evaluate_pr_gate,
    build_annotation_list,
    PrGateError,
)

# EVM chain catalog / capability lookup.
from chains import (  # noqa: E402,F401
    resolve_chain,
    get_chain_capabilities,
    load_chains_config,
    ChainsConfigError,
)

# Mechanized deterministic pipeline (Steps 3->7->8 retry<=2->9); never Step 6.
from analyze_pipeline import (  # noqa: E402,F401
    run_analyze_pipeline,
    AnalyzePipelineError,
)
