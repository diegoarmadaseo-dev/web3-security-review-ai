#!/usr/bin/env python3
"""Minimal, provider-agnostic PR/CI security gate (V2.10, docs/decisiones.md
D-065).

Four capabilities:

  G1 (ingest_pr_changed_files) - turns an ALREADY-FETCHED list of a PR's
     changed files (one ref at a time - "base" or "head") into a
     preprocess.py-compatible multi-file bundle, reusing
     ingest_onchain.build_bundle() UNCHANGED for path sanitization and
     bundle-marker-injection rejection. A PR's changed files (especially
     from a fork) are exactly as untrusted as the explorer-sourced files
     D-055 already designed that defense for - this is the SAME threat
     model, so the SAME, already-audited defense applies without
     modification, not a re-derived copy of it.

  G2+G3 (evaluate_pr_gate) - diffs a base-ref report against a head-ref
     report using diff_reports.diff_reports() UNCHANGED (V2.5/D-054) for
     new/resolved/modified findings (G2), then evaluates a PASS/FAIL gate
     decision using ONLY newFindings against a caller-supplied severity
     threshold policy (G3) - resolvedFindings/modifiedFindings describe the
     BASELINE's own history, never something the PR itself introduced, and
     are never considered for the gate decision. The policy's
     blockingSeverities is ALWAYS an explicit caller input; this module has
     no hardcoded severity list and no code path that invents one.

  G4 (build_annotation_list) - a PURELY STRUCTURED, provider-agnostic
     annotation shape (file/line/contract/function/severity/category/
     stableKey) for every new finding. It NEVER includes free-text fields
     (description/evidence/recommendation/patch) or any reproduction of
     source/diff content - only the same bounded, structured fields
     locations[] and severity/category already carry, so a secret that
     happens to appear in a finding's free-text prose or evidence can never
     be echoed into a PR comment/annotation built from this list.

Architecture boundary (explicit, matching D-055's "network calls stay
outside the Skill" precedent, extended here): this module makes NO GitHub
API calls, holds NO credentials, and posts NO comments/annotations/commit
statuses itself. It never fetches a diff, a PR, or a file list - the
calling CI workflow (which already has its own token/permissions via
whatever mechanism its provider uses) does all of that, and is responsible
for turning this module's structured output into actual GitHub/GitLab/etc.
API calls, including any retries/timeouts/rate-limit handling those calls
need. This module is provider-agnostic by construction: nothing in its
input or output shape names a specific Git hosting provider.

No new detectors: G1 is pure ingestion reuse, G2 is pure diff_reports reuse,
G3 is a policy/aggregation layer over already-computed findings (never a
new judgment about a contract), and G4 is a pure re-shaping of already-
existing finding fields.

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

from ingest_onchain import build_bundle  # noqa: E402
from diff_reports import diff_reports, DiffError  # noqa: E402
from score import compute_stable_key  # noqa: E402

PR_GATE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_VALID_SEVERITIES = frozenset(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f]")

NEVER_A_GITHUB_CLIENT_NOTE = (
    "This module made no network calls, holds no credentials, and posted "
    "nothing itself. gateStatus/diff/annotations are structured facts for "
    "the calling CI workflow (which already has its own provider "
    "credentials) to act on - posting comments/annotations, setting a "
    "commit status, and any retry/timeout/rate-limit handling for those "
    "API calls are entirely that workflow's responsibility."
)

NEVER_SAFE_BY_SILENCE_NOTE = (
    "A gateStatus of PASS describes only what this specific comparison, "
    "given the specific base/head reports it was given, could determine "
    "under the caller's OWN threshold policy. It is never proof of safety: "
    "resolvedFindings/modifiedFindings are informational only and never "
    "affect the gate, a lower-severity newFinding below the policy "
    "threshold still exists, and only reviewing the underlying diff "
    "confirms whether a change is actually safe."
)


class PrGateError(Exception):
    """Raised when an input is too malformed/incomplete to ingest or gate
    (e.g. a malformed refLabel, or a policy missing blockingSeverities).
    Per-file ingestion problems within an otherwise valid PR are never
    raised - they are recorded in skippedFiles, exactly like
    ingest_onchain.build_bundle()'s own established contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PrGateError(message)


# ---------------------------------------------------------------------------
# G1: PR ingestion contract
# ---------------------------------------------------------------------------

def _require_safe_ref_label(ref_label: Any) -> str:
    _require(isinstance(ref_label, str) and ref_label.strip() != "", "refLabel must be a non-empty string")
    _require(
        not _CONTROL_CHAR_RE.search(ref_label),
        "refLabel must not contain control characters (including newlines) - it becomes part "
        "of the bundle's virtual path prefix and must never be able to inject a fake file "
        "boundary into the bundle build_bundle() produces",
    )
    return ref_label.strip()


def ingest_pr_changed_files(ref_label: Any, changed_files: Any) -> Dict[str, Any]:
    """G1.  ref_label is an OPAQUE caller-supplied label identifying which
    ref/commit these files belong to (e.g. "base", "head", or a real SHA -
    never parsed, never validated as a real git ref, matching monitor_diff.py's
    "caller-declared, never inferred" convention). changed_files is a list of
    {"path": str, "content": str} - the CALLER (an already-authenticated CI
    workflow) is responsible for fetching this from its Git provider; this
    function never touches the network.

    Reuses ingest_onchain.build_bundle() UNCHANGED for path sanitization,
    duplicate-path rejection, and bundle-marker-injection rejection - a PR's
    changed files (especially from a fork) are exactly as untrusted as
    explorer-sourced files, so the SAME, already-audited defense applies."""
    label = _require_safe_ref_label(ref_label)
    _require(isinstance(changed_files, list), "changedFiles must be an array")
    bundle, accepted_count, skipped = build_bundle("pr://%s/" % label, changed_files)
    return {
        "prGateVersion": PR_GATE_VERSION,
        "refLabel": label,
        "bundle": bundle,
        "acceptedFileCount": accepted_count,
        "skippedFiles": skipped,
    }


# ---------------------------------------------------------------------------
# G4: provider-agnostic annotation shape
# ---------------------------------------------------------------------------

def build_annotation_list(findings: Any) -> List[Dict[str, Any]]:
    """G4.  Provider-agnostic, purely STRUCTURED annotation shape - never a
    GitHub/GitLab/etc.-specific payload (no workflow-command syntax, no API
    request shape) and never a free-text field. Only file/lineStart/lineEnd/
    contract/function/severity/category/stableKey - the same bounded fields
    report-schema.json's locations[] and top-level severity/category already
    constrain - so a secret that happens to appear in a finding's free-text
    description/evidence/recommendation/patch can never be echoed here."""
    if not isinstance(findings, list):
        return []
    annotations = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        locations = finding.get("locations") or []
        loc = locations[0] if locations and isinstance(locations[0], dict) else {}
        annotations.append({
            "file": loc.get("file"),
            "lineStart": loc.get("lineStart"),
            "lineEnd": loc.get("lineEnd"),
            "contract": loc.get("contract"),
            "function": loc.get("function"),
            "severity": finding.get("severity"),
            "category": finding.get("category"),
            "stableKey": compute_stable_key(finding),
        })
    return annotations


# ---------------------------------------------------------------------------
# G2+G3: baseline-vs-PR diff and deterministic gate
# ---------------------------------------------------------------------------

def _require_blocking_severities(policy: Any) -> List[str]:
    _require(isinstance(policy, dict), "policy must be a JSON object")
    severities = policy.get("blockingSeverities")
    _require(
        isinstance(severities, list) and all(isinstance(s, str) for s in severities),
        "policy.blockingSeverities is required and must be a list of severity strings - "
        "thresholds are always an explicit caller input, never hardcoded or guessed",
    )
    unknown = sorted(set(severities) - _VALID_SEVERITIES)
    _require(
        not unknown,
        "policy.blockingSeverities contains unrecognized severity value(s) %r - must be a "
        "subset of %s (report-schema.json's own severity enum, never a different vocabulary)"
        % (unknown, sorted(_VALID_SEVERITIES)),
    )
    return list(dict.fromkeys(severities))  # de-duplicate, preserve caller-given order


def evaluate_pr_gate(base_report: Dict[str, Any], head_report: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """G2 (diff) + G3 (gate).

    G2: calls diff_reports.diff_reports() UNCHANGED (V2.5/D-054) - never
    re-derived, never modified.

    G3: the gate decision considers ONLY diff["newFindings"] - a finding
    already present in the baseline (resolvedFindings/modifiedFindings)
    describes the codebase's pre-existing history, not something this PR
    introduced, and never blocks it. blockingSeverities is REQUIRED,
    explicit, caller-supplied input; an empty list is a valid (if unusual)
    caller choice meaning nothing blocks."""
    diff = diff_reports(base_report, head_report)
    blocking_severities = _require_blocking_severities(policy)

    new_findings = diff["newFindings"]
    blocking_findings = [f for f in new_findings if isinstance(f, dict) and f.get("severity") in blocking_severities]

    return {
        "prGateVersion": PR_GATE_VERSION,
        "gateStatus": "FAIL" if blocking_findings else "PASS",
        "policy": {"blockingSeverities": blocking_severities},
        "diff": diff,
        "blockingFindingCount": len(blocking_findings),
        "annotations": build_annotation_list(new_findings),
        "note": NEVER_SAFE_BY_SILENCE_NOTE,
        "boundaryNote": NEVER_A_GITHUB_CLIENT_NOTE,
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
        raise PrGateError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pr_gate.py",
        description=(
            "Minimal, provider-agnostic PR/CI security gate (V2.10). Never fetches a PR "
            "itself; never calls a Git-hosting API; never posts anything."
        ),
    )
    subparsers = parser.add_subparsers(dest="gate_mode", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Build a preprocess.py-ready bundle from one ref's already-fetched changed files.")
    ingest_parser.add_argument("input", help="Path to a JSON file: {\"refLabel\": str, \"changedFiles\": [{\"path\",\"content\"}, ...]}")
    ingest_parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    ingest_parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")

    gate_parser = subparsers.add_parser("gate", help="Diff base vs head scored reports and evaluate the PASS/FAIL policy.")
    gate_parser.add_argument("base_report", help="Path to the BASE ref's scored report JSON.")
    gate_parser.add_argument("head_report", help="Path to the HEAD ref's scored report JSON.")
    gate_parser.add_argument("policy", help="Path to a JSON file: {\"blockingSeverities\": [...]}")
    gate_parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    gate_parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        if args.gate_mode == "ingest":
            payload = _read_json_file(args.input)
            _require(isinstance(payload, dict), "%s must contain a JSON object" % args.input)
            result = ingest_pr_changed_files(payload.get("refLabel"), payload.get("changedFiles"))
        else:
            base_report = _read_json_file(args.base_report)
            head_report = _read_json_file(args.head_report)
            policy = _read_json_file(args.policy)
            result = evaluate_pr_gate(base_report, head_report, policy)
    except (PrGateError, DiffError, OSError, json.JSONDecodeError) as exc:
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
