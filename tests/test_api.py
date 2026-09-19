"""Tests for scripts/api.py (V2.11 - Thin Python API Facade, docs/
decisiones.md D-066, capability A-02).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import api  # noqa: E402
import preprocess  # noqa: E402
import ingest_onchain  # noqa: E402
import compare_bytecode  # noqa: E402
import diff_reports  # noqa: E402
import score  # noqa: E402
import validate_report  # noqa: E402
import render_report  # noqa: E402
import monitor_diff  # noqa: E402
import pr_gate  # noqa: E402
import chains  # noqa: E402
import analyze_pipeline  # noqa: E402

# (facade attribute name, source module, source attribute name)
REEXPORTS = [
    ("preprocess_run", preprocess, "run"),
    ("PreprocessError", preprocess, "PreprocessError"),
    ("ModesConfigError", preprocess, "ModesConfigError"),
    ("load_modes_config", preprocess, "load_modes_config"),
    ("ingest_onchain_record", ingest_onchain, "ingest"),
    ("build_bundle", ingest_onchain, "build_bundle"),
    ("find_contradictory_duplicate_identities", ingest_onchain, "find_contradictory_duplicate_identities"),
    ("check_network_identity_consistency", ingest_onchain, "check_network_identity_consistency"),
    ("IngestError", ingest_onchain, "IngestError"),
    ("compare_bytecode", compare_bytecode, "compare"),
    ("byte_divergence_profile", compare_bytecode, "byte_divergence_profile"),
    ("normalize_hex", compare_bytecode, "normalize_hex"),
    ("strip_cbor_metadata", compare_bytecode, "strip_cbor_metadata"),
    ("CompareError", compare_bytecode, "CompareError"),
    ("diff_reports", diff_reports, "diff_reports"),
    ("diff_preprocess", diff_reports, "diff_preprocess"),
    ("DiffError", diff_reports, "DiffError"),
    ("score_report", score, "score_report"),
    ("compute_stable_key", score, "compute_stable_key"),
    ("ScoreError", score, "ScoreError"),
    ("validate_report", validate_report, "validate_report"),
    ("ReportValidationError", validate_report, "ReportValidationError"),
    ("render_markdown", render_report, "render_markdown"),
    ("render_html", render_report, "render_html"),
    ("ReportRenderError", render_report, "ReportRenderError"),
    ("monitor_snapshot_pair", monitor_diff, "monitor_snapshot_pair"),
    ("compute_temporal_snapshot_drift", monitor_diff, "compute_temporal_snapshot_drift"),
    ("compute_finding_lifecycle", monitor_diff, "compute_finding_lifecycle"),
    ("compute_snapshot_coverage_status", monitor_diff, "compute_snapshot_coverage_status"),
    ("compute_snapshot_content_hash", monitor_diff, "compute_snapshot_content_hash"),
    ("snapshots_are_identical", monitor_diff, "snapshots_are_identical"),
    ("MonitorDiffError", monitor_diff, "MonitorDiffError"),
    ("ingest_pr_changed_files", pr_gate, "ingest_pr_changed_files"),
    ("evaluate_pr_gate", pr_gate, "evaluate_pr_gate"),
    ("build_annotation_list", pr_gate, "build_annotation_list"),
    ("PrGateError", pr_gate, "PrGateError"),
    ("resolve_chain", chains, "resolve_chain"),
    ("get_chain_capabilities", chains, "get_chain_capabilities"),
    ("load_chains_config", chains, "load_chains_config"),
    ("ChainsConfigError", chains, "ChainsConfigError"),
    ("run_analyze_pipeline", analyze_pipeline, "run_analyze_pipeline"),
    ("AnalyzePipelineError", analyze_pipeline, "AnalyzePipelineError"),
]


class ReexportIdentityTests(unittest.TestCase):
    """A-02's own rule: 're-exports only; no duplicated logic'. Identity
    (`is`), not equality, is the only check that actually proves this - a
    copy could still be equal-by-value but would silently drift from the
    original the moment either side changed."""

    def test_every_reexport_is_the_identical_object_from_its_source_module(self):
        for facade_name, source_module, source_name in REEXPORTS:
            with self.subTest(facade_name=facade_name):
                self.assertTrue(hasattr(api, facade_name), "api.py is missing %r" % facade_name)
                self.assertIs(
                    getattr(api, facade_name),
                    getattr(source_module, source_name),
                    "api.%s is not the SAME object as %s.%s - looks duplicated, not re-exported"
                    % (facade_name, source_module.__name__, source_name),
                )

    def test_api_version_is_a_string(self):
        self.assertIsInstance(api.API_VERSION, str)
        self.assertTrue(api.API_VERSION)


class FunctionalSmokeTests(unittest.TestCase):
    """A couple of calls through the facade against the real modules, not
    just identity - proves the re-exports are actually usable, not merely
    present."""

    def test_compute_stable_key_through_facade_matches_direct_call(self):
        finding = {"category": "SC01", "locations": [{"file": "A.sol"}]}
        self.assertEqual(api.compute_stable_key(finding), score.compute_stable_key(finding))

    def test_resolve_chain_through_facade_matches_direct_call(self):
        self.assertEqual(api.resolve_chain(1), chains.resolve_chain(1))

    def test_build_bundle_through_facade_matches_direct_call(self):
        files = [{"path": "A.sol", "content": "contract A {}"}]
        self.assertEqual(api.build_bundle("onchain://1/0xabc/", files), ingest_onchain.build_bundle("onchain://1/0xabc/", files))

    def test_diff_error_through_facade_is_raised_by_diff_reports(self):
        with self.assertRaises(api.DiffError):
            api.diff_reports({"findings": "not-a-list"}, {"findings": []})

    def test_evaluate_pr_gate_through_facade_matches_direct_call(self):
        base = {"findings": [], "categoryCoverage": []}
        head = {"findings": [], "categoryCoverage": []}
        policy = {"blockingSeverities": ["HIGH"]}
        self.assertEqual(
            api.evaluate_pr_gate(base, head, policy)["gateStatus"],
            pr_gate.evaluate_pr_gate(base, head, policy)["gateStatus"],
        )


if __name__ == "__main__":
    unittest.main()
