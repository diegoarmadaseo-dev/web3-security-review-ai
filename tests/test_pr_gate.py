"""Tests for scripts/pr_gate.py (V2.10 - Minimal, Provider-Agnostic PR/CI
Security Gate, docs/decisiones.md D-065).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import pr_gate  # noqa: E402
import preprocess  # noqa: E402
from score import compute_stable_key  # noqa: E402

REFERENCES_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "references"


def make_finding(function, category="SC01", severity="HIGH"):
    return {
        "id": function,
        "category": category,
        "severity": severity,
        "confidence": "high",
        "status": "confirmed",
        "locations": [{"file": "A.sol", "contract": "A", "function": function, "lineStart": 10, "lineEnd": 12}],
        "evidence": ["evidence line"],
        "description": "a secret-adjacent description mentioning API_KEY=abc123",
        "recommendation": "fix it",
        "patch": None,
    }


def make_report(findings):
    return {"findings": findings, "categoryCoverage": []}


# ---------------------------------------------------------------------------
# G1: PR ingestion contract
# ---------------------------------------------------------------------------

class PrIngestionTests(unittest.TestCase):
    def test_positive_single_valid_file(self):
        result = pr_gate.ingest_pr_changed_files("head", [{"path": "A.sol", "content": "contract A {}"}])
        self.assertEqual(result["acceptedFileCount"], 1)
        self.assertEqual(result["skippedFiles"], [])
        self.assertIn("pr://head/A.sol", result["bundle"])

    def test_bundle_is_genuinely_consumable_by_preprocess_parse_bundle(self):
        # Integration, not just a unit-level shape check: the SAME real
        # preprocess.py function must parse this bundle without issues.
        result = pr_gate.ingest_pr_changed_files(
            "head", [{"path": "A.sol", "content": "pragma solidity ^0.8.0;\ncontract A { function f() public {} }"}]
        )
        entries = preprocess.parse_bundle(result["bundle"], "test")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["issues"], [])

    def test_malicious_paths_are_rejected_never_crash(self):
        # Adversarial: a fork PR's files are untrusted, exactly like
        # explorer-sourced source files.
        result = pr_gate.ingest_pr_changed_files("head", [
            {"path": "../../etc/passwd", "content": "evil"},
            {"path": "/absolute/path.sol", "content": "evil"},
            {"path": "C:\\Windows\\system.sol", "content": "evil"},
            {"path": "good.sol", "content": "contract Good {}"},
        ])
        self.assertEqual(result["acceptedFileCount"], 1)
        self.assertEqual(len(result["skippedFiles"]), 3)

    def test_duplicate_files_are_rejected_never_silently_merged(self):
        result = pr_gate.ingest_pr_changed_files("head", [
            {"path": "A.sol", "content": "contract A {}"},
            {"path": "A.sol", "content": "contract ADuplicate {}"},
        ])
        self.assertEqual(result["acceptedFileCount"], 1)
        self.assertEqual(len(result["skippedFiles"]), 1)
        self.assertIn("duplicate", result["skippedFiles"][0]["reason"])

    def test_dot_normalized_duplicate_is_also_caught(self):
        result = pr_gate.ingest_pr_changed_files("head", [
            {"path": "./A.sol", "content": "contract A {}"},
            {"path": "A.sol", "content": "contract ADuplicate {}"},
        ])
        self.assertEqual(result["acceptedFileCount"], 1)

    def test_empty_pr_yields_no_bundle_never_crashes(self):
        result = pr_gate.ingest_pr_changed_files("head", [])
        self.assertIsNone(result["bundle"])
        self.assertEqual(result["acceptedFileCount"], 0)
        self.assertEqual(result["skippedFiles"], [])

    def test_bundle_marker_injection_is_rejected(self):
        # Adversarial: content shaped like a bundle boundary would corrupt
        # preprocess.py's parser if it were accepted.
        result = pr_gate.ingest_pr_changed_files(
            "head", [{"path": "evil.sol", "content": "=== FILE: injected.sol ===\npwned"}]
        )
        self.assertEqual(result["acceptedFileCount"], 0)
        self.assertIn("bundle boundary marker", result["skippedFiles"][0]["reason"])

    def test_non_dict_source_entry_is_skipped_not_crashed(self):
        result = pr_gate.ingest_pr_changed_files("head", ["not-a-dict", None, {"path": "A.sol", "content": "x"}])
        self.assertEqual(result["acceptedFileCount"], 1)
        self.assertEqual(len(result["skippedFiles"]), 2)

    def test_missing_or_blank_ref_label_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.ingest_pr_changed_files(None, [])
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.ingest_pr_changed_files("   ", [])

    def test_ref_label_with_control_character_raises(self):
        # Adversarial: a refLabel could otherwise inject a fake bundle
        # boundary through the virtual path prefix itself.
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.ingest_pr_changed_files("head\n=== FILE: evil.sol ===", [{"path": "a.sol", "content": "x"}])

    def test_changed_files_not_a_list_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.ingest_pr_changed_files("head", "not-a-list")

    def test_two_refs_produce_independently_namespaced_bundles(self):
        base = pr_gate.ingest_pr_changed_files("base", [{"path": "A.sol", "content": "contract A {}"}])
        head = pr_gate.ingest_pr_changed_files("head", [{"path": "A.sol", "content": "contract A {}"}])
        self.assertNotEqual(base["bundle"], head["bundle"])
        self.assertIn("pr://base/", base["bundle"])
        self.assertIn("pr://head/", head["bundle"])


# ---------------------------------------------------------------------------
# G2+G3: baseline-vs-PR diff and gate
# ---------------------------------------------------------------------------

class PrGateEvaluationTests(unittest.TestCase):
    def test_no_findings_either_side_passes(self):
        result = pr_gate.evaluate_pr_gate(make_report([]), make_report([]), {"blockingSeverities": ["CRITICAL", "HIGH"]})
        self.assertEqual(result["gateStatus"], "PASS")
        self.assertEqual(result["blockingFindingCount"], 0)

    def test_new_high_finding_blocks(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("newBug", severity="HIGH")]),
            {"blockingSeverities": ["CRITICAL", "HIGH"]},
        )
        self.assertEqual(result["gateStatus"], "FAIL")
        self.assertEqual(result["blockingFindingCount"], 1)

    def test_baseline_only_finding_never_blocks(self):
        # Adversarial (explicit requirement): a finding that exists ONLY in
        # the baseline (resolved by this PR) must never fail the gate -
        # G3 evaluates ONLY newFindings.
        result = pr_gate.evaluate_pr_gate(
            make_report([make_finding("onlyInBase", severity="CRITICAL")]), make_report([]),
            {"blockingSeverities": ["CRITICAL", "HIGH"]},
        )
        self.assertEqual(result["gateStatus"], "PASS")
        self.assertEqual(len(result["diff"]["resolvedFindings"]), 1)

    def test_finding_present_on_both_sides_unchanged_never_blocks(self):
        f = make_finding("stable", severity="CRITICAL")
        result = pr_gate.evaluate_pr_gate(make_report([f]), make_report([f]), {"blockingSeverities": ["CRITICAL"]})
        self.assertEqual(result["gateStatus"], "PASS")
        self.assertEqual(result["diff"]["newFindings"], [])

    def test_severity_below_threshold_does_not_block(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("minor", severity="LOW")]),
            {"blockingSeverities": ["CRITICAL", "HIGH"]},
        )
        self.assertEqual(result["gateStatus"], "PASS")

    def test_threshold_edge_exact_boundary_severity_blocks(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("edge", severity="MEDIUM")]),
            {"blockingSeverities": ["MEDIUM"]},
        )
        self.assertEqual(result["gateStatus"], "FAIL")

    def test_threshold_edge_empty_blocking_list_never_blocks(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("f", severity="CRITICAL")]),
            {"blockingSeverities": []},
        )
        self.assertEqual(result["gateStatus"], "PASS")

    def test_case_sensitivity_lowercase_severity_in_policy_is_malformed(self):
        # Adversarial: severities are never case-folded/coerced - "critical"
        # is not a recognized value, exactly the D-056-style strictness.
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(make_report([]), make_report([]), {"blockingSeverities": ["critical"]})

    def test_malformed_policy_missing_key_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(make_report([]), make_report([]), {})

    def test_malformed_policy_wrong_type_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(make_report([]), make_report([]), {"blockingSeverities": "HIGH"})

    def test_malformed_policy_non_string_entries_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(make_report([]), make_report([]), {"blockingSeverities": [1, 2]})

    def test_malformed_policy_unknown_severity_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(make_report([]), make_report([]), {"blockingSeverities": ["MADE_UP"]})

    def test_policy_not_a_dict_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(make_report([]), make_report([]), None)

    def test_duplicate_blocking_severities_are_deduplicated(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([]), {"blockingSeverities": ["HIGH", "HIGH", "CRITICAL"]}
        )
        self.assertEqual(result["policy"]["blockingSeverities"], ["HIGH", "CRITICAL"])

    def test_malformed_report_propagates_diff_reports_own_error(self):
        # Adversarial: this module never re-implements diff_reports.py's own
        # input validation - it must surface DiffError, never crash differently.
        from diff_reports import DiffError
        with self.assertRaises(DiffError):
            pr_gate.evaluate_pr_gate({"findings": "not-a-list"}, make_report([]), {"blockingSeverities": ["HIGH"]})

    def test_never_affected_by_a_duplicate_finding_within_one_report(self):
        # A report with 2 findings sharing the same stableKey is a caller
        # bug (findings must be deduplicated by score.py first) - this must
        # surface diff_reports.py's own existing guard, never be silently
        # merged into a wrong gate decision.
        from diff_reports import DiffError
        dup_report = make_report([make_finding("dup"), make_finding("dup")])
        with self.assertRaises(DiffError):
            pr_gate.evaluate_pr_gate(make_report([]), dup_report, {"blockingSeverities": ["HIGH"]})


# ---------------------------------------------------------------------------
# V3 Block 1 "CI Security Gate 2.0": policy-as-config (minConfidence /
# blockingCategories), strict validation, --strict-exit, --format text.
# ---------------------------------------------------------------------------

class PolicyAsConfigTests(unittest.TestCase):
    """Positive/negative/adversarial coverage for the new, OPTIONAL policy
    fields. Every case that used only blockingSeverities before this block
    is covered by the untouched PrGateEvaluationTests above - this class
    only adds cases for the new filters."""

    # --- positive: minConfidence ---------------------------------------

    def test_min_confidence_high_excludes_a_medium_confidence_finding(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]),
            make_report([{**make_finding("f", severity="HIGH"), "confidence": "medium"}]),
            {"blockingSeverities": ["HIGH"], "minConfidence": "high"},
        )
        self.assertEqual(result["gateStatus"], "PASS")
        self.assertEqual(result["blockingFindingCount"], 0)

    def test_min_confidence_high_still_blocks_a_high_confidence_finding(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]),
            make_report([{**make_finding("f", severity="HIGH"), "confidence": "high"}]),
            {"blockingSeverities": ["HIGH"], "minConfidence": "high"},
        )
        self.assertEqual(result["gateStatus"], "FAIL")

    def test_min_confidence_is_omittable_and_preserves_v2_10_behavior(self):
        # Backward compatibility: a policy with ONLY blockingSeverities
        # (the entire V2.10 policy shape) must gate exactly as before.
        result = pr_gate.evaluate_pr_gate(
            make_report([]),
            make_report([{**make_finding("f", severity="HIGH"), "confidence": "low"}]),
            {"blockingSeverities": ["HIGH"]},
        )
        self.assertEqual(result["gateStatus"], "FAIL")
        self.assertNotIn("minConfidence", result["policy"])

    def test_adversarial_missing_confidence_on_finding_still_blocks_fail_closed(self):
        finding = make_finding("f", severity="HIGH")
        del finding["confidence"]
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([finding]),
            {"blockingSeverities": ["HIGH"], "minConfidence": "high"},
        )
        self.assertEqual(result["gateStatus"], "FAIL", "a missing confidence must never be a free pass")

    def test_adversarial_malformed_confidence_value_on_finding_still_blocks_fail_closed(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]),
            make_report([{**make_finding("f", severity="HIGH"), "confidence": "VERY HIGH!!"}]),
            {"blockingSeverities": ["HIGH"], "minConfidence": "high"},
        )
        self.assertEqual(result["gateStatus"], "FAIL")

    # --- positive: blockingCategories -----------------------------------

    def test_blocking_categories_excludes_a_category_not_in_the_list(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("f", category="SC08", severity="HIGH")]),
            {"blockingSeverities": ["HIGH"], "blockingCategories": ["SC01"]},
        )
        self.assertEqual(result["gateStatus"], "PASS")

    def test_blocking_categories_still_blocks_a_category_in_the_list(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("f", category="SC01", severity="HIGH")]),
            {"blockingSeverities": ["HIGH"], "blockingCategories": ["SC01"]},
        )
        self.assertEqual(result["gateStatus"], "FAIL")

    def test_threshold_edge_empty_blocking_categories_never_blocks(self):
        # Same semantics as the pre-existing blockingSeverities: [] edge
        # case (test_threshold_edge_empty_blocking_list_never_blocks): an
        # empty allowlist is a valid (if unusual) caller choice meaning
        # nothing blocks via this filter - never a free pass for OTHER
        # findings, just an empty set of categories that qualify.
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("f", category="SC01", severity="CRITICAL")]),
            {"blockingSeverities": ["CRITICAL"], "blockingCategories": []},
        )
        self.assertEqual(result["gateStatus"], "PASS")
        self.assertEqual(result["blockingFindingCount"], 0)

    def test_adversarial_missing_category_on_finding_still_blocks_fail_closed(self):
        finding = make_finding("f", severity="HIGH")
        del finding["category"]
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([finding]),
            {"blockingSeverities": ["HIGH"], "blockingCategories": ["SC01"]},
        )
        self.assertEqual(result["gateStatus"], "FAIL", "a missing category must never be a free pass")

    def test_combined_filters_all_must_agree_to_block(self):
        result = pr_gate.evaluate_pr_gate(
            make_report([]),
            make_report([{**make_finding("f", category="SC01", severity="HIGH"), "confidence": "low"}]),
            {"blockingSeverities": ["HIGH"], "minConfidence": "high", "blockingCategories": ["SC01"]},
        )
        # HIGH severity + SC01 both match, but confidence "low" < "high" -> excluded.
        self.assertEqual(result["gateStatus"], "PASS")

    # --- negative: strict, fail-closed validation ------------------------

    def test_unknown_policy_key_raises_never_silently_ignored(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(
                make_report([]), make_report([]),
                {"blockingSeverities": ["HIGH"], "blockingSeverity": ["HIGH"]},  # typo'd key
            )

    def test_invalid_min_confidence_value_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(
                make_report([]), make_report([]),
                {"blockingSeverities": ["HIGH"], "minConfidence": "VERY_HIGH"},
            )

    def test_min_confidence_wrong_type_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(
                make_report([]), make_report([]),
                {"blockingSeverities": ["HIGH"], "minConfidence": 1},
            )

    def test_blocking_categories_wrong_type_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(
                make_report([]), make_report([]),
                {"blockingSeverities": ["HIGH"], "blockingCategories": "SC01"},
            )

    def test_blocking_categories_unknown_category_raises(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(
                make_report([]), make_report([]),
                {"blockingSeverities": ["HIGH"], "blockingCategories": ["SC99"]},
            )

    def test_blocking_categories_non_string_entries_raise(self):
        with self.assertRaises(pr_gate.PrGateError):
            pr_gate.evaluate_pr_gate(
                make_report([]), make_report([]),
                {"blockingSeverities": ["HIGH"], "blockingCategories": [1]},
            )

    def test_reuses_preprocess_categories_never_a_second_hardcoded_list(self):
        # Single-source-of-truth check: every SC01-SC10 key must be valid.
        for category in preprocess.CATEGORIES:
            result = pr_gate.evaluate_pr_gate(
                make_report([]), make_report([make_finding("f", category=category, severity="HIGH")]),
                {"blockingSeverities": ["HIGH"], "blockingCategories": [category]},
            )
            self.assertEqual(result["gateStatus"], "FAIL", category)


# ---------------------------------------------------------------------------
# G4: provider-agnostic annotations, secrets safety
# ---------------------------------------------------------------------------

class AnnotationListTests(unittest.TestCase):
    def test_annotation_has_only_structured_fields(self):
        annotations = pr_gate.build_annotation_list([make_finding("f")])
        self.assertEqual(
            set(annotations[0].keys()),
            {"file", "lineStart", "lineEnd", "contract", "function", "severity", "category", "stableKey"},
        )

    def test_annotation_never_includes_free_text_fields(self):
        # Adversarial (secrets safety): description/evidence/recommendation/
        # patch must NEVER appear, even though the finding itself carries a
        # description containing something that looks like a secret.
        annotations = pr_gate.build_annotation_list([make_finding("f")])
        serialized = json.dumps(annotations)
        self.assertNotIn("API_KEY", serialized)
        self.assertNotIn("description", annotations[0])
        self.assertNotIn("evidence", annotations[0])
        self.assertNotIn("recommendation", annotations[0])
        self.assertNotIn("patch", annotations[0])

    def test_annotation_stable_key_matches_score_computation(self):
        f = make_finding("f")
        annotations = pr_gate.build_annotation_list([f])
        self.assertEqual(annotations[0]["stableKey"], compute_stable_key(f))

    def test_non_list_input_returns_empty_never_crashes(self):
        self.assertEqual(pr_gate.build_annotation_list(None), [])
        self.assertEqual(pr_gate.build_annotation_list("not-a-list"), [])

    def test_non_dict_entries_are_skipped(self):
        annotations = pr_gate.build_annotation_list([None, "not-a-dict", make_finding("f")])
        self.assertEqual(len(annotations), 1)

    def test_missing_locations_never_crashes(self):
        f = make_finding("f")
        f["locations"] = []
        annotations = pr_gate.build_annotation_list([f])
        self.assertIsNone(annotations[0]["file"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = pr_gate.main(argv)
        return exit_code, stdout.getvalue()

    def test_ingest_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"refLabel": "head", "changedFiles": [{"path": "A.sol", "content": "contract A {}"}]}), encoding="utf-8")
            exit_code, out = self._run_cli(["ingest", str(p)])
            self.assertEqual(exit_code, pr_gate.EXIT_OK)
            self.assertEqual(json.loads(out)["acceptedFileCount"], 1)

    def test_gate_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_p = Path(tmp) / "base.json"
            head_p = Path(tmp) / "head.json"
            policy_p = Path(tmp) / "policy.json"
            base_p.write_text(json.dumps(make_report([])), encoding="utf-8")
            head_p.write_text(json.dumps(make_report([make_finding("f", severity="HIGH")])), encoding="utf-8")
            policy_p.write_text(json.dumps({"blockingSeverities": ["HIGH"]}), encoding="utf-8")
            exit_code, out = self._run_cli(["gate", str(base_p), str(head_p), str(policy_p)])
            self.assertEqual(exit_code, pr_gate.EXIT_OK)  # script succeeds even when gateStatus is FAIL
            self.assertEqual(json.loads(out)["gateStatus"], "FAIL")

    def test_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli(["ingest", str(bad)])
            self.assertEqual(exit_code, pr_gate.EXIT_FAILED)
            envelope = json.loads(out)
            self.assertFalse(envelope["ok"])
            self.assertIn("error", envelope)

    def _run_cli_with_stdin(self, argv, stdin_text):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
        try:
            return self._run_cli(argv)
        finally:
            sys.stdin = old_stdin

    def test_ingest_reads_from_stdin_when_input_omitted(self):
        # V2.10 -> V2.11 (A-04): "ingest" now matches the stdin fallback
        # every other single-file script CLI already has.
        payload = json.dumps({"refLabel": "head", "changedFiles": [{"path": "A.sol", "content": "contract A {}"}]})
        exit_code, out = self._run_cli_with_stdin(["ingest"], payload)
        self.assertEqual(exit_code, pr_gate.EXIT_OK)
        self.assertEqual(json.loads(out)["acceptedFileCount"], 1)

    def test_ingest_stdin_result_matches_file_based_result(self):
        payload = {"refLabel": "head", "changedFiles": [{"path": "A.sol", "content": "contract A {}"}]}
        stdin_exit, stdin_out = self._run_cli_with_stdin(["ingest"], json.dumps(payload))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps(payload), encoding="utf-8")
            file_exit, file_out = self._run_cli(["ingest", str(p)])
        self.assertEqual(stdin_exit, file_exit)
        self.assertEqual(stdin_out, file_out)

    def test_ingest_malformed_stdin_yields_clean_error_envelope_mentioning_stdin(self):
        exit_code, out = self._run_cli_with_stdin(["ingest"], "not json")
        self.assertEqual(exit_code, pr_gate.EXIT_FAILED)
        envelope = json.loads(out)
        self.assertFalse(envelope["ok"])
        self.assertIn("stdin", envelope["error"])

    def test_gate_still_requires_all_three_file_arguments(self):
        # A-04 explicitly does NOT extend "gate" (3 required files) - no
        # single-optional-positional precedent exists to copy there.
        with self.assertRaises(SystemExit):
            pr_gate.main(["gate", "only_one.json"])

    def _write_gate_inputs(self, tmp, head_findings, policy):
        base_p, head_p, policy_p = Path(tmp) / "base.json", Path(tmp) / "head.json", Path(tmp) / "policy.json"
        base_p.write_text(json.dumps(make_report([])), encoding="utf-8")
        head_p.write_text(json.dumps(make_report(head_findings)), encoding="utf-8")
        policy_p.write_text(json.dumps(policy), encoding="utf-8")
        return str(base_p), str(head_p), str(policy_p)

    def test_strict_exit_is_opt_in_default_behavior_is_byte_for_byte_unchanged(self):
        # Same scenario as test_gate_cli_end_to_end, asserted again here to
        # make the V3 Block 1 non-regression explicit: omitting --strict-exit
        # must still exit EXIT_OK on a FAIL gateStatus.
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(
                tmp, [make_finding("f", severity="HIGH")], {"blockingSeverities": ["HIGH"]}
            )
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p])
        self.assertEqual(exit_code, pr_gate.EXIT_OK)
        self.assertEqual(json.loads(out)["gateStatus"], "FAIL")

    def test_strict_exit_returns_gate_blocked_code_on_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(
                tmp, [make_finding("f", severity="HIGH")], {"blockingSeverities": ["HIGH"]}
            )
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p, "--strict-exit"])
        self.assertEqual(exit_code, pr_gate.EXIT_GATE_BLOCKED)
        self.assertNotEqual(pr_gate.EXIT_GATE_BLOCKED, pr_gate.EXIT_FAILED, "a gate FAIL must be distinguishable from a tool/input error")
        self.assertEqual(json.loads(out)["gateStatus"], "FAIL")  # --strict-exit never changes the JSON payload itself

    def test_strict_exit_still_returns_ok_code_on_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(tmp, [], {"blockingSeverities": ["HIGH"]})
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p, "--strict-exit"])
        self.assertEqual(exit_code, pr_gate.EXIT_OK)
        self.assertEqual(json.loads(out)["gateStatus"], "PASS")

    def test_strict_exit_on_a_tool_error_is_still_exit_failed_not_gate_blocked(self):
        # Adversarial: an invalid policy must never be mistaken for (or
        # silently downgraded to) a normal gate FAIL - it is a distinct,
        # explicit tool error even with --strict-exit set.
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(tmp, [], {"blockingSeverities": ["NOT_REAL"]})
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p, "--strict-exit"])
        self.assertEqual(exit_code, pr_gate.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])

    def test_format_text_is_opt_in_default_is_still_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(
                tmp, [make_finding("f", severity="HIGH")], {"blockingSeverities": ["HIGH"]}
            )
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p])
        json.loads(out)  # must not raise

    def test_format_text_renders_a_human_readable_non_json_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(
                tmp, [make_finding("f", severity="HIGH")], {"blockingSeverities": ["HIGH"]}
            )
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p, "--format", "text"])
        with self.assertRaises(json.JSONDecodeError):
            json.loads(out)
        self.assertIn("PR Security Gate: FAIL", out)
        self.assertIn("1 blocking finding", out)

    def test_format_text_never_includes_a_findings_free_text_field(self):
        # Same secrets-safety property as G4's structured annotations,
        # verified again at the human-readable-rendering boundary.
        with tempfile.TemporaryDirectory() as tmp:
            base_p, head_p, policy_p = self._write_gate_inputs(
                tmp, [make_finding("f", severity="HIGH")], {"blockingSeverities": ["HIGH"]}
            )
            exit_code, out = self._run_cli(["gate", base_p, head_p, policy_p, "--format", "text"])
        self.assertNotIn("API_KEY", out)
        self.assertNotIn("a secret-adjacent description", out)


# ---------------------------------------------------------------------------
# Schema drift
# ---------------------------------------------------------------------------

class SchemaDriftTests(unittest.TestCase):
    def test_ingest_result_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "pr-gate-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["ingestResult"]["required"])
        result = pr_gate.ingest_pr_changed_files("head", [{"path": "A.sol", "content": "contract A {}"}])
        self.assertEqual(required, set(result.keys()))

    def test_gate_result_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "pr-gate-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["gateResult"]["required"])
        result = pr_gate.evaluate_pr_gate(make_report([]), make_report([make_finding("f")]), {"blockingSeverities": ["HIGH"]})
        self.assertEqual(required, set(result.keys()))

    def test_annotation_item_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "pr-gate-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["gateResult"]["properties"]["annotations"]["items"]["required"])
        annotations = pr_gate.build_annotation_list([make_finding("f")])
        self.assertEqual(required, set(annotations[0].keys()))

    def test_policy_optional_fields_are_declared_in_schema_not_just_in_code(self):
        # V3 Block 1: the schema's policy.properties must name every key
        # _validate_policy() accepts, or the schema silently drifts from
        # the real, permissive-when-valid contract. blockingCategories is
        # deliberately NOT schema-enum-validated against a fixed list (see
        # the schema's own description) - preprocess.CATEGORIES is broader
        # than SC01-SC10 (it also has supplementary EXTRA-* checks) and is
        # itself the single source of truth _validate_policy() reuses.
        schema = json.loads((REFERENCES_DIR / "pr-gate-schema.json").read_text(encoding="utf-8"))
        policy_schema = schema["definitions"]["gateResult"]["properties"]["policy"]
        self.assertEqual(set(policy_schema["properties"].keys()), pr_gate._KNOWN_POLICY_KEYS)
        self.assertNotIn("enum", policy_schema["properties"]["blockingCategories"]["items"])
        self.assertTrue(set(preprocess.CATEGORIES) - {"SC01", "SC02", "SC03", "SC04", "SC05", "SC06", "SC07", "SC08", "SC09", "SC10"})

    def test_gate_result_with_full_v3_policy_still_matches_schema_required_fields(self):
        # The extended policy shape must not add/remove any TOP-LEVEL
        # gateResult key - only policy's own (optional) sub-fields grow.
        schema = json.loads((REFERENCES_DIR / "pr-gate-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["gateResult"]["required"])
        result = pr_gate.evaluate_pr_gate(
            make_report([]), make_report([make_finding("f")]),
            {"blockingSeverities": ["HIGH"], "minConfidence": "medium", "blockingCategories": ["SC01"]},
        )
        self.assertEqual(required, set(result.keys()))


if __name__ == "__main__":
    unittest.main()
