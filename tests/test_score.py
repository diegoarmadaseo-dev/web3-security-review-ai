"""Tests for scripts/score.py (Subfase 1.2 - Report: deduplication and scoring).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import score  # noqa: E402


def make_finding(**overrides):
    base = {
        "category": "SC01",
        "signature": "unprotected-admin-function",
        "severity": "HIGH",
        "confidence": "high",
        "status": "suspected",
        "locations": [{"file": "A.sol", "lineStart": 10, "lineEnd": 12, "contract": "A", "function": "setFee"}],
        "evidence": ["function setFee(uint f) public { fee = f; }"],
        "description": "desc",
        "recommendation": "rec",
        "patch": None,
    }
    base.update(overrides)
    return base


class StableKeyTests(unittest.TestCase):
    def test_same_category_location_signature_yields_same_key(self):
        a = make_finding()
        b = make_finding(severity="MEDIUM", confidence="medium", description="different wording")
        self.assertEqual(score.compute_stable_key(a), score.compute_stable_key(b))

    def test_different_signature_yields_different_key(self):
        a = make_finding(signature="unprotected-admin-function")
        b = make_finding(signature="reentrancy-no-guard")
        self.assertNotEqual(score.compute_stable_key(a), score.compute_stable_key(b))

    def test_id_is_derived_from_stable_key_prefix(self):
        key = score.compute_stable_key(make_finding())
        self.assertEqual(score.compute_id(key), "F-" + key.split(":", 1)[1][:8])

    def test_missing_locations_still_produces_a_key(self):
        finding = make_finding(locations=[])
        key = score.compute_stable_key(finding)
        self.assertTrue(key.startswith("sha256:"))


class DeduplicationTests(unittest.TestCase):
    def test_same_root_cause_merges_into_one_finding(self):
        a = make_finding(severity="MEDIUM", confidence="medium", evidence=["line1"])
        b = make_finding(severity="HIGH", confidence="high", evidence=["line1", "line2"])
        merged = score.deduplicate_findings([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["severity"], "HIGH")
        self.assertEqual(merged[0]["confidence"], "high")
        self.assertEqual(merged[0]["evidence"], ["line1", "line2"])
        self.assertEqual(merged[0]["mergedCount"], 2)

    def test_multiple_locations_are_unioned_not_duplicated(self):
        loc1 = {"file": "A.sol", "lineStart": 1, "lineEnd": 1, "contract": "A", "function": "f"}
        loc2 = {"file": "B.sol", "lineStart": 2, "lineEnd": 2, "contract": "B", "function": "g"}
        a = make_finding(locations=[loc1])
        b = make_finding(locations=[loc1, loc2])
        merged = score.deduplicate_findings([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["locations"]), 2)

    def test_evidence_union_is_capped_at_five_lines(self):
        a = make_finding(evidence=["1", "2", "3"])
        b = make_finding(evidence=["3", "4", "5", "6", "7"])
        merged = score.deduplicate_findings([a, b])
        self.assertLessEqual(len(merged[0]["evidence"]), 5)

    def test_different_root_causes_stay_separate(self):
        a = make_finding(category="SC01")
        b = make_finding(category="SC08", signature="reentrancy-no-guard")
        merged = score.deduplicate_findings([a, b])
        self.assertEqual(len(merged), 2)

    def test_empty_input_yields_empty_output(self):
        self.assertEqual(score.deduplicate_findings([]), [])


class ScoreFormulaTests(unittest.TestCase):
    def test_clean_report_scores_100_low(self):
        result = score.compute_score([])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["band"], "LOW")
        self.assertIn("lowBandNote", result)

    def test_single_high_high_confidence_penalty(self):
        finding = make_finding(severity="HIGH", confidence="high")
        result = score.compute_score([finding])
        self.assertEqual(result["score"], 85)  # 100 - 15*1.0
        self.assertEqual(result["band"], "LOW")

    def test_confidence_weight_reduces_penalty(self):
        finding = make_finding(severity="HIGH", confidence="low")
        result = score.compute_score([finding])
        self.assertEqual(result["score"], 94)  # 100 - round(15*0.4) = 100-6

    def test_score_never_goes_below_zero(self):
        findings = [make_finding(category="SC0%d" % i, signature="x%d" % i, severity="CRITICAL", confidence="high") for i in range(1, 9)]
        result = score.compute_score(findings)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "CRITICAL")

    def test_high_confidence_critical_caps_score_at_40(self):
        findings = [make_finding(category="SC08", signature="reentrancy", severity="CRITICAL", confidence="high")]
        result = score.compute_score(findings)
        self.assertEqual(result["score"], 40)  # 100-25=75, capped to 40 by the CRITICAL+high rule

    def test_low_confidence_critical_does_not_trigger_cap(self):
        findings = [make_finding(category="SC08", signature="reentrancy", severity="CRITICAL", confidence="low")]
        result = score.compute_score(findings)
        self.assertEqual(result["score"], 90)  # 100 - round(25*0.4)=10
        self.assertGreater(result["score"], 40)

    def test_informational_findings_never_affect_score(self):
        info = make_finding(category="EXTRA-prompt-injection", signature="injection", severity="INFORMATIONAL", confidence="high", status="informational")
        result_with = score.compute_score([info])
        result_without = score.compute_score([])
        self.assertEqual(result_with["score"], result_without["score"])

    def test_band_boundaries(self):
        self.assertEqual(score.score_band(85), "LOW")
        self.assertEqual(score.score_band(84), "MODERATE")
        self.assertEqual(score.score_band(60), "MODERATE")
        self.assertEqual(score.score_band(59), "HIGH")
        self.assertEqual(score.score_band(40), "HIGH")
        self.assertEqual(score.score_band(39), "CRITICAL")
        self.assertEqual(score.score_band(0), "CRITICAL")

    def test_result_always_carries_scope_note_and_explanation(self):
        result = score.compute_score([])
        self.assertEqual(result["scopeNote"], "according to the analyzed scope")
        self.assertIn("analyzed scope", result["explanation"])


class ScoreReportTests(unittest.TestCase):
    def test_full_report_is_scored_end_to_end(self):
        report = {"generatedBy": "ai", "mode": "standard", "findings": [make_finding()]}
        updated = score.score_report(report)
        self.assertEqual(updated["scoreStatus"], "computed")
        self.assertEqual(len(updated["findings"]), 1)
        self.assertTrue(updated["findings"][0]["id"].startswith("F-"))
        self.assertEqual(updated["mode"], "standard")  # untouched fields pass through

    def test_findings_are_sorted_by_severity_descending(self):
        low = make_finding(category="SC02", signature="low-issue", severity="LOW", confidence="high")
        critical = make_finding(category="SC08", signature="crit-issue", severity="CRITICAL", confidence="high")
        updated = score.score_report({"generatedBy": "ai", "mode": "pro", "findings": [low, critical]})
        self.assertEqual(updated["findings"][0]["severity"], "CRITICAL")

    def test_non_dict_report_raises(self):
        with self.assertRaises(score.ScoreError):
            score.score_report([])

    def test_missing_severity_raises_clear_error(self):
        bad = make_finding()
        del bad["severity"]
        with self.assertRaises(score.ScoreError):
            score.score_report({"generatedBy": "ai", "mode": "quick", "findings": [bad]})

    def test_invalid_severity_value_raises(self):
        bad = make_finding(severity="SUPER_BAD")
        with self.assertRaises(score.ScoreError):
            score.score_report({"generatedBy": "ai", "mode": "quick", "findings": [bad]})

    def test_informational_status_requires_informational_severity(self):
        bad = make_finding(status="informational", severity="HIGH")
        with self.assertRaises(score.ScoreError):
            score.score_report({"generatedBy": "ai", "mode": "quick", "findings": [bad]})


class CLITests(unittest.TestCase):
    def test_invalid_json_returns_error_envelope_and_exit_1(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), unittest_stdin("not json"):
            exit_code = score.main([])
        self.assertEqual(exit_code, score.EXIT_FAILED)
        payload = json.loads(buf.getvalue())
        self.assertFalse(payload["ok"])

    def test_normal_input_via_stdin_produces_scored_json(self):
        report = json.dumps({"generatedBy": "ai", "mode": "quick", "findings": []})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), unittest_stdin(report):
            exit_code = score.main([])
        self.assertEqual(exit_code, score.EXIT_OK)
        updated = json.loads(buf.getvalue())
        self.assertEqual(updated["riskIndicator"]["score"], 100)


import io as _io  # noqa: E402


@contextlib.contextmanager
def unittest_stdin(text: str):
    old = sys.stdin
    sys.stdin = _io.StringIO(text)
    try:
        yield
    finally:
        sys.stdin = old


if __name__ == "__main__":
    unittest.main()
