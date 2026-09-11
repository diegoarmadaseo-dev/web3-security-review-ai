"""Tests for scripts/validate_report.py (Subfase 1.2 - Report).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import score  # noqa: E402
import validate_report  # noqa: E402

SC_CATEGORIES = ["SC%02d" % n for n in range(1, 11)]


def _base_finding():
    return {
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


def make_valid_report(mode: str = "standard", with_finding: bool = True) -> dict:
    coverage = [{"category": c, "status": "NOT_DETECTED"} for c in SC_CATEGORIES]
    findings = []
    if with_finding:
        coverage[0]["status"] = "DETECTED"
        findings = [_base_finding()]
    draft = {
        "generatedBy": "ai",
        "skillVersion": "1.0.0",
        "analysisEngineVersion": "1.0.0",
        "checklistVersion": "2026.1",
        "scoreVersion": "2026.1",
        "mode": mode,
        "language": "es",
        "compilerVersion": "0.8.20",
        "scriptsAvailable": True,
        "inputHash": "sha256:" + "a" * 64,
        "scope": {"completeness": "complete", "reasons": []},
        "categoryCoverage": coverage,
        "findings": findings,
        "limitations": ["Off-chain infrastructure was not assessed."],
        "riskIndicator": {"scoreStatus": "not_computed", "score": None, "band": None},
        "scoreStatus": "not_computed",
    }
    return score.score_report(draft)


class ValidReportTests(unittest.TestCase):
    def test_valid_report_with_finding_passes(self):
        errors = validate_report.validate_report(make_valid_report())
        self.assertEqual(errors, [])

    def test_valid_clean_report_with_no_findings_passes(self):
        errors = validate_report.validate_report(make_valid_report(with_finding=False))
        self.assertEqual(errors, [])

    def test_not_computed_score_status_is_valid_when_consistent(self):
        report = make_valid_report(with_finding=False)
        report["riskIndicator"] = {"scoreStatus": "not_computed", "score": None, "band": None, "message": "Automated deterministic scoring was unavailable in this runtime."}
        report["scoreStatus"] = "not_computed"
        errors = validate_report.validate_report(report)
        self.assertEqual(errors, [])


class BusinessRuleTests(unittest.TestCase):
    def setUp(self):
        self.report = make_valid_report()

    def test_r02_tampered_stable_key_is_rejected(self):
        bad = copy.deepcopy(self.report)
        bad["findings"][0]["stableKey"] = "sha256:" + "f" * 64
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-02" in e for e in errors))

    def test_r02_tampered_id_is_rejected(self):
        bad = copy.deepcopy(self.report)
        bad["findings"][0]["id"] = "F-deadbeef"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-02" in e for e in errors))

    def test_r04_coverage_must_say_detected_when_finding_exists(self):
        bad = copy.deepcopy(self.report)
        bad["categoryCoverage"][0]["status"] = "NOT_DETECTED"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-04" in e for e in errors))

    def test_r05_partial_without_not_assessed_is_rejected(self):
        bad = copy.deepcopy(self.report)
        bad["scope"]["completeness"] = "partial"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-05" in e for e in errors))

    def test_r05_partial_with_not_assessed_passes(self):
        ok = copy.deepcopy(self.report)
        ok["scope"]["completeness"] = "partial"
        ok["categoryCoverage"][5]["status"] = "NOT_ASSESSED"
        errors = validate_report.validate_report(ok)
        self.assertEqual(errors, [])

    def test_r06_quick_mode_forbids_patch(self):
        bad = copy.deepcopy(self.report)
        bad["mode"] = "quick"
        bad["findings"][0]["patch"] = {"format": "unified-diff", "diff": "--- a\n+++ b\n"}
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-06" in e for e in errors))

    def test_r06_quick_mode_forbids_gas_suggestions(self):
        bad = copy.deepcopy(self.report)
        bad["mode"] = "quick"
        bad["gasSuggestions"] = [{"technique": "t", "location": {"file": "A.sol"}, "explanation": "e", "impact": "low"}]
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-06" in e for e in errors))

    def test_r06_standard_mode_allows_patch(self):
        ok = copy.deepcopy(self.report)
        ok["mode"] = "standard"
        ok["findings"][0]["patch"] = {"format": "unified-diff", "diff": "--- a\n+++ b\n"}
        errors = validate_report.validate_report(ok)
        self.assertEqual(errors, [])

    def test_r07_informational_status_requires_informational_severity(self):
        bad = copy.deepcopy(self.report)
        bad["findings"][0]["status"] = "informational"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-07" in e for e in errors))

    def test_r08_score_status_mismatch_is_rejected(self):
        bad = copy.deepcopy(self.report)
        bad["scoreStatus"] = "not_computed"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-08" in e for e in errors))

    def test_r08_band_must_match_score(self):
        bad = copy.deepcopy(self.report)
        bad["riskIndicator"]["band"] = "CRITICAL"  # score is 85, band should be LOW
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-08" in e for e in errors))

    def test_r09_pro_mode_allows_executive_summary_and_architecture_notes(self):
        ok = copy.deepcopy(self.report)
        ok["mode"] = "pro"
        ok["executiveSummary"] = "Overall risk is low within the analyzed scope."
        ok["architectureNotes"] = [{"title": "Upgrade surface", "description": "The proxy admin is a single EOA."}]
        errors = validate_report.validate_report(ok)
        self.assertEqual(errors, [])

    def test_r09_standard_mode_forbids_executive_summary(self):
        bad = copy.deepcopy(self.report)
        bad["mode"] = "standard"
        bad["executiveSummary"] = "Should not be here."
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-09" in e for e in errors))

    def test_r09_standard_mode_forbids_architecture_notes(self):
        bad = copy.deepcopy(self.report)
        bad["mode"] = "standard"
        bad["architectureNotes"] = [{"title": "t", "description": "d"}]
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-09" in e for e in errors))

    def test_r09_quick_mode_forbids_both(self):
        bad = copy.deepcopy(self.report)
        bad["mode"] = "quick"
        bad["executiveSummary"] = "Should not be here."
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("R-09" in e for e in errors))


class ShapeAndEnumTests(unittest.TestCase):
    def test_missing_top_level_field_is_rejected(self):
        bad = make_valid_report()
        del bad["limitations"]
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("limitations" in e for e in errors))

    def test_unknown_top_level_field_is_rejected(self):
        bad = make_valid_report()
        bad["unexpectedField"] = "surprise"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("unknown top-level fields" in e for e in errors))

    def test_category_coverage_must_have_exactly_ten_entries(self):
        bad = make_valid_report()
        bad["categoryCoverage"] = bad["categoryCoverage"][:9]
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("SC10" in e for e in errors))

    def test_category_coverage_rejects_duplicate_category(self):
        bad = make_valid_report()
        bad["categoryCoverage"][1]["category"] = "SC01"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("duplicate entry" in e for e in errors))

    def test_empty_locations_is_rejected(self):
        # D-022 / Probe B: an empty locations array degenerates the primary-location
        # component of stableKey, letting unrelated findings collapse into one.
        bad = make_valid_report()
        bad["findings"][0]["locations"] = []
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("at least one entry" in e for e in errors))

    def test_evidence_over_five_lines_is_rejected(self):
        bad = make_valid_report()
        bad["findings"][0]["evidence"] = ["line"] * 6
        # stableKey/id must still match after this mutation since evidence is not part of the key
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("at most 5 lines" in e for e in errors))

    def test_invalid_severity_is_rejected(self):
        bad = make_valid_report()
        bad["findings"][0]["severity"] = "SUPER_BAD"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("severity" in e for e in errors))

    def test_invalid_mode_is_rejected(self):
        bad = make_valid_report()
        bad["mode"] = "ultra"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("mode must be one of" in e for e in errors))

    def test_bad_input_hash_format_is_rejected(self):
        bad = make_valid_report()
        bad["inputHash"] = "not-a-hash"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("inputHash" in e for e in errors))

    def test_duplicate_finding_ids_after_validation_are_flagged(self):
        bad = make_valid_report()
        second = copy.deepcopy(bad["findings"][0])
        bad["findings"].append(second)
        bad["categoryCoverage"][0]["status"] = "DETECTED"
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("duplicate finding id" in e for e in errors))

    def test_architecture_note_missing_description_is_rejected(self):
        bad = make_valid_report(mode="pro")
        bad["mode"] = "pro"
        bad["architectureNotes"] = [{"title": "Upgrade surface"}]
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("architectureNotes[0].description" in e for e in errors))

    def test_architecture_note_unknown_field_is_rejected(self):
        bad = make_valid_report(mode="pro")
        bad["architectureNotes"] = [{"title": "t", "description": "d", "extra": "nope"}]
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("architectureNotes[0] has unknown fields" in e for e in errors))

    def test_executive_summary_must_be_a_string(self):
        bad = make_valid_report(mode="pro")
        bad["executiveSummary"] = 12345
        errors = validate_report.validate_report(bad)
        self.assertTrue(any("executiveSummary must be a string" in e for e in errors))


class InvalidInputTests(unittest.TestCase):
    def test_non_dict_top_level_raises(self):
        with self.assertRaises(validate_report.ReportValidationError):
            validate_report.validate_report([1, 2, 3])

    def test_string_top_level_raises(self):
        with self.assertRaises(validate_report.ReportValidationError):
            validate_report.validate_report("not an object")


class SchemaDriftTests(unittest.TestCase):
    """references/report-schema.json and validate_report.py must not silently diverge."""

    def test_required_fields_match_schema_document(self):
        schema_path = SCRIPTS_DIR.parent / "references" / "report-schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), set(validate_report.TOP_LEVEL_REQUIRED))

    def test_finding_required_fields_match_schema_document(self):
        schema_path = SCRIPTS_DIR.parent / "references" / "report-schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["definitions"]["finding"]["required"]), set(validate_report.FINDING_REQUIRED))


class ModesConfigFailsLoudlyTests(unittest.TestCase):
    """A broken config/modes.json must stop validation, not fall back silently."""

    def test_broken_modes_config_propagates_as_modes_config_error(self):
        report = make_valid_report()
        with mock.patch.object(validate_report, "load_modes_config", side_effect=validate_report.ModesConfigError("boom")):
            with self.assertRaises(validate_report.ModesConfigError):
                validate_report.validate_report(report)

    def test_cli_reports_broken_modes_config_as_a_clean_error_envelope(self):
        old = sys.stdin
        sys.stdin = io.StringIO(json.dumps(make_valid_report()))
        buf = io.StringIO()
        try:
            with mock.patch.object(validate_report, "load_modes_config", side_effect=validate_report.ModesConfigError("boom")):
                with contextlib.redirect_stdout(buf):
                    exit_code = validate_report.main([])
        finally:
            sys.stdin = old
        self.assertEqual(exit_code, validate_report.EXIT_FAILED)
        self.assertFalse(json.loads(buf.getvalue())["ok"])


class CLITests(unittest.TestCase):
    def test_invalid_json_input_returns_error_envelope(self):
        import io as _io
        old = sys.stdin
        sys.stdin = _io.StringIO("not json")
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exit_code = validate_report.main([])
        finally:
            sys.stdin = old
        self.assertEqual(exit_code, validate_report.EXIT_FAILED)
        self.assertFalse(json.loads(buf.getvalue())["ok"])

    def test_valid_report_via_stdin_reports_valid(self):
        import io as _io
        old = sys.stdin
        sys.stdin = _io.StringIO(json.dumps(make_valid_report()))
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exit_code = validate_report.main([])
        finally:
            sys.stdin = old
        self.assertEqual(exit_code, validate_report.EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["reportStatus"], "valid")


if __name__ == "__main__":
    unittest.main()
