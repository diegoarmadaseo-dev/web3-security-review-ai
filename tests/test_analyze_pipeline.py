"""Tests for scripts/analyze_pipeline.py (V2.11 - Mechanized Deterministic
Pipeline, docs/decisiones.md D-066, capability A-03).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_pipeline as ap  # noqa: E402

REFERENCES_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "references"

SC_CATEGORIES = ["SC%02d" % n for n in range(1, 11)]
SOURCE_TEXT = "pragma solidity ^0.8.0;\ncontract A { function setFee(uint f) public { } }\n"


def _base_finding():
    return {
        "category": "SC01", "signature": "unprotected-admin-function", "severity": "HIGH",
        "confidence": "high", "status": "suspected",
        "locations": [{"file": "A.sol", "lineStart": 1, "lineEnd": 1, "contract": "A", "function": "setFee"}],
        "evidence": ["x"], "description": "desc", "recommendation": "rec", "patch": None,
    }


def make_raw_draft(mode="standard", with_finding=True):
    """A PRE-score draft, exactly SKILL.md Step 6's own output shape - never
    carries id/stableKey/riskIndicator (score.py owns those)."""
    coverage = [{"category": c, "status": "NOT_DETECTED"} for c in SC_CATEGORIES]
    findings = []
    if with_finding:
        coverage[0]["status"] = "DETECTED"
        findings = [_base_finding()]
    return {
        "generatedBy": "ai", "skillVersion": "1.0.0", "analysisEngineVersion": "1.0.0",
        "checklistVersion": "2026.1", "scoreVersion": "2026.1", "mode": mode, "language": "en",
        "compilerVersion": "0.8.20", "scriptsAvailable": True, "inputHash": "sha256:" + "a" * 64,
        "scope": {"completeness": "complete", "reasons": []}, "categoryCoverage": coverage,
        "findings": findings, "limitations": ["x"],
        "riskIndicator": {"scoreStatus": "not_computed", "score": None, "band": None},
        "scoreStatus": "not_computed",
    }


class AnalyzePipelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.src_path = str(Path(self._tmp.name) / "A.sol")
        with open(self.src_path, "w", encoding="utf-8") as fh:
            fh.write(SOURCE_TEXT)

    def test_valid_draft_on_attempt_1_renders(self):
        result = ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=1)
        self.assertEqual(result["status"], "rendered")
        self.assertEqual(result["renderFormat"], "markdown")
        self.assertIn("SC01", result["rendered"])
        self.assertIn("scoredReport", result)
        self.assertIn("riskIndicator", result["scoredReport"])

    def test_preprocess_artifact_is_the_real_step3_output(self):
        result = ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=1)
        self.assertIn("mode", result["preprocessArtifact"])
        self.assertEqual(result["preprocessArtifact"]["mode"], "standard")

    def test_invalid_draft_attempt_1_returns_needs_revision_not_raised(self):
        bad = make_raw_draft()
        del bad["compilerVersion"]
        result = ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=bad, attempt=1)
        self.assertEqual(result["status"], "needs_revision")
        self.assertEqual(result["attemptsRemaining"], 2)
        self.assertTrue(any("compilerVersion" in e for e in result["errors"]))
        self.assertNotIn("rendered", result)

    def test_invalid_draft_attempt_2_still_needs_revision(self):
        bad = make_raw_draft()
        del bad["compilerVersion"]
        result = ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=bad, attempt=2)
        self.assertEqual(result["status"], "needs_revision")
        self.assertEqual(result["attemptsRemaining"], 1)

    def test_invalid_draft_attempt_3_hard_fails(self):
        # Adversarial (explicit requirement): SKILL.md's retry cap (2 retries,
        # 3 attempts total) must be a hard stop, never a soft result.
        bad = make_raw_draft()
        del bad["compilerVersion"]
        with self.assertRaises(ap.AnalyzePipelineError):
            ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=bad, attempt=3)

    def test_valid_draft_on_attempt_3_still_renders(self):
        # The cap only blocks a STILL-INVALID report; a valid draft on the
        # last allowed attempt is a normal success, not a forced failure.
        result = ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=3)
        self.assertEqual(result["status"], "rendered")

    def test_attempt_out_of_range_rejected(self):
        for bad_attempt in (0, 4, -1, 99):
            with self.assertRaises(ap.AnalyzePipelineError):
                ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=bad_attempt)

    def test_attempt_wrong_type_rejected(self):
        # Adversarial (D-056-style strictness): a bool is an int subclass in
        # Python but must never be silently accepted as an attempt number.
        for bad_attempt in ("1", 1.5, True, None, [1]):
            with self.assertRaises(ap.AnalyzePipelineError):
                ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=bad_attempt)

    def test_attempt_cap_checked_before_step3_preprocess_runs(self):
        # Adversarial: an out-of-range attempt must fail fast, before doing
        # any real work - even when the source path itself would also fail.
        with self.assertRaises(ap.AnalyzePipelineError) as ctx:
            ap.run_analyze_pipeline(["/definitely/does/not/exist.sol"], mode="standard", draft_report=make_raw_draft(), attempt=99)
        self.assertIn("attempt", str(ctx.exception))

    def test_never_performs_step6_draft_content_is_never_inspected(self):
        # A completely fabricated, structurally-valid finding is accepted
        # verbatim - this module has no judgment over finding substance.
        draft = make_raw_draft()
        draft["findings"][0]["description"] = "anything at all, never interpreted"
        result = ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=draft, attempt=1)
        self.assertEqual(result["status"], "rendered")

    def test_html_format_rejected_for_mode_without_allow_html_report(self):
        with self.assertRaises(ap.ReportRenderError):
            ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=1, render_format="html")

    def test_html_format_renders_for_pro_mode(self):
        result = ap.run_analyze_pipeline([self.src_path], mode="pro", draft_report=make_raw_draft(mode="pro"), attempt=1, render_format="html")
        self.assertEqual(result["status"], "rendered")
        self.assertIn("<html", result["rendered"].lower())

    def test_invalid_render_format_rejected(self):
        with self.assertRaises(ap.AnalyzePipelineError):
            ap.run_analyze_pipeline([self.src_path], mode="standard", draft_report=make_raw_draft(), attempt=1, render_format="pdf")

    def test_malformed_source_path_propagates_preprocess_error_uncaught(self):
        # This module never re-implements preprocess.py's own input validation.
        with self.assertRaises(ap.PreprocessError):
            ap.run_analyze_pipeline(["/definitely/does/not/exist.sol"], mode="standard", draft_report=make_raw_draft(), attempt=1)

    def test_unknown_mode_propagates_modes_config_error_uncaught(self):
        with self.assertRaises(ap.ModesConfigError):
            ap.run_analyze_pipeline([self.src_path], mode="not-a-real-mode", draft_report=make_raw_draft(), attempt=1)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ap.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "A.sol"
            draft_path = Path(tmp) / "draft.json"
            src_path.write_text(SOURCE_TEXT, encoding="utf-8")
            draft_path.write_text(json.dumps(make_raw_draft()), encoding="utf-8")
            exit_code, out = self._run_cli([str(src_path), "--draft-report", str(draft_path), "--mode", "standard"])
            self.assertEqual(exit_code, ap.EXIT_OK)
            self.assertEqual(json.loads(out)["status"], "rendered")

    def test_cli_needs_revision_still_exits_ok(self):
        # Script exit code reflects "did it run successfully," never "did
        # the report happen to be valid" - same convention as pr_gate.py's
        # gateStatus=FAIL still exiting EXIT_OK.
        with tempfile.TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "A.sol"
            draft_path = Path(tmp) / "draft.json"
            bad = make_raw_draft()
            del bad["compilerVersion"]
            src_path.write_text(SOURCE_TEXT, encoding="utf-8")
            draft_path.write_text(json.dumps(bad), encoding="utf-8")
            exit_code, out = self._run_cli([str(src_path), "--draft-report", str(draft_path), "--mode", "standard", "--attempt", "1"])
            self.assertEqual(exit_code, ap.EXIT_OK)
            self.assertEqual(json.loads(out)["status"], "needs_revision")

    def test_cli_hard_fail_at_cap_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "A.sol"
            draft_path = Path(tmp) / "draft.json"
            bad = make_raw_draft()
            del bad["compilerVersion"]
            src_path.write_text(SOURCE_TEXT, encoding="utf-8")
            draft_path.write_text(json.dumps(bad), encoding="utf-8")
            exit_code, out = self._run_cli([str(src_path), "--draft-report", str(draft_path), "--mode", "standard", "--attempt", "3"])
            self.assertEqual(exit_code, ap.EXIT_FAILED)
            envelope = json.loads(out)
            self.assertFalse(envelope["ok"])
            self.assertIn("error", envelope)

    def test_cli_malformed_draft_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "A.sol"
            draft_path = Path(tmp) / "draft.json"
            src_path.write_text(SOURCE_TEXT, encoding="utf-8")
            draft_path.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(src_path), "--draft-report", str(draft_path)])
            self.assertEqual(exit_code, ap.EXIT_FAILED)
            self.assertFalse(json.loads(out)["ok"])

    def test_cli_reads_source_from_stdin_when_no_paths_given(self):
        # preprocess.run()'s stdin path reads sys.stdin.buffer (binary) to
        # run its own encoding detection - only a REAL OS pipe provides
        # that, so this goes through a subprocess rather than an in-process
        # io.StringIO mock (which has no .buffer attribute).
        with tempfile.TemporaryDirectory() as tmp:
            draft_path = Path(tmp) / "draft.json"
            draft_path.write_text(json.dumps(make_raw_draft()), encoding="utf-8")
            script = str(SCRIPTS_DIR / "analyze_pipeline.py")
            proc = subprocess.run(
                [sys.executable, script, "--draft-report", str(draft_path), "--mode", "standard"],
                input=SOURCE_TEXT, capture_output=True, text=True, cwd=str(SCRIPTS_DIR),
            )
            self.assertEqual(proc.returncode, ap.EXIT_OK, proc.stdout + proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], "rendered")


class SchemaDriftTests(unittest.TestCase):
    def _schema(self):
        return json.loads((REFERENCES_DIR / "analyze-pipeline-schema.json").read_text(encoding="utf-8"))

    def _draft_and_source(self, tmp):
        src_path = Path(tmp) / "A.sol"
        src_path.write_text(SOURCE_TEXT, encoding="utf-8")
        return str(src_path)

    def test_needs_revision_result_matches_schema_required_fields(self):
        schema = self._schema()
        required = set(schema["definitions"]["needsRevisionResult"]["required"])
        with tempfile.TemporaryDirectory() as tmp:
            src_path = self._draft_and_source(tmp)
            bad = make_raw_draft()
            del bad["compilerVersion"]
            result = ap.run_analyze_pipeline([src_path], mode="standard", draft_report=bad, attempt=1)
        self.assertEqual(required, set(result.keys()))

    def test_rendered_result_matches_schema_required_fields(self):
        schema = self._schema()
        required = set(schema["definitions"]["renderedResult"]["required"])
        with tempfile.TemporaryDirectory() as tmp:
            src_path = self._draft_and_source(tmp)
            result = ap.run_analyze_pipeline([src_path], mode="standard", draft_report=make_raw_draft(), attempt=1)
        self.assertEqual(required, set(result.keys()))


if __name__ == "__main__":
    unittest.main()
