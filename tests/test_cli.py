"""Tests for scripts/cli.py (V2.11 - Unified CLI Dispatcher, docs/
decisiones.md D-066, capability A-01).

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

import cli  # noqa: E402
import preprocess  # noqa: E402
import score  # noqa: E402
import validate_report  # noqa: E402
import render_report  # noqa: E402
import ingest_onchain  # noqa: E402
import compare_bytecode  # noqa: E402
import diff_reports  # noqa: E402
import monitor_diff  # noqa: E402
import pr_gate  # noqa: E402
import analyze_pipeline  # noqa: E402


def _capture(func, argv):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = func(argv)
    return exit_code, stdout.getvalue()


class DispatchTests(unittest.TestCase):
    """Backward compatibility (explicit requirement): cli.py must forward
    arguments UNCHANGED, never alter a script's own behavior. Each case
    below runs the SAME argv through cli.py and through the target script's
    own main() and asserts byte-identical stdout + exit code."""

    def _assert_parity(self, command, module, argv):
        direct_exit, direct_out = _capture(module.main, argv)
        cli_exit, cli_out = _capture(cli.main, [command] + argv)
        self.assertEqual(direct_exit, cli_exit, "%s: exit code differs" % command)
        self.assertEqual(direct_out, cli_out, "%s: stdout differs" % command)

    def test_preprocess_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "A.sol"
            src.write_text("pragma solidity ^0.8.0;\ncontract A {}\n", encoding="utf-8")
            self._assert_parity("preprocess", preprocess, [str(src), "--mode", "quick"])

    def test_score_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.json"
            draft.write_text(json.dumps({"findings": []}), encoding="utf-8")
            self._assert_parity("score", score, [str(draft)])

    def test_validate_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"not": "a valid report"}), encoding="utf-8")
            self._assert_parity("validate", validate_report, [str(report)])

    def test_render_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"mode": "standard", "findings": []}), encoding="utf-8")
            self._assert_parity("render", render_report, [str(report)])

    def test_ingest_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw.json"
            raw.write_text(json.dumps({"address": "0x" + "1" * 40, "network": 1}), encoding="utf-8")
            self._assert_parity("ingest", ingest_onchain, [str(raw)])

    def test_compare_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw.json"
            raw.write_text(json.dumps({}), encoding="utf-8")
            self._assert_parity("compare", compare_bytecode, [str(raw)])

    def test_diff_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1 = Path(tmp) / "v1.json"
            v2 = Path(tmp) / "v2.json"
            v1.write_text(json.dumps({"findings": [], "categoryCoverage": []}), encoding="utf-8")
            v2.write_text(json.dumps({"findings": [], "categoryCoverage": []}), encoding="utf-8")
            self._assert_parity("diff", diff_reports, ["reports", str(v1), str(v2)])

    def test_monitor_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = Path(tmp) / "scans.json"
            scans.write_text(json.dumps({"scans": []}), encoding="utf-8")
            self._assert_parity("monitor", monitor_diff, ["finding-lifecycle", str(scans)])

    def test_pr_gate_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "payload.json"
            payload.write_text(json.dumps({"refLabel": "head", "changedFiles": []}), encoding="utf-8")
            self._assert_parity("pr-gate", pr_gate, ["ingest", str(payload)])

    def test_analyze_pipeline_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "A.sol"
            draft = Path(tmp) / "draft.json"
            src.write_text("pragma solidity ^0.8.0;\ncontract A {}\n", encoding="utf-8")
            draft.write_text(json.dumps({"findings": []}), encoding="utf-8")
            self._assert_parity("analyze-pipeline", analyze_pipeline, [str(src), "--draft-report", str(draft), "--mode", "quick"])


class TopLevelTests(unittest.TestCase):
    def test_no_args_prints_usage_and_fails(self):
        exit_code, out = _capture(cli.main, [])
        self.assertEqual(exit_code, cli.EXIT_FAILED)
        self.assertIn("usage:", out)

    def test_help_prints_usage_and_succeeds(self):
        for flag in ("-h", "--help"):
            with self.subTest(flag=flag):
                exit_code, out = _capture(cli.main, [flag])
                self.assertEqual(exit_code, cli.EXIT_OK)
                self.assertIn("usage:", out)

    def test_unknown_command_yields_clean_error_envelope(self):
        exit_code, out = _capture(cli.main, ["not-a-real-command"])
        self.assertEqual(exit_code, cli.EXIT_FAILED)
        envelope = json.loads(out)
        self.assertFalse(envelope["ok"])
        self.assertIn("not-a-real-command", envelope["error"])

    def test_every_documented_command_is_dispatchable(self):
        # Adversarial: catches a typo'd module name in COMMANDS before it
        # ever reaches a user - every value must be an importable module
        # that actually defines main().
        import importlib
        for command, module_name in cli.COMMANDS.items():
            with self.subTest(command=command):
                module = importlib.import_module(module_name)
                self.assertTrue(callable(getattr(module, "main", None)), "%s has no main()" % module_name)

    def test_usage_text_lists_every_command(self):
        text = cli._usage_text()
        for command in cli.COMMANDS:
            self.assertIn(command, text)


if __name__ == "__main__":
    unittest.main()
