"""Tests for scripts/initializer_safety.py (V3 Block 5, D1, docs/decisiones.md
D-073): deterministic upgrade initializer-safety check.

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

import initializer_safety as isf  # noqa: E402


def fn(name, modifiers=()):
    return {"name": name, "modifiers": [{"name": m[0], "args": m[1] if len(m) > 1 else None} for m in modifiers]}


def contract(key, *functions):
    return {"key": key, "functions": list(functions)}


def artifact(*contracts):
    return {"contracts": list(contracts)}


class DiffInitializerSafetyTests(unittest.TestCase):
    def test_positive_no_change_is_unchanged(self):
        c1 = contract("A", fn("initialize", [("initializer",)]))
        c2 = contract("A", fn("initialize", [("initializer",)]))
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_positive_new_reinitializer_with_novel_version_is_unchanged(self):
        c1 = contract("A", fn("initialize", [("initializer",)]))
        c2 = contract("A", fn("initialize", [("initializer",)]), fn("initializeV2", [("reinitializer", "2")]))
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_adversarial_guard_removed_while_function_persists(self):
        c1 = contract("A", fn("initialize", [("initializer",)]))
        c2 = contract("A", fn("initialize"))  # same function, modifier stripped
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["findings"], [{"type": "guard_removed", "function": "initialize", "modifierBefore": "initializer"}])

    def test_negative_function_removed_entirely_is_not_guard_removed(self):
        c1 = contract("A", fn("initialize", [("initializer",)]))
        c2 = contract("A")  # function gone entirely, not just its modifier
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_adversarial_reinitializer_version_reused_against_v1(self):
        c1 = contract("A", fn("initialize", [("reinitializer", "1")]))
        c2 = contract("A", fn("initialize", [("reinitializer", "1")]), fn("initializeAgain", [("reinitializer", "1")]))
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["findings"], [{"type": "reinitializer_version_reused", "function": "initializeAgain", "version": 1}])

    def test_adversarial_two_new_functions_collide_with_each_other(self):
        c1 = contract("A")
        c2 = contract("A", fn("initA", [("reinitializer", "3")]), fn("initB", [("reinitializer", "3")]))
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["status"], "flagged")
        kinds = [(f["type"], f["function"]) for f in result["findings"]]
        self.assertIn(("reinitializer_version_reused", "initB"), kinds)
        self.assertNotIn(("reinitializer_version_reused", "initA"), kinds)  # the FIRST claim of a version is never itself flagged.

    def test_only_initializing_modifier_is_recognized(self):
        c1 = contract("A", fn("step", [("onlyInitializing",)]))
        c2 = contract("A", fn("step"))
        result = isf.diff_initializer_safety(c1, c2)
        self.assertEqual(result["findings"][0]["modifierBefore"], "onlyInitializing")

    def test_never_returns_a_severity_field(self):
        c1 = contract("A", fn("initialize", [("initializer",)]))
        c2 = contract("A", fn("initialize"))
        result = isf.diff_initializer_safety(c1, c2)
        self.assertNotIn("severity", result)
        for f in result["findings"]:
            self.assertNotIn("severity", f)

    def test_never_mutates_either_input(self):
        c1 = contract("A", fn("initialize", [("initializer",)]))
        c2 = contract("A", fn("initialize"))
        c1_before, c2_before = json.loads(json.dumps(c1)), json.loads(json.dumps(c2))
        isf.diff_initializer_safety(c1, c2)
        self.assertEqual(c1, c1_before)
        self.assertEqual(c2, c2_before)


class ComputeInitializerSafetyReportTests(unittest.TestCase):
    def test_flags_only_the_affected_contract(self):
        v1 = artifact(contract("Safe", fn("initialize", [("initializer",)])), contract("Risky", fn("initialize", [("initializer",)])))
        v2 = artifact(contract("Safe", fn("initialize", [("initializer",)])), contract("Risky", fn("initialize")))
        report = isf.compute_initializer_safety_report(v1, v2)
        self.assertEqual(report["contractsFlagged"], ["Risky"])

    def test_malformed_v1_raises(self):
        with self.assertRaises(isf.InitializerSafetyError):
            isf.compute_initializer_safety_report("not-a-dict", artifact())

    def test_malformed_v2_raises(self):
        with self.assertRaises(isf.InitializerSafetyError):
            isf.compute_initializer_safety_report(artifact(), {"contracts": "not-a-list"})


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = isf.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1_path = Path(tmp) / "v1.json"
            v2_path = Path(tmp) / "v2.json"
            v1_path.write_text(json.dumps(artifact(contract("A", fn("initialize", [("initializer",)])))), encoding="utf-8")
            v2_path.write_text(json.dumps(artifact(contract("A", fn("initialize")))), encoding="utf-8")
            exit_code, out = self._run_cli([str(v1_path), str(v2_path)])
        self.assertEqual(exit_code, isf.EXIT_OK)
        self.assertEqual(json.loads(out)["contractsFlagged"], ["A"])

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            good = Path(tmp) / "good.json"
            bad.write_text("not json", encoding="utf-8")
            good.write_text(json.dumps(artifact()), encoding="utf-8")
            exit_code, out = self._run_cli([str(bad), str(good)])
        self.assertEqual(exit_code, isf.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_initializer_safety_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["initializer-safety"], "initializer_safety")


if __name__ == "__main__":
    unittest.main()
