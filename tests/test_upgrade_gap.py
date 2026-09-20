"""Tests for scripts/upgrade_gap.py (V3 Block 4, C3, docs/decisiones.md
D-072): deterministic OpenZeppelin-style __gap reserved-array check.

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

import upgrade_gap as ug  # noqa: E402


def sv(name, type_):
    return {"name": name, "type": type_}


def contract(key, *vars_):
    return {"key": key, "name": key, "stateVariables": list(vars_)}


def artifact(*contracts):
    return {"contracts": list(contracts)}


class DiffUpgradeGapTests(unittest.TestCase):
    def test_shrink(self):
        c1 = contract("A", sv("__gap", "uint256[50]"))
        c2 = contract("A", sv("__gap", "uint256[40]"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "shrunk")
        self.assertEqual(result["gaps"]["__gap"], {"status": "shrunk", "sizeBefore": 50, "sizeAfter": 40})

    def test_remove(self):
        c1 = contract("A", sv("__gap", "uint256[50]"))
        c2 = contract("A")
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "removed")
        self.assertEqual(result["gaps"]["__gap"]["status"], "removed")
        self.assertIsNone(result["gaps"]["__gap"]["sizeAfter"])

    def test_unchanged(self):
        c1 = contract("A", sv("__gap", "uint256[50]"))
        c2 = contract("A", sv("__gap", "uint256[50]"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "unchanged")

    def test_expand(self):
        c1 = contract("A", sv("__gap", "uint256[50]"))
        c2 = contract("A", sv("__gap", "uint256[60]"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "expanded")

    def test_added_gap_is_expanded_overall(self):
        c1 = contract("A")
        c2 = contract("A", sv("__gap", "uint256[50]"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["gaps"]["__gap"]["status"], "added")
        self.assertEqual(result["overall"], "expanded")

    def test_not_present_on_either_side(self):
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("owner", "address"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "not_present")
        self.assertEqual(result["gaps"], {})

    def test_multiple_gap_names_tracked_independently(self):
        c1 = contract("A", sv("__gap", "uint256[50]"), sv("__gap1", "uint256[10]"))
        c2 = contract("A", sv("__gap", "uint256[40]"), sv("__gap1", "uint256[10]"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["gaps"]["__gap"]["status"], "shrunk")
        self.assertEqual(result["gaps"]["__gap1"]["status"], "unchanged")
        self.assertEqual(result["overall"], "shrunk")

    def test_removed_takes_priority_over_shrunk_in_overall(self):
        c1 = contract("A", sv("__gap", "uint256[50]"), sv("__gap1", "uint256[10]"))
        c2 = contract("A", sv("__gap", "uint256[40]"))  # __gap shrunk, __gap1 removed
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "removed")

    def test_non_array_gap_name_is_skipped_never_guessed(self):
        c1 = contract("A", sv("__gap", "mapping(address => uint256)"))
        c2 = contract("A", sv("__gap", "mapping(address => uint256)"))
        result = ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(result["overall"], "not_present")

    def test_never_mutates_either_input(self):
        c1 = contract("A", sv("__gap", "uint256[50]"))
        c2 = contract("A", sv("__gap", "uint256[40]"))
        c1_before, c2_before = json.loads(json.dumps(c1)), json.loads(json.dumps(c2))
        ug.diff_upgrade_gap(c1, c2)
        self.assertEqual(c1, c1_before)
        self.assertEqual(c2, c2_before)


class ComputeUpgradeGapReportTests(unittest.TestCase):
    def test_flags_only_shrunk_and_removed_contracts(self):
        v1 = artifact(
            contract("Safe", sv("__gap", "uint256[50]")),
            contract("Shrunk", sv("__gap", "uint256[50]")),
            contract("Removed", sv("__gap", "uint256[50]")),
        )
        v2 = artifact(
            contract("Safe", sv("__gap", "uint256[60]")),
            contract("Shrunk", sv("__gap", "uint256[40]")),
            contract("Removed"),
        )
        report = ug.compute_upgrade_gap_report(v1, v2)
        self.assertEqual(report["contractsFlagged"], ["Removed", "Shrunk"])

    def test_malformed_v1_raises(self):
        with self.assertRaises(ug.UpgradeGapError):
            ug.compute_upgrade_gap_report("not-a-dict", artifact())

    def test_malformed_v2_raises(self):
        with self.assertRaises(ug.UpgradeGapError):
            ug.compute_upgrade_gap_report(artifact(), {"contracts": "not-a-list"})


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ug.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1_path = Path(tmp) / "v1.json"
            v2_path = Path(tmp) / "v2.json"
            v1_path.write_text(json.dumps(artifact(contract("A", sv("__gap", "uint256[50]")))), encoding="utf-8")
            v2_path.write_text(json.dumps(artifact(contract("A", sv("__gap", "uint256[40]")))), encoding="utf-8")
            exit_code, out = self._run_cli([str(v1_path), str(v2_path)])
        self.assertEqual(exit_code, ug.EXIT_OK)
        self.assertEqual(json.loads(out)["contractsFlagged"], ["A"])

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            good = Path(tmp) / "good.json"
            bad.write_text("not json", encoding="utf-8")
            good.write_text(json.dumps(artifact()), encoding="utf-8")
            exit_code, out = self._run_cli([str(bad), str(good)])
        self.assertEqual(exit_code, ug.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_upgrade_gap_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["upgrade-gap"], "upgrade_gap")


if __name__ == "__main__":
    unittest.main()
