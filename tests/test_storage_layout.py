"""Tests for scripts/storage_layout.py (V3 Block 3, B1, docs/decisiones.md
D-071): deterministic storage-layout compatibility check.

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

import storage_layout as sl  # noqa: E402


def sv(name, type_, constant=False, immutable=False):
    return {"name": name, "type": type_, "constant": constant, "immutable": immutable}


def contract(key, *vars_):
    return {"key": key, "name": key, "stateVariables": list(vars_)}


def artifact(*contracts):
    return {"contracts": list(contracts)}


class DiffStorageLayoutTests(unittest.TestCase):
    def test_positive_unchanged_is_unchanged(self):
        c1 = contract("A", sv("owner", "address"), sv("balance", "uint256"))
        c2 = contract("A", sv("owner", "address"), sv("balance", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["collisions"], [])

    def test_positive_safe_append_at_end(self):
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("owner", "address"), sv("balance", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "safe_append")
        self.assertEqual(result["firstDivergenceIndex"], None)
        self.assertEqual(result["collisions"], [])

    def test_adversarial_reorder_two_variables_is_collision_risk(self):
        c1 = contract("A", sv("owner", "address"), sv("balance", "uint256"))
        c2 = contract("A", sv("balance", "uint256"), sv("owner", "address"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "collision_risk")
        self.assertEqual(result["firstDivergenceIndex"], 0)

    def test_adversarial_remove_middle_variable_is_collision_risk(self):
        c1 = contract("A", sv("a", "uint256"), sv("b", "uint256"), sv("c", "uint256"))
        c2 = contract("A", sv("a", "uint256"), sv("c", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "collision_risk")
        self.assertEqual(result["firstDivergenceIndex"], 1)

    def test_adversarial_retype_in_place_is_collision_risk(self):
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("owner", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "collision_risk")
        self.assertEqual(result["collisions"][0]["v1"], {"name": "owner", "type": "address"})
        self.assertEqual(result["collisions"][0]["v2"], {"name": "owner", "type": "uint256"})

    def test_adversarial_rename_in_place_is_collision_risk(self):
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("admin", "address"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "collision_risk")

    def test_adversarial_insert_in_middle_is_collision_risk(self):
        c1 = contract("A", sv("a", "uint256"), sv("b", "uint256"))
        c2 = contract("A", sv("a", "uint256"), sv("new", "uint256"), sv("b", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "collision_risk")
        self.assertEqual(result["firstDivergenceIndex"], 1)

    def test_regression_constant_inserted_before_real_variable_is_not_collision_risk(self):
        # A brand-new `constant` never occupies a real storage slot - even
        # though it appears BEFORE `owner` positionally in source, nothing
        # about the real on-chain layout moved.
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("MAX_SUPPLY", "uint256", constant=True), sv("owner", "address"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_regression_immutable_inserted_before_real_variable_is_not_collision_risk(self):
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("deployer", "address", immutable=True), sv("owner", "address"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_regression_constant_removed_is_not_collision_risk(self):
        c1 = contract("A", sv("MAX_SUPPLY", "uint256", constant=True), sv("owner", "address"))
        c2 = contract("A", sv("owner", "address"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_regression_constant_retyped_and_reordered_freely_is_not_collision_risk(self):
        c1 = contract("A", sv("owner", "address"), sv("MAX", "uint256", constant=True))
        c2 = contract("A", sv("MAX", "string", constant=True), sv("owner", "address"), sv("MAX2", "uint256", constant=True))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "unchanged")

    def test_regression_real_append_still_safe_alongside_constants(self):
        c1 = contract("A", sv("K", "uint256", constant=True), sv("owner", "address"))
        c2 = contract("A", sv("K", "uint256", constant=True), sv("owner", "address"), sv("balance", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "safe_append")

    def test_shrink_from_end_is_collision_risk_never_safe(self):
        c1 = contract("A", sv("a", "uint256"), sv("b", "uint256"))
        c2 = contract("A", sv("a", "uint256"))
        result = sl.diff_storage_layout(c1, c2)
        self.assertEqual(result["status"], "collision_risk")

    def test_no_state_variables_on_either_side_is_unchanged(self):
        result = sl.diff_storage_layout(contract("A"), contract("A"))
        self.assertEqual(result["status"], "unchanged")

    def test_never_mutates_either_input(self):
        c1 = contract("A", sv("owner", "address"))
        c2 = contract("A", sv("owner", "address"), sv("balance", "uint256"))
        c1_before, c2_before = json.loads(json.dumps(c1)), json.loads(json.dumps(c2))
        sl.diff_storage_layout(c1, c2)
        self.assertEqual(c1, c1_before)
        self.assertEqual(c2, c2_before)


class ComputeStorageLayoutReportTests(unittest.TestCase):
    def test_multi_contract_report_isolates_at_risk_contract(self):
        v1 = artifact(
            contract("Safe", sv("a", "uint256")),
            contract("Risky", sv("a", "uint256"), sv("b", "uint256")),
        )
        v2 = artifact(
            contract("Safe", sv("a", "uint256"), sv("c", "uint256")),
            contract("Risky", sv("b", "uint256"), sv("a", "uint256")),
        )
        report = sl.compute_storage_layout_report(v1, v2)
        self.assertEqual(sorted(report["contractsCompared"]), ["Risky", "Safe"])
        self.assertEqual(report["contractsAtRisk"], ["Risky"])
        self.assertEqual(report["results"]["Safe"]["status"], "safe_append")
        self.assertEqual(report["results"]["Risky"]["status"], "collision_risk")

    def test_contract_only_on_one_side_is_excluded_never_crashes(self):
        v1 = artifact(contract("Only1", sv("a", "uint256")))
        v2 = artifact(contract("Only2", sv("a", "uint256")))
        report = sl.compute_storage_layout_report(v1, v2)
        self.assertEqual(report["contractsCompared"], [])
        self.assertEqual(report["results"], {})

    def test_malformed_v1_not_dict_raises(self):
        with self.assertRaises(sl.StorageLayoutError):
            sl.compute_storage_layout_report("not-a-dict", artifact())

    def test_malformed_v2_missing_contracts_raises(self):
        with self.assertRaises(sl.StorageLayoutError):
            sl.compute_storage_layout_report(artifact(), {"contracts": "not-a-list"})


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = sl.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1_path = Path(tmp) / "v1.json"
            v2_path = Path(tmp) / "v2.json"
            v1_path.write_text(json.dumps(artifact(contract("A", sv("owner", "address")))), encoding="utf-8")
            v2_path.write_text(json.dumps(artifact(contract("A", sv("balance", "uint256"), sv("owner", "address")))), encoding="utf-8")
            exit_code, out = self._run_cli([str(v1_path), str(v2_path)])
        self.assertEqual(exit_code, sl.EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["results"]["A"]["status"], "collision_risk")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            good = Path(tmp) / "good.json"
            bad.write_text("not json", encoding="utf-8")
            good.write_text(json.dumps(artifact()), encoding="utf-8")
            exit_code, out = self._run_cli([str(bad), str(good)])
        self.assertEqual(exit_code, sl.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_storage_layout_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["storage-layout"], "storage_layout")


if __name__ == "__main__":
    unittest.main()
