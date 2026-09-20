"""Tests for scripts/upgrade_authority_guard.py (V3 Block 7, F1,
docs/decisiones.md D-075): deterministic unprotected upgrade-authority
function check.

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

import upgrade_authority_guard as uag  # noqa: E402


def param(type_):
    return {"type": type_}


def fn(name, params=None, modifiers=None, kind="function"):
    return {"kind": kind, "name": name, "params": params or [], "modifiers": modifiers or []}


def modifier(name):
    return {"name": name}


def contract(key, *functions):
    return {"key": key, "functions": list(functions)}


def artifact(*contracts):
    return {"contracts": list(contracts)}


class FindUnprotectedUpgradeAuthorityTests(unittest.TestCase):
    def test_positive_authorize_upgrade_zero_modifiers_is_flagged(self):
        c = contract("A", fn("_authorizeUpgrade", [param("address")]))
        flagged = uag.find_unprotected_upgrade_authority(c)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["signature"], "_authorizeUpgrade(address)")
        self.assertEqual(flagged[0]["confidence"], "low")

    def test_positive_upgrade_to_zero_modifiers_is_flagged(self):
        c = contract("A", fn("upgradeTo", [param("address")]))
        flagged = uag.find_unprotected_upgrade_authority(c)
        self.assertEqual(flagged[0]["signature"], "upgradeTo(address)")

    def test_positive_upgrade_to_and_call_zero_modifiers_is_flagged(self):
        c = contract("A", fn("upgradeToAndCall", [param("address"), param("bytes")]))
        flagged = uag.find_unprotected_upgrade_authority(c)
        self.assertEqual(flagged[0]["signature"], "upgradeToAndCall(address,bytes)")

    def test_negative_guarded_authorize_upgrade_is_not_flagged(self):
        c = contract("A", fn("_authorizeUpgrade", [param("address")], modifiers=[modifier("onlyOwner")]))
        self.assertEqual(uag.find_unprotected_upgrade_authority(c), [])

    def test_negative_unrelated_function_name_is_not_flagged(self):
        c = contract("A", fn("withdraw", [param("uint256")]))
        self.assertEqual(uag.find_unprotected_upgrade_authority(c), [])

    def test_adversarial_right_name_wrong_param_type_is_not_flagged(self):
        # A "version bump" style function that happens to share a name but
        # not the real UUPS signature must never be matched (D-054).
        c = contract("A", fn("upgradeTo", [param("uint256")]))
        self.assertEqual(uag.find_unprotected_upgrade_authority(c), [])

    def test_adversarial_right_name_wrong_arity_is_not_flagged(self):
        c = contract("A", fn("upgradeTo", []))
        self.assertEqual(uag.find_unprotected_upgrade_authority(c), [])

    def test_adversarial_constructor_kind_never_matched(self):
        c = contract("A", fn("upgradeTo", [param("address")], kind="constructor"))
        self.assertEqual(uag.find_unprotected_upgrade_authority(c), [])

    def test_adversarial_non_dict_function_never_crashes(self):
        c = {"key": "A", "functions": ["not-a-dict", None, fn("upgradeTo", [param("address")])]}
        flagged = uag.find_unprotected_upgrade_authority(c)
        self.assertEqual(len(flagged), 1)

    def test_adversarial_function_missing_name_never_crashes(self):
        c = {"key": "A", "functions": [{"kind": "function", "params": [param("address")], "modifiers": []}]}
        self.assertEqual(uag.find_unprotected_upgrade_authority(c), [])

    def test_never_mutates_contract(self):
        c = contract("A", fn("upgradeTo", [param("address")]))
        before = json.loads(json.dumps(c))
        uag.find_unprotected_upgrade_authority(c)
        self.assertEqual(c, before)


class ComputeUpgradeAuthorityGuardReportTests(unittest.TestCase):
    def test_end_to_end_positive_with_correct_contract_key(self):
        art = artifact(
            contract("Safe", fn("upgradeTo", [param("address")], modifiers=[modifier("onlyOwner")])),
            contract("Vulnerable", fn("_authorizeUpgrade", [param("address")])),
        )
        result = uag.compute_upgrade_authority_guard_report(art)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(len(result["flagged"]), 1)
        self.assertEqual(result["flagged"][0]["contractKey"], "Vulnerable")

    def test_negative_all_guarded_yields_clean(self):
        art = artifact(contract("A", fn("upgradeTo", [param("address")], modifiers=[modifier("onlyOwner")])))
        result = uag.compute_upgrade_authority_guard_report(art)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["flagged"], [])

    def test_never_returns_a_severity_field(self):
        art = artifact(contract("A", fn("upgradeTo", [param("address")])))
        result = uag.compute_upgrade_authority_guard_report(art)
        self.assertNotIn("severity", result)
        for entry in result["flagged"]:
            self.assertNotIn("severity", entry)

    def test_malformed_artifact_raises(self):
        with self.assertRaises(uag.UpgradeAuthorityGuardError):
            uag.compute_upgrade_authority_guard_report("not-a-dict")
        with self.assertRaises(uag.UpgradeAuthorityGuardError):
            uag.compute_upgrade_authority_guard_report({"contracts": "not-a-list"})

    def test_adversarial_contract_without_key_is_skipped_not_crashed(self):
        art = {"contracts": [{"functions": [fn("upgradeTo", [param("address")])]}]}
        result = uag.compute_upgrade_authority_guard_report(art)
        self.assertEqual(result["status"], "clean")


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = uag.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        art = artifact(contract("A", fn("_authorizeUpgrade", [param("address")])))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps(art), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, uag.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "flagged")

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(artifact()))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, uag.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "clean")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, uag.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_upgrade_authority_guard_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["upgrade-authority-guard"], "upgrade_authority_guard")


if __name__ == "__main__":
    unittest.main()
