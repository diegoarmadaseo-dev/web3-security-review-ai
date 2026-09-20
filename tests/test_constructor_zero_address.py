"""Tests for scripts/constructor_zero_address.py (V3 Block 6, E2,
docs/decisiones.md D-074): deterministic constructor zero-address sanity
check.

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

import constructor_zero_address as cza  # noqa: E402


def param(name, is_address, type_="address"):
    return {"name": name, "type": type_, "isAddress": is_address}


def constructor(*params_):
    return {"kind": "constructor", "params": list(params_)}


def contract(key, *functions):
    return {"key": key, "functions": list(functions)}


def artifact(*contracts):
    return {"contracts": list(contracts)}


class FindConstructorZeroAddressesTests(unittest.TestCase):
    def test_positive_zero_address_full_form_is_flagged(self):
        c = contract("A", constructor(param("owner", True)))
        result = cza.find_constructor_zero_addresses(c, ["0x0000000000000000000000000000000000000000"])
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["flagged"], [{"paramName": "owner", "paramIndex": 0}])

    def test_adversarial_zero_address_short_form_is_also_flagged(self):
        c = contract("A", constructor(param("owner", True)))
        result = cza.find_constructor_zero_addresses(c, ["0x0"])
        self.assertEqual(result["status"], "flagged")

    def test_negative_real_address_is_clean(self):
        c = contract("A", constructor(param("owner", True)))
        result = cza.find_constructor_zero_addresses(c, ["0x000000000000000000000000000000000000dEaD"])
        self.assertEqual(result["status"], "clean")

    def test_adversarial_zero_valued_non_address_param_is_never_flagged(self):
        # A uint256 argument of 0 is completely ordinary - only isAddress
        # params are ever inspected.
        c = contract("A", constructor(param("supply", False, "uint256")))
        result = cza.find_constructor_zero_addresses(c, [0])
        self.assertEqual(result["status"], "clean")

    def test_negative_no_constructor_at_all(self):
        c = contract("A")
        result = cza.find_constructor_zero_addresses(c, [])
        self.assertEqual(result["status"], "no_constructor")

    def test_fewer_args_than_params_never_crashes(self):
        c = contract("A", constructor(param("owner", True), param("admin", True)))
        result = cza.find_constructor_zero_addresses(c, ["0xdead"])  # only 1 of 2 args supplied
        self.assertEqual(result["status"], "clean")

    def test_mixed_params_only_address_ones_are_checked(self):
        c = contract("A", constructor(param("amount", False, "uint256"), param("owner", True)))
        result = cza.find_constructor_zero_addresses(c, [0, "0x0"])
        self.assertEqual(result["flagged"], [{"paramName": "owner", "paramIndex": 1}])

    def test_never_mutates_contract_or_args(self):
        c = contract("A", constructor(param("owner", True)))
        args = ["0x0"]
        c_before, args_before = json.loads(json.dumps(c)), json.loads(json.dumps(args))
        cza.find_constructor_zero_addresses(c, args)
        self.assertEqual(c, c_before)
        self.assertEqual(args, args_before)


class ComputeConstructorZeroAddressReportTests(unittest.TestCase):
    def test_end_to_end_positive(self):
        art = artifact(contract("A", constructor(param("owner", True))))
        result = cza.compute_constructor_zero_address_report({"artifact": art, "contractKey": "A", "constructorArgs": ["0x0"]})
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["contractKey"], "A")

    def test_never_returns_a_severity_field(self):
        art = artifact(contract("A", constructor(param("owner", True))))
        result = cza.compute_constructor_zero_address_report({"artifact": art, "contractKey": "A", "constructorArgs": ["0x0"]})
        self.assertNotIn("severity", result)

    def test_malformed_missing_fields_raises(self):
        with self.assertRaises(cza.ConstructorZeroAddressError):
            cza.compute_constructor_zero_address_report({})

    def test_malformed_unknown_contract_key_raises(self):
        art = artifact(contract("A", constructor(param("owner", True))))
        with self.assertRaises(cza.ConstructorZeroAddressError):
            cza.compute_constructor_zero_address_report({"artifact": art, "contractKey": "DoesNotExist", "constructorArgs": []})

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(cza.ConstructorZeroAddressError):
            cza.compute_constructor_zero_address_report("not-a-dict")


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cza.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        art = artifact(contract("A", constructor(param("owner", True))))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"artifact": art, "contractKey": "A", "constructorArgs": ["0x0"]}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, cza.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "flagged")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, cza.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_constructor_zero_address_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["constructor-zero-address"], "constructor_zero_address")


if __name__ == "__main__":
    unittest.main()
