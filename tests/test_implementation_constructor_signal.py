"""Tests for scripts/implementation_constructor_signal.py (V3 Block 7, F3,
docs/decisiones.md D-075): deterministic proxy-implementation
constructor-safety signal.

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

import implementation_constructor_signal as ics  # noqa: E402


def param(name, type_="address"):
    return {"name": name, "type": type_}


def constructor(*params_):
    return {"kind": "constructor", "params": list(params_)}


def contract(key, *functions):
    return {"key": key, "functions": list(functions)}


def proxy_entry(proxy_key, impl_key, status="resolved"):
    return {"proxy": proxy_key, "implementation": impl_key, "status": status}


def system_graph(proxies, computed=True):
    return {"status": "computed" if computed else "not_computed", "nodes": [], "edges": [], "proxies": proxies}


def artifact(contracts, proxies, computed=True):
    return {"contracts": contracts, "systemGraph": system_graph(proxies, computed)}


class ComputeImplementationConstructorSignalReportTests(unittest.TestCase):
    def test_positive_implementation_constructor_with_one_param_is_flagged(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["flagged"], [{"proxyKey": "Proxy", "implementationKey": "Impl", "constructorParamCount": 1, "confidence": "low"}])

    def test_positive_multiple_params_counted_correctly(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("a"), param("b"), param("c", "uint256")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["flagged"][0]["constructorParamCount"], 3)

    def test_negative_zero_param_constructor_is_clean(self):
        contracts = [contract("Proxy"), contract("Impl", constructor())]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["flagged"], [])

    def test_negative_no_constructor_at_all_is_clean(self):
        contracts = [contract("Proxy"), contract("Impl")]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")

    def test_negative_unresolved_proxy_entry_is_skipped(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl", status="unresolved")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")

    def test_negative_no_implementation_key_is_skipped(self):
        contracts = [contract("Proxy")]
        art = artifact(contracts, [{"proxy": "Proxy", "implementation": None, "status": "resolved"}])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")

    def test_adversarial_missing_proxy_key_entirely_is_skipped_never_null(self):
        # docs/decisiones.md D-075 F3 hardening: implementation resolved but
        # the "proxy" key is entirely absent must never surface as
        # proxyKey: null - the whole malformed entry is skipped instead.
        contracts = [contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [{"implementation": "Impl", "status": "resolved"}])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["flagged"], [])

    def test_adversarial_proxy_explicitly_null_is_skipped_never_null_in_output(self):
        contracts = [contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [{"proxy": None, "implementation": "Impl", "status": "resolved"}])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["flagged"], [])

    def test_regression_valid_proxy_and_implementation_still_flagged_with_real_proxy_key(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["flagged"][0]["proxyKey"], "Proxy")
        self.assertIsInstance(result["flagged"][0]["proxyKey"], str)

    def test_system_graph_not_computed_yields_not_computed_status(self):
        art = artifact([], [], computed=False)
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "not_computed")
        self.assertEqual(result["flagged"], [])

    def test_never_returns_a_severity_field(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertNotIn("severity", result)
        self.assertNotIn("severity", result["flagged"][0])

    def test_malformed_artifact_raises(self):
        with self.assertRaises(ics.ImplementationConstructorSignalError):
            ics.compute_implementation_constructor_signal_report("not-a-dict")
        with self.assertRaises(ics.ImplementationConstructorSignalError):
            ics.compute_implementation_constructor_signal_report({"contracts": "not-a-list"})

    def test_adversarial_non_dict_system_graph_raises_clean_error(self):
        with self.assertRaises(ics.ImplementationConstructorSignalError):
            ics.compute_implementation_constructor_signal_report({"contracts": [], "systemGraph": "garbage"})

    def test_adversarial_non_list_proxies_raises_clean_error(self):
        art = {"contracts": [], "systemGraph": {"status": "computed", "proxies": "not-a-list"}}
        with self.assertRaises(ics.ImplementationConstructorSignalError):
            ics.compute_implementation_constructor_signal_report(art)

    def test_adversarial_non_dict_proxy_entry_never_crashes(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [None, "not-a-dict", proxy_entry("Proxy", "Impl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(len(result["flagged"]), 1)

    def test_adversarial_implementation_key_not_found_in_contracts_never_crashes(self):
        art = artifact([contract("Proxy")], [proxy_entry("Proxy", "GhostImpl")])
        result = ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(result["status"], "clean")

    def test_never_mutates_artifact(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        before = json.loads(json.dumps(art))
        ics.compute_implementation_constructor_signal_report(art)
        self.assertEqual(art, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ics.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        contracts = [contract("Proxy"), contract("Impl", constructor(param("registry")))]
        art = artifact(contracts, [proxy_entry("Proxy", "Impl")])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps(art), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, ics.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "flagged")

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(artifact([], [], computed=False)))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, ics.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "not_computed")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, ics.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_implementation_constructor_signal_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["implementation-constructor-signal"], "implementation_constructor_signal")


if __name__ == "__main__":
    unittest.main()
