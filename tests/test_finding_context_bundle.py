"""Tests for scripts/finding_context_bundle.py (V3 Block 8, G1,
docs/decisiones.md D-076): deterministic context assembly for one
contract/function target.

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

import finding_context_bundle as fcb  # noqa: E402


def fn(name, params=None, modifiers=None, kind="function"):
    return {"kind": kind, "name": name, "params": params or [], "modifiers": modifiers or []}


def contract(key, name=None, *functions, state_vars=None):
    return {"key": key, "name": name or key, "file": "%s.sol" % key, "functions": list(functions), "stateVariables": state_vars or []}


def edge(kind, from_key, to_key, function=None, method=None):
    e = {"kind": kind, "from": from_key, "to": to_key}
    if function is not None:
        e["function"] = function
    if method is not None:
        e["method"] = method
    return e


def system_graph(edges, computed=True):
    return {"status": "computed" if computed else "not_computed", "nodes": [], "edges": edges, "proxies": []}


def artifact(contracts, edges=None, computed=True):
    return {"contracts": contracts, "systemGraph": system_graph(edges or [], computed)}


class ComputeFindingContextBundleTests(unittest.TestCase):
    def test_positive_contract_only_no_function_requested(self):
        art = artifact([contract("A")])
        result = fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A"})
        self.assertEqual(result["contractKey"], "A")
        self.assertIsNone(result["function"])
        self.assertIsNone(result["matchedFunction"])
        self.assertEqual(result["contract"]["key"], "A")

    def test_positive_contract_and_unique_function(self):
        c = contract("A", "A", fn("withdraw", [{"type": "uint256"}]))
        art = artifact([c])
        result = fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A", "function": "withdraw"})
        self.assertEqual(result["matchedFunction"]["name"], "withdraw")

    def test_positive_contract_and_function_edges_filtered_correctly(self):
        c_a = contract("A", "A", fn("trigger"))
        c_b = contract("B", "B", fn("drain"))
        edges = [
            edge("calls", "A", "B", function="trigger", method="drain"),
            edge("inherits", "A", "SomeBase"),
        ]
        art = artifact([c_a, c_b], edges)
        result = fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A", "function": "trigger"})
        self.assertEqual(result["systemGraph"]["status"], "computed")
        self.assertEqual(len(result["systemGraph"]["contractEdges"]), 2)  # both edges touch A
        self.assertEqual(len(result["systemGraph"]["functionEdges"]), 1)  # only the calls-edge names "trigger"
        self.assertEqual(result["systemGraph"]["functionEdges"][0]["method"], "drain")

    def test_negative_no_function_requested_function_edges_is_null_not_empty_list(self):
        art = artifact([contract("A")], [edge("inherits", "A", "Base")])
        result = fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A"})
        self.assertIsNone(result["systemGraph"]["functionEdges"])
        self.assertEqual(len(result["systemGraph"]["contractEdges"]), 1)

    def test_system_graph_not_computed_yields_not_computed_status(self):
        art = artifact([contract("A")], [], computed=False)
        result = fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A"})
        self.assertEqual(result["systemGraph"]["status"], "not_computed")
        self.assertEqual(result["systemGraph"]["contractEdges"], [])

    def test_adversarial_contract_key_not_found_raises(self):
        art = artifact([contract("A")])
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "DoesNotExist"})

    def test_adversarial_function_not_found_raises(self):
        art = artifact([contract("A", "A", fn("withdraw"))])
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A", "function": "deposit"})

    def test_adversarial_ambiguous_overloaded_function_raises(self):
        c = contract("A", "A", fn("upgradeTo", [{"type": "address"}]), fn("upgradeTo", [{"type": "address"}, {"type": "bool"}]))
        art = artifact([c])
        with self.assertRaises(fcb.FindingContextBundleError) as ctx:
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A", "function": "upgradeTo"})
        self.assertIn("ambiguous", str(ctx.exception))

    def test_malformed_artifact_raises(self):
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": "not-a-dict", "contractKey": "A"})
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": {"contracts": "not-a-list"}, "contractKey": "A"})

    def test_malformed_contract_key_raises(self):
        art = artifact([contract("A")])
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": ""})
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": 123})

    def test_adversarial_non_dict_system_graph_raises_clean_error(self):
        art = {"contracts": [contract("A")], "systemGraph": "garbage"}
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A"})

    def test_adversarial_non_list_edges_raises_clean_error(self):
        art = {"contracts": [contract("A")], "systemGraph": {"status": "computed", "edges": "not-a-list"}}
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A"})

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(fcb.FindingContextBundleError):
            fcb.compute_finding_context_bundle("not-a-dict")

    def test_never_returns_a_severity_field(self):
        art = artifact([contract("A")])
        result = fcb.compute_finding_context_bundle({"artifact": art, "contractKey": "A"})
        self.assertNotIn("severity", result)

    def test_never_mutates_payload(self):
        art = artifact([contract("A", "A", fn("withdraw"))], [edge("inherits", "A", "Base")])
        payload = {"artifact": art, "contractKey": "A", "function": "withdraw"}
        before = json.loads(json.dumps(payload))
        fcb.compute_finding_context_bundle(payload)
        self.assertEqual(payload, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = fcb.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        art = artifact([contract("A")])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"artifact": art, "contractKey": "A"}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, fcb.EXIT_OK)
        self.assertEqual(json.loads(out)["contractKey"], "A")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, fcb.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_finding_context_bundle_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["finding-context-bundle"], "finding_context_bundle")


if __name__ == "__main__":
    unittest.main()
