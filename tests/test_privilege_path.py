"""Tests for scripts/privilege_path.py (V3 Block 3, B2, docs/decisiones.md
D-071): deterministic cross-contract privilege-path detection.

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

import privilege_path as pp  # noqa: E402


def fn(name, visibility="external", mutability="nonpayable", modifiers=()):
    return {"name": name, "visibility": visibility, "mutability": mutability, "modifiers": [{"name": m} for m in modifiers]}


def contract(key, *functions):
    return {"key": key, "name": key, "functions": list(functions)}


def calls_edge(from_key, function, to_key, method):
    return {"kind": "calls", "from": from_key, "to": to_key, "function": function, "method": method}


def delegates_edge(from_key, to_key):
    return {"kind": "delegatesTo", "from": from_key, "to": to_key}


def artifact(contracts, edges, computed=True):
    return {
        "contracts": contracts,
        "systemGraph": {"status": "computed" if computed else "not_computed", "nodes": [], "edges": edges, "proxies": []},
    }


class ComputePrivilegePathsTests(unittest.TestCase):
    def test_positive_unguarded_cross_contract_call_to_unguarded_mutator_is_flagged(self):
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("bar"))],
            [calls_edge("A", "foo", "B", "bar")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["status"], "computed")
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["entry"], {"contract": "A", "function": "foo"})
        self.assertEqual(result["paths"][0]["target"], {"contract": "B", "function": "bar"})
        self.assertEqual(result["paths"][0]["confidence"], "low")

    def test_adversarial_guarded_target_is_never_flagged(self):
        # bar has an explicit modifier - an INTENTIONAL, correctly-guarded
        # cross-contract call - must never be reported as a privilege path.
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("bar", modifiers=("onlyOwner",)))],
            [calls_edge("A", "foo", "B", "bar")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def test_adversarial_readonly_target_is_never_flagged(self):
        # bar is view (read-only) - not state-mutating, never a privilege target.
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("bar", mutability="view"))],
            [calls_edge("A", "foo", "B", "bar")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def test_adversarial_guarded_entry_is_never_a_path_source(self):
        # foo itself is guarded - not reachable-by-anyone, so it is never
        # used as a starting point at all.
        art = artifact(
            [contract("A", fn("foo", modifiers=("onlyOwner",))), contract("B", fn("bar"))],
            [calls_edge("A", "foo", "B", "bar")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def test_same_contract_call_is_never_flagged(self):
        art = artifact(
            [contract("A", fn("foo"), fn("bar"))],
            [calls_edge("A", "foo", "A", "bar")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def test_multi_hop_through_unguarded_intermediate_is_flagged(self):
        # "mid" is view (read-only): not itself a mutating/exposed target or
        # entry point on its own, but unguarded, so the walk passes through
        # it to reach the real state-mutating target two hops away.
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("mid", mutability="view")), contract("C", fn("baz"))],
            [calls_edge("A", "foo", "B", "mid"), calls_edge("B", "mid", "C", "baz")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["target"], {"contract": "C", "function": "baz"})
        self.assertEqual(len(result["paths"][0]["hops"]), 2)

    def test_guarded_intermediate_stops_the_branch_never_traversed_past(self):
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("mid", modifiers=("onlyOwner",))), contract("C", fn("baz"))],
            [calls_edge("A", "foo", "B", "mid"), calls_edge("B", "mid", "C", "baz")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def _overloaded_sweep(self, guarded_first):
        # Real Solidity overloads must differ in parameter types (two
        # identical signatures with the same name is a compile error) -
        # sweep() vs sweep(address) here.
        no_args = fn("sweep", modifiers=("onlyOwner",) if guarded_first else ())
        no_args["params"] = []
        with_arg = fn("sweep", modifiers=() if guarded_first else ("onlyOwner",))
        with_arg["params"] = [{"type": "address"}]
        return [no_args, with_arg]

    def test_regression_overload_with_different_guard_status_no_false_negative(self):
        # sweep() is guarded, sweep(address) is not. A "calls" edge only
        # ever carries the bare name "sweep" - the exposed overload must
        # still be found, never silently overwritten by its guarded sibling.
        art = artifact(
            [contract("A", fn("foo")), contract("B", *self._overloaded_sweep(guarded_first=True))],
            [calls_edge("A", "foo", "B", "sweep")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["target"], {"contract": "B", "function": "sweep"})
        self.assertTrue(result["paths"][0]["ambiguousOverload"])
        self.assertEqual(result["paths"][0]["matchedOverloads"], ["(address)"])

    def test_regression_overload_order_reversed_still_no_false_negative(self):
        # Same pair, declaration order flipped - the original bug was
        # order-dependent (last-wins); the fix must not be.
        art = artifact(
            [contract("A", fn("foo")), contract("B", *self._overloaded_sweep(guarded_first=False))],
            [calls_edge("A", "foo", "B", "sweep")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["matchedOverloads"], ["()"])

    def test_adversarial_all_overloads_guarded_is_never_flagged(self):
        no_args = fn("sweep", modifiers=("onlyOwner",))
        no_args["params"] = []
        with_arg = fn("sweep", modifiers=("onlyAdmin",))
        with_arg["params"] = [{"type": "address"}]
        art = artifact(
            [contract("A", fn("foo")), contract("B", no_args, with_arg)],
            [calls_edge("A", "foo", "B", "sweep")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def test_single_overload_is_never_marked_ambiguous(self):
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("bar"))],
            [calls_edge("A", "foo", "B", "bar")],
        )
        result = pp.compute_privilege_paths(art)
        self.assertFalse(result["paths"][0]["ambiguousOverload"])
        self.assertEqual(result["paths"][0]["matchedOverloads"], ["()"])

    def test_overload_disambiguated_by_param_signature_in_index(self):
        distinct = [fn("sweep"), fn("sweep")]
        distinct[0]["params"] = [{"type": "uint256"}]
        distinct[1]["params"] = [{"type": "uint256"}, {"type": "address"}]
        idx = pp._function_index([contract("B", *distinct)])
        self.assertEqual(len(idx), 2)  # both overloads kept, never collapsed to one.

    def test_unresolved_method_is_never_guessed(self):
        art = artifact(
            [contract("A", fn("foo")), contract("B", fn("bar"))],
            [calls_edge("A", "foo", "B", None)],
        )
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["paths"], [])

    def test_delegates_to_exposes_every_exposed_target_function(self):
        art = artifact(
            [contract("Proxy", fn("fallback")), contract("Impl", fn("drain"), fn("safe", modifiers=("onlyOwner",)))],
            [delegates_edge("Proxy", "Impl")],
        )
        result = pp.compute_privilege_paths(art)
        targets = {p["target"]["function"] for p in result["paths"]}
        self.assertEqual(targets, {"drain"})

    def test_system_graph_not_computed_yields_not_computed_status(self):
        art = artifact([contract("A", fn("foo"))], [], computed=False)
        result = pp.compute_privilege_paths(art)
        self.assertEqual(result["status"], "not_computed")
        self.assertEqual(result["paths"], [])

    def test_malformed_artifact_raises(self):
        with self.assertRaises(pp.PrivilegePathError):
            pp.compute_privilege_paths("not-a-dict")
        with self.assertRaises(pp.PrivilegePathError):
            pp.compute_privilege_paths({"contracts": "not-a-list"})

    def test_never_mutates_input(self):
        art = artifact([contract("A", fn("foo")), contract("B", fn("bar"))], [calls_edge("A", "foo", "B", "bar")])
        before = json.loads(json.dumps(art))
        pp.compute_privilege_paths(art)
        self.assertEqual(art, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = pp.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        art = artifact([contract("A", fn("foo")), contract("B", fn("bar"))], [calls_edge("A", "foo", "B", "bar")])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps(art), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, pp.EXIT_OK)
        self.assertEqual(len(json.loads(out)["paths"]), 1)

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(artifact([], [], computed=False)))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, pp.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "not_computed")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, pp.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_privilege_path_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["privilege-path"], "privilege_path")


if __name__ == "__main__":
    unittest.main()
