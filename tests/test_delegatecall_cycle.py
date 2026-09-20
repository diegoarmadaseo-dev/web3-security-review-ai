"""Tests for scripts/delegatecall_cycle.py (V3 Block 6, E1, docs/decisiones.md
D-074): deterministic delegatecall-cycle detection.

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

import delegatecall_cycle as dc  # noqa: E402


def delegates_edge(from_key, to_key):
    return {"kind": "delegatesTo", "from": from_key, "to": to_key}


def system_graph(edges, computed=True):
    return {"status": "computed" if computed else "not_computed", "nodes": [], "edges": edges, "proxies": []}


def artifact(contracts, edges, computed=True):
    return {"contracts": contracts, "systemGraph": system_graph(edges, computed)}


class FindDelegatecallCyclesTests(unittest.TestCase):
    def test_positive_two_node_cycle_is_found(self):
        cycles = dc.find_delegatecall_cycles(system_graph([delegates_edge("A", "B"), delegates_edge("B", "A")]))
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0]), {"A", "B"})

    def test_negative_no_cycle_in_a_simple_chain(self):
        cycles = dc.find_delegatecall_cycles(system_graph([delegates_edge("A", "B"), delegates_edge("B", "C")]))
        self.assertEqual(cycles, [])

    def test_adversarial_three_node_cycle_is_found(self):
        cycles = dc.find_delegatecall_cycles(system_graph([delegates_edge("A", "B"), delegates_edge("B", "C"), delegates_edge("C", "A")]))
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0]), {"A", "B", "C"})

    def test_adversarial_self_loop_is_found(self):
        cycles = dc.find_delegatecall_cycles(system_graph([delegates_edge("A", "A")]))
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0], ["A", "A"])

    def test_adversarial_cycle_is_never_duplicated_regardless_of_starting_node(self):
        # A<->B<->C is NOT what this builds - this is one single 3-cycle,
        # reachable by starting a DFS from any of its 3 members; the
        # canonical-rotation dedup must still report it exactly once.
        edges = [delegates_edge("A", "B"), delegates_edge("B", "C"), delegates_edge("C", "A")]
        cycles = dc.find_delegatecall_cycles(system_graph(edges))
        self.assertEqual(len(cycles), 1)

    def test_branch_with_no_delegatesto_edges_yields_no_cycle(self):
        cycles = dc.find_delegatecall_cycles(system_graph([]))
        self.assertEqual(cycles, [])

    def test_never_mutates_system_graph(self):
        sg = system_graph([delegates_edge("A", "B"), delegates_edge("B", "A")])
        before = json.loads(json.dumps(sg))
        dc.find_delegatecall_cycles(sg)
        self.assertEqual(sg, before)

    def test_adversarial_non_dict_system_graph_raises_clean_error(self):
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.find_delegatecall_cycles("not-a-dict")

    def test_adversarial_non_list_edges_raises_clean_error(self):
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.find_delegatecall_cycles({"edges": "not-a-list"})

    def test_adversarial_non_dict_edge_raises_clean_error(self):
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.find_delegatecall_cycles({"edges": ["not-a-dict", delegates_edge("A", "B")]})

    def test_adversarial_none_edge_raises_clean_error(self):
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.find_delegatecall_cycles({"edges": [None, delegates_edge("A", "B")]})


class ComputeDelegatecallCycleReportTests(unittest.TestCase):
    def test_positive_report_status_and_confidence(self):
        art = artifact([], [delegates_edge("A", "B"), delegates_edge("B", "A")])
        result = dc.compute_delegatecall_cycle_report(art)
        self.assertEqual(result["status"], "cycle_found")
        self.assertEqual(result["cycles"][0]["confidence"], "low")

    def test_negative_no_cycle_status(self):
        art = artifact([], [delegates_edge("A", "B")])
        result = dc.compute_delegatecall_cycle_report(art)
        self.assertEqual(result["status"], "no_cycle")

    def test_system_graph_not_computed_yields_not_computed_status(self):
        art = artifact([], [], computed=False)
        result = dc.compute_delegatecall_cycle_report(art)
        self.assertEqual(result["status"], "not_computed")
        self.assertEqual(result["cycles"], [])

    def test_never_returns_a_severity_field(self):
        art = artifact([], [delegates_edge("A", "B"), delegates_edge("B", "A")])
        result = dc.compute_delegatecall_cycle_report(art)
        self.assertNotIn("severity", result)

    def test_malformed_artifact_raises(self):
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.compute_delegatecall_cycle_report("not-a-dict")
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.compute_delegatecall_cycle_report({"contracts": "not-a-list"})

    def test_adversarial_non_dict_system_graph_via_artifact_raises_clean_error(self):
        # The exact crash originally found by adversarial audit: a non-dict
        # systemGraph reached a bare `.get("status")` call before this fix.
        with self.assertRaises(dc.DelegatecallCycleError):
            dc.compute_delegatecall_cycle_report({"contracts": [], "systemGraph": "garbage"})


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = dc.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        art = artifact([], [delegates_edge("A", "B"), delegates_edge("B", "A")])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps(art), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, dc.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "cycle_found")

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(artifact([], [], computed=False)))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, dc.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "not_computed")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, dc.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_delegatecall_cycle_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["delegatecall-cycle"], "delegatecall_cycle")


if __name__ == "__main__":
    unittest.main()
