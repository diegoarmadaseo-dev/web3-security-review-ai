"""Tests for scripts/change_impact.py (V3 Block 3, B4, docs/decisiones.md
D-071): deterministic change-impact classification over a diff_reports.py
'preprocess'-mode structural diff.

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

import change_impact as ci  # noqa: E402


def surface(functions_added=None, functions_removed=None, functions_changed=None,
            vars_added=None, vars_removed=None, vars_changed=None):
    return {
        "functionsAdded": functions_added or [],
        "functionsRemoved": functions_removed or [],
        "functionsChanged": functions_changed or [],
        "unresolvedFunctionsV1": [], "unresolvedFunctionsV2": [],
        "stateVariablesAdded": vars_added or [],
        "stateVariablesRemoved": vars_removed or [],
        "stateVariablesChanged": vars_changed or [],
    }


def diff_obj(function_surface_delta, contracts_added=None, contracts_removed=None, system_graph_delta=None):
    return {
        "mode": "preprocess",
        "contractsAdded": contracts_added or [],
        "contractsRemoved": contracts_removed or [],
        "contractsMatched": list(function_surface_delta),
        "functionSurfaceDelta": function_surface_delta,
        "chainContext": {},
        "systemGraphDelta": system_graph_delta or {"status": "not_computed"},
        "diffVersion": "x", "v1Meta": {}, "v2Meta": {}, "sameInput": False,
        "note": "", "modifierScopeNote": "", "renameNote": "",
        # deliberately no "findings" key anywhere: this diff object never
        # carries findings at all, proving the classifier below cannot be
        # reading them even by accident.
    }


class ComputeChangeImpactTests(unittest.TestCase):
    def test_no_change_is_no_change(self):
        diff = diff_obj({"A": surface()})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "NO_CHANGE")
        self.assertEqual(result["overall"], "NO_CHANGE")

    def test_pure_addition_is_safe(self):
        diff = diff_obj({"A": surface(functions_added=["function:mint(uint256)"], vars_added=["newFlag"])})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "SAFE")
        self.assertEqual(result["overall"], "SAFE")

    def test_adversarial_modifier_removed_flags_review_with_no_findings_involved(self):
        # This diff object carries no "findings" key anywhere - the
        # classification below must come purely from the structural
        # functionsChanged data, proving a regression surfaces even when
        # no detector/AI finding exists to point at it.
        changed = [{"identity": "function:withdraw()", "changes": {"modifiersRemoved": ["onlyOwner"]}}]
        diff = diff_obj({"A": surface(functions_changed=changed)})
        self.assertNotIn("findings", diff)
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "REVIEW_RECOMMENDED")
        self.assertIn("modifier(s) removed", result["perContract"]["A"]["reasons"][0])

    def test_visibility_widened_flags_review(self):
        changed = [{"identity": "function:foo()", "changes": {"visibility": {"from": "internal", "to": "external"}}}]
        diff = diff_obj({"A": surface(functions_changed=changed)})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "REVIEW_RECOMMENDED")

    def test_visibility_narrowed_is_not_flagged_as_widened(self):
        changed = [{"identity": "function:foo()", "changes": {"visibility": {"from": "external", "to": "internal"}}}]
        diff = diff_obj({"A": surface(functions_changed=changed)})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["reasons"], [])
        self.assertEqual(result["perContract"]["A"]["classification"], "SAFE")

    def test_function_removed_flags_review(self):
        diff = diff_obj({"A": surface(functions_removed=["function:foo()"])})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "REVIEW_RECOMMENDED")

    def test_state_variable_removed_flags_review(self):
        diff = diff_obj({"A": surface(vars_removed=["owner"])})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "REVIEW_RECOMMENDED")

    def test_state_variable_type_changed_flags_review(self):
        changed = [{"name": "owner", "changes": {"type": {"from": "address", "to": "uint256"}}}]
        diff = diff_obj({"A": surface(vars_changed=changed)})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["perContract"]["A"]["classification"], "REVIEW_RECOMMENDED")

    def test_contract_removed_flags_overall_review_even_with_empty_surface_delta(self):
        diff = diff_obj({}, contracts_removed=["Old"])
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["overall"], "REVIEW_RECOMMENDED")
        self.assertIn("contract(s) removed", result["overallReasons"][0])

    def test_inherits_edge_removed_flags_overall_review(self):
        sgd = {"status": "computed", "nodesAdded": [], "nodesRemoved": [], "edgesAdded": [],
               "edgesRemoved": [{"kind": "inherits", "from": "A", "to": "Base"}], "proxiesChanged": []}
        diff = diff_obj({"A": surface()}, system_graph_delta=sgd)
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["overall"], "REVIEW_RECOMMENDED")

    def test_system_graph_delta_not_computed_never_crashes(self):
        diff = diff_obj({"A": surface(functions_added=["function:foo()"])}, system_graph_delta={"status": "not_computed"})
        result = ci.compute_change_impact(diff)
        self.assertEqual(result["overall"], "SAFE")

    def test_malformed_wrong_mode_raises(self):
        with self.assertRaises(ci.ChangeImpactError):
            ci.compute_change_impact({"mode": "reports"})

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(ci.ChangeImpactError):
            ci.compute_change_impact("not-a-dict")

    def test_never_mutates_input(self):
        diff = diff_obj({"A": surface(functions_added=["x"])})
        before = json.loads(json.dumps(diff))
        ci.compute_change_impact(diff)
        self.assertEqual(diff, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ci.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        diff = diff_obj({"A": surface(functions_removed=["function:foo()"])})
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps(diff), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, ci.EXIT_OK)
        self.assertEqual(json.loads(out)["overall"], "REVIEW_RECOMMENDED")

    def test_cli_reads_from_stdin_when_input_omitted(self):
        diff = diff_obj({"A": surface()})
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(diff))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, ci.EXIT_OK)
        self.assertEqual(json.loads(out)["overall"], "NO_CHANGE")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, ci.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_change_impact_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["change-impact"], "change_impact")


if __name__ == "__main__":
    unittest.main()
