"""Tests for scripts/advisory_gate.py (V3 Block 8, G2, docs/decisiones.md
D-076): deterministic pass/fail gate over a bundle of already-computed
advisory tool outputs.

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

import advisory_gate as ag  # noqa: E402


class ComputeAdvisoryGateSimpleToolsTests(unittest.TestCase):
    def test_positive_all_ok_yields_overall_pass(self):
        bundle = {
            "storageLayout": {"status": "unchanged"},
            "constructorZeroAddress": {"status": "clean"},
        }
        result = ag.compute_advisory_gate(bundle)
        self.assertEqual(result["overall"], "PASS")
        self.assertEqual(result["flagCount"], 0)
        self.assertEqual(result["notAssessedCount"], 0)
        self.assertEqual(result["okCount"], 2)

    def test_positive_safe_append_is_ok(self):
        result = ag.compute_advisory_gate({"storageLayout": {"status": "safe_append"}})
        self.assertEqual(result["tools"]["storageLayout"]["outcome"], "OK")

    def test_negative_one_flag_yields_overall_fail(self):
        bundle = {
            "storageLayout": {"status": "collision_risk"},
            "constructorZeroAddress": {"status": "clean"},
        }
        result = ag.compute_advisory_gate(bundle)
        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["flagCount"], 1)

    def test_adversarial_unrecognized_status_value_is_not_assessed_never_ok(self):
        result = ag.compute_advisory_gate({"storageLayout": {"status": "some_future_status_value"}})
        self.assertEqual(result["tools"]["storageLayout"]["outcome"], "NOT_ASSESSED")
        self.assertEqual(result["overall"], "INCOMPLETE")

    def test_adversarial_unknown_tool_key_is_not_assessed_never_crashes(self):
        result = ag.compute_advisory_gate({"someFutureTool": {"status": "clean"}})
        self.assertEqual(result["tools"]["someFutureTool"]["outcome"], "NOT_ASSESSED")

    def test_adversarial_non_dict_section_is_not_assessed_never_crashes(self):
        result = ag.compute_advisory_gate({"storageLayout": "not-a-dict"})
        self.assertEqual(result["tools"]["storageLayout"]["outcome"], "NOT_ASSESSED")

    def test_adversarial_non_string_status_on_simple_tool_never_raises_type_error(self):
        # docs/decisiones.md D-076 G2 hardening: a non-string `status` used
        # to be passed straight into a dict-key lookup and crashed with an
        # uncaught TypeError for any unhashable value (list/dict). Every
        # non-string type - including hashable ones like None/bool/number,
        # which never crashed but must still never become OK/FLAG - must
        # now cleanly resolve to NOT_ASSESSED.
        for label, bad_status in [
            ("list", ["a", "list"]),
            ("dict", {"nested": "dict"}),
            ("null", None),
            ("number", 42),
            ("bool", True),
        ]:
            with self.subTest(label=label):
                result = ag.compute_advisory_gate({"storageLayout": {"status": bad_status}})
                self.assertEqual(result["tools"]["storageLayout"]["outcome"], "NOT_ASSESSED")
                self.assertEqual(result["overall"], "INCOMPLETE")

    def test_empty_bundle_is_incomplete_never_pass(self):
        result = ag.compute_advisory_gate({})
        self.assertEqual(result["overall"], "INCOMPLETE")
        self.assertEqual(result["okCount"], 0)

    def test_proxy_fingerprint_never_flags_either_value(self):
        self.assertEqual(ag.compute_advisory_gate({"proxyFingerprint": {"status": "matched"}})["tools"]["proxyFingerprint"]["outcome"], "OK")
        self.assertEqual(ag.compute_advisory_gate({"proxyFingerprint": {"status": "no_match"}})["tools"]["proxyFingerprint"]["outcome"], "OK")

    def test_compiler_bugs_three_way(self):
        self.assertEqual(ag.compute_advisory_gate({"compilerBugs": {"status": "not_affected"}})["tools"]["compilerBugs"]["outcome"], "OK")
        self.assertEqual(ag.compute_advisory_gate({"compilerBugs": {"status": "affected"}})["tools"]["compilerBugs"]["outcome"], "FLAG")
        self.assertEqual(ag.compute_advisory_gate({"compilerBugs": {"status": "unparseable_version"}})["tools"]["compilerBugs"]["outcome"], "NOT_ASSESSED")

    def test_delegatecall_cycle_not_computed_is_not_assessed(self):
        result = ag.compute_advisory_gate({"delegatecallCycle": {"status": "not_computed"}})
        self.assertEqual(result["tools"]["delegatecallCycle"]["outcome"], "NOT_ASSESSED")

    def test_constructor_zero_address_no_constructor_is_ok(self):
        result = ag.compute_advisory_gate({"constructorZeroAddress": {"status": "no_constructor"}})
        self.assertEqual(result["tools"]["constructorZeroAddress"]["outcome"], "OK")


class ComputeAdvisoryGateSpecialToolsTests(unittest.TestCase):
    def test_privilege_path_empty_paths_is_ok(self):
        result = ag.compute_advisory_gate({"privilegePath": {"status": "computed", "paths": []}})
        self.assertEqual(result["tools"]["privilegePath"]["outcome"], "OK")

    def test_privilege_path_non_empty_paths_is_flag(self):
        result = ag.compute_advisory_gate({"privilegePath": {"status": "computed", "paths": [{"entry": "x"}]}})
        self.assertEqual(result["tools"]["privilegePath"]["outcome"], "FLAG")

    def test_privilege_path_not_computed_is_not_assessed(self):
        result = ag.compute_advisory_gate({"privilegePath": {"status": "not_computed"}})
        self.assertEqual(result["tools"]["privilegePath"]["outcome"], "NOT_ASSESSED")

    def test_bytecode_advisory_empty_advisories_is_ok(self):
        result = ag.compute_advisory_gate({"bytecodeAdvisory": {"status": "computed", "advisories": []}})
        self.assertEqual(result["tools"]["bytecodeAdvisory"]["outcome"], "OK")

    def test_bytecode_advisory_non_empty_advisories_is_flag(self):
        result = ag.compute_advisory_gate({"bytecodeAdvisory": {"status": "computed", "advisories": [{"opcode": "SELFDESTRUCT"}]}})
        self.assertEqual(result["tools"]["bytecodeAdvisory"]["outcome"], "FLAG")

    def test_change_impact_no_change_and_safe_are_ok_review_recommended_is_flag(self):
        self.assertEqual(ag.compute_advisory_gate({"changeImpact": {"overall": "NO_CHANGE"}})["tools"]["changeImpact"]["outcome"], "OK")
        self.assertEqual(ag.compute_advisory_gate({"changeImpact": {"overall": "SAFE"}})["tools"]["changeImpact"]["outcome"], "OK")
        self.assertEqual(ag.compute_advisory_gate({"changeImpact": {"overall": "REVIEW_RECOMMENDED"}})["tools"]["changeImpact"]["outcome"], "FLAG")

    def test_change_impact_unrecognized_overall_is_not_assessed(self):
        result = ag.compute_advisory_gate({"changeImpact": {"overall": "SOMETHING_NEW"}})
        self.assertEqual(result["tools"]["changeImpact"]["outcome"], "NOT_ASSESSED")

    def test_adversarial_non_string_overall_on_change_impact_never_raises_type_error(self):
        for label, bad_overall in [
            ("list", ["REVIEW_RECOMMENDED"]),
            ("dict", {"nested": "dict"}),
            ("null", None),
            ("number", 1),
            ("bool", False),
        ]:
            with self.subTest(label=label):
                result = ag.compute_advisory_gate({"changeImpact": {"overall": bad_overall}})
                self.assertEqual(result["tools"]["changeImpact"]["outcome"], "NOT_ASSESSED")

    def test_adversarial_non_string_nested_compiler_bug_report_status_never_raises_type_error(self):
        # bytecodeCompilerBugs (D3) reuses _simple() on the NESTED
        # compilerBugReport - the same hardening must hold through that
        # reuse, not just at the top level.
        for label, bad_status in [("list", [1, 2, 3]), ("dict", {}), ("null", None)]:
            with self.subTest(label=label):
                section = {"status": "version_extracted", "compilerBugReport": {"status": bad_status}}
                result = ag.compute_advisory_gate({"bytecodeCompilerBugs": section})
                self.assertEqual(result["tools"]["bytecodeCompilerBugs"]["outcome"], "NOT_ASSESSED")

    def test_upgrade_gap_empty_flagged_is_ok_non_empty_is_flag(self):
        self.assertEqual(ag.compute_advisory_gate({"upgradeGap": {"contractsFlagged": []}})["tools"]["upgradeGap"]["outcome"], "OK")
        self.assertEqual(ag.compute_advisory_gate({"upgradeGap": {"contractsFlagged": ["A"]}})["tools"]["upgradeGap"]["outcome"], "FLAG")

    def test_upgrade_gap_missing_contracts_flagged_is_not_assessed(self):
        result = ag.compute_advisory_gate({"upgradeGap": {}})
        self.assertEqual(result["tools"]["upgradeGap"]["outcome"], "NOT_ASSESSED")

    def test_bytecode_compiler_bugs_version_not_found_is_not_assessed(self):
        result = ag.compute_advisory_gate({"bytecodeCompilerBugs": {"status": "version_not_found"}})
        self.assertEqual(result["tools"]["bytecodeCompilerBugs"]["outcome"], "NOT_ASSESSED")

    def test_bytecode_compiler_bugs_extracted_and_not_affected_is_ok(self):
        section = {"status": "version_extracted", "compilerBugReport": {"status": "not_affected"}}
        result = ag.compute_advisory_gate({"bytecodeCompilerBugs": section})
        self.assertEqual(result["tools"]["bytecodeCompilerBugs"]["outcome"], "OK")

    def test_bytecode_compiler_bugs_extracted_and_affected_is_flag(self):
        section = {"status": "version_extracted", "compilerBugReport": {"status": "affected"}}
        result = ag.compute_advisory_gate({"bytecodeCompilerBugs": section})
        self.assertEqual(result["tools"]["bytecodeCompilerBugs"]["outcome"], "FLAG")

    def test_bytecode_compiler_bugs_extracted_but_malformed_nested_report_is_not_assessed(self):
        section = {"status": "version_extracted", "compilerBugReport": "not-a-dict"}
        result = ag.compute_advisory_gate({"bytecodeCompilerBugs": section})
        self.assertEqual(result["tools"]["bytecodeCompilerBugs"]["outcome"], "NOT_ASSESSED")


class ComputeAdvisoryGateGeneralTests(unittest.TestCase):
    def test_malformed_bundle_not_a_dict_raises(self):
        with self.assertRaises(ag.AdvisoryGateError):
            ag.compute_advisory_gate("not-a-dict")

    def test_never_returns_a_severity_field(self):
        result = ag.compute_advisory_gate({"storageLayout": {"status": "unchanged"}})
        self.assertNotIn("severity", result)

    def test_never_mutates_bundle(self):
        bundle = {"storageLayout": {"status": "unchanged"}}
        before = json.loads(json.dumps(bundle))
        ag.compute_advisory_gate(bundle)
        self.assertEqual(bundle, before)

    def test_never_modifies_a_tools_own_output_values_in_result(self):
        original_section = {"status": "collision_risk", "detail": "kept as-is"}
        bundle = {"storageLayout": original_section}
        ag.compute_advisory_gate(bundle)
        self.assertEqual(bundle["storageLayout"], original_section)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ag.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"storageLayout": {"status": "unchanged"}}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, ag.EXIT_OK)
        self.assertEqual(json.loads(out)["overall"], "PASS")

    def test_cli_default_exit_code_is_ok_even_on_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"storageLayout": {"status": "collision_risk"}}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, ag.EXIT_OK)
        self.assertEqual(json.loads(out)["overall"], "FAIL")

    def test_cli_strict_exit_returns_gate_failed_on_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"storageLayout": {"status": "collision_risk"}}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p), "--strict-exit"])
        self.assertEqual(exit_code, ag.EXIT_GATE_FAILED)

    def test_cli_strict_exit_returns_ok_on_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"storageLayout": {"status": "unchanged"}}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p), "--strict-exit"])
        self.assertEqual(exit_code, ag.EXIT_OK)

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, ag.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_advisory_gate_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["advisory-gate"], "advisory_gate")


if __name__ == "__main__":
    unittest.main()
