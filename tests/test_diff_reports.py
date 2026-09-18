"""Tests for scripts/diff_reports.py (V2.5 - Version Comparison + Security
Diff, docs/decisiones.md D-054).

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

import diff_reports  # noqa: E402

REFERENCES_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "references"


def make_finding(**overrides):
    base = {
        "id": "F-00000000",
        "stableKey": "sha256:" + "0" * 64,
        "category": "SC01",
        "signature": "unprotected-admin-function",
        "severity": "HIGH",
        "confidence": "high",
        "status": "suspected",
        "locations": [{"file": "A.sol", "lineStart": 10, "lineEnd": 12, "contract": "A", "function": "setFee"}],
        "evidence": [],
        "description": "desc",
        "recommendation": "rec",
        "patch": None,
    }
    base.update(overrides)
    return base


def make_report(findings=None, coverage=None, **overrides):
    base = {"findings": findings or [], "categoryCoverage": coverage or [], "inputHash": "sha256:" + "a" * 64, "mode": "standard"}
    base.update(overrides)
    return base


def make_function(name, **overrides):
    base = {
        "name": name, "kind": "function", "lineStart": 1, "lineEnd": 2, "visibility": "external",
        "mutability": "nonpayable", "modifiers": [], "params": [], "returns": "", "virtual": False,
        "override": False, "hasBody": True, "signatureText": "",
    }
    base.update(overrides)
    return base


def make_param(type_, name="p"):
    return {"type": type_, "name": name, "location": None, "isAddress": type_.startswith("address")}


def make_state_var(name, **overrides):
    base = {"name": name, "type": "uint256", "visibility": "public", "constant": False, "immutable": False}
    base.update(overrides)
    return base


def make_contract(key, functions=None, state_vars=None):
    return {"key": key, "file": key.split("#")[0], "name": key.split("#")[-1], "functions": functions or [], "stateVariables": state_vars or []}


NOT_COMPUTED_GRAPH = {"status": "not_computed", "message": "x", "nodes": [], "edges": [], "proxies": []}


def make_preprocess(contracts=None, system_graph=None, **overrides):
    base = {"contracts": contracts or [], "systemGraph": system_graph or dict(NOT_COMPUTED_GRAPH), "inputHash": "sha256:" + "a" * 64, "mode": "standard"}
    base.update(overrides)
    return base


class FindingMatchingTests(unittest.TestCase):
    def test_unchanged_exact_match_produces_no_diff(self):
        f1 = make_finding()
        f2 = make_finding()
        result = diff_reports.diff_reports(make_report([f1]), make_report([f2]))
        self.assertEqual(result["newFindings"], [])
        self.assertEqual(result["resolvedFindings"], [])
        self.assertEqual(result["modifiedFindings"], [])

    def test_severity_change_on_matched_stable_key_is_modified(self):
        f1 = make_finding(severity="HIGH")
        f2 = make_finding(severity="CRITICAL")
        result = diff_reports.diff_reports(make_report([f1]), make_report([f2]))
        self.assertEqual(len(result["modifiedFindings"]), 1)
        entry = result["modifiedFindings"][0]
        self.assertEqual(entry["matchedBy"], "stableKey")
        self.assertEqual(entry["changedFields"], ["severity"])
        self.assertEqual(entry["stableKeyV1"], entry["stableKeyV2"])

    def test_location_line_shift_matches_by_stable_key_and_is_modified(self):
        f1 = make_finding(locations=[{"file": "A.sol", "contract": "A", "function": "setFee", "lineStart": 10, "lineEnd": 10}])
        f2 = make_finding(locations=[{"file": "A.sol", "contract": "A", "function": "setFee", "lineStart": 25, "lineEnd": 25}])
        result = diff_reports.diff_reports(make_report([f1]), make_report([f2]))
        self.assertEqual(len(result["modifiedFindings"]), 1)
        self.assertEqual(result["modifiedFindings"][0]["changedFields"], ["locations"])

    def test_signature_drift_matches_by_secondary_key_not_new_plus_resolved(self):
        f1 = make_finding(signature="old-slug")
        f2 = make_finding(signature="new-slug")
        result = diff_reports.diff_reports(make_report([f1]), make_report([f2]))
        self.assertEqual(result["newFindings"], [])
        self.assertEqual(result["resolvedFindings"], [])
        self.assertEqual(len(result["modifiedFindings"]), 1)
        entry = result["modifiedFindings"][0]
        self.assertEqual(entry["matchedBy"], "secondary")
        self.assertIn("signature", entry["changedFields"])

    def test_ambiguous_secondary_key_is_never_paired(self):
        f1a = make_finding(signature="sig-a")
        f1b = make_finding(signature="sig-b")
        f2a = make_finding(signature="sig-c")
        result = diff_reports.diff_reports(make_report([f1a, f1b]), make_report([f2a]))
        self.assertEqual(result["modifiedFindings"], [])
        self.assertEqual(len(result["resolvedFindings"]), 2)
        self.assertEqual(len(result["newFindings"]), 1)

    def test_unrelated_findings_are_new_and_resolved(self):
        f1 = make_finding(function="onlyInV1")
        f2 = make_finding(category="SC02", function="onlyInV2")
        result = diff_reports.diff_reports(make_report([f1]), make_report([f2]))
        self.assertEqual(len(result["newFindings"]), 1)
        self.assertEqual(len(result["resolvedFindings"]), 1)
        self.assertEqual(result["modifiedFindings"], [])

    def test_duplicate_stable_key_within_one_side_raises(self):
        f1 = make_finding()
        f1b = make_finding()
        with self.assertRaises(diff_reports.DiffError):
            diff_reports.diff_reports(make_report([f1, f1b]), make_report([]))


class CategoryCoverageDeltaTests(unittest.TestCase):
    def test_only_changed_categories_are_reported(self):
        v1_cov = [{"category": "SC01", "status": "NOT_DETECTED"}, {"category": "SC03", "status": "DETECTED"}]
        v2_cov = [{"category": "SC01", "status": "DETECTED"}, {"category": "SC03", "status": "DETECTED"}]
        result = diff_reports.diff_reports(make_report(coverage=v1_cov), make_report(coverage=v2_cov))
        self.assertEqual(result["categoryCoverageDelta"], [{"category": "SC01", "from": "NOT_DETECTED", "to": "DETECTED"}])

    def test_no_changes_yields_empty_delta(self):
        cov = [{"category": "SC01", "status": "DETECTED"}]
        result = diff_reports.diff_reports(make_report(coverage=cov), make_report(coverage=list(cov)))
        self.assertEqual(result["categoryCoverageDelta"], [])


class ReportsModeMetadataTests(unittest.TestCase):
    def test_same_input_true_when_hashes_match(self):
        result = diff_reports.diff_reports(make_report(inputHash="sha256:aa"), make_report(inputHash="sha256:aa"))
        self.assertTrue(result["sameInput"])

    def test_same_input_false_when_hashes_differ(self):
        result = diff_reports.diff_reports(make_report(inputHash="sha256:aa"), make_report(inputHash="sha256:bb"))
        self.assertFalse(result["sameInput"])

    def test_missing_findings_key_raises(self):
        with self.assertRaises(diff_reports.DiffError):
            diff_reports.diff_reports({"categoryCoverage": []}, make_report())

    def test_non_dict_input_raises(self):
        with self.assertRaises(diff_reports.DiffError):
            diff_reports.diff_reports(["not", "a", "dict"], make_report())


class ContractMatchingTests(unittest.TestCase):
    def test_contract_added_and_removed_by_key(self):
        result = diff_reports.diff_preprocess(make_preprocess([make_contract("A.sol#A")]), make_preprocess([make_contract("B.sol#B")]))
        self.assertEqual(result["contractsAdded"], ["B.sol#B"])
        self.assertEqual(result["contractsRemoved"], ["A.sol#A"])
        self.assertEqual(result["contractsMatched"], [])

    def test_rename_is_reported_as_remove_plus_add_never_renamed(self):
        # Same logical contract, moved to a new file - D-054 decision 2:
        # never inferred as a rename, always remove+add.
        result = diff_reports.diff_preprocess(make_preprocess([make_contract("Old.sol#Vault")]), make_preprocess([make_contract("New.sol#Vault")]))
        self.assertEqual(result["contractsAdded"], ["New.sol#Vault"])
        self.assertEqual(result["contractsRemoved"], ["Old.sol#Vault"])
        self.assertNotIn("renamed", json.dumps(result).lower().replace("renamenote", ""))


class FunctionSurfaceTests(unittest.TestCase):
    def _delta(self, v1_functions, v2_functions):
        result = diff_reports.diff_preprocess(
            make_preprocess([make_contract("A.sol#A", functions=v1_functions)]),
            make_preprocess([make_contract("A.sol#A", functions=v2_functions)]),
        )
        return result["functionSurfaceDelta"]["A.sol#A"]

    def test_function_added(self):
        delta = self._delta([], [make_function("newFn", params=[make_param("bool")])])
        self.assertEqual(len(delta["functionsAdded"]), 1)
        self.assertIn("newFn", delta["functionsAdded"][0])

    def test_function_removed(self):
        delta = self._delta([make_function("oldFn", params=[make_param("uint256")])], [])
        self.assertEqual(len(delta["functionsRemoved"]), 1)
        self.assertIn("oldFn", delta["functionsRemoved"][0])

    def test_visibility_change_detected(self):
        delta = self._delta(
            [make_function("f", visibility="external", params=[make_param("address")])],
            [make_function("f", visibility="public", params=[make_param("address")])],
        )
        self.assertEqual(len(delta["functionsChanged"]), 1)
        self.assertEqual(delta["functionsChanged"][0]["changes"]["visibility"], {"from": "external", "to": "public"})

    def test_mutability_change_detected(self):
        delta = self._delta(
            [make_function("f", mutability="view", params=[make_param("uint256")])],
            [make_function("f", mutability="pure", params=[make_param("uint256")])],
        )
        self.assertEqual(delta["functionsChanged"][0]["changes"]["mutability"], {"from": "view", "to": "pure"})

    def test_modifiers_added_and_removed_detected(self):
        delta = self._delta(
            [make_function("f", modifiers=[{"name": "onlyOwner", "args": None}], params=[make_param("uint256")])],
            [make_function("f", modifiers=[{"name": "whenNotPaused", "args": None}], params=[make_param("uint256")])],
        )
        changes = delta["functionsChanged"][0]["changes"]
        self.assertEqual(changes["modifiersAdded"], ["whenNotPaused"])
        self.assertEqual(changes["modifiersRemoved"], ["onlyOwner"])

    def test_virtual_and_override_change_detected(self):
        delta = self._delta(
            [make_function("f", virtual=False, override=False, params=[])],
            [make_function("f", virtual=True, override=True, params=[])],
        )
        changes = delta["functionsChanged"][0]["changes"]
        self.assertEqual(changes["virtual"], {"from": False, "to": True})
        self.assertEqual(changes["override"], {"from": False, "to": True})

    def test_internal_function_matched_by_canonical_signature(self):
        # D-054 decision 4: internal/private functions have no ABI selector
        # but still get a stable structural identity (name + canonical
        # param types), generalized from the public/external-only
        # selector-clash signature.
        delta = self._delta(
            [make_function("_helper", visibility="internal", mutability="view", params=[make_param("uint256")])],
            [make_function("_helper", visibility="internal", mutability="pure", params=[make_param("uint256")])],
        )
        self.assertEqual(len(delta["functionsChanged"]), 1)
        self.assertEqual(delta["functionsChanged"][0]["changes"]["mutability"], {"from": "view", "to": "pure"})

    def test_private_function_matched_by_canonical_signature(self):
        delta = self._delta(
            [make_function("_calc", visibility="private", params=[make_param("uint256"), make_param("address")])],
            [make_function("_calc", visibility="private", params=[make_param("uint256"), make_param("address")], mutability="view")],
        )
        self.assertEqual(len(delta["functionsChanged"]), 1)

    def test_struct_param_function_is_unresolved_on_both_sides_not_matched(self):
        fn1 = make_function("withStruct", params=[make_param("MyStruct memory", name="s")])
        fn2 = make_function("withStruct", params=[make_param("MyStruct memory", name="s")])
        delta = self._delta([fn1], [fn2])
        self.assertEqual(len(delta["unresolvedFunctionsV1"]), 1)
        self.assertEqual(len(delta["unresolvedFunctionsV2"]), 1)
        self.assertEqual(delta["functionsAdded"], [])
        self.assertEqual(delta["functionsRemoved"], [])
        self.assertEqual(delta["functionsChanged"], [])

    def test_ambiguous_duplicate_identity_on_one_side_is_unresolved(self):
        dup_a = make_function("dup", params=[make_param("uint256")], lineStart=5)
        dup_b = make_function("dup", params=[make_param("uint256")], lineStart=50)
        delta = self._delta([dup_a, dup_b], [])
        self.assertEqual(len(delta["unresolvedFunctionsV1"]), 2)
        self.assertEqual(delta["functionsRemoved"], [])

    def test_unrelated_function_kept_unchanged_produces_no_change_entry(self):
        fn = make_function("stable", params=[make_param("uint256")])
        delta = self._delta([fn], [dict(fn)])
        self.assertEqual(delta["functionsChanged"], [])
        self.assertEqual(delta["functionsAdded"], [])
        self.assertEqual(delta["functionsRemoved"], [])


class StateVariableSurfaceTests(unittest.TestCase):
    def test_state_variable_added_removed_changed(self):
        v1_vars = [make_state_var("removedVar"), make_state_var("changedVar", visibility="public")]
        v2_vars = [make_state_var("addedVar", type="bool"), make_state_var("changedVar", visibility="private")]
        result = diff_reports.diff_preprocess(
            make_preprocess([make_contract("A.sol#A", state_vars=v1_vars)]),
            make_preprocess([make_contract("A.sol#A", state_vars=v2_vars)]),
        )
        delta = result["functionSurfaceDelta"]["A.sol#A"]
        self.assertEqual(delta["stateVariablesAdded"], ["addedVar"])
        self.assertEqual(delta["stateVariablesRemoved"], ["removedVar"])
        self.assertEqual(delta["stateVariablesChanged"], [{"name": "changedVar", "changes": {"visibility": {"from": "public", "to": "private"}}}])


class SystemGraphDeltaTests(unittest.TestCase):
    def test_not_computed_when_either_side_lacks_pro_graph(self):
        computed = {"status": "computed", "nodes": [], "edges": [], "proxies": []}
        result = diff_reports.diff_preprocess(make_preprocess(system_graph=dict(NOT_COMPUTED_GRAPH)), make_preprocess(system_graph=computed))
        self.assertEqual(result["systemGraphDelta"]["status"], "not_computed")

    def test_nodes_and_edges_added_removed(self):
        sg1 = {"status": "computed", "nodes": [{"key": "A.sol#A", "file": "A.sol", "name": "A", "kind": "contract"}],
               "edges": [{"kind": "inherits", "from": "A.sol#A", "to": "B.sol#B"}], "proxies": []}
        sg2 = {"status": "computed",
               "nodes": [{"key": "A.sol#A", "file": "A.sol", "name": "A", "kind": "contract"}, {"key": "C.sol#C", "file": "C.sol", "name": "C", "kind": "contract"}],
               "edges": [{"kind": "inherits", "from": "A.sol#A", "to": "B.sol#B"}, {"kind": "calls", "from": "A.sol#A", "to": "C.sol#C", "function": "f", "method": "g"}],
               "proxies": []}
        result = diff_reports.diff_preprocess(make_preprocess(system_graph=sg1), make_preprocess(system_graph=sg2))
        delta = result["systemGraphDelta"]
        self.assertEqual(delta["status"], "computed")
        self.assertEqual(delta["nodesAdded"], ["C.sol#C"])
        self.assertEqual(delta["nodesRemoved"], [])
        self.assertEqual(len(delta["edgesAdded"]), 1)
        self.assertEqual(delta["edgesAdded"][0]["kind"], "calls")
        self.assertEqual(delta["edgesRemoved"], [])

    def test_proxy_implementation_change_detected(self):
        sg1 = {"status": "computed", "nodes": [], "edges": [], "proxies": [{"proxy": "P.sol#P", "implementation": "Old.sol#Old", "status": "resolved", "reason": "x"}]}
        sg2 = {"status": "computed", "nodes": [], "edges": [], "proxies": [{"proxy": "P.sol#P", "implementation": "New.sol#New", "status": "resolved", "reason": "y"}]}
        result = diff_reports.diff_preprocess(make_preprocess(system_graph=sg1), make_preprocess(system_graph=sg2))
        changed = result["systemGraphDelta"]["proxiesChanged"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["from"]["implementation"], "Old.sol#Old")
        self.assertEqual(changed[0]["to"]["implementation"], "New.sol#New")

    def test_proxy_unchanged_produces_no_entry(self):
        proxy = {"proxy": "P.sol#P", "implementation": "Impl.sol#Impl", "status": "resolved", "reason": "x"}
        sg = {"status": "computed", "nodes": [], "edges": [], "proxies": [proxy]}
        result = diff_reports.diff_preprocess(make_preprocess(system_graph=dict(sg)), make_preprocess(system_graph=dict(sg)))
        self.assertEqual(result["systemGraphDelta"]["proxiesChanged"], [])


class PreprocessModeMetadataTests(unittest.TestCase):
    def test_missing_contracts_key_raises(self):
        with self.assertRaises(diff_reports.DiffError):
            diff_reports.diff_preprocess({"systemGraph": dict(NOT_COMPUTED_GRAPH)}, make_preprocess())


class CLITests(unittest.TestCase):
    def _write(self, directory, name, data):
        path = Path(directory) / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_reports_mode_end_to_end_via_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1_path = self._write(tmp, "v1.json", make_report([make_finding()]))
            v2_path = self._write(tmp, "v2.json", make_report([]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = diff_reports.main(["reports", v1_path, v2_path])
            self.assertEqual(exit_code, diff_reports.EXIT_OK)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["mode"], "reports")
            self.assertEqual(len(payload["resolvedFindings"]), 1)

    def test_preprocess_mode_end_to_end_via_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1_path = self._write(tmp, "v1.json", make_preprocess([make_contract("A.sol#A")]))
            v2_path = self._write(tmp, "v2.json", make_preprocess([make_contract("A.sol#A"), make_contract("B.sol#B")]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = diff_reports.main(["preprocess", v1_path, v2_path])
            self.assertEqual(exit_code, diff_reports.EXIT_OK)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["mode"], "preprocess")
            self.assertEqual(payload["contractsAdded"], ["B.sol#B"])

    def test_malformed_json_file_returns_error_envelope_and_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            v1_path = Path(tmp) / "bad.json"
            v1_path.write_text("{not valid json", encoding="utf-8")
            v2_path = self._write(tmp, "v2.json", make_report([]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = diff_reports.main(["reports", str(v1_path), v2_path])
            self.assertEqual(exit_code, diff_reports.EXIT_FAILED)
            self.assertFalse(json.loads(buf.getvalue())["ok"])

    def test_missing_file_returns_error_envelope_and_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            v2_path = self._write(tmp, "v2.json", make_report([]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = diff_reports.main(["reports", str(Path(tmp) / "missing.json"), v2_path])
            self.assertEqual(exit_code, diff_reports.EXIT_FAILED)
            self.assertFalse(json.loads(buf.getvalue())["ok"])


class SchemaDriftTests(unittest.TestCase):
    """references/version-diff-*-schema.json and diff_reports.py must not
    silently diverge - same discipline as test_validate_report.py's own
    report-schema.json drift check."""

    def test_reports_mode_output_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "version-diff-reports-schema.json").read_text(encoding="utf-8"))
        result = diff_reports.diff_reports(make_report([make_finding()]), make_report([]))
        self.assertEqual(set(schema["required"]), set(result.keys()))

    def test_preprocess_mode_output_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "version-diff-preprocess-schema.json").read_text(encoding="utf-8"))
        result = diff_reports.diff_preprocess(make_preprocess([make_contract("A.sol#A")]), make_preprocess([make_contract("A.sol#A")]))
        self.assertEqual(set(schema["required"]), set(result.keys()))


class ChainContextTests(unittest.TestCase):
    """V2.8 Block 2 (C-06): onchain-sourced contract keys in a preprocess
    diff must carry an explicit {chainId, address} identity, so a reviewer
    never has to parse it back out of the raw key string themselves."""

    ADDR = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def test_onchain_key_gets_chain_context(self):
        key = "onchain:/1/%s/Vault.sol#Vault" % self.ADDR
        v1 = make_preprocess([])
        v2 = make_preprocess([make_contract(key)])
        result = diff_reports.diff_preprocess(v1, v2)
        self.assertEqual(result["chainContext"], {key: {"chainId": 1, "address": self.ADDR}})
        self.assertIn(key, result["contractsAdded"])

    def test_local_key_never_appears_in_chain_context(self):
        # Negative control: a purely local contract must never be assigned
        # a fabricated chain identity.
        v1 = make_preprocess([])
        v2 = make_preprocess([make_contract("Vault.sol#Vault")])
        result = diff_reports.diff_preprocess(v1, v2)
        self.assertEqual(result["chainContext"], {})

    def test_chain_context_always_present_even_when_empty(self):
        v1 = make_preprocess([make_contract("A.sol#A")])
        result = diff_reports.diff_preprocess(v1, v1)
        self.assertIn("chainContext", result)
        self.assertEqual(result["chainContext"], {})

    def test_two_chains_never_conflated_in_chain_context(self):
        # Adversarial (chain isolation): same address, two different chains,
        # each must carry its OWN correct chainId - never mixed up.
        key1 = "onchain:/1/%s/Vault.sol#Vault" % self.ADDR
        key137 = "onchain:/137/%s/Vault.sol#Vault" % self.ADDR
        v1 = make_preprocess([])
        v2 = make_preprocess([make_contract(key1), make_contract(key137)])
        result = diff_reports.diff_preprocess(v1, v2)
        self.assertEqual(result["chainContext"][key1]["chainId"], 1)
        self.assertEqual(result["chainContext"][key137]["chainId"], 137)

    def test_malformed_onchain_looking_key_is_skipped_not_crashed(self):
        self.assertIsNone(diff_reports._onchain_identity("onchain:/not-a-number/addr/Vault.sol#Vault"))
        self.assertIsNone(diff_reports._onchain_identity("Vault.sol#Vault"))
        self.assertIsNone(diff_reports._onchain_identity(None))


if __name__ == "__main__":
    unittest.main()
