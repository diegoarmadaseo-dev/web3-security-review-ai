#!/usr/bin/env python3
"""Tests for backend/context_selection.py - deterministic, file-level LLM
context selection (introduced for the ~10K effective-LOC milestone, the
phase after the pre-Step-6 completeness guard - see that module's own
docstring for the full rationale).

Uses small, synthetic, hand-built artifacts (see _artifact() below) for
every precisely-engineered scenario (dependency closure, budget
boundaries, disconnected components) - real preprocess.run() output is
exercised separately by tests/test_backend_llm_client.py's integration
tests and by this session's own offline ~9.7K-fixture validation (not a
unit test - see the final report for that task).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.context_selection as cs  # noqa: E402


def _artifact(file_specs, edges=None, imports=None, calls=None, signals=None):
    """file_specs: iterable of (file, priorityScore, padBytes). padBytes
    controls that file's serialized weight precisely via a single ASCII
    (no-escaping-needed) comment text of that exact length, so tests can
    reason about byte budgets without guessing JSON overhead."""
    contracts, comments, priority_ranking, files = [], [], [], []
    for file, score, pad in file_specs:
        name = file.replace("/", "_").replace(".", "_")
        key = "%s#%s" % (file, name)
        contracts.append({
            "file": file, "name": name, "key": key, "kind": "contract",
            "lineStart": 1, "lineEnd": 10, "bases": [], "basesResolved": [], "basesUnresolved": [],
            "functions": [], "modifiers": [], "stateVariables": [], "usingFor": [], "truncated": False,
        })
        comments.append({"file": file, "attachedTo": None, "kind": "line", "lineStart": 1, "lineEnd": 1, "text": "x" * pad, "truncated": False})
        priority_ranking.append({"file": file, "signalCount": 0, "publicStateChangingFunctions": 0, "effectiveLoc": 10, "priorityScore": score})
        files.append({
            "path": file, "origin": "directory", "language": "solidity", "kind": "source",
            "hash": "sha256:0", "lineEndings": "lf",
            "lines": {"total": 10, "effective": 10, "blank": 0, "commentOnly": 0},
            "issues": [], "parseConfidence": {"score": 1.0, "label": "high", "issues": []},
            "pragma": {"present": True, "expression": "^0.8.19", "minVersion": "0.8.19", "floating": True, "line": 1},
        })
    priority_ranking.sort(key=lambda e: (-e["priorityScore"], e["file"]))
    nodes = [{"key": c["key"], "file": c["file"], "name": c["name"], "kind": c["kind"]} for c in contracts]
    system_graph = {"status": "computed", "nodes": nodes, "edges": edges or [], "proxies": []}
    return {
        "generatedBy": "test", "preprocessVersion": "test", "checklistVersion": "test",
        "signalRegistryVersion": "test", "mode": "pro", "inputHash": "sha256:" + "0" * 64,
        "totals": {"sourceFiles": len(file_specs), "totalFiles": len(file_specs), "totalEffectiveLoc": 10 * len(file_specs), "totalLoc": 10 * len(file_specs)},
        "completeness": {"status": "partial", "reasons": [{"code": "LOC_LIMIT_EXCEEDED", "detail": "test"}]},
        "limits": {"maxEffectiveLoc": 10, "maxSourceFiles": None},
        "categories": {},
        "contracts": contracts, "signals": signals or [], "comments": comments,
        "calls": calls or [], "imports": imports or [], "freeFunctions": [],
        "files": files, "systemGraph": system_graph, "priorityRanking": priority_ranking,
        "secrets": [{"file": "A.sol", "line": 1, "kind": "test-secret", "context": "code"}], "secretsDetected": True,
        "injectionSignals": [{"file": "A.sol", "line": 1}], "contextDocuments": [{"path": "README.md", "text": "hi", "truncated": False}],
    }


def _size_with(artifact, files, reasons=()):
    # NOTE: default () matches select_context()'s own default
    # (selection_reasons=None -> []) - a mismatch here would silently
    # reserve the wrong number of bytes for contextSelection's own
    # "selectionReasons" field and throw off exact-boundary tests by
    # exactly the byte-length of whatever reasons were assumed but not
    # actually passed to the real select_context() call.
    """The exact budget_bytes select_context() needs to admit precisely
    this file set: the bare serialized content size PLUS the same
    contextSelection metadata reserve select_context() itself subtracts
    internally before comparing against the budget (see
    _metadata_reserve_bytes()'s own docstring) - without this, a test
    budget set to the bare content size alone would be silently too
    tight by exactly that reserve. Uses the module's own real
    filtering/serialization path directly (private functions, same
    "test the real internals" convention this codebase already applies
    elsewhere - e.g. backend/http_app.py's _read_body tests) rather than
    hand-computing JSON overhead."""
    filtered = cs._filtered_artifact(artifact, set(files))  # noqa: SLF001 - intentional, see docstring above.
    bare = len(json.dumps(filtered, ensure_ascii=False).encode("utf-8"))
    all_files = sorted(e["file"] for e in artifact["priorityRanking"])
    reserve = cs._metadata_reserve_bytes(all_files, list(reasons), bare)  # noqa: SLF001
    return bare + reserve


class NotNeededTests(unittest.TestCase):
    """1: small artifact, everything fits."""

    def test_status_not_needed_when_everything_fits(self):
        artifact = _artifact([("A.sol", 10, 5), ("B.sol", 5, 5)])
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        self.assertEqual(meta["status"], "not_needed")
        self.assertEqual(sorted(meta["includedFiles"]), ["A.sol", "B.sol"])
        self.assertEqual(meta["excludedFiles"], [])

    def test_not_needed_result_carries_every_original_file(self):
        artifact = _artifact([("A.sol", 10, 5), ("B.sol", 5, 5), ("C.sol", 1, 5)])
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        self.assertEqual(len(result["contracts"]), 3)
        self.assertEqual(len(result["files"]), 3)

    def test_not_needed_estimated_bytes_matches_actual(self):
        artifact = _artifact([("A.sol", 10, 5)])
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        actual = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        self.assertEqual(meta["estimatedContextBytes"], actual)


class BudgetActivatesSelectionTests(unittest.TestCase):
    """2: selection activates and excludes at least one file when the
    full artifact does not fit."""

    def test_selection_applied_excludes_at_least_one_file(self):
        artifact = _artifact([("A.sol", 10, 2000), ("B.sol", 5, 2000), ("C.sol", 1, 2000)])
        full_size = _size_with(artifact, ["A.sol", "B.sol", "C.sol"])
        result, meta = cs.select_context(artifact, budget_bytes=full_size - 500)
        self.assertEqual(meta["status"], "applied")
        self.assertGreaterEqual(len(meta["excludedFiles"]), 1)

    def test_selected_result_fits_within_the_exact_budget(self):
        artifact = _artifact([("A.sol", 10, 2000), ("B.sol", 5, 2000), ("C.sol", 1, 2000)])
        full_size = _size_with(artifact, ["A.sol", "B.sol", "C.sol"])
        budget = full_size - 500
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        actual = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        self.assertLessEqual(actual, budget)
        self.assertEqual(meta["estimatedContextBytes"], actual)


class DependencyClosureTests(unittest.TestCase):
    """3/4: a higher-priority file's dependency is included regardless of
    its own priority position, via BOTH systemGraph edges and resolved
    imports."""

    def test_systemgraph_calls_edge_pulls_in_lower_priority_dependency(self):
        artifact = _artifact(
            [("A.sol", 100, 50), ("B.sol", 0, 50), ("Z.sol", 50, 5000)],
            edges=[{"kind": "calls", "from": "A.sol#A_sol", "to": "B.sol#B_sol", "function": "f", "line": 1, "method": "g"}],
        )
        # Budget fits A+B comfortably but not Z (Z is deliberately huge) -
        # proves B is included BECAUSE A depends on it, not because it
        # would have made a generous cutoff on its own (B's priority is
        # the lowest of the three, yet it must still appear).
        budget = _size_with(artifact, ["A.sol", "B.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertIn("A.sol", meta["includedFiles"])
        self.assertIn("B.sol", meta["includedFiles"])
        self.assertNotIn("Z.sol", meta["includedFiles"])

    def test_inherits_edge_pulls_in_dependency(self):
        artifact = _artifact(
            [("Child.sol", 100, 50), ("Base.sol", 0, 50)],
            edges=[{"kind": "inherits", "from": "Child.sol#Child_sol", "to": "Base.sol#Base_sol"}],
        )
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        self.assertEqual(sorted(meta["includedFiles"]), ["Base.sol", "Child.sol"])

    def test_delegatesto_edge_pulls_in_implementation(self):
        artifact = _artifact(
            [("Proxy.sol", 100, 50), ("Impl.sol", 0, 50)],
            edges=[{"kind": "delegatesTo", "from": "Proxy.sol#Proxy_sol", "to": "Impl.sol#Impl_sol"}],
        )
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        self.assertEqual(sorted(meta["includedFiles"]), ["Impl.sol", "Proxy.sol"])

    def test_resolved_import_pulls_in_dependency_with_no_systemgraph_edge(self):
        # No systemGraph edge at all between these two files - only a
        # resolved imports[] record. systemGraph does not represent
        # imports (confirmed by reading preprocess.py's
        # compute_system_graph() directly - see module docstring), so
        # this proves the import-following path independently of the
        # graph-edge path above.
        artifact = _artifact(
            [("A.sol", 100, 50), ("C.sol", 0, 50)],
            imports=[{"file": "A.sol", "line": 1, "shape": "relative", "path": "./C.sol", "resolved": True, "resolvedTo": "C.sol", "symbols": [], "alias": None}],
        )
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        self.assertEqual(sorted(meta["includedFiles"]), ["A.sol", "C.sol"])

    def test_unresolved_import_never_invents_a_dependency(self):
        artifact = _artifact(
            [("A.sol", 100, 50)],
            imports=[{"file": "A.sol", "line": 1, "shape": "package", "path": "@openzeppelin/Foo.sol", "resolved": False, "resolvedTo": None, "symbols": [], "alias": None}],
        )
        result, meta = cs.select_context(artifact, budget_bytes=10**6)
        self.assertEqual(meta["includedFiles"], ["A.sol"])

    def test_dependency_direction_is_forward_only(self):
        # B is depended ON by A (A -> B). Selecting B on its OWN merits
        # must never pull in A (the reverse would not be a closure, it
        # would be "everything that ever references what I selected").
        artifact = _artifact(
            [("A.sol", 0, 5000), ("B.sol", 100, 50)],
            edges=[{"kind": "calls", "from": "A.sol#A_sol", "to": "B.sol#B_sol", "function": "f", "line": 1, "method": "g"}],
        )
        budget = _size_with(artifact, ["B.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertIn("B.sol", meta["includedFiles"])
        self.assertNotIn("A.sol", meta["includedFiles"])


class DisconnectedComponentTests(unittest.TestCase):
    """5: a disconnected, low-priority file can be excluded even though
    it has no dependency relationship to what WAS selected - it is
    excluded purely because there is no budget left, not because
    disconnection is itself a special case."""

    def test_disconnected_low_priority_file_excluded_when_budget_is_tight(self):
        artifact = _artifact([("A.sol", 100, 2000), ("D.sol", 0, 2000)])  # no edges/imports between them at all.
        budget = _size_with(artifact, ["A.sol"]) + 10  # room for A alone, not for both.
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(meta["includedFiles"], ["A.sol"])
        self.assertEqual(meta["excludedFiles"], [{"file": "D.sol", "reason": "closure_exceeds_budget"}])

    def test_disconnected_low_priority_file_still_included_when_room_remains(self):
        # Same shape, but enough budget for both - proves disconnection
        # itself is never a reason to exclude; only the budget is.
        artifact = _artifact([("A.sol", 100, 2000), ("D.sol", 0, 2000)])
        budget = _size_with(artifact, ["A.sol", "D.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(sorted(meta["includedFiles"]), ["A.sol", "D.sol"])


class ClosureTooLargeTests(unittest.TestCase):
    """6: a whole closure that does not fit is excluded whole, and lower-
    priority candidates are still evaluated afterward (never stops at
    the first miss)."""

    def test_oversized_closure_excluded_whole_lower_priority_still_considered(self):
        artifact = _artifact(
            [("E.sol", 100, 50), ("F.sol", 90, 50000), ("G.sol", 10, 50)],
            edges=[{"kind": "calls", "from": "E.sol#E_sol", "to": "F.sol#F_sol", "function": "f", "line": 1, "method": "g"}],
        )
        # Budget fits G alone (and would fit E alone), but not E+F
        # together (F is deliberately huge) - E's closure must be
        # rejected WHOLE (E is never included without F), while G (lower
        # priority than E, no dependency on F) still gets its own chance.
        budget = _size_with(artifact, ["G.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertNotIn("E.sol", meta["includedFiles"])
        self.assertNotIn("F.sol", meta["includedFiles"])
        self.assertIn("G.sol", meta["includedFiles"])
        reasons = {e["file"]: e["reason"] for e in meta["excludedFiles"]}
        self.assertEqual(reasons["E.sol"], "closure_exceeds_budget")

    def test_partial_closure_is_never_included(self):
        # F (E's dependency) must never appear alone without E, and E
        # must never appear alone without F - "whole closure or nothing".
        # F also gets its own independent turn later in priorityRanking
        # (every file does - see module docstring) and is excluded there
        # too, on its own solo merits this time.
        artifact = _artifact(
            [("E.sol", 100, 50), ("F.sol", 90, 50000)],
            edges=[{"kind": "calls", "from": "E.sol#E_sol", "to": "F.sol#F_sol", "function": "f", "line": 1, "method": "g"}],
        )
        budget = _size_with(artifact, ["E.sol"]) + 10  # enough for E alone, not for E+F.
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(meta["includedFiles"], [])
        reasons = {e["file"]: e["reason"] for e in meta["excludedFiles"]}
        self.assertEqual(reasons["E.sol"], "closure_exceeds_budget")
        self.assertEqual(reasons["F.sol"], "file_exceeds_budget_alone")
        self.assertEqual(sorted(reasons), ["E.sol", "F.sol"])


class OversizedSingleFileTests(unittest.TestCase):
    """7: a single file that by itself exceeds the entire budget is
    excluded with file_exceeds_budget_alone, never partially truncated."""

    def test_single_oversized_file_gets_its_own_specific_reason(self):
        artifact = _artifact([("Huge.sol", 100, 50000), ("Small.sol", 50, 50)])
        budget = _size_with(artifact, ["Small.sol"]) + 10  # enough for Small alone, nowhere near Huge alone.
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        reasons = {e["file"]: e["reason"] for e in meta["excludedFiles"]}
        self.assertEqual(reasons["Huge.sol"], "file_exceeds_budget_alone")
        self.assertIn("Small.sol", meta["includedFiles"])

    def test_oversized_file_is_never_partially_included(self):
        artifact = _artifact([("Huge.sol", 100, 50000)])
        budget = 1000  # far below Huge.sol's own solo size.
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(meta["status"], "failed")
        self.assertEqual(result["contracts"] if "contracts" in result and meta["status"] != "failed" else [], [])


class ExactBudgetBoundaryTests(unittest.TestCase):
    """8: a closure that fits by exactly the available budget vs. one
    that exceeds it by a single byte."""

    def test_closure_that_fits_exactly_is_included(self):
        artifact = _artifact([("A.sol", 100, 500)])
        exact = _size_with(artifact, ["A.sol"])
        result, meta = cs.select_context(artifact, budget_bytes=exact)
        self.assertEqual(meta["includedFiles"], ["A.sol"])
        self.assertEqual(meta["status"], "not_needed")  # single file, nothing to exclude.

    def test_closure_that_exceeds_by_one_byte_is_excluded(self):
        artifact = _artifact([("A.sol", 100, 500), ("B.sol", 50, 50)])
        exact_a_only = _size_with(artifact, ["A.sol"])
        result, meta = cs.select_context(artifact, budget_bytes=exact_a_only - 1)
        self.assertNotIn("A.sol", meta["includedFiles"])


class DeterminismTests(unittest.TestCase):
    """9: repeated runs produce byte-identical selected artifacts and
    metadata - no dependence on set/dict iteration order."""

    def test_repeated_runs_are_byte_identical(self):
        artifact = _artifact(
            [("A.sol", 100, 2000), ("B.sol", 90, 2000), ("C.sol", 80, 2000), ("D.sol", 10, 2000)],
            edges=[{"kind": "calls", "from": "A.sol#A_sol", "to": "B.sol#B_sol", "function": "f", "line": 1, "method": "g"}],
        )
        budget = _size_with(artifact, ["A.sol", "B.sol", "C.sol"])
        results = [cs.select_context(artifact, budget_bytes=budget) for _ in range(5)]
        serialized = [json.dumps(r, sort_keys=True) for r, _ in results]
        self.assertEqual(len(set(serialized)), 1)
        metas = [json.dumps(m, sort_keys=True) for _, m in results]
        self.assertEqual(len(set(metas)), 1)

    def test_tie_breaking_matches_priority_ranking_ascending_file_order(self):
        # Two files with IDENTICAL priorityScore - preprocess.py's own
        # compute_priority_ranking() breaks ties by ascending file path;
        # this module must never re-sort priorityRanking, so the same
        # tie-break is inherited automatically.
        artifact = _artifact([("Z.sol", 50, 2000), ("A.sol", 50, 2000)])
        self.assertEqual([e["file"] for e in artifact["priorityRanking"]], ["A.sol", "Z.sol"])
        budget = _size_with(artifact, ["A.sol"]) + 10  # room for exactly one of the two.
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(meta["includedFiles"], ["A.sol"])


class GraphIntegrityTests(unittest.TestCase):
    """10: no dangling selected graph references - every edge in the
    filtered systemGraph has both endpoints among the selected nodes."""

    def test_no_dangling_edges_in_filtered_systemgraph(self):
        # Excluded.sol DEPENDS ON B.sol (edge from Excluded to B) -
        # deliberately the reverse of "B depends on Excluded", so that
        # selecting B (forward closure only follows a file's OWN
        # dependencies, never its dependents - see
        # DependencyClosureTests.test_dependency_direction_is_forward_only)
        # never obligates including Excluded.sol too. Excluded.sol is
        # huge and low-priority, so it is independently excluded on its
        # own turn - proving the edge-filter drops an edge even when only
        # ONE endpoint (here, the source) is missing, not just when both are.
        artifact = _artifact(
            [("A.sol", 100, 50), ("B.sol", 90, 50), ("Excluded.sol", 0, 50000)],
            edges=[
                {"kind": "calls", "from": "A.sol#A_sol", "to": "B.sol#B_sol", "function": "f", "line": 1, "method": "g"},
                {"kind": "calls", "from": "Excluded.sol#Excluded_sol", "to": "B.sol#B_sol", "function": "f", "line": 1, "method": "g"},
            ],
        )
        budget = _size_with(artifact, ["A.sol", "B.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(sorted(meta["includedFiles"]), ["A.sol", "B.sol"])
        self.assertNotIn("Excluded.sol", meta["includedFiles"])
        selected_keys = {n["key"] for n in result["systemGraph"]["nodes"]}
        for edge in result["systemGraph"]["edges"]:
            self.assertIn(edge["from"], selected_keys)
            self.assertIn(edge["to"], selected_keys)
        # The edge FROM Excluded.sol must be gone entirely, not dangling,
        # even though its target (B.sol) is itself still present.
        self.assertFalse(any(e["from"] == "Excluded.sol#Excluded_sol" for e in result["systemGraph"]["edges"]))

    def test_no_orphaned_contract_or_signal_records(self):
        artifact = _artifact([("A.sol", 100, 2000), ("B.sol", 0, 2000)])
        budget = _size_with(artifact, ["A.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        included = set(meta["includedFiles"])
        for c in result["contracts"]:
            self.assertIn(c["file"], included)
        for cm in result["comments"]:
            self.assertIn(cm["file"], included)

    def test_security_critical_signals_are_never_filtered(self):
        # secrets/injectionSignals describe the FULL raw source, not what
        # entered the LLM's context - see module docstring. Must survive
        # selection completely untouched even when their own file is
        # excluded (the synthetic artifact's secret/injection both name
        # "A.sol", which this test deliberately excludes).
        artifact = _artifact([("A.sol", 0, 50000), ("B.sol", 100, 50)])
        budget = _size_with(artifact, ["B.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertNotIn("A.sol", meta["includedFiles"])
        self.assertEqual(result["secrets"], artifact["secrets"])
        self.assertEqual(result["secretsDetected"], artifact["secretsDetected"])
        self.assertEqual(result["injectionSignals"], artifact["injectionSignals"])
        self.assertEqual(result["contextDocuments"], artifact["contextDocuments"])

    def test_completeness_and_priority_ranking_are_never_mutated(self):
        artifact = _artifact([("A.sol", 100, 2000), ("B.sol", 0, 2000)])
        budget = _size_with(artifact, ["A.sol"]) + 10
        result, meta = cs.select_context(artifact, budget_bytes=budget)
        self.assertEqual(result["completeness"], artifact["completeness"])
        self.assertEqual(result["priorityRanking"], artifact["priorityRanking"])


if __name__ == "__main__":
    unittest.main()
