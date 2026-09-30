#!/usr/bin/env python3
"""Deterministic, file-level LLM context selection for large submissions
(introduced for the ~10K effective-LOC milestone - docs/decisiones.md,
the phase after the pre-Step-6 completeness guard).

WHY THIS EXISTS: backend/llm_client.py's pre-Step-6 completeness guard
(added the phase before this one) fails a job closed whenever
preprocessing reports completeness.status == "partial" with
LOC_LIMIT_EXCEEDED/FILE_LIMIT_EXCEEDED - correct as a safety backstop,
but it means ANY submission over a mode's configured maxEffectiveLoc is
simply rejected outright, even when a large-but-legitimate submission
could be usefully analyzed within a bounded LLM context. This module is
what lets the worker choose a smaller, still-coherent subset instead of
failing outright - the automated equivalent of a human, shown
priorityRanking by SKILL.md's Step 4, choosing "accept a partial review
of the top-priority items" instead of narrowing the input themselves.

SELECTION UNIT IS ALWAYS A WHOLE FILE. Never a function, never a
contract, never a byte range, never mid-JSON. A file is either entirely
present (with everything that belongs to it: its contracts, signals,
comments, calls, imports, free functions) or entirely absent - this is
the single non-negotiable invariant that keeps every reference inside an
included file meaningfully resolvable. No source text is ever truncated;
no JSON is ever sliced.

PRIORITY ORDER comes from preprocess.py's own compute_priority_ranking()
output, completely unmodified - this module never recomputes or
second-guesses that score.

DEPENDENCY CLOSURE is computed from two sources, matching exactly what
the artifact already represents explicitly (never inferring a
relationship that isn't already there):
  * systemGraph edges (inherits/calls/delegatesTo) - contract-level,
    mapped back to their owning file.
  * imports[] entries with resolved=True (resolvedTo is the target
    file) - systemGraph does NOT cover imports at all (confirmed by
    reading preprocess.py's compute_system_graph() directly), so this
    is a REQUIRED second source, not a redundant one.
Traversal is FORWARD/DIRECTIONAL only (if file A is selected, whatever A
depends on must be included too) - never the reverse (selecting a base
contract's file does not pull in every file that happens to inherit from
it). This is ordinary dependency-closure semantics, the same shape a
Python import graph's own transitive closure has.

BUDGET ACCOUNTING is FIRST-FIT IN PRIORITY ORDER: for each candidate file
(most important first, per priorityRanking's own deterministic order),
compute its full dependency closure, and include the ENTIRE closure only
if it fits in what remains of the budget - never a partial closure
(that would reintroduce dangling references). A rejected candidate's
closure is skipped WHOLE; evaluation continues with the next,
lower-priority candidate (never stops at the first miss) - a smaller
low-priority file/closure can still fit even after a larger high-priority
one did not. Two distinct exclusion reasons are recorded, because they
mean different things operationally: file_exceeds_budget_alone (this ONE
file, by itself, with nothing else selected, already exceeds the entire
budget - an absolute, order-independent fact about that file) vs
closure_exceeds_budget (the file itself would fit, but it plus what it
depends on does not, or the running total already selected leaves too
little room). No third "below_priority_cutoff" reason is manufactured -
this implementation never stops early or applies an arbitrary rank
cutoff; it evaluates every candidate against the real remaining budget,
so every exclusion has one of the two concrete, evidence-based reasons
above.

DETERMINISM: priorityRanking's own order is never re-sorted here: ties
are already broken by ascending file path in preprocess.py itself. All
internal traversal (dependency closures) sorts every intermediate
frontier before expanding it - never relies on Python set/dict iteration
order for anything observable. Repeated calls with the same artifact
produce byte-identical selected artifacts and metadata (see this
module's own tests).

SECURITY-CRITICAL SIGNALS ARE NEVER FILTERED: secrets[], secretsDetected
and injectionSignals[] describe what preprocessing found in the FULL,
complete raw source - not what entered the LLM's context. SKILL.md's own
Step 5 says to warn the user immediately whenever secretsDetected is
true, unconditionally; hiding a detected credential just because its
file wasn't selected for AI analysis would be a real safety regression,
not a neutral side effect of a context budget. contextDocuments (optional
user-supplied protocol documentation, not Solidity source) is likewise
untouched - it is not part of the per-file selection this module governs.

APPLICATION CONTEXT BUDGET, NOT A PROVIDER LIMIT: backend/main.py
requires LLM_MODEL as an environment variable with no default or
hardcoded value anywhere in this repository (confirmed by inspection
before choosing a number here) - there is no configured model identifier
in this codebase to look up an authoritative provider context window
against, even in principle. APPLICATION_CONTEXT_BUDGET_BYTES below is
therefore explicitly an APPLICATION-level ceiling this codebase itself
chooses to stay under, not a claim about what any specific Anthropic or
DeepSeek model's real context window is. A real provider SIZE check has
since been done for DeepSeek "deepseek-flash" only (docs/decisiones.md,
D-095): it accepted a real Step 6 prompt of 1,522,718 UTF-8 bytes and a
padded prompt of exactly this budget. That is provider-side size
acceptance only - not an end-to-end validation of the worker pipeline,
not a validation of any other provider/model, and not a measure of
model accuracy; this constant stays an application ceiling, never a
provider guarantee.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

SELECTION_VERSION = "1.0"

# 1.5 MiB. Derivation, using only measurements already established in
# this repository's own capacity-probe work (never a guessed provider
# limit or a runtime percentage of the current artifact):
#   ~7,548 effLOC prompt  ~= 1.61 MB (measured)
#   ~9,700 effLOC prompt  ~= 2.09 MB (measured)
# 1.5 MiB (1,572,864 bytes) sits BELOW both already-measured points, not
# just below the larger one - a deliberately conservative anchor, not a
# number picked to barely clear the current fixture. Relative to the
# ~9,700 effLOC fixture's 2.09 MB full artifact, this is a ~27% reduction
# ("materially below", so the selector is actually exercised rather than
# trivially passing everything through); relative to file weights in that
# same fixture (2.09 MB / 159 files, weighted toward the higher-priority,
# often larger files first), it is large enough to admit a substantial,
# still-connected majority of the bundle, not just a handful of files.
# A single fixed constant, never adjusted at runtime based on the current
# artifact's own size (that would defeat its purpose as a ceiling).
APPLICATION_CONTEXT_BUDGET_BYTES = 1536 * 1024

_CLOSURE_EXCEEDS_BUDGET = "closure_exceeds_budget"
_FILE_EXCEEDS_BUDGET_ALONE = "file_exceeds_budget_alone"


def _contract_key_to_file(contracts: List[Dict[str, Any]]) -> Dict[str, str]:
    return {c["key"]: c["file"] for c in contracts if c.get("key")}


def _forward_dependencies(artifact: Dict[str, Any], contract_key_to_file: Dict[str, str]) -> Dict[str, Set[str]]:
    """file -> set of OTHER files it depends on, forward/directional only
    (a file that is depended ON is never made to depend back on its
    dependents). Two sources, see module docstring: systemGraph edges
    (mapped from contract key to owning file) and resolved imports."""
    deps: Dict[str, Set[str]] = {}
    system_graph = artifact.get("systemGraph") or {}
    for edge in system_graph.get("edges") or []:
        from_file = contract_key_to_file.get(edge.get("from"))
        to_file = contract_key_to_file.get(edge.get("to"))
        if from_file and to_file and from_file != to_file:
            deps.setdefault(from_file, set()).add(to_file)
    for record in artifact.get("imports") or []:
        if record.get("resolved") and record.get("resolvedTo"):
            from_file = record.get("file")
            to_file = record["resolvedTo"]
            if from_file and to_file and from_file != to_file:
                deps.setdefault(from_file, set()).add(to_file)
    return deps


def _closure(start_file: str, dependencies: Dict[str, Set[str]], known_files: Set[str]) -> List[str]:
    """Deterministic transitive forward closure of start_file (itself
    included). known_files bounds traversal to files that actually exist
    in priorityRanking for this artifact - a resolvedTo/edge target
    naming something outside the bundle is never followed (conservative:
    never invents a file). Every frontier is sorted before expansion, so
    the visiting order - and therefore the final result, already a sorted
    list - never depends on set/dict iteration order."""
    visited: Set[str] = set()
    frontier = [start_file]
    while frontier:
        current_batch = sorted(set(frontier) - visited)
        frontier = []
        for current in current_batch:
            if current in visited or current not in known_files:
                continue
            visited.add(current)
            frontier.extend(sorted(dependencies.get(current, ())))
    return sorted(visited)


def _filtered_artifact(artifact: Dict[str, Any], files: Set[str]) -> Dict[str, Any]:
    """A new artifact dict with every file-scoped collection restricted to
    `files`. Never mutates the input. secrets/secretsDetected/
    injectionSignals/contextDocuments and every metadata field
    (inputHash, mode, totals, completeness, priorityRanking,
    generatedBy, versions, limits, categories) are copied through
    UNCHANGED - see module docstring's SECURITY-CRITICAL SIGNALS section
    for why secrets/injectionSignals specifically are never filtered.
    priorityRanking is likewise left whole (not reduced to the selected
    subset) so a reader can see the full ranking that drove the
    decision - contextSelection.includedFiles/excludedFiles is the
    authoritative record of what was actually selected."""
    out = dict(artifact)
    out["contracts"] = [c for c in artifact.get("contracts") or [] if c.get("file") in files]
    out["signals"] = [s for s in artifact.get("signals") or [] if s.get("file") in files]
    out["comments"] = [c for c in artifact.get("comments") or [] if c.get("file") in files]
    out["calls"] = [c for c in artifact.get("calls") or [] if c.get("file") in files]
    out["imports"] = [i for i in artifact.get("imports") or [] if i.get("file") in files]
    out["freeFunctions"] = [f for f in artifact.get("freeFunctions") or [] if f.get("file") in files]
    out["files"] = [f for f in artifact.get("files") or [] if f.get("path") in files]

    system_graph = artifact.get("systemGraph") or {}
    if system_graph.get("status") == "computed":
        nodes = [n for n in system_graph.get("nodes") or [] if n.get("file") in files]
        node_keys = {n["key"] for n in nodes}
        edges = [
            e for e in system_graph.get("edges") or []
            if e.get("from") in node_keys and e.get("to") in node_keys
        ]
        proxies = [
            p for p in system_graph.get("proxies") or []
            if p.get("proxy") in node_keys and (not p.get("implementation") or p.get("implementation") in node_keys)
        ]
        out["systemGraph"] = {"status": "computed", "nodes": nodes, "edges": edges, "proxies": proxies}
    # else: "not_computed" (quick/standard mode) - nothing to filter, pass through unchanged.

    return out


def _serialized_bytes(value: Dict[str, Any]) -> int:
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def _metadata_reserve_bytes(all_files: List[str], reasons: List[str], budget_bytes: int) -> int:
    """A safe upper bound for contextSelection's OWN serialized size:
    every file double-counted, once as included and once as excluded - a
    real run only ever lists each file in exactly one of the two, so this
    always overestimates the metadata object's true eventual size. Used
    to compute the effective budget the fitting loop compares core
    artifact content against, so there is always room left for the
    metadata object actually attached to the final result. Exposed (not
    just inlined) so callers - including this module's own tests, which
    need to construct exact-boundary budgets - can reproduce the exact
    same reservation select_context() itself applies."""
    worst_case_metadata = _metadata(
        "applied", budget_bytes, budget_bytes, all_files,
        [{"file": f, "reason": _CLOSURE_EXCEEDS_BUDGET} for f in all_files], reasons,
    )
    return _serialized_bytes({"contextSelection": worst_case_metadata}) - _serialized_bytes({"contextSelection": None})


def _exact_total_bytes(result: Dict[str, Any], metadata: Dict[str, Any]) -> int:
    """result["contextSelection"] IS metadata (same object, not a copy) -
    estimatedContextBytes is self-referential (the field measures the very
    structure it is part of), so this converges it by fixed point: each
    pass's byte count already reflects the previous pass's digit count,
    and a total's digit count only ever changes by crossing a power-of-10
    boundary, so two passes are enough in every realistic case (a third
    pass is taken purely as a belt-and-suspenders check, not because it
    is expected to differ)."""
    for _ in range(3):
        total = _serialized_bytes(result)
        if metadata["estimatedContextBytes"] == total:
            return total
        metadata["estimatedContextBytes"] = total
    return _serialized_bytes(result)


def _metadata(status: str, budget_bytes: int, estimated_bytes: int, included: List[str], excluded: List[Dict[str, str]], reasons: List[str]) -> Dict[str, Any]:
    return {
        "selectionVersion": SELECTION_VERSION,
        "status": status,
        "budgetBytes": budget_bytes,
        "estimatedContextBytes": estimated_bytes,
        "includedFiles": list(included),
        "excludedFiles": list(excluded),
        "selectionReasons": list(reasons),
    }


def select_context(
    artifact: Dict[str, Any],
    budget_bytes: int = APPLICATION_CONTEXT_BUDGET_BYTES,
    selection_reasons: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Runs the algorithm described in this module's own docstring.
    Returns (result_artifact, metadata) where metadata is also embedded
    in result_artifact["contextSelection"] (except when status=="failed" -
    see below). Pure/deterministic: never touches a clock, never reads
    global state besides its own module-level constants, never mutates
    `artifact`.

    metadata["status"]:
      "not_needed" - the complete, unfiltered artifact already fits the
        budget; result_artifact is `artifact` plus contextSelection,
        every file included, nothing excluded.
      "applied"    - one or more files were excluded; result_artifact is
        the filtered subset plus contextSelection.
      "failed"     - not even the single highest-priority file's own
        closure fits the budget, so no non-empty selection exists;
        result_artifact is the ORIGINAL, UNFILTERED `artifact` (the
        caller must never build a prompt from it in this case - see
        backend/llm_client.py's own completeness-gate integration,
        which raises Step6Failed instead of proceeding)."""
    priority_ranking = artifact.get("priorityRanking") or []
    all_files = sorted(entry["file"] for entry in priority_ranking)
    all_files_set = set(all_files)
    contract_key_to_file = _contract_key_to_file(artifact.get("contracts") or [])
    dependencies = _forward_dependencies(artifact, contract_key_to_file)
    reasons = list(selection_reasons or [])

    def _bare_size(files: Set[str]) -> int:
        return _serialized_bytes(_filtered_artifact(artifact, files))

    effective_budget = budget_bytes - _metadata_reserve_bytes(all_files, reasons, budget_bytes)

    full_size = _bare_size(all_files_set)
    if full_size <= effective_budget:
        metadata = _metadata("not_needed", budget_bytes, 0, all_files, [], reasons)
        result = dict(artifact)
        result["contextSelection"] = metadata
        metadata["estimatedContextBytes"] = _exact_total_bytes(result, metadata)
        return result, metadata

    selected: Set[str] = set()
    excluded: List[Dict[str, str]] = []
    for entry in priority_ranking:
        file = entry["file"]
        if file in selected:
            continue
        solo_size = _bare_size({file})
        if solo_size > effective_budget:
            excluded.append({"file": file, "reason": _FILE_EXCEEDS_BUDGET_ALONE})
            continue
        closure_files = set(_closure(file, dependencies, all_files_set)) - selected
        if not closure_files:
            continue  # already fully covered by an earlier candidate's closure.
        trial = selected | closure_files
        trial_size = _bare_size(trial)
        if trial_size <= effective_budget:
            selected = trial
        else:
            excluded.append({"file": file, "reason": _CLOSURE_EXCEEDS_BUDGET})

    excluded.sort(key=lambda e: e["file"])
    if not selected:
        metadata = _metadata("failed", budget_bytes, 0, [], excluded, reasons)
        return artifact, metadata

    metadata = _metadata("applied", budget_bytes, 0, sorted(selected), excluded, reasons)
    result = _filtered_artifact(artifact, selected)
    result["contextSelection"] = metadata
    metadata["estimatedContextBytes"] = _exact_total_bytes(result, metadata)
    return result, metadata
