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
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import backend.context_encoding as context_encoding

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
    """The default measure: UTF-8 bytes of the canonical JSON form - the
    representation Step 6 embeds by default (backend/context_encoding.py's
    CONTEXT_FORMAT_V1, byte-identical to this). A caller embedding another
    representation passes its own measure to select_context() so the budget
    is always applied to the exact bytes that will be sent."""
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


MeasureBytes = Callable[[Dict[str, Any]], int]


def _metadata_reserve_bytes(all_files: List[str], reasons: List[str], budget_bytes: int, measure_bytes: Optional[MeasureBytes] = None) -> int:
    """A safe upper bound for contextSelection's OWN serialized size:
    every file double-counted, once as included and once as excluded - a
    real run only ever lists each file in exactly one of the two, so this
    always overestimates the metadata object's true eventual size. Used
    to compute the effective budget the fitting loop compares core
    artifact content against, so there is always room left for the
    metadata object actually attached to the final result. Exposed (not
    just inlined) so callers - including this module's own tests, which
    need to construct exact-boundary budgets - can reproduce the exact
    same reservation select_context() itself applies. measure_bytes
    defaults to _serialized_bytes (see select_context())."""
    measure = measure_bytes or _serialized_bytes
    worst_case_metadata = _metadata(
        "applied", budget_bytes, budget_bytes, all_files,
        [{"file": f, "reason": _CLOSURE_EXCEEDS_BUDGET} for f in all_files], reasons,
    )
    return measure({"contextSelection": worst_case_metadata}) - measure({"contextSelection": None})


def _exact_total_bytes(result: Dict[str, Any], metadata: Dict[str, Any], measure_bytes: Optional[MeasureBytes] = None) -> int:
    """result["contextSelection"] IS metadata (same object, not a copy) -
    estimatedContextBytes is self-referential (the field measures the very
    structure it is part of), so this converges it by fixed point: each
    pass's byte count already reflects the previous pass's digit count,
    and a total's digit count only ever changes by crossing a power-of-10
    boundary, so two passes are enough in every realistic case (a third
    pass is taken purely as a belt-and-suspenders check, not because it
    is expected to differ). measure_bytes defaults to _serialized_bytes
    (see select_context())."""
    measure = measure_bytes or _serialized_bytes
    for _ in range(3):
        total = measure(result)
        if metadata["estimatedContextBytes"] == total:
            return total
        metadata["estimatedContextBytes"] = total
    return measure(result)


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


# ---------------------------------------------------------------------------
# Exact incremental sizing (pre-15K-B hardening, docs/decisiones.md D-096).
#
# The first-fit loop below needs the size of _filtered_artifact(artifact, S)
# for one candidate set S per ranked file. Measuring that by filtering every
# record and re-serializing the whole artifact costs O(total records) plus
# the full priorityRanking per candidate - O(n * N) overall, which made a
# 2 MiB submission of thousands of tiny files exceed the worker's wall
# clock. Both context formats are exactly additive over the artifact's
# top-level keys, and _filtered_artifact() only changes the file-scoped
# lists, so:
#     size(S) = size(filtered to no file) + sum over those lists of
#               (list size for S - 2)                 # 2 = "[]"
# where each list size comes from the format's own size model
# (context_encoding.size_model) and per-record byte counts computed once.
# Nothing is approximated; the final selected set is re-measured with the
# real measure and any mismatch falls back to the original full-measure
# path, as does any input the model's preconditions do not cover.
# ---------------------------------------------------------------------------

_FILE_KEYED_LISTS = (
    ("contracts", "file"), ("signals", "file"), ("comments", "file"), ("calls", "file"),
    ("imports", "file"), ("freeFunctions", "file"), ("files", "path"),
)


class _SizerUnsupported(Exception):
    """The artifact does not meet a size-model precondition - use the
    full-measure path instead."""


def _size_model_for(measure_bytes: Optional[MeasureBytes]) -> Any:
    """The size model matching `measure_bytes`, or None for a measure this
    module cannot model (then every size is taken from the measure itself)."""
    if measure_bytes is None or measure_bytes is _serialized_bytes:
        return context_encoding.size_model(context_encoding.CONTEXT_FORMAT_V1)
    context_format = getattr(measure_bytes, "context_format", None)
    if context_format in context_encoding.SUPPORTED_CONTEXT_FORMATS:
        return context_encoding.size_model(context_format)
    return None


class _ListModel:
    """One list of the filtered artifact whose items are included
    independently (a generic list in the format's model): per-item parts
    by original index, and whether its size can be taken from running
    totals alone (order_free) or needs the included items in order."""

    def __init__(self, model: Any, parts: List[Tuple[Tuple[str, ...], int, int]]) -> None:
        self.parts = parts
        signatures = {part[0] for part in parts}
        homogeneous = len(signatures) <= 1 and () not in signatures
        self.order_free = model.order_free or homogeneous
        self.header = model.header_bytes(next(iter(signatures))) if (homogeneous and signatures and not model.order_free) else 0

    def size(self, model: Any, state: Tuple[int, int, int, Tuple[int, ...]]) -> int:
        count, item_bytes, row_bytes, indices = state
        if self.order_free:
            return model.homogeneous_list_bytes(count, item_bytes, row_bytes, self.header)
        return model.list_bytes([self.parts[i] for i in indices])

    def add(self, state: Tuple[int, int, int, Tuple[int, ...]], new: Iterable[int]) -> Tuple[int, int, int, Tuple[int, ...]]:
        new = sorted(new)
        if not new:
            return state
        count, item_bytes, row_bytes, indices = state
        count += len(new)
        item_bytes += sum(self.parts[i][1] for i in new)
        row_bytes += sum(self.parts[i][2] for i in new)
        if not self.order_free:
            indices = tuple(sorted(indices + tuple(new)))
        return count, item_bytes, row_bytes, indices


_EMPTY_LIST_STATE = (0, 0, 0, ())


class _ExactSizer:
    """size(S) of _filtered_artifact(artifact, S) for S within known_files,
    built once per select_context() call. States are immutable tuples/dicts,
    so a rejected candidate never touches the committed state."""

    def __init__(self, artifact: Dict[str, Any], known_files: Set[str], model: Any, base_bytes: int) -> None:
        self.model = model
        self.base = base_bytes
        self.lists: Dict[str, _ListModel] = {}
        self.indices_by_file: Dict[str, Dict[str, List[int]]] = {}
        self.runs_by_file: Dict[str, Dict[str, Tuple[int, int]]] = {}
        for key, field in _FILE_KEYED_LISTS:
            records = [r for r in artifact.get(key) or [] if r.get(field) in known_files]
            if key in model.file_run_sections:
                self.runs_by_file[key] = self._file_runs(key, records)
            else:
                self._add_file_keyed_list(key, field, records)

        self.graph = False
        self.keys_by_file: Dict[str, List[Any]] = {}
        self.edges_by_key: Dict[Any, List[int]] = {}
        self.proxies_by_key: Dict[Any, List[int]] = {}
        system_graph = artifact.get("systemGraph") or {}
        if system_graph.get("status") == "computed":
            self.graph = True
            nodes = [n for n in system_graph.get("nodes") or [] if n.get("file") in known_files]
            self._add_file_keyed_list("systemGraph.nodes", "file", nodes)
            for node in nodes:
                self.keys_by_file.setdefault(node["file"], []).append(node["key"])
            edges = list(system_graph.get("edges") or [])
            self.edge_ends = [(e.get("from"), e.get("to")) for e in edges]
            for index, (start, end) in enumerate(self.edge_ends):
                for key in {start, end}:
                    self.edges_by_key.setdefault(key, []).append(index)
            self.lists["systemGraph.edges"] = _ListModel(model, [model.item_parts(e) for e in edges])
            proxies = list(system_graph.get("proxies") or [])
            self.proxy_ends = [(p.get("proxy"), p.get("implementation")) for p in proxies]
            for index, (proxy, implementation) in enumerate(self.proxy_ends):
                for key in {proxy, implementation} if implementation else {proxy}:
                    self.proxies_by_key.setdefault(key, []).append(index)
            self.lists["systemGraph.proxies"] = _ListModel(model, [model.item_parts(p) for p in proxies])

    def _add_file_keyed_list(self, key: str, field: str, records: List[Dict[str, Any]]) -> None:
        self.lists[key] = _ListModel(self.model, [self.model.item_parts(r) for r in records])
        by_file: Dict[str, List[int]] = {}
        for index, record in enumerate(records):
            by_file.setdefault(record[field], []).append(index)
        self.indices_by_file[key] = by_file

    def _file_runs(self, key: str, records: List[Dict[str, Any]]) -> Dict[str, Tuple[int, int]]:
        # Runs of different files never merge, and a file's own runs are
        # the same in any subset, only if each file's records are contiguous.
        blocks: Dict[str, List[Dict[str, Any]]] = {}
        previous = None
        for record in records:
            path = record["file"]
            if path != previous and path in blocks:
                raise _SizerUnsupported("%s records of %s are not contiguous" % (key, path))
            blocks.setdefault(path, []).append(record)
            previous = path
        return {path: self.model.file_run_parts(path, block) for path, block in blocks.items()}

    def empty_state(self) -> Dict[str, Any]:
        state: Dict[str, Any] = {key: _EMPTY_LIST_STATE for key in self.lists}
        state.update({key: (0, 0) for key in self.runs_by_file})
        state["keyCounts"] = {}
        return state

    def size(self, state: Dict[str, Any]) -> int:
        total = self.base
        for key, list_model in self.lists.items():
            total += list_model.size(self.model, state[key]) - 2
        for key in self.runs_by_file:
            total += self.model.run_section_bytes(*state[key]) - 2
        return total

    def add_files(self, state: Dict[str, Any], files: Iterable[str]) -> Dict[str, Any]:
        """A NEW state with `files` (none of them already in `state`) added."""
        files = list(files)
        new = dict(state)
        for key, by_file in self.indices_by_file.items():
            new[key] = self.lists[key].add(state[key], [i for f in files for i in by_file.get(f, ())])
        for key, by_file in self.runs_by_file.items():
            runs, run_bytes = state[key]
            for path in files:
                file_runs, file_bytes = by_file.get(path, (0, 0))
                runs += file_runs
                run_bytes += file_bytes
            new[key] = (runs, run_bytes)
        if self.graph:
            counts = dict(state["keyCounts"])
            activated = set()
            for path in files:
                for key in self.keys_by_file.get(path, ()):
                    if not counts.get(key):
                        activated.add(key)
                    counts[key] = counts.get(key, 0) + 1
            new["keyCounts"] = counts
            edges = {i for key in activated for i in self.edges_by_key.get(key, ())
                     if counts.get(self.edge_ends[i][0]) and counts.get(self.edge_ends[i][1])}
            new["systemGraph.edges"] = self.lists["systemGraph.edges"].add(state["systemGraph.edges"], edges)
            proxies = {i for key in activated for i in self.proxies_by_key.get(key, ())
                       if counts.get(self.proxy_ends[i][0]) and (not self.proxy_ends[i][1] or counts.get(self.proxy_ends[i][1]))}
            new["systemGraph.proxies"] = self.lists["systemGraph.proxies"].add(state["systemGraph.proxies"], proxies)
        return new


def _build_exact_sizer(artifact: Dict[str, Any], known_files: Set[str], measure: MeasureBytes, measure_bytes: Optional[MeasureBytes]) -> Optional[_ExactSizer]:
    """None when the measure has no size model or the artifact does not
    meet a model precondition (non-contiguous file runs, unexpected record
    shapes): the caller then measures every candidate directly, exactly as
    before this optimization."""
    model = _size_model_for(measure_bytes)
    if model is None:
        return None
    try:
        return _ExactSizer(artifact, known_files, model, measure(_filtered_artifact(artifact, set())))
    except (_SizerUnsupported, AttributeError, KeyError, TypeError, ValueError):
        return None


def _first_fit(
    priority_ranking: List[Dict[str, Any]],
    dependencies: Dict[str, Set[str]],
    all_files_set: Set[str],
    effective_budget: int,
    bare_size: Callable[[Set[str]], int],
    sizer: Optional[_ExactSizer],
) -> Tuple[Set[str], List[Dict[str, str]], Optional[int]]:
    """The first-fit loop described in the module docstring. Sizes come
    from `sizer` when given (exact, incremental) or from bare_size() (the
    real measure of the filtered artifact); the decisions are identical
    either way. Returns (selected, excluded, size of the selected set as
    computed by the sizer, or None without one)."""
    selected: Set[str] = set()
    excluded: List[Dict[str, str]] = []
    state = sizer.empty_state() if sizer is not None else None
    empty = sizer.empty_state() if sizer is not None else None
    for entry in priority_ranking:
        file = entry["file"]
        if file in selected:
            continue
        solo_size = sizer.size(sizer.add_files(empty, [file])) if sizer is not None else bare_size({file})
        if solo_size > effective_budget:
            excluded.append({"file": file, "reason": _FILE_EXCEEDS_BUDGET_ALONE})
            continue
        closure_files = set(_closure(file, dependencies, all_files_set)) - selected
        if not closure_files:
            continue  # already fully covered by an earlier candidate's closure.
        if sizer is not None:
            trial_state = sizer.add_files(state, sorted(closure_files))
            trial_size = sizer.size(trial_state)
        else:
            trial_size = bare_size(selected | closure_files)
        if trial_size <= effective_budget:
            selected = selected | closure_files
            if sizer is not None:
                state = trial_state
        else:
            excluded.append({"file": file, "reason": _CLOSURE_EXCEEDS_BUDGET})
    return selected, excluded, (sizer.size(state) if sizer is not None else None)


def select_context(
    artifact: Dict[str, Any],
    budget_bytes: int = APPLICATION_CONTEXT_BUDGET_BYTES,
    selection_reasons: Optional[List[str]] = None,
    measure_bytes: Optional[MeasureBytes] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Runs the algorithm described in this module's own docstring.
    Returns (result_artifact, metadata) where metadata is also embedded
    in result_artifact["contextSelection"] (except when status=="failed" -
    see below). Pure/deterministic: never touches a clock, never reads
    global state besides its own module-level constants, never mutates
    `artifact`.

    measure_bytes: how an artifact's size is counted against budget_bytes
    - every fitting decision, the metadata reserve and
    estimatedContextBytes use it. Defaults to _serialized_bytes (canonical
    JSON, the default Step 6 representation); a caller that embeds a
    different representation (backend/context_encoding.py) must pass that
    representation's own measure, so the selector never budgets one
    encoding while the prompt sends another. Selection itself - whole
    files, forward closure, priority order, first-fit - is identical for
    every measure.

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

    measure = measure_bytes or _serialized_bytes

    def _bare_size(files: Set[str]) -> int:
        return measure(_filtered_artifact(artifact, files))

    effective_budget = budget_bytes - _metadata_reserve_bytes(all_files, reasons, budget_bytes, measure)

    full_size = _bare_size(all_files_set)
    if full_size <= effective_budget:
        metadata = _metadata("not_needed", budget_bytes, 0, all_files, [], reasons)
        result = dict(artifact)
        result["contextSelection"] = metadata
        metadata["estimatedContextBytes"] = _exact_total_bytes(result, metadata, measure)
        return result, metadata

    sizer = _build_exact_sizer(artifact, all_files_set, measure, measure_bytes)
    selected, excluded, final_size = _first_fit(priority_ranking, dependencies, all_files_set, effective_budget, _bare_size, sizer)
    if sizer is not None and selected and final_size != _bare_size(selected):
        # Defensive: the size model disagreed with the real measure, so no
        # decision it made is trusted - redo the selection measuring every
        # candidate directly (the original path).
        selected, excluded, _ = _first_fit(priority_ranking, dependencies, all_files_set, effective_budget, _bare_size, None)

    excluded.sort(key=lambda e: e["file"])
    if not selected:
        metadata = _metadata("failed", budget_bytes, 0, [], excluded, reasons)
        return artifact, metadata

    metadata = _metadata("applied", budget_bytes, 0, sorted(selected), excluded, reasons)
    result = _filtered_artifact(artifact, selected)
    result["contextSelection"] = metadata
    metadata["estimatedContextBytes"] = _exact_total_bytes(result, metadata, measure)
    return result, metadata
