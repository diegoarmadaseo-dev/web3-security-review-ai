#!/usr/bin/env python3
"""Deterministic multi-pass Step 6 (phase 15K-B - docs/decisiones.md D-097).

WHY: one Step 6 prompt is bounded by context_selection.
APPLICATION_CONTEXT_BUDGET_BYTES, so a submission whose artifact does not
fit is analyzed only partially by single-pass context selection (~62-67% of
a real ~15K effLOC project with compact-v2, ~40-44% with canonical JSON).
Multi-pass covers the whole submission with several prompts, each within
that same budget and the same final pre-provider check, then merges the
per-pass drafts into ONE draft that score.py / validate_report / render
process once, exactly as for a single pass.

This module is the deterministic part only - planning, per-pass artifacts
and prompt note, per-pass scope rules, merge and global scope. It never
calls a provider or an LLM (backend/llm_client.py runs the passes), never
reads files or the environment, and never scores, validates or renders.

PARTITIONING (plan_passes): the same units and rules as single-pass
selection - whole files, the forward dependency closure
(context_selection._forward_dependencies/_closure, unchanged) and the
existing priorityRanking order - applied repeatedly. Each pass starts empty
and walks the still-unassigned files in ranking order; a candidate's full
closure is added when the pass artifact stays within the artifact budget
(measured exactly, in the context format actually sent, by
context_selection's exact sizer). Every closure file not yet assigned
becomes PRIMARY in that pass; closure files already primary in an earlier
pass are CONTEXT (reference only) in this one. A file whose closure does
not fit even an empty pass can never be assigned (recorded with the
selector's own reasons); files left when max_passes is reached are recorded
as such. Each file is primary in at most one pass. Same artifact, format
and limits -> identical plan.

PRIMARY vs CONTEXT: a context file is physically in the pass prompt so the
model can read its dependencies, but it is analyzed as primary in another
pass. A pass may only place structured locations (findings, gas
suggestions) in its own PRIMARY files - never in context files, excluded
files or unknown paths - so a finding always comes from the one pass that
analyzed its file as primary, and never from a file no pass received. A
finding or gas suggestion that breaks this rule is discarded whole and
recorded (discard_out_of_scope, docs/decisiones.md D-100): never edited,
never reassigned, never merged.

MERGE (merge_pass_drafts): successful pass drafts, in pass order, become
one draft: findings concatenated (score.py deduplicates by stableKey, its
first occurrence being kept as the group's primary; by the rule above two
passes can never share a finding's primary-location file, and
_order_findings still puts a finding whose first location is primary in
its pass ahead of any other if that ever changed); gas suggestions,
architecture notes and limitations concatenated with exact duplicates
removed; categoryCoverage combined conservatively (DETECTED if any pass
detected it and a merged non-informational finding backs it - otherwise
NOT_ASSESSED, D-102 - NOT_ASSESSED if any pass did not assess it or if any
file was not analyzed); scope built from the plan and the pass outcomes
only, never from the model: "complete" only when every ranked file was analyzed as
primary by a successful pass, no pass failed, no finding or gas suggestion
was discarded, and preprocessing reported no completeness reason other than
the mode size limits multi-pass exists to cover (LOC_LIMIT_EXCEEDED /
FILE_LIMIT_EXCEEDED).

Standard library only.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional, Set, Tuple

import backend.context_encoding as context_encoding
import backend.context_selection as context_selection

PASS_VERSION = "1.0"
PASS_FIELD = "contextPass"

PASS_SUCCESS = "SUCCESS"
PASS_FAILED = "FAILED"

UNASSIGNED_MAX_PASSES = "max_passes_reached"
MULTI_PASS_REASON_CODE = "MULTI_PASS_ANALYSIS"
FAILED_PASSES_REASON_CODE = "MULTI_PASS_FAILED_PASSES"
UNASSIGNED_REASON_CODE = "MULTI_PASS_UNASSIGNED_FILES"
DISCARDED_REASON_CODE = "MULTI_PASS_DISCARDED_FINDINGS"
DISCARD_REASON = "location outside pass primary files"

# The preprocessing completeness reasons multi-pass exists to cover: the
# mode's size limits. Any OTHER reason (missing import, Vyper, low parse
# confidence, ...) keeps the global scope "partial" whatever the coverage.
SIZE_LIMIT_REASONS = frozenset({"LOC_LIMIT_EXCEEDED", "FILE_LIMIT_EXCEEDED"})

MULTI_PASS_LIMITATION = (
    "This review was performed in several deterministic passes, each covering whole files within one "
    "context budget; interactions between files analyzed as primary in different passes may not be detected."
)


MULTI_PASS_DISCARD_LIMITATION = (
    "This report contains only findings and gas suggestions whose locations were within the primary files of the "
    "pass that produced them; items with a location outside that scope were discarded and are not part of this result."
)


class PassPlan:
    """The deterministic partition of one artifact into passes (file lists
    only - the per-pass artifacts are built on demand, one at a time)."""

    def __init__(self, passes: List[Dict[str, Any]], unassigned: List[Dict[str, str]], ranked_files: List[str], context_format: str, artifact_budget: int, prompt_budget: int) -> None:
        self.passes = passes
        self.unassigned = unassigned
        self.ranked_files = ranked_files
        self.context_format = context_format
        self.artifact_budget = artifact_budget
        self.prompt_budget = prompt_budget

    @property
    def pass_count(self) -> int:
        return len(self.passes)

    def primary_owner(self) -> Dict[str, int]:
        return {path: p["passIndex"] for p in self.passes for path in p["primaryFiles"]}


def _pass_metadata(index: int, count: int, primary: List[str], context: List[str], excluded: List[str], artifact_budget: int, prompt_budget: int, estimated: int) -> Dict[str, Any]:
    return {
        "passVersion": PASS_VERSION,
        "passIndex": index,
        "passCount": count,
        "primaryFiles": list(primary),
        "contextFiles": list(context),
        "excludedFiles": list(excluded),
        "budgetBytes": artifact_budget,
        "promptBudgetBytes": prompt_budget,
        "estimatedContextBytes": estimated,
    }


def _metadata_reserve(ranked: List[str], artifact_budget: int, prompt_budget: int, measure: Any) -> int:
    """Upper bound of the contextPass object's own encoded size: every
    ranked file listed in all three lists (a real pass lists each once),
    with the largest numbers it can hold - the same worst-case approach
    as context_selection._metadata_reserve_bytes()."""
    worst = _pass_metadata(len(ranked), len(ranked), ranked, ranked, ranked, artifact_budget, prompt_budget, artifact_budget)
    return measure({PASS_FIELD: worst}) - measure({PASS_FIELD: None})


def plan_passes(artifact: Dict[str, Any], context_format: str, max_passes: int, artifact_budget: int, prompt_budget: int) -> PassPlan:
    """See the module docstring's PARTITIONING section."""
    context_encoding.check_context_format(context_format)
    if not isinstance(max_passes, int) or isinstance(max_passes, bool) or max_passes < 1:
        raise ValueError("max_passes must be a positive integer")
    ranked = [entry["file"] for entry in artifact.get("priorityRanking") or []]
    known = set(ranked)
    dependencies = context_selection._forward_dependencies(artifact, context_selection._contract_key_to_file(artifact.get("contracts") or []))
    measure = context_encoding.context_bytes_measure(context_format)
    budget = artifact_budget - _metadata_reserve(sorted(ranked), artifact_budget, prompt_budget, measure)
    sizer = context_selection._build_exact_sizer(artifact, known, measure, measure)

    def size_of(state: Any, files: Set[str], add: List[str]) -> Tuple[int, Any]:
        if sizer is not None:
            new_state = sizer.add_files(state, add)
            return sizer.size(new_state), new_state
        return measure(context_selection._filtered_artifact(artifact, files | set(add))), None

    unassigned: List[str] = list(ranked)
    unassignable: Dict[str, str] = {}
    passes: List[Dict[str, Any]] = []
    while len(passes) < max_passes:
        remaining = [f for f in unassigned if f not in unassignable]
        if not remaining:
            break
        # Any still-unassigned file a fitting closure brings in becomes
        # primary here - including one marked unassignable on its own.
        remaining_set = set(unassigned)
        pass_files: Set[str] = set()
        primary: Set[str] = set()
        state = sizer.empty_state() if sizer is not None else None
        for candidate in remaining:
            if candidate in pass_files:
                continue
            closure = context_selection._closure(candidate, dependencies, known)
            new_files = sorted(set(closure) - pass_files)
            size, new_state = size_of(state, pass_files, new_files)
            if size <= budget:
                pass_files.update(new_files)
                primary.update(f for f in new_files if f in remaining_set)
                state = new_state
            elif not pass_files:
                # Does not fit an EMPTY pass, so it never will.
                alone, _ = size_of(sizer.empty_state() if sizer is not None else None, set(), [candidate])
                unassignable[candidate] = context_selection._FILE_EXCEEDS_BUDGET_ALONE if alone > budget else context_selection._CLOSURE_EXCEEDS_BUDGET
        if not primary:
            break
        passes.append({"primaryFiles": sorted(primary), "contextFiles": sorted(pass_files - primary)})
        unassigned = [f for f in unassigned if f not in primary]
        for path in primary:
            unassignable.pop(path, None)

    count = len(passes)
    for index, entry in enumerate(passes, start=1):
        entry["passIndex"] = index
        entry["passCount"] = count
    left = [{"file": f, "reason": unassignable.get(f, UNASSIGNED_MAX_PASSES)} for f in unassigned]
    left.sort(key=lambda item: item["file"])
    return PassPlan(passes, left, ranked, context_format, artifact_budget, prompt_budget)


def build_pass_artifact(artifact: Dict[str, Any], plan: PassPlan, pass_entry: Dict[str, Any]) -> Dict[str, Any]:
    """The artifact one pass sends: the whole-file filter of its primary +
    context files plus its contextPass object, whose estimatedContextBytes
    is the exact encoded size of the returned artifact."""
    files = set(pass_entry["primaryFiles"]) | set(pass_entry["contextFiles"])
    excluded = sorted(f for f in plan.ranked_files if f not in files)
    result = context_selection._filtered_artifact(artifact, files)
    metadata = _pass_metadata(pass_entry["passIndex"], pass_entry["passCount"], pass_entry["primaryFiles"], pass_entry["contextFiles"], excluded, plan.artifact_budget, plan.prompt_budget, 0)
    result[PASS_FIELD] = metadata
    measure = context_encoding.context_bytes_measure(plan.context_format)
    for _ in range(3):  # self-referential size, converged as in context_selection._exact_total_bytes()
        total = measure(result)
        if metadata["estimatedContextBytes"] == total:
            break
        metadata["estimatedContextBytes"] = total
    return result


# The pass note replaces, for a pass prompt, the single-pass contract's rule
# that a "partial" report needs a NOT_ASSESSED category (llm_client omits
# that rule when the artifact carries contextPass): a pass is "partial"
# because it covers part of the submission, and R-05 applies only to the
# merged report (docs/decisiones.md D-098). Location rules state what
# pass_scope_errors() enforces: every structured location in a primary file.
_PASS_PROMPT_NOTE = (
    "\n\nMulti-pass analysis: this prompt is pass %d of %d of ONE review that was split deterministically into "
    "whole-file passes. The artifact's contextPass object is authoritative. Analyze ONLY the files in "
    "contextPass.primaryFiles. Files in contextPass.contextFiles are included solely as reference for "
    "dependencies (another pass analyzes them as primary). Files in contextPass.excludedFiles are not in this "
    "prompt at all. The report's scope.completeness MUST be \"partial\" (this pass covers only part of the "
    "submission), and scope.reasons must carry over any artifact completeness.reasons. Do not claim or imply "
    "that files outside contextPass.primaryFiles were analyzed in this pass."
    "\n\nLocations in this pass: locations[0] is the identity and ownership anchor of the finding and MUST be a "
    "file listed in contextPass.primaryFiles - a context-only file must NEVER be used as locations[0]. If the "
    "root cause is in a context-only file, do NOT report it in this pass: that file is owned and analyzed by its "
    "own primary pass. If code in a context-only file affects a finding whose root/primary location is in a "
    "primary file, keep the finding anchored to the primary file and describe the dependency in description or "
    "evidence. Every other location (locations[1..n]) and every gas suggestion location must also be a file "
    "listed in contextPass.primaryFiles - never a context-only, excluded or unknown file. Do not invent or "
    "substitute a primary location merely to satisfy these rules."
    "\n\nCategory coverage in this pass: categoryCoverage describes what this pass could assess within "
    "contextPass.primaryFiles. DETECTED is REQUIRED for any category that has at least one non-informational "
    "finding in this pass. NOT_DETECTED means the category was assessed within this pass's primary files and no "
    "matching finding was identified. NOT_ASSESSED means the category could not be properly evaluated within "
    "this pass's primary files. This pass being \"partial\" because it covers only part of the repository does "
    "NOT by itself require any category to be NOT_ASSESSED - never mark a category NOT_ASSESSED merely because "
    "other passes cover other files."
)


def pass_prompt_note(pass_artifact: Dict[str, Any]) -> str:
    """Fixed-size note (only the two pass numbers vary) for an artifact
    carrying contextPass; "" otherwise, so every other prompt is
    byte-identical to before."""
    metadata = pass_artifact.get(PASS_FIELD) if isinstance(pass_artifact, dict) else None
    if not isinstance(metadata, dict):
        return ""
    return _PASS_PROMPT_NOTE % (metadata.get("passIndex"), metadata.get("passCount"))


# A pass prompt is ~1.5 MB and the contract's own format rule sits before the
# artifact, so a short restatement closes every pass prompt (docs/decisiones.md
# D-103, H-5). Format only - it adds no content rule.
_PASS_FINAL_FORMAT_CHECK = (
    "\n\nFINAL FORMAT CHECK: respond with ONLY one valid JSON object - no markdown code fences, no prose before "
    "or after it. Do not omit any required field."
)


def pass_final_format_check(pass_artifact: Dict[str, Any]) -> str:
    """The fixed closing format reminder for an artifact carrying
    contextPass; "" otherwise, so every other prompt is byte-identical."""
    metadata = pass_artifact.get(PASS_FIELD) if isinstance(pass_artifact, dict) else None
    return _PASS_FINAL_FORMAT_CHECK if isinstance(metadata, dict) else ""


def _normalize(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _structured_locations(draft: Dict[str, Any]) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    findings = draft.get("findings")
    for index, finding in enumerate(findings if isinstance(findings, list) else []):
        locations = finding.get("locations") if isinstance(finding, dict) else None
        for loc_index, loc in enumerate(locations if isinstance(locations, list) else []):
            out.append(("findings[%d].locations[%d]" % (index, loc_index), loc))
    gas = draft.get("gasSuggestions")
    for index, item in enumerate(gas if isinstance(gas, list) else []):
        if isinstance(item, dict):
            out.append(("gasSuggestions[%d].location" % index, item.get("location")))
    return out


def pass_completeness_errors(draft: Dict[str, Any], pass_entry: Dict[str, Any]) -> List[str]:
    """A pass draft's scope must be "partial" (it covers part of the
    submission); "complete" is a validation failure - the attempt is
    consumed and the error goes to that pass's next attempt."""
    scope = draft.get("scope")
    if isinstance(scope, dict) and scope.get("completeness") == "complete":
        return ["scope.completeness must not be 'complete': this is pass %d of %d of a multi-pass analysis - use 'partial'" % (pass_entry["passIndex"], pass_entry["passCount"])]
    return []


def pass_location_errors(draft: Dict[str, Any], pass_entry: Dict[str, Any]) -> List[str]:
    """Every structured location (finding locations, gas suggestion
    locations) that is not one of the pass's primary files."""
    errors: List[str] = []
    primary = {_normalize(f) for f in pass_entry["primaryFiles"]}
    context = {_normalize(f) for f in pass_entry["contextFiles"]}
    for path, loc in _structured_locations(draft):
        if isinstance(loc, dict) and isinstance(loc.get("file"), str) and _normalize(loc["file"]) not in primary:
            kind = "a context-only file of this pass (reference, analyzed in another pass)" if _normalize(loc["file"]) in context else "not a primary file of this pass"
            errors.append("%s.file %r is %s - locations must be in contextPass.primaryFiles; remove or relocate that entry" % (path, loc["file"], kind))
    return errors


def pass_scope_errors(draft: Dict[str, Any], pass_entry: Dict[str, Any]) -> List[str]:
    """Both scope rules of ONE pass draft: pass_completeness_errors() plus
    pass_location_errors(). A pass run applies them separately: location
    errors are handled by discard_out_of_scope() (finding-level discard,
    docs/decisiones.md D-100), not by failing the attempt."""
    return pass_completeness_errors(draft, pass_entry) + pass_location_errors(draft, pass_entry)


def _file_kind(path: str, primary: Set[str], context: Set[str], known: Optional[Set[str]]) -> str:
    normalized = _normalize(path)
    if normalized in primary:
        return "primary"
    if normalized in context:
        return "context"
    if known is not None and normalized in known:
        return "excluded"
    return "unknown"


def discard_out_of_scope(draft: Dict[str, Any], pass_entry: Dict[str, Any], known_files: Optional[List[str]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Finding-level discard (docs/decisiones.md D-100). Pure: never mutates
    draft; same input -> same output. Returns (filtered_draft, record).

    * A finding with ANY location (locations[0] or locations[1..n]) outside
      the pass's primary files is discarded whole - never edited, never
      reassigned. A gas suggestion with such a location is discarded alone.
      Every other finding and gas suggestion is kept exactly as given.
    * A category the draft marked DETECTED whose non-informational findings
      were all discarded (at least one was) becomes NOT_ASSESSED: nothing
      retained supports DETECTED, and the pass did find something there, so
      NOT_DETECTED would be false too.
    * record = {"discards": [...], "discardedFindings": n,
      "discardedGasSuggestions": m, "coverageAdjusted": [categories]}; each
      discard lists every invalid location with its fileKind ("context",
      "excluded" when the file is in known_files, else "unknown").
    Only locations that are objects with a string file are checked here, as
    in pass_location_errors(); any other shape is left to validation."""
    primary = {_normalize(f) for f in pass_entry["primaryFiles"]}
    context = {_normalize(f) for f in pass_entry["contextFiles"]}
    known = {_normalize(f) for f in known_files} if known_files is not None else None
    filtered = copy.deepcopy(draft)
    discards: List[Dict[str, Any]] = []

    def invalid(loc: Any, index: Optional[int]) -> Optional[Dict[str, Any]]:
        if not (isinstance(loc, dict) and isinstance(loc.get("file"), str)):
            return None
        kind = _file_kind(loc["file"], primary, context, known)
        if kind == "primary":
            return None
        entry: Dict[str, Any] = {"file": loc["file"], "fileKind": kind}
        if index is not None:
            entry = {"index": index, **entry}
        return entry

    findings = filtered.get("findings")
    if isinstance(findings, list):
        kept = []
        for index, finding in enumerate(findings):
            locations = finding.get("locations") if isinstance(finding, dict) else None
            bad = [b for b in (invalid(loc, i) for i, loc in enumerate(locations if isinstance(locations, list) else [])) if b]
            if not bad:
                kept.append(finding)
                continue
            discards.append({"kind": "finding", "index": index, "category": finding.get("category"), "severity": finding.get("severity"),
                             "status": finding.get("status"), "invalidLocations": bad, "reason": DISCARD_REASON})
        filtered["findings"] = kept
    gas = filtered.get("gasSuggestions")
    if isinstance(gas, list):
        kept_gas = []
        for index, item in enumerate(gas):
            bad_loc = invalid(item.get("location"), None) if isinstance(item, dict) else None
            if bad_loc is None:
                kept_gas.append(item)
                continue
            discards.append({"kind": "gas", "index": index, "location": bad_loc["file"], "fileKind": bad_loc["fileKind"], "reason": DISCARD_REASON})
        filtered["gasSuggestions"] = kept_gas

    def non_informational(finding: Any) -> bool:
        return isinstance(finding, dict) and finding.get("status") != "informational"

    dropped = {d["category"] for d in discards if d["kind"] == "finding" and d.get("status") != "informational"}
    still = {f.get("category") for f in filtered.get("findings") or [] if non_informational(f)}
    adjusted: List[str] = []
    coverage = filtered.get("categoryCoverage")
    if isinstance(coverage, list):
        for entry in coverage:
            if isinstance(entry, dict) and entry.get("status") == "DETECTED" and entry.get("category") in dropped and entry.get("category") not in still:
                entry["status"] = "NOT_ASSESSED"
                adjusted.append(entry["category"])
    record = {"discards": discards, "discardedFindings": sum(1 for d in discards if d["kind"] == "finding"),
              "discardedGasSuggestions": sum(1 for d in discards if d["kind"] == "gas"), "coverageAdjusted": adjusted}
    return filtered, record


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _first_location_file(finding: Any) -> Optional[str]:
    locations = finding.get("locations") if isinstance(finding, dict) else None
    if isinstance(locations, list) and locations and isinstance(locations[0], dict) and isinstance(locations[0].get("file"), str):
        return _normalize(locations[0]["file"])
    return None


def _order_findings(tagged: List[Tuple[int, int, Dict[str, Any]]], owner: Dict[str, int]) -> List[Tuple[int, int, Dict[str, Any]]]:
    """Stable order score.py deduplicates in (it keeps a group's FIRST
    finding as primary): a finding whose first location is primary in its
    own pass before any other, then pass order, then the pass's own order."""
    normalized_owner = {_normalize(path): index for path, index in owner.items()}
    return sorted(tagged, key=lambda item: (0 if normalized_owner.get(_first_location_file(item[2])) == item[0] else 1, item[0], item[1]))


def _dedupe(items: List[Any]) -> List[Any]:
    seen: Set[str] = set()
    out = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def global_scope(artifact: Dict[str, Any], plan: PassPlan, outcomes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The merged report's scope, from the plan and the pass outcomes only."""
    completeness = artifact.get("completeness") or {}
    pre_reasons = [r for r in completeness.get("reasons") or [] if isinstance(r, dict)]
    failed = sorted((o for o in outcomes if o["status"] != PASS_SUCCESS), key=lambda o: o["passIndex"])
    analyzed = sorted({f for o in outcomes if o["status"] == PASS_SUCCESS for f in o["primaryFiles"]})
    total = len(plan.ranked_files)
    other_reasons = [r for r in pre_reasons if r.get("code") not in SIZE_LIMIT_REASONS]
    # Discards count only for passes whose (filtered) draft is merged.
    with_discards = sorted((o for o in outcomes if o["status"] == PASS_SUCCESS and (o.get("discardedFindings") or o.get("discardedGasSuggestions"))),
                           key=lambda o: o["passIndex"])
    complete = not failed and not plan.unassigned and not other_reasons and len(analyzed) == total and not with_discards

    reasons: List[Dict[str, str]] = [{"code": str(r.get("code")), "detail": str(r.get("detail", ""))} for r in pre_reasons]
    reasons.append({
        "code": MULTI_PASS_REASON_CODE,
        "detail": "Analyzed in %d deterministic whole-file pass(es): %d of %d source files analyzed as primary by a successful pass (application prompt budget %d bytes per pass)."
                  % (plan.pass_count, len(analyzed), total, plan.prompt_budget),
    })
    if failed:
        reasons.append({
            "code": FAILED_PASSES_REASON_CODE,
            "detail": "; ".join("pass %d of %d failed (%s) - files not analyzed: %s" % (o["passIndex"], o["passCount"], o["failureReason"], ", ".join(o["primaryFiles"])) for o in failed),
        })
    if plan.unassigned:
        reasons.append({
            "code": UNASSIGNED_REASON_CODE,
            "detail": "Files not assigned to any pass (not analyzed): %s" % ", ".join("%s (%s)" % (u["file"], u["reason"]) for u in plan.unassigned),
        })
    if with_discards:
        reasons.append({
            "code": DISCARDED_REASON_CODE,
            "detail": "%d finding(s) and %d gas suggestion(s) discarded because a location was outside the primary files of the pass that produced them (not included in this report): %s"
                      % (sum(o.get("discardedFindings") or 0 for o in with_discards), sum(o.get("discardedGasSuggestions") or 0 for o in with_discards),
                         "; ".join("pass %d of %d: %s" % (o["passIndex"], o["passCount"], ", ".join(_discard_label(d) for d in o.get("discards") or [])) for o in with_discards)),
        })
    return {"completeness": "complete" if complete else "partial", "reasons": reasons}


def _discard_label(discard: Dict[str, Any]) -> str:
    if discard["kind"] == "gas":
        return "gas suggestion at %s" % discard["location"]
    anchor = discard["invalidLocations"][0]["file"]
    return "%s/%s at %s" % (discard.get("category"), discard.get("severity"), anchor)


_SC_CATEGORIES = ["SC%02d" % n for n in range(1, 11)]


def _merge_coverage(drafts: List[Dict[str, Any]], complete: bool, backed_categories: Set[str]) -> List[Dict[str, str]]:
    """backed_categories: categories with at least one non-informational
    finding in the merged report (docs/decisiones.md D-102). A pass's
    DETECTED survives only for those; otherwise it becomes NOT_ASSESSED -
    never NOT_DETECTED: a pass reported a detection, so absence is not shown."""
    merged = []
    for category in _SC_CATEGORIES:
        statuses = []
        for draft in drafts:
            for entry in draft.get("categoryCoverage") or []:
                if isinstance(entry, dict) and entry.get("category") == category:
                    statuses.append(entry.get("status"))
        if "DETECTED" in statuses and category in backed_categories:
            status = "DETECTED"
        elif "DETECTED" in statuses:
            status = "NOT_ASSESSED"
        elif not complete or "NOT_ASSESSED" in statuses or not statuses:
            status = "NOT_ASSESSED"
        else:
            status = "NOT_DETECTED"
        merged.append({"category": category, "status": status})
    return merged


def merge_pass_drafts(artifact: Dict[str, Any], plan: PassPlan, outcomes: List[Dict[str, Any]], mode: str) -> Tuple[Dict[str, Any], List[Tuple[int, Dict[str, Any]]]]:
    """One global draft from the SUCCESSFUL pass outcomes (in pass order).
    Returns (draft, provenance) where provenance lists (passIndex, finding)
    in the merged findings' order, for merged_location_errors()."""
    successes = [o for o in sorted(outcomes, key=lambda o: o["passIndex"]) if o["status"] == PASS_SUCCESS]
    if not successes:
        raise ValueError("no successful pass to merge")
    drafts = [o["draft"] for o in successes]
    scope = global_scope(artifact, plan, outcomes)

    tagged = []
    for outcome in successes:
        for position, finding in enumerate(outcome["draft"].get("findings") or []):
            tagged.append((outcome["passIndex"], position, finding))
    ordered = _order_findings(tagged, plan.primary_owner())

    first = drafts[0]
    merged: Dict[str, Any] = {}
    for key in ("generatedBy", "skillVersion", "analysisEngineVersion", "checklistVersion", "mode", "compilerVersion", "scriptsAvailable"):
        if key in first:
            merged[key] = first[key]
    merged["mode"] = mode
    merged["inputHash"] = artifact.get("inputHash", first.get("inputHash"))
    languages = [d["language"] for d in drafts if isinstance(d.get("language"), str) and d.get("language")]
    if languages:
        merged["language"] = languages[0]
    merged["scope"] = scope
    findings = [finding for _, _, finding in ordered]
    # Evidence visible in the report: the merged (already scope-filtered)
    # findings, non-informational only (D-102).
    backed_categories = {f.get("category") for f in findings if isinstance(f, dict) and f.get("status") != "informational"}
    merged["categoryCoverage"] = _merge_coverage(drafts, scope["completeness"] == "complete", backed_categories)
    merged["findings"] = findings
    fixed = [MULTI_PASS_LIMITATION] + ([MULTI_PASS_DISCARD_LIMITATION] if any(o.get("discardedFindings") or o.get("discardedGasSuggestions") for o in successes) else [])
    merged["limitations"] = _dedupe([item for d in drafts for item in (d.get("limitations") or [])] + fixed)
    gas = [item for d in drafts for item in (d.get("gasSuggestions") or [])]
    if any("gasSuggestions" in d for d in drafts):
        merged["gasSuggestions"] = _dedupe(gas)
    notes = [item for d in drafts for item in (d.get("architectureNotes") or [])]
    if any("architectureNotes" in d for d in drafts):
        merged["architectureNotes"] = _dedupe(notes)
    summaries = [d["executiveSummary"] for d in drafts if isinstance(d.get("executiveSummary"), str) and d["executiveSummary"].strip()]
    if summaries:
        merged["executiveSummary"] = "\n\n".join(summaries)
    return merged, [(index, finding) for index, _, finding in ordered]


def merged_location_errors(provenance: List[Tuple[int, Dict[str, Any]]], merged: Dict[str, Any], plan: PassPlan, outcomes: List[Dict[str, Any]]) -> List[str]:
    """Final global check before scoring: every merged structured location
    is a primary file of the pass that produced it, and every gas
    suggestion location is a primary file of some successful pass."""
    primary_of = {p["passIndex"]: {_normalize(f) for f in p["primaryFiles"]} for p in plan.passes}
    analyzed = {_normalize(f) for o in outcomes if o["status"] == PASS_SUCCESS for f in o["primaryFiles"]}
    errors = []
    for index, (pass_index, finding) in enumerate(provenance):
        for loc in finding.get("locations") or []:
            if isinstance(loc, dict) and isinstance(loc.get("file"), str) and _normalize(loc["file"]) not in primary_of.get(pass_index, set()):
                errors.append("findings[%d] (pass %d) has a location outside that pass's primary files: %r" % (index, pass_index, loc["file"]))
    for index, item in enumerate(merged.get("gasSuggestions") or []):
        loc = item.get("location") if isinstance(item, dict) else None
        if isinstance(loc, dict) and isinstance(loc.get("file"), str) and _normalize(loc["file"]) not in analyzed:
            errors.append("gasSuggestions[%d].location is outside every successful pass's primary files: %r" % (index, loc["file"]))
    return errors


def plan_summary(plan: PassPlan, outcomes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Compact, deterministic, JSON-safe description of a run (for tests,
    logs and measurement) - file counts and per-pass outcome only."""
    return {
        "passCount": plan.pass_count,
        "contextFormat": plan.context_format,
        "rankedFiles": len(plan.ranked_files),
        "unassigned": list(plan.unassigned),
        "passes": [
            {
                "passIndex": p["passIndex"], "primaryFiles": len(p["primaryFiles"]), "contextFiles": len(p["contextFiles"]),
                **({k: v for k, v in (outcomes[i] if outcomes else {}).items() if k in ("status", "attempts", "promptBytes", "selectedBytes", "providerOutcome", "validationOutcome", "failureReason",
                                                                                         "discardedFindings", "discardedGasSuggestions", "discards", "coverageAdjusted")}),
            }
            for i, p in enumerate(plan.passes)
        ],
    }
