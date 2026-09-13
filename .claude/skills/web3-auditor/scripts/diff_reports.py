#!/usr/bin/env python3
"""Deterministic version comparison / security diff (V2.5, docs/decisiones.md
D-054). Compares two ALREADY-PRODUCED artifacts of this Skill's pipeline that
the user/workflow has explicitly declared to be two versions ("V1" and "V2")
of the same system - this script never guesses that relationship itself; it
is always given two file paths and treats them as declared.

Two independent, explicit modes:

* `reports`  - diffs two post-analysis report JSONs (references/report-schema.json,
  produced after Step 6/7). Findings-level: new/resolved/modified findings,
  categoryCoverage changes. Requires the AI-authored analysis step to have
  already run on both sides.
* `preprocess` - diffs two raw preprocess.py JSON outputs (Step 3 only, no AI
  involved). Structural: contracts/functions/state variables/modifiers added,
  removed or changed, plus systemGraph deltas (pro mode only). 100%
  deterministic and available even when the analysis step never ran.

Both modes reuse existing, unmodified pipeline output as-is:
* `stableKey` is recomputed with score.py's own compute_stable_key - never
  reimplemented - so identity stays byte-for-byte consistent with whatever
  score.py already guarantees (see references/severity-and-score.md).
* Contract identity is preprocess.py's own systemGraph node key (file#name).
  A file or contract rename/move is reported as one removal plus one
  addition - NEVER inferred as a rename, matching the same "never invent a
  relationship the data does not state" principle Diego required for the
  V1/V2 pairing itself.
* Function identity (including internal/private functions, which have no ABI
  selector) is a local, independent re-derivation of the same canonical
  "name(type1,type2,...)" shape preprocess.py's own _canonical_signature
  already uses for the cross-contract selector-clash check - generalized to
  every visibility, since nothing about that canonicalization is
  visibility-specific. A function whose parameters cannot be canonicalized
  (a struct/enum/contract-typed parameter) is never guessed at: it is
  reported as unresolved on that side, not matched, exactly like
  _canonical_param_type's own "return None, callers must skip this function,
  never guess" contract.
* This is a deliberately independent, local copy of that canonicalization
  logic (not an import from preprocess.py): scripts/*.py do not import each
  other's underscore-prefixed, module-private helpers (see text_utils.py's
  own docstring for why detectors/ get shared helpers through a dedicated
  module rather than importing preprocess.py directly) - only ELEMENTARY_TYPES
  itself is shared, already-public infrastructure, imported from text_utils.

This script never authors a finding, never calls a model, and never
modifies score.py, validate_report.py, preprocess.py, the detectors/
registry, or any of their outputs - it only reads two already-produced JSON
files and writes a new, separate diff artifact.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from text_utils import ELEMENTARY_TYPES  # noqa: E402
from score import compute_stable_key  # noqa: E402

DIFF_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

STRUCTURAL_ONLY_NOTE = (
    "newFindings/resolvedFindings/modifiedFindings and functionSurfaceDelta/"
    "systemGraphDelta describe STRUCTURAL differences between two "
    "already-produced analysis runs. They are not, by themselves, security "
    "conclusions: a 'resolved' finding may have moved or simply not been "
    "re-surfaced rather than truly fixed, and a 'modified' or 'new' finding "
    "may or may not be a real regression. Judging that requires reviewing "
    "the underlying source (see SKILL.md Step 6)."
)
MODIFIER_SCOPE_NOTE = (
    "Modifier/permission changes reflect only NAMED modifiers applied to a "
    "function's own declaration. Inline body-level checks (e.g. a bare "
    "require(msg.sender == owner) with no modifier) are not present in "
    "preprocess.py's public JSON output and are not visible to this diff; "
    "reviewing those remains the analysis step's (AI's) job."
)
RENAME_NOTE = (
    "Contract identity is file+name (matching systemGraph's own node key). "
    "A file or contract rename/move is reported as one removal plus one "
    "addition, never inferred as a rename."
)


class DiffError(Exception):
    """Raised when an input file is too malformed/incompatible to diff."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DiffError(message)


# ---------------------------------------------------------------------------
# `reports` mode: findings-level diff of two post-analysis report JSONs
# ---------------------------------------------------------------------------

def _index_findings_unique(findings: List[Dict[str, Any]], label: str) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        key = compute_stable_key(finding)
        _require(key not in index, "%s.findings contains duplicate stableKey %r - findings must be deduplicated (run through score.py) before diffing" % (label, key))
        index[key] = finding
    return index


def _secondary_key(finding: Dict[str, Any]) -> str:
    locations = finding.get("locations") or []
    loc = locations[0] if locations and isinstance(locations[0], dict) else {}
    file_ = str(loc.get("file") or "")
    contract = str(loc.get("contract") or "")
    function = str(loc.get("function") or "")
    category = str(finding.get("category") or "")
    return "%s#%s#%s|%s" % (file_, contract, function, category)


def _group_by(findings: List[Dict[str, Any]], key_fn) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        groups.setdefault(key_fn(finding), []).append(finding)
    return groups


def _structural_finding_changes(f1: Dict[str, Any], f2: Dict[str, Any]) -> List[str]:
    changed = []
    for field in ("severity", "confidence", "status"):
        if f1.get(field) != f2.get(field):
            changed.append(field)
    if (f1.get("locations") or []) != (f2.get("locations") or []):
        changed.append("locations")
    return changed


def diff_findings(v1_findings: List[Dict[str, Any]], v2_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    v1_by_key = _index_findings_unique(v1_findings, "v1")
    v2_by_key = _index_findings_unique(v2_findings, "v2")

    matched_v1: set = set()
    matched_v2: set = set()
    modified: List[Dict[str, Any]] = []

    for key in sorted(set(v1_by_key) & set(v2_by_key)):
        f1, f2 = v1_by_key[key], v2_by_key[key]
        matched_v1.add(id(f1))
        matched_v2.add(id(f2))
        changes = _structural_finding_changes(f1, f2)
        if changes:
            modified.append({"matchedBy": "stableKey", "stableKeyV1": key, "stableKeyV2": key, "changedFields": changes, "v1": f1, "v2": f2})

    remaining_v1 = [f for f in v1_findings if id(f) not in matched_v1]
    remaining_v2 = [f for f in v2_findings if id(f) not in matched_v2]
    v1_by_secondary = _group_by(remaining_v1, _secondary_key)
    v2_by_secondary = _group_by(remaining_v2, _secondary_key)

    for skey in sorted(set(v1_by_secondary) & set(v2_by_secondary)):
        group1, group2 = v1_by_secondary[skey], v2_by_secondary[skey]
        if len(group1) != 1 or len(group2) != 1:
            continue  # ambiguous (0/many on either side) - never guess a pairing
        f1, f2 = group1[0], group2[0]
        matched_v1.add(id(f1))
        matched_v2.add(id(f2))
        changes = sorted(set(["signature"] + _structural_finding_changes(f1, f2)))
        modified.append({"matchedBy": "secondary", "stableKeyV1": compute_stable_key(f1), "stableKeyV2": compute_stable_key(f2), "changedFields": changes, "v1": f1, "v2": f2})

    new_findings = [f for f in v2_findings if id(f) not in matched_v2]
    resolved_findings = [f for f in v1_findings if id(f) not in matched_v1]
    modified.sort(key=lambda m: (m["stableKeyV1"], m["stableKeyV2"]))
    return {
        "newFindings": new_findings,
        "resolvedFindings": resolved_findings,
        "modifiedFindings": modified,
    }


def diff_category_coverage(v1_coverage: List[Dict[str, Any]], v2_coverage: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    v1_by_cat = {c["category"]: c.get("status") for c in v1_coverage or [] if isinstance(c, dict) and c.get("category")}
    v2_by_cat = {c["category"]: c.get("status") for c in v2_coverage or [] if isinstance(c, dict) and c.get("category")}
    deltas = []
    for category in sorted(set(v1_by_cat) | set(v2_by_cat)):
        status1, status2 = v1_by_cat.get(category), v2_by_cat.get(category)
        if status1 != status2:
            deltas.append({"category": category, "from": status1, "to": status2})
    return deltas


def diff_reports(v1: Dict[str, Any], v2: Dict[str, Any]) -> Dict[str, Any]:
    _require(isinstance(v1, dict) and isinstance(v2, dict), "both inputs must be JSON objects")
    _require(isinstance(v1.get("findings"), list), "v1.findings must be an array (is this a scored report? see report-schema.json)")
    _require(isinstance(v2.get("findings"), list), "v2.findings must be an array (is this a scored report? see report-schema.json)")

    result = diff_findings(v1["findings"], v2["findings"])
    result["categoryCoverageDelta"] = diff_category_coverage(v1.get("categoryCoverage", []), v2.get("categoryCoverage", []))
    result["diffVersion"] = DIFF_VERSION
    result["mode"] = "reports"
    result["v1Meta"] = {"inputHash": v1.get("inputHash"), "mode": v1.get("mode")}
    result["v2Meta"] = {"inputHash": v2.get("inputHash"), "mode": v2.get("mode")}
    result["sameInput"] = v1.get("inputHash") is not None and v1.get("inputHash") == v2.get("inputHash")
    result["note"] = STRUCTURAL_ONLY_NOTE
    return result


# ---------------------------------------------------------------------------
# `preprocess` mode: structural diff of two raw preprocess.py JSON outputs
# ---------------------------------------------------------------------------

# Independent, local re-derivation of preprocess.py's own
# _canonical_param_type/_canonical_signature (cross-contract selector-clash
# check) - see module docstring for why this is a copy, not an import.
_SELECTOR_ALIASES = {"uint": "uint256", "int": "int256", "fixed": "fixed128x18", "ufixed": "ufixed128x18"}
_ARRAY_SUFFIX_RE = re.compile(r"^(.*?)((?:\s*\[\s*\d*\s*\])+)$")


def _canonical_param_type(raw_type: Optional[str]) -> Optional[str]:
    text = (raw_type or "").strip()
    if not text:
        return None
    match = _ARRAY_SUFFIX_RE.match(text)
    base, suffix = (match.group(1).strip(), re.sub(r"\s+", "", match.group(2))) if match else (text, "")
    base = re.sub(r"\bpayable\b", "", base)
    base = re.sub(r"\s+", "", base)
    base = _SELECTOR_ALIASES.get(base, base)
    if not ELEMENTARY_TYPES.match(base):
        return None
    return base + suffix


def _function_identity(fn: Dict[str, Any]) -> Optional[str]:
    """Structural identity for ANY function regardless of visibility
    (generalizes _external_function_signatures' own restriction to
    public/external - nothing about canonicalizing a parameter type is
    visibility-specific, and internal/private functions have no ABI
    selector to fall back on otherwise). None means "cannot be resolved
    with confidence" (a struct/enum/contract-typed parameter) - callers
    must treat that as unresolved, never guess a match."""
    parts = []
    for param in fn.get("params", []) or []:
        canonical = _canonical_param_type(param.get("type"))
        if canonical is None:
            return None
        parts.append(canonical)
    return "%s:%s(%s)" % (fn.get("kind") or "function", fn.get("name") or "", ",".join(parts))


def _unresolved_entry(fn: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {"name": fn.get("name"), "kind": fn.get("kind"), "lineStart": fn.get("lineStart"), "reason": reason}


def _index_functions(functions: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    unresolved: List[Dict[str, Any]] = []
    for fn in functions:
        identity = _function_identity(fn)
        if identity is None:
            unresolved.append(_unresolved_entry(fn, "a parameter type could not be canonicalized (non-elementary type)"))
            continue
        groups.setdefault(identity, []).append(fn)
    by_id: Dict[str, Dict[str, Any]] = {}
    for identity, fns in groups.items():
        if len(fns) == 1:
            by_id[identity] = fns[0]
        else:
            for fn in fns:
                unresolved.append(_unresolved_entry(fn, "identity is ambiguous (shared by %d functions on this side)" % len(fns)))
    return by_id, unresolved


def diff_functions(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
    v1_by_id, unresolved_v1 = _index_functions(c1.get("functions", []) or [])
    v2_by_id, unresolved_v2 = _index_functions(c2.get("functions", []) or [])

    added = sorted(set(v2_by_id) - set(v1_by_id))
    removed = sorted(set(v1_by_id) - set(v2_by_id))
    changed = []
    for identity in sorted(set(v1_by_id) & set(v2_by_id)):
        f1, f2 = v1_by_id[identity], v2_by_id[identity]
        changes: Dict[str, Any] = {}
        for field in ("visibility", "mutability"):
            if f1.get(field) != f2.get(field):
                changes[field] = {"from": f1.get(field), "to": f2.get(field)}
        for field in ("virtual", "override"):
            if bool(f1.get(field)) != bool(f2.get(field)):
                changes[field] = {"from": bool(f1.get(field)), "to": bool(f2.get(field))}
        mods1 = sorted(m.get("name") for m in (f1.get("modifiers") or []) if m.get("name"))
        mods2 = sorted(m.get("name") for m in (f2.get("modifiers") or []) if m.get("name"))
        if mods1 != mods2:
            changes["modifiersAdded"] = sorted(set(mods2) - set(mods1))
            changes["modifiersRemoved"] = sorted(set(mods1) - set(mods2))
        if changes:
            changed.append({"identity": identity, "changes": changes})

    return {
        "functionsAdded": added,
        "functionsRemoved": removed,
        "functionsChanged": changed,
        "unresolvedFunctionsV1": unresolved_v1,
        "unresolvedFunctionsV2": unresolved_v2,
    }


def diff_state_variables(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
    v1_vars = {v["name"]: v for v in (c1.get("stateVariables") or []) if v.get("name")}
    v2_vars = {v["name"]: v for v in (c2.get("stateVariables") or []) if v.get("name")}
    added = sorted(set(v2_vars) - set(v1_vars))
    removed = sorted(set(v1_vars) - set(v2_vars))
    changed = []
    for name in sorted(set(v1_vars) & set(v2_vars)):
        a, b = v1_vars[name], v2_vars[name]
        changes = {}
        for field in ("type", "visibility", "constant", "immutable"):
            if a.get(field) != b.get(field):
                changes[field] = {"from": a.get(field), "to": b.get(field)}
        if changes:
            changed.append({"name": name, "changes": changes})
    return {"stateVariablesAdded": added, "stateVariablesRemoved": removed, "stateVariablesChanged": changed}


def diff_contracts(v1_contracts: List[Dict[str, Any]], v2_contracts: List[Dict[str, Any]]) -> Dict[str, Any]:
    v1_by_key = {c["key"]: c for c in v1_contracts if c.get("key")}
    v2_by_key = {c["key"]: c for c in v2_contracts if c.get("key")}
    added = sorted(set(v2_by_key) - set(v1_by_key))
    removed = sorted(set(v1_by_key) - set(v2_by_key))
    matched = sorted(set(v1_by_key) & set(v2_by_key))

    function_surface_delta = {}
    for key in matched:
        c1, c2 = v1_by_key[key], v2_by_key[key]
        entry = diff_functions(c1, c2)
        entry.update(diff_state_variables(c1, c2))
        function_surface_delta[key] = entry

    return {"contractsAdded": added, "contractsRemoved": removed, "contractsMatched": matched, "functionSurfaceDelta": function_surface_delta}


def _edge_id(edge: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    return (edge.get("kind") or "", edge.get("from") or "", edge.get("to") or "", edge.get("function") or "", edge.get("method") or "")


def diff_system_graph(sg1: Dict[str, Any], sg2: Dict[str, Any]) -> Dict[str, Any]:
    if (sg1 or {}).get("status") != "computed" or (sg2 or {}).get("status") != "computed":
        return {"status": "not_computed", "message": "Both v1 and v2 must have systemGraph.status == 'computed' (pro mode, config/modes.json allowSystemGraph) to compute a systemGraphDelta."}

    nodes1 = {n["key"] for n in sg1.get("nodes", [])}
    nodes2 = {n["key"] for n in sg2.get("nodes", [])}
    edges1 = {_edge_id(e): e for e in sg1.get("edges", [])}
    edges2 = {_edge_id(e): e for e in sg2.get("edges", [])}
    proxies1 = {p["proxy"]: p for p in sg1.get("proxies", []) if p.get("proxy")}
    proxies2 = {p["proxy"]: p for p in sg2.get("proxies", []) if p.get("proxy")}

    proxies_changed = []
    for proxy in sorted(set(proxies1) & set(proxies2)):
        a, b = proxies1[proxy], proxies2[proxy]
        if a.get("implementation") != b.get("implementation") or a.get("status") != b.get("status"):
            proxies_changed.append({
                "proxy": proxy,
                "from": {"implementation": a.get("implementation"), "status": a.get("status")},
                "to": {"implementation": b.get("implementation"), "status": b.get("status")},
            })

    return {
        "status": "computed",
        "nodesAdded": sorted(nodes2 - nodes1),
        "nodesRemoved": sorted(nodes1 - nodes2),
        "edgesAdded": [edges2[k] for k in sorted(set(edges2) - set(edges1))],
        "edgesRemoved": [edges1[k] for k in sorted(set(edges1) - set(edges2))],
        "proxiesChanged": proxies_changed,
    }


def diff_preprocess(v1: Dict[str, Any], v2: Dict[str, Any]) -> Dict[str, Any]:
    _require(isinstance(v1, dict) and isinstance(v2, dict), "both inputs must be JSON objects")
    _require(isinstance(v1.get("contracts"), list), "v1.contracts must be an array (is this a preprocess.py output?)")
    _require(isinstance(v2.get("contracts"), list), "v2.contracts must be an array (is this a preprocess.py output?)")

    result = diff_contracts(v1["contracts"], v2["contracts"])
    result["systemGraphDelta"] = diff_system_graph(v1.get("systemGraph") or {}, v2.get("systemGraph") or {})
    result["diffVersion"] = DIFF_VERSION
    result["mode"] = "preprocess"
    result["v1Meta"] = {"inputHash": v1.get("inputHash"), "mode": v1.get("mode")}
    result["v2Meta"] = {"inputHash": v2.get("inputHash"), "mode": v2.get("mode")}
    result["sameInput"] = v1.get("inputHash") is not None and v1.get("inputHash") == v2.get("inputHash")
    result["note"] = STRUCTURAL_ONLY_NOTE
    result["modifierScopeNote"] = MODIFIER_SCOPE_NOTE
    result["renameNote"] = RENAME_NOTE
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _read_json_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DiffError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diff_reports.py",
        description="Deterministic version comparison / security diff between two explicitly-declared runs of this Skill's pipeline.",
    )
    subparsers = parser.add_subparsers(dest="diff_mode", required=True)

    reports_parser = subparsers.add_parser("reports", help="Diff two post-analysis report JSONs (findings-level).")
    reports_parser.add_argument("v1", help="Path to the V1 (baseline) report JSON.")
    reports_parser.add_argument("v2", help="Path to the V2 (current) report JSON.")
    reports_parser.add_argument("--out", default=None, help="Write the diff to this file instead of stdout.")
    reports_parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")

    preprocess_parser = subparsers.add_parser("preprocess", help="Diff two preprocess.py JSON outputs (structural, no findings).")
    preprocess_parser.add_argument("v1", help="Path to the V1 (baseline) preprocess.py output JSON.")
    preprocess_parser.add_argument("v2", help="Path to the V2 (current) preprocess.py output JSON.")
    preprocess_parser.add_argument("--out", default=None, help="Write the diff to this file instead of stdout.")
    preprocess_parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        v1 = _read_json_file(args.v1)
        v2 = _read_json_file(args.v2)
        if args.diff_mode == "reports":
            result = diff_reports(v1, v2)
        else:
            result = diff_preprocess(v1, v2)
    except (DiffError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
