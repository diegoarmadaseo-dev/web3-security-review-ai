# -*- coding: utf-8 -*-
"""Vyper's limited signal coverage (checklist.md: inventory plus a small,
explicit subset of the Solidity families). Moved verbatim from the pre-V2.1
detect_vyper_signals monolith. Orchestrated separately from the Solidity
checks (see preprocess.py) since Vyper's structural inventory shape differs,
but every check here still reads from the shared registry for its metadata
and reuses the same checkIds as their Solidity counterparts (e.g.
"tx-origin.general") - one family, one piece of metadata, two languages.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .context import collapse_ws
from text_utils import matching_paren, split_top_level

RANDOM_USE_RE = re.compile(r"keccak256|abi\.encodePacked|abi\.encode\b|%|\brandom|\bseed\b|\blottery|\bwinner|\bdraw\b|\bdice|\broll\b|\braffle", re.I)


def build_vyper_context(entry: Dict[str, Any], registry: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    from .context import SignalCollector
    masked = entry["masked"]
    line_index = entry["lineIndex"]
    structure = entry["structure"]
    contract = structure["contracts"][0]
    return {
        "masked": masked,
        "line_index": line_index,
        "structure": structure,
        "contract": contract,
        "cname": contract["name"],
        "collector": SignalCollector(entry["path"], line_index, registry),
        "call_offsets": [],
    }


def scope_for(ctx: Dict[str, Any], offset: int) -> Dict[str, Optional[str]]:
    line = ctx["line_index"].line_of(offset)
    for fn in ctx["contract"]["functions"]:
        if fn["lineStart"] <= line <= fn["lineEnd"]:
            return {"function": fn["name"], "modifier": None, "kind": fn["kind"]}
    return {"function": None, "modifier": None, "kind": None}


def detect_pragma_missing(ctx: Dict[str, Any]) -> None:
    pragma = ctx["structure"]["pragma"]
    if pragma["present"]:
        return
    ctx["collector"].add("pragma-missing.general", 0, ctx["cname"], {"function": None, "modifier": None, "kind": None}, {"language": "vyper"}, line=1)


def detect_floating_pragma(ctx: Dict[str, Any]) -> None:
    pragma = ctx["structure"]["pragma"]
    if not pragma["present"] or not pragma["floating"]:
        return
    ctx["collector"].add("floating-pragma.general", ctx["line_index"].offset_of_line(pragma["line"]), ctx["cname"], {"function": None, "modifier": None, "kind": None}, {"expression": pragma["expression"], "minVersion": pragma["minVersion"]}, line=pragma["line"])


def detect_tx_origin(ctx: Dict[str, Any]) -> None:
    for match in re.finditer(r"\btx\.origin\b", ctx["masked"]):
        ctx["collector"].add("tx-origin.general", match.start(), ctx["cname"], scope_for(ctx, match.start()), {"inCondition": True})


def detect_selfdestruct(ctx: Dict[str, Any]) -> None:
    for match in re.finditer(r"\bselfdestruct\s*\(", ctx["masked"]):
        ctx["collector"].add("selfdestruct.general", match.start(), ctx["cname"], scope_for(ctx, match.start()), {"guarded": False, "inAssembly": False})


def detect_timestamp_dependence(ctx: Dict[str, Any]) -> None:
    line_index = ctx["line_index"]
    for match in re.finditer(r"\bblock\.timestamp\b", ctx["masked"]):
        stmt = collapse_ws(line_index.line_text(line_index.line_of(match.start())))
        usage = "randomness" if RANDOM_USE_RE.search(stmt) else "comparison" if re.search(r"[<>]=?|==|!=", stmt) else "other"
        ctx["collector"].add("timestamp-dependence.general", match.start(), ctx["cname"], scope_for(ctx, match.start()), {"usage": usage})


def detect_weak_randomness(ctx: Dict[str, Any]) -> None:
    line_index = ctx["line_index"]
    for match in re.finditer(r"\bblock\.prevrandao\b|\bblock\.difficulty\b|\bblockhash\s*\(", ctx["masked"]):
        stmt = collapse_ws(line_index.line_text(line_index.line_of(match.start())))
        ctx["collector"].add("weak-randomness.general", match.start(), ctx["cname"], scope_for(ctx, match.start()), {"sources": [collapse_ws(match.group(0)).rstrip("(")], "usedWithHash": "keccak256" in stmt, "usedWithModulo": "%" in stmt})


def detect_low_level_call(ctx: Dict[str, Any]) -> None:
    """Also emits delegatecall.general for is_delegate_call=True raw_call()
    sites, and appends every match offset to ctx['call_offsets'] (read later
    by detect_reentrancy_pattern) - same coupling as the Solidity module."""
    masked, line_index = ctx["masked"], ctx["line_index"]
    for match in re.finditer(r"\b(raw_call|send)\s*\(", masked):
        open_paren = match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        args = collapse_ws(masked[open_paren + 1:close_paren]) if close_paren != -1 else ""
        is_delegate = "is_delegate_call=True" in args.replace(" ", "")
        scope = scope_for(ctx, match.start())
        if is_delegate:
            ctx["collector"].add("delegatecall.general", match.start(), ctx["cname"], scope, {"target": split_top_level(args)[0] if split_top_level(args) else None, "inAssembly": False, "targetIsParameter": False, "inFallback": scope.get("function") == "__default__", "guarded": False})
        line_text = collapse_ws(line_index.line_text(line_index.line_of(match.start())))
        prefix = line_text[:line_text.find(match.group(1))]
        checked = "=" in prefix or "assert" in prefix or "revert_on_failure=False" not in args.replace(" ", "")
        ctx["collector"].add("low-level-call.general", match.start(), ctx["cname"], scope, {"kind": match.group(1), "target": split_top_level(args)[0] if split_top_level(args) else None, "returnChecked": checked, "valueForwarded": "value=" in args.replace(" ", ""), "targetIsParameter": False})
        ctx["call_offsets"].append(match.start())


def enrich_and_detect_reentrancy(ctx: Dict[str, Any]) -> None:
    """Vyper's per-function enrichment and reentrancy-pattern check are as
    tightly coupled in the source monolith as their Solidity counterparts
    (context.enrich_function / access_control.detect_reentrancy_pattern) -
    kept together here for the same reason: no shared side list to avoid
    duplicating the pass over every function."""
    masked, line_index, contract = ctx["masked"], ctx["line_index"], ctx["contract"]
    for fn in contract["functions"]:
        if fn["visibility"] != "external" or fn["mutability"] in ("view", "pure"):
            continue
        guarded = any(m["name"] == "nonreentrant" for m in fn["modifiers"])
        fn_calls = [off for off in ctx["call_offsets"] if fn["lineStart"] <= line_index.line_of(off) <= fn["lineEnd"]]
        if fn_calls and not guarded:
            first = fn_calls[0]
            after = masked[first:line_index.offset_of_line(fn["lineEnd"]) + len(line_index.line_text(fn["lineEnd"]))]
            writes = sorted(set(line_index.line_of(first + m.start()) for m in re.finditer(r"\bself\.\w+(\[[^\]]*\])?\s*(=(?!=)|\+=|-=)", after)))
            if writes:
                ctx["collector"].add("reentrancy-pattern.general", first, ctx["cname"], {"function": fn["name"], "modifier": None, "kind": fn["kind"]}, {"callLine": line_index.line_of(first), "stateWritesAfterCall": writes, "internalCallsAfterCall": [], "guarded": False, "externalCallCount": len(fn_calls)})
        fn["accessControl"] = {"modifiers": [], "bodyGuards": sorted(set(collapse_ws(m.group(0)) for m in re.finditer(r"msg\.sender\s*==\s*self\.\w+|assert\s+msg\.sender", fn["_body"]))), "guarded": bool(re.search(r"msg\.sender\s*==|assert\s+msg\.sender", fn["_body"]))}
        fn["stateChanging"] = True
        fn["reentrancyGuarded"] = guarded


# Called in this exact order by preprocess.py's Vyper orchestrator - low-level
# call detection must run before enrich_and_detect_reentrancy (populates
# call_offsets it depends on).
CHECKS = [
    detect_pragma_missing,
    detect_floating_pragma,
    detect_tx_origin,
    detect_selfdestruct,
    detect_timestamp_dependence,
    detect_weak_randomness,
    detect_low_level_call,
    enrich_and_detect_reentrancy,
]
