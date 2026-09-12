# -*- coding: utf-8 -*-
"""Scope-level arithmetic/gas/randomness checks (phase="scope"). Moved
verbatim from the pre-V2.1 detect_solidity_signals monolith.

unbounded-loop and msg-value-in-loop both need the same per-loop analysis
(loop_spans() plus which arrays/external-calls/state-writes appear in each
loop body); rather than share that analysis in a mutable side list, each
detector below recomputes it via _analyze_loops - a bounded cost (proportional
to the number of loops in the contract, not file size) that keeps both
detectors genuinely independent and callable on their own.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .context import collapse_ws, fn_at, in_assembly, loop_spans, locate_scope, param_names, statement_at
from text_utils import matching_paren, truncate

DIVISION_RE = re.compile(r"[\w\)\]]\s*/(?![/=*])\s*[\w\(\[][^;{}]*?(?<![*/])\*(?!\*|/)")
HARDCODED_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
RANDOM_SOURCE_RE = re.compile(r"\bblock\.timestamp\b|\bnow\b|\bblock\.prevrandao\b|\bblock\.difficulty\b|\bblockhash\s*\(|\bblock\.number\b|\bblock\.coinbase\b|\bgasleft\s*\(")
RANDOM_USE_RE = re.compile(r"keccak256|abi\.encodePacked|abi\.encode\b|%|\brandom|\bseed\b|\blottery|\bwinner|\bdraw\b|\bdice|\broll\b|\braffle", re.I)
RANDOM_FUNCTION_RE = re.compile(r"random|lottery|draw|winner|seed|dice|roll|raffle|jackpot", re.I)
# --- V2.1 detector-expansion, second block (docs/decisiones.md D-033) ---
NARROW_CAST_RE = re.compile(r"\b(u?int)(\d{1,3})\s*\(")
LITERAL_ARG_RE = re.compile(r"^(\d+|0x[0-9a-fA-F]+)$")


def detect_hardcoded_address(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in HARDCODED_ADDRESS_RE.finditer(body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        stmt, _ = statement_at(masked, offset, span_start, ctx["span_end"])
        ctx["collector"].add("hardcoded-address.general", offset, ctx["cname"], scope, {"value": match.group(0), "statement": truncate(collapse_ws(stmt), 120)[0]})


def detect_unchecked_block(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    pairs = ctx["pairs"]
    for match in re.finditer(r"\bunchecked\s*\{", body):
        offset = span_start + match.start()
        open_brace = span_start + match.end() - 1
        close_brace = pairs.get(open_brace, ctx["span_end"])
        block = masked[open_brace:close_brace]
        scope = locate_scope(contract, offset)
        ctx["collector"].add("unchecked-block.general", offset, ctx["cname"], scope, {
            "lineEnd": ctx["line_index"].line_of(close_brace),
            "containsArithmetic": bool(re.search(r"[\w\)\]]\s*[+\-*]\s*[\w\(]|\+\+|--|[+\-*]=", block)),
            "containsSubtraction": bool(re.search(r"[\w\)\]]\s*-\s*[\w\(]|-=|--", block)),
        })


def detect_timestamp_dependence(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in re.finditer(r"\bblock\.timestamp\b|(?<![\w.])now(?![\w(])", body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        stmt, _ = statement_at(masked, offset, span_start, ctx["span_end"])
        collapsed = collapse_ws(stmt)
        if RANDOM_USE_RE.search(collapsed):
            usage = "randomness"
        elif re.search(r"[<>]=?|==|!=", collapsed):
            usage = "comparison"
        elif re.search(r"[+\-*/]", collapsed):
            usage = "arithmetic"
        else:
            usage = "other"
        ctx["collector"].add("timestamp-dependence.general", offset, ctx["cname"], scope, {"usage": usage})


def detect_weak_randomness(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    seen: set = set()
    for match in RANDOM_SOURCE_RE.finditer(body):
        offset = span_start + match.start()
        stmt, stmt_start = statement_at(masked, offset, span_start, ctx["span_end"])
        if stmt_start in seen:
            continue
        collapsed = collapse_ws(stmt)
        fn = fn_at(ctx, offset)
        fn_name = (fn["name"] or "") if fn else ""
        if not (RANDOM_USE_RE.search(collapsed) or RANDOM_FUNCTION_RE.search(fn_name)):
            continue
        seen.add(stmt_start)
        scope = locate_scope(contract, offset)
        sources = sorted(set(collapse_ws(m.group(0)).rstrip("(") for m in RANDOM_SOURCE_RE.finditer(collapsed)))
        ctx["collector"].add("weak-randomness.general", offset, ctx["cname"], scope, {
            "sources": sources,
            "usedWithHash": bool(re.search(r"keccak256|abi\.encodePacked|abi\.encode\b", collapsed)),
            "usedWithModulo": "%" in collapsed,
        })


def detect_division_before_multiplication(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in DIVISION_RE.finditer(body):
        offset = span_start + match.start()
        if in_assembly(ctx, offset):
            continue
        stmt, _ = statement_at(masked, offset, span_start, ctx["span_end"])
        collapsed = collapse_ws(stmt)
        if not re.search(r"=|\breturn\b", collapsed):
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("division-before-multiplication.general", offset, ctx["cname"], scope, {"expression": truncate(collapsed, 120)[0]})


def _analyze_loops(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    masked, span_start, span_end, pairs = ctx["masked"], ctx["span_start"], ctx["span_end"], ctx["pairs"]
    state_types = ctx["state_types"]
    results = []
    for loop in loop_spans(masked, span_start, span_end, pairs):
        fn = fn_at(ctx, loop["start"])
        header = loop["header"]
        arrays: List[Dict[str, str]] = []
        for arr in re.findall(r"([A-Za-z_$][\w$.]*)\s*\.length\b", header):
            root = arr.split(".")[0]
            if root in state_types:
                kind = "state"
            elif fn and root in param_names(fn):
                kind = "parameter"
            else:
                kind = "unknown"
            arrays.append({"name": arr, "kind": kind})
        no_condition = header.replace(" ", "") in ("", ";;", "true") or re.match(r"^\s*;\s*;\s*$", header) is not None
        loop_body = masked[loop["bodyStart"]:loop["bodyEnd"]]
        external_in_loop = any(loop["bodyStart"] <= off <= loop["bodyEnd"] for off, _ in ctx["external_call_offsets"])
        msg_value_in_loop = re.search(r"\bmsg\.value\b", loop_body) is not None
        unbounded = no_condition or any(a["kind"] in ("state", "unknown") for a in arrays) or (external_in_loop and bool(arrays))
        results.append({"loop": loop, "arrays": arrays, "noCondition": no_condition, "loopBody": loop_body, "externalInLoop": external_in_loop, "msgValueInLoop": msg_value_in_loop, "unbounded": unbounded})
    return results


def detect_unbounded_loop(ctx: Dict[str, Any]) -> None:
    contract = ctx["contract"]
    for r in _analyze_loops(ctx):
        if not r["unbounded"]:
            continue
        loop = r["loop"]
        scope = locate_scope(contract, loop["start"])
        ctx["collector"].add("unbounded-loop.general", loop["start"], ctx["cname"], scope, {
            "loopKind": loop["kind"],
            "arrays": r["arrays"],
            "noCondition": r["noCondition"],
            "externalCallInLoop": r["externalInLoop"],
            "msgValueInLoop": r["msgValueInLoop"],
            "stateWriteInLoop": bool(ctx["state_names"]) and any(re.search(r"\b" + re.escape(name) + r"\b(\s*\[[^\]]*\])*\s*(=(?!=)|\+=|-=|\+\+|--)|\b" + re.escape(name) + r"\s*\.\s*push\s*\(", r["loopBody"]) for name in ctx["state_names"]),
            "lineEnd": ctx["line_index"].line_of(loop["bodyEnd"]),
        })


def detect_msg_value_in_loop(ctx: Dict[str, Any]) -> None:
    contract = ctx["contract"]
    for r in _analyze_loops(ctx):
        if not r["msgValueInLoop"]:
            continue
        loop = r["loop"]
        mv = re.search(r"\bmsg\.value\b", r["loopBody"])
        mv_offset = loop["bodyStart"] + (mv.start() if mv else 0)
        ctx["collector"].add("msg-value-in-loop.general", mv_offset, ctx["cname"], locate_scope(contract, mv_offset), {"loopLine": ctx["line_index"].line_of(loop["start"])})


def detect_external_call_in_loop(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, first block (docs/decisiones.md D-032).
    Distinct root cause from unbounded-loop: even a loop with a small, fixed
    bound is a gas-griefing/DoS surface if one iteration's external call can
    revert (a malicious or just broken recipient blocks the whole batch) -
    the loop's bound doesn't matter, only whether a call sits inside it.
    Reuses `_analyze_loops` (already computed for unbounded-loop/
    msg-value-in-loop, recomputed here per the module's documented
    independent-detectors tradeoff) rather than adding a new scan."""
    contract = ctx["contract"]
    for r in _analyze_loops(ctx):
        if not r["externalInLoop"]:
            continue
        loop = r["loop"]
        scope = locate_scope(contract, loop["start"])
        ctx["collector"].add("external-call-in-loop.general", loop["start"], ctx["cname"], scope, {
            "loopKind": loop["kind"],
            "arrays": r["arrays"],
            "noCondition": r["noCondition"],
            "lineEnd": ctx["line_index"].line_of(loop["bodyEnd"]),
        })


def detect_gas_unbounded_storage_array_push(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, first block (docs/decisiones.md D-032).
    A storage array that only ever grows (public/external `.push()`, no
    visible upper-bound check) is a potential future gas-DoS on whatever
    later iterates it - a signal about unbounded *growth over many
    transactions*, distinct from unbounded-loop's single-call iteration
    concern. Potential signal only: many such arrays are bounded by an
    orthogonal business rule (e.g. a whitelist capped elsewhere) this
    heuristic cannot see - hence fpRisk high."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    state_types = ctx["state_types"]
    array_names = [n for n in ctx["state_names"] if "[" in (state_types.get(n) or "")]
    for name in array_names:
        pattern = re.compile(r"\b" + re.escape(name) + r"\s*\.\s*push\s*\(")
        for match in pattern.finditer(body):
            offset = span_start + match.start()
            fn = fn_at(ctx, offset)
            if not fn or fn["visibility"] not in ("public", "external"):
                continue
            fbody = fn.get("_body", "")
            has_cap = bool(re.search(r"\b" + re.escape(name) + r"\s*\.\s*length\b\s*[<>]=?|require\s*\([^;]*\b" + re.escape(name) + r"\.length\b[^;]*\)", fbody))
            if has_cap:
                continue
            scope = locate_scope(contract, offset)
            ctx["collector"].add("gas-unbounded-storage-array-push.general", offset, ctx["cname"], scope, {"array": name, "function": scope.get("function")})


def detect_unsafe_downcast(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, second block (docs/decisiones.md D-033).
    An explicit narrowing cast (`uint128(x)`, `int64(x)`, ...) truncates
    silently instead of reverting, unlike OpenZeppelin's SafeCast
    (`x.toUint128()` - a different, camelCase method-name syntax that this
    cast-syntax regex never matches, so no explicit SafeCast exclusion is
    needed). Skips casts of a plain numeric/hex literal (provably safe,
    cannot overflow) to cut the most obvious false positives."""
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in NARROW_CAST_RE.finditer(body):
        bits = int(match.group(2))
        if bits >= 256 or bits % 8 != 0:
            continue
        offset = span_start + match.start()
        if in_assembly(ctx, offset):
            continue
        open_paren = span_start + match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        if close_paren == -1:
            continue
        arg = collapse_ws(masked[open_paren + 1:close_paren])
        if LITERAL_ARG_RE.match(arg):
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("unsafe-downcast.general", offset, ctx["cname"], scope, {"targetType": match.group(1) + match.group(2), "expression": truncate(arg, 80)[0]})


CHECKS = [
    ("hardcoded-address.general", detect_hardcoded_address),
    ("unchecked-block.general", detect_unchecked_block),
    ("timestamp-dependence.general", detect_timestamp_dependence),
    ("weak-randomness.general", detect_weak_randomness),
    ("division-before-multiplication.general", detect_division_before_multiplication),
    ("unbounded-loop.general", detect_unbounded_loop),
    ("msg-value-in-loop.general", detect_msg_value_in_loop),
    ("external-call-in-loop.general", detect_external_call_in_loop),
    ("gas-unbounded-storage-array-push.general", detect_gas_unbounded_storage_array_push),
    ("unsafe-downcast.general", detect_unsafe_downcast),
]
