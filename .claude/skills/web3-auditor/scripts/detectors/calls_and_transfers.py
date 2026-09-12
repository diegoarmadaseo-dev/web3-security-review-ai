# -*- coding: utf-8 -*-
"""Scope-level checks around external calls, tokens and low-level primitives
(phase="scope"). Moved verbatim from the pre-V2.1 detect_solidity_signals
monolith.

Ordering matters here and is enforced by registration order in registry.py,
not by this module: low-level-call, token-transfer-unchecked and
external-call each append to the shared `ctx["external_call_offsets"]` list
(read later, in this same scope, by reentrancy-pattern and unbounded-loop -
see arithmetic_and_gas.py and access_control.py) - a documented, minimal
exception to "no shared side effects" needed because those two checks
require the *aggregate* view across all three call-shaped families, and
re-deriving it independently inside each would mean duplicating three
separate regexes rather than one. arbitrary-external-call and
arbitrary-from-transfer used to share a regex match with low-level-call and
token-transfer-unchecked respectively; V2.1 gives each its own independent
scan instead (same pattern, negligible extra cost) so they are genuinely
standalone checks.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from .context import ASSEMBLY_OPCODES_RE, classify_call_hint, collapse_ws, fn_at as _fn_at, function_access_info, in_assembly, locate_scope, param_names, statement_at
from text_utils import ELEMENTARY_TYPES, matching_paren, split_top_level

ETH_LIKE_BASE_RE = re.compile(r"^(payable\s*\(|address\s*\(|msg\.sender$|tx\.origin$|owner$|_owner$|recipient$|to$|_to$|receiver$|beneficiary$)")
# --- V2.1 detector-expansion, second block (docs/decisiones.md D-033) ---
CALL_VALUE_RE = re.compile(r"\.(call|send)\s*\{([^}]*)\}\s*\(")
VALUE_ARG_RE = re.compile(r"\bvalue\s*:\s*([A-Za-z_$][\w$]*)\s*(,|$)")
BALANCE_CHECK_RE_TEMPLATE = r"\b([A-Za-z_$][\w$]*)\s*\[[^\]]*\]\s*>=\s*{v}\b"
BALANCE_DECREMENT_RE_TEMPLATE = r"\b{name}\s*\[[^\]]*\]\s*-=\s*{v}\b"


def detect_tx_origin(ctx: Dict[str, Any]) -> None:
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    masked = ctx["masked"]
    for match in re.finditer(r"\btx\.origin\b", body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        stmt, _ = statement_at(masked, offset, span_start, ctx["span_end"])
        in_condition = bool(re.search(r"\b(require|if|assert)\s*\(|[!=]=", stmt))
        ctx["collector"].add("tx-origin.general", offset, ctx["cname"], scope, {"inCondition": in_condition})


def detect_delegatecall(ctx: Dict[str, Any]) -> None:
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in re.finditer(r"([A-Za-z_$][\w$.\[\]()]*?)\s*\.delegatecall\s*(\{[^}]*\})?\s*\(|(?<![.\w])delegatecall\s*\(", body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        assembly_hit = match.group(0).lstrip().startswith("delegatecall")
        if assembly_hit and not in_assembly(ctx, offset):
            continue
        target = collapse_ws(match.group(1) or "") if not assembly_hit else None
        fn = _fn_at(ctx, offset)
        ctx["collector"].add("delegatecall.general", offset, ctx["cname"], scope, {
            "target": target,
            "inAssembly": assembly_hit or in_assembly(ctx, offset),
            "targetIsParameter": bool(target and target in param_names(fn)),
            "inFallback": scope.get("kind") == "fallback",
            "guarded": function_access_info(fn)["guarded"] if fn else False,
        })


def detect_selfdestruct(ctx: Dict[str, Any]) -> None:
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in re.finditer(r"\b(selfdestruct|suicide)\s*\(", body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        fn = _fn_at(ctx, offset)
        ctx["collector"].add("selfdestruct.general", offset, ctx["cname"], scope, {"guarded": function_access_info(fn)["guarded"] if fn else False, "inAssembly": in_assembly(ctx, offset)})


def detect_low_level_call(ctx: Dict[str, Any]) -> None:
    """Also appends (offset, kind) to ctx['external_call_offsets'] for every
    non-staticcall match - see the module docstring."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    masked = ctx["masked"]
    for match in re.finditer(r"([A-Za-z_$][\w$.\[\]()]*?)\s*\.(call|send|staticcall|callcode)\s*(\{[^}]*\})?\s*\(", body):
        offset = span_start + match.start()
        if in_assembly(ctx, offset):
            continue
        scope = locate_scope(contract, offset)
        stmt, stmt_start = statement_at(masked, offset, span_start, ctx["span_end"])
        prefix = collapse_ws(masked[stmt_start:offset])
        checked = bool(re.search(r"(=|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\(\s*bool\b|&&|\|\|)", prefix))
        value_forwarded = "{" in (match.group(3) or "") and "value" in (match.group(3) or "")
        kind = match.group(2)
        target = collapse_ws(match.group(1))
        fn = _fn_at(ctx, offset)
        ctx["collector"].add("low-level-call.general", offset, ctx["cname"], scope, {
            "kind": kind,
            "target": target,
            "returnChecked": checked,
            "valueForwarded": value_forwarded,
            "targetIsParameter": target in param_names(fn),
        })
        if kind != "staticcall":
            ctx["external_call_offsets"].append((offset, "low-level-call"))


def detect_arbitrary_external_call(ctx: Dict[str, Any]) -> None:
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    masked = ctx["masked"]
    for match in re.finditer(r"([A-Za-z_$][\w$.\[\]()]*?)\s*\.(call|send|staticcall|callcode)\s*(\{[^}]*\})?\s*\(", body):
        offset = span_start + match.start()
        if in_assembly(ctx, offset):
            continue
        kind = match.group(2)
        if kind != "call":
            continue
        target = collapse_ws(match.group(1))
        fn = _fn_at(ctx, offset)
        data_match = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\)", masked[span_start + match.end():span_start + match.end() + 80])
        base_ident = re.sub(r"^(address|payable)\s*\(\s*", "", target).rstrip(") ")
        if fn and data_match and data_match.group(1) in param_names(fn) and base_ident in param_names(fn):
            scope = locate_scope(contract, offset)
            ctx["collector"].add("arbitrary-external-call.general", offset, ctx["cname"], scope, {"targetParam": base_ident, "dataParam": data_match.group(1), "guarded": function_access_info(fn)["guarded"]})


def _classify_transfer_match(ctx, match):
    span_start = ctx["span_start"]
    offset = span_start + match.start()
    base = collapse_ws(match.group(1))
    method = match.group(2)
    base_ident = re.sub(r"\s*\(.*$", "", base)
    fn = _fn_at(ctx, offset)
    base_type = ctx["state_types"].get(base_ident) or next((p["type"] for p in (fn["params"] if fn else []) if p.get("name") == base_ident), None)
    if base_type is None and "(" in base and base_ident[:1].isupper():
        base_type = base_ident
    is_eth_transfer = method == "transfer" and (ETH_LIKE_BASE_RE.match(base) is not None or (base_type is not None and base_type.startswith("address")))
    return offset, base, method, base_ident, base_type, fn, is_eth_transfer


def detect_token_transfer_unchecked(ctx: Dict[str, Any]) -> None:
    """Also appends (offset, "eth-transfer"|"token-transfer") to
    ctx['external_call_offsets'] for every transfer-shaped match, checked or
    not - see the module docstring."""
    contract, body = ctx["contract"], ctx["body"]
    masked = ctx["masked"]
    for match in re.finditer(r"([A-Za-z_$][\w$]*(?:\s*\([^()]*\))?)\s*\.(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(", body):
        offset, base, method, base_ident, base_type, fn, is_eth_transfer = _classify_transfer_match(ctx, match)
        if in_assembly(ctx, offset):
            continue
        if is_eth_transfer:
            ctx["external_call_offsets"].append((offset, "eth-transfer"))
            continue
        ctx["external_call_offsets"].append((offset, "token-transfer"))
        scope = locate_scope(contract, offset)
        stmt, stmt_start = statement_at(masked, offset, ctx["span_start"], ctx["span_end"])
        prefix = collapse_ws(masked[stmt_start:offset])
        checked = bool(re.search(r"(=|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\(\s*bool\b|&&|\|\|)", prefix))
        if method in ("safeTransfer", "safeTransferFrom"):
            checked = True
        if not checked:
            ctx["collector"].add("token-transfer-unchecked.general", offset, ctx["cname"], scope, {"method": method, "callee": base_ident, "calleeType": base_type, "typeKnown": base_type is not None})


def detect_arbitrary_from_transfer(ctx: Dict[str, Any]) -> None:
    contract, body = ctx["contract"], ctx["body"]
    masked = ctx["masked"]
    for match in re.finditer(r"([A-Za-z_$][\w$]*(?:\s*\([^()]*\))?)\s*\.(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(", body):
        offset, base, method, base_ident, base_type, fn, is_eth_transfer = _classify_transfer_match(ctx, match)
        if in_assembly(ctx, offset):
            continue
        if is_eth_transfer:
            continue
        if method not in ("transferFrom", "safeTransferFrom") or not fn:
            continue
        args = masked[ctx["span_start"] + match.end():ctx["span_start"] + match.end() + 120]
        first = re.match(r"\s*([A-Za-z_$][\w$]*)\s*,", args)
        if first and first.group(1) in param_names(fn) and first.group(1) not in ("msg", "this"):
            scope = locate_scope(contract, offset)
            ctx["collector"].add("arbitrary-from-transfer.general", offset, ctx["cname"], scope, {"fromParam": first.group(1), "method": method, "guarded": function_access_info(fn)["guarded"]})


def detect_external_call(ctx: Dict[str, Any]) -> None:
    """Also appends (offset, "external-call") to
    ctx['external_call_offsets'], and a call record to ctx['calls'] - see the
    module docstring."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    cname, state_user_types = ctx["cname"], ctx["state_user_types"]
    declared_types = ctx["declared_types"]
    for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*(\(([^()]*)\))?\s*\.\s*([A-Za-z_$][\w$]*)\s*(\{[^}]*\})?\s*\(", body):
        offset = span_start + match.start()
        if in_assembly(ctx, offset):
            continue
        base = match.group(1)
        cast_args = match.group(3)
        method = match.group(4)
        if base in ("msg", "abi", "block", "tx", "type", "bytes", "string", "address", "payable", "super", "keccak256", "require", "assert", "revert", "unchecked"):
            continue
        if method in ("call", "delegatecall", "staticcall", "callcode", "send", "transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "push", "pop", "length", "selector", "encode", "encodePacked", "decode", "encodeWithSelector", "encodeWithSignature", "code", "balance", "max", "min"):
            continue
        fn = _fn_at(ctx, offset)
        callee_type = None
        if cast_args is not None:
            if base[0].isupper() and base not in ("Math", "SafeMath", "SafeCast", "Strings", "Address"):
                callee_type = base
            else:
                continue
        elif base == "this":
            callee_type = cname
        elif base in state_user_types:
            callee_type = state_user_types[base]
        else:
            ptype = next((p["type"] for p in (fn["params"] if fn else []) if p.get("name") == base), None)
            if ptype and not ELEMENTARY_TYPES.match(ptype.split("[")[0].split(" ")[0]):
                callee_type = re.sub(r"\[.*$", "", ptype)
            else:
                continue
        if callee_type and declared_types.get(callee_type) == "library":
            continue
        scope = locate_scope(contract, offset)
        hints = classify_call_hint(method)
        signal = ctx["collector"].add("external-call.general", offset, cname, scope, {
            "callee": base,
            "calleeType": callee_type,
            "method": method,
            "valueForwarded": bool(match.group(5) and "value" in match.group(5)),
            "categoryHints": hints,
        })
        ctx["calls"].append({"contract": cname, "function": scope.get("function"), "line": signal["line"], "callee": base, "calleeType": callee_type, "method": method})
        ctx["external_call_offsets"].append((offset, "external-call"))


def detect_assembly_block(ctx: Dict[str, Any]) -> None:
    original = ctx["original"]
    for match_start, open_brace, close_brace in ctx["assembly_spans"]:
        block = ctx["masked"][open_brace:close_brace]
        opcodes = sorted(set(ASSEMBLY_OPCODES_RE.findall(block)))
        memory_safe = "memory-safe" in original[match_start:open_brace]
        scope = locate_scope(ctx["contract"], open_brace)
        ctx["collector"].add("assembly-block.general", match_start, ctx["cname"], scope, {"opcodes": opcodes, "memorySafe": memory_safe, "lineEnd": ctx["line_index"].line_of(close_brace)})


def detect_call_value_from_parameter(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, second block (docs/decisiones.md D-033).
    `.call{value: X}(...)`/`.send{value: X}(...)` where X is exactly a
    caller-supplied function parameter (not a derived expression - the
    trailing `(,|$)` in VALUE_ARG_RE requires the captured identifier to be
    the *whole* value option, so `value: amt / 2` does not match). Reuses
    `param_names`/`in_assembly`/`locate_scope`, already imported for the
    module's other checks.

    Suppresses the extremely common, checks-effects-interactions-correct
    withdraw idiom - `require(balances[msg.sender] >= amount); balances[msg.
    sender] -= amount; ... .call{value: amount}(...)` - by looking, in the
    text strictly before the call within the same function, for a
    `mapping[...] >= amount`-shaped check *and* a `mapping[...] -= amount`
    decrement of that same mapping, both before the call. Found via the
    FP audit against evals/cases/ (docs/decisiones.md D-033): the
    unrefined version fired on 2 of the suite's "clean" fixtures using
    exactly this idiom - fixed here, not shipped with the looser fpRisk
    that would have masked it."""
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in CALL_VALUE_RE.finditer(body):
        offset = span_start + match.start()
        if in_assembly(ctx, offset):
            continue
        opts = collapse_ws(match.group(2)).strip()
        value_match = VALUE_ARG_RE.search(opts)
        if not value_match:
            continue
        value_expr = value_match.group(1)
        fn = _fn_at(ctx, offset)
        if value_expr not in param_names(fn):
            continue
        if fn["_bodyStart"] is not None:
            before_call = masked[fn["_bodyStart"]:offset]
            check_match = re.search(BALANCE_CHECK_RE_TEMPLATE.format(v=re.escape(value_expr)), before_call)
            if check_match:
                decrement_re = re.compile(BALANCE_DECREMENT_RE_TEMPLATE.format(name=re.escape(check_match.group(1)), v=re.escape(value_expr)))
                if decrement_re.search(before_call):
                    continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("call-value-from-parameter.general", offset, ctx["cname"], scope, {"kind": match.group(1), "valueParam": value_expr})


CHECKS = [
    ("assembly-block.general", detect_assembly_block),
    ("low-level-call.general", detect_low_level_call),
    ("arbitrary-external-call.general", detect_arbitrary_external_call),
    ("token-transfer-unchecked.general", detect_token_transfer_unchecked),
    ("arbitrary-from-transfer.general", detect_arbitrary_from_transfer),
    ("external-call.general", detect_external_call),
    ("tx-origin.general", detect_tx_origin),
    ("delegatecall.general", detect_delegatecall),
    ("selfdestruct.general", detect_selfdestruct),
    ("call-value-from-parameter.general", detect_call_value_from_parameter),
]
