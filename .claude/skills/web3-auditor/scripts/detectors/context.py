# -*- coding: utf-8 -*-
"""Shared, deterministic context that every detector in this package reads
from - never re-parses raw text on its own (V2.1, docs/decisiones.md).

A detector is a pure function of this context: given the same context dict,
it always returns the same signals, with no side effects other than
appending to the shared SignalCollector (and, for the small, explicitly
documented set of detectors that also populate `external_call_offsets`,
that one shared list - see the note on CALL_OFFSET_CONTRIBUTORS below).
Nothing here does its own top-level regex scan of a whole file; scans happen
once (here, or inside a single detector) and the result is shared.

Everything in this module is moved, not rewritten, from the pre-V2.1
`detect_solidity_signals` monolith: same regexes, same logic, same order of
operations, so detection behavior is byte-for-byte unchanged. See
docs/decisiones.md for the migration record and the before/after
preprocess.py output diff that verified this.
"""
from __future__ import annotations

import functools
import re
from typing import Any, Dict, List, Optional, Tuple

from text_utils import LineIndex, collapse_ws  # noqa: F401 - re-exported for detector modules

# ---------------------------------------------------------------------------
# Shared regexes used by more than one detector (family-specific regexes live
# in their own detector module instead).
# ---------------------------------------------------------------------------

ACCESS_MODIFIER_RE = re.compile(r"^(only|auth|requires?|restricted|isOwner|isAdmin|when|has|check|protected|guarded|permissioned)", re.I)
NON_ACCESS_MODIFIERS = {"whenNotPaused", "whenPaused", "nonReentrant", "noReentrant", "nonreentrant", "lock", "initializer", "reinitializer", "onlyInitializing", "payable"}
BODY_GUARD_RE = re.compile(r"msg\.sender\s*[!=]=|[!=]=\s*msg\.sender|require\s*\(\s*msg\.sender|_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\(|_onlyOwner\s*\(|_onlyAdmin\s*\(|isOwner\s*\(|_msgSender\s*\(\s*\)\s*[!=]=|[!=]=\s*_msgSender\s*\(\s*\)|revert\s+\w*(Unauthorized|NotOwner|NotAdmin|OnlyOwner|Forbidden)|onlyOwner\s*\(|_requireOwner|_authorizeCaller|_checkAuth|auth\s*\(")
REENTRANCY_GUARD_RE = re.compile(r"^(nonReentrant|noReentrant|nonreentrant|lock|locked|mutex|reentrancyGuard|noReentrancy|nonReentrantView)$", re.I)
INTERNAL_STATE_CALL_RE = re.compile(r"\b(_mint|_burn|_transfer|_update|_set\w*|_add\w*|_remove\w*|_write\w*|_increase\w*|_decrease\w*|_deposit\w*|_withdraw\w*|_credit\w*|_debit\w*)\s*\(")
LOOP_RE = re.compile(r"\b(for|while)\s*\(")
ASSEMBLY_OPCODES_RE = re.compile(r"\b(call|delegatecall|staticcall|callcode|sstore|sload|create2?|selfdestruct|mstore|mload|return|revert|extcodesize|extcodecopy|origin|gas|balance|calldatacopy|returndatacopy|log[0-4]|tstore|tload)\b")


def snippet_for(line_index: LineIndex, line: int) -> str:
    # redact()/MAX_SNIPPET_CHARS live in preprocess.py (the secrets-scanning
    # subsystem, out of V2.1's scope to move) - imported here, not at module
    # level, since preprocess.py imports this package and only finishes
    # loading detectors.orchestrator's names after this module's own import
    # line would otherwise need them. By the time any detector actually
    # runs (calling collector.add(), which calls this), preprocess.py has
    # already finished loading, so the import below always succeeds.
    from preprocess import redact, MAX_SNIPPET_CHARS
    from text_utils import truncate
    text, _ = truncate(redact(line_index.line_text(line).strip(), "code"), MAX_SNIPPET_CHARS)
    return text


def statement_at(masked: str, offset: int, lower: int, upper: int) -> Tuple[str, int]:
    """Return the statement fragment containing offset and its start."""
    start = offset
    while start > lower and masked[start - 1] not in ";{}":
        start -= 1
    end = offset
    while end < upper and masked[end] not in ";{}":
        end += 1
    return masked[start:end], start


def locate_scope(contract: Optional[Dict[str, Any]], offset: int) -> Dict[str, Optional[str]]:
    scope: Dict[str, Optional[str]] = {"function": None, "modifier": None, "kind": None}
    if contract is None:
        return scope
    for fn in contract.get("functions", []):
        if fn.get("_headStart") is not None and fn["_headStart"] <= offset <= (fn.get("_bodyEnd") or fn["_headStart"]):
            scope["function"] = fn["name"] or fn["kind"]
            scope["kind"] = fn["kind"]
            return scope
    for mod in contract.get("modifiers", []):
        if mod["_start"] <= offset <= mod["_end"]:
            scope["modifier"] = mod["name"]
            return scope
    return scope


class SignalCollector:
    def __init__(self, path: str, line_index: LineIndex, registry: Dict[str, Dict[str, Any]]) -> None:
        self.path = path
        self.line_index = line_index
        self.registry = registry
        self.signals: List[Dict[str, Any]] = []

    def add(self, check_id: str, offset: int, contract: Optional[str], scope: Dict[str, Optional[str]], details: Dict[str, Any], line: Optional[int] = None) -> Dict[str, Any]:
        meta = self.registry[check_id]
        line_no = line if line is not None else self.line_index.line_of(offset)
        signal = {
            "family": meta["family"],
            "checkId": check_id,
            "categories": list(meta["categories"]),
            "needsContext": meta["needsContext"],
            "fpRisk": meta["fpRisk"],
            "file": self.path,
            "line": line_no,
            "column": self.line_index.col_of(offset) if line is None else 0,
            "contract": contract,
            "function": scope.get("function"),
            "modifier": scope.get("modifier"),
            "snippet": snippet_for(self.line_index, line_no),
            "details": details,
        }
        self.signals.append(signal)
        return signal


def function_access_info(fn: Dict[str, Any]) -> Dict[str, Any]:
    access_modifiers = [m["name"] for m in fn["modifiers"] if ACCESS_MODIFIER_RE.match(m["name"]) and m["name"] not in NON_ACCESS_MODIFIERS]
    body = fn.get("_body", "")
    guards = sorted(set(collapse_ws(m.group(0)) for m in BODY_GUARD_RE.finditer(body)))
    return {"modifiers": access_modifiers, "bodyGuards": guards, "guarded": bool(access_modifiers or guards)}


def is_reentrancy_guarded(fn: Dict[str, Any]) -> bool:
    if any(REENTRANCY_GUARD_RE.match(m["name"]) for m in fn["modifiers"]):
        return True
    body = fn.get("_body", "")
    return bool(re.search(r"_nonReentrantBefore|_status\s*=\s*_?ENTERED|locked\s*=\s*true|require\s*\(\s*!\s*locked|_reentrancyGuardEntered|ReentrancyGuard", body))


@functools.lru_cache(maxsize=2048)
def _state_write_pattern(name: str) -> "re.Pattern[str]":
    """Compiled state-write regex for one variable name.

    A pure function of `name` alone - callers across context.py,
    business_logic.py and access_control.py re-derive the same pattern for
    the same name repeatedly (once per function it is checked against, per
    detector). Profiling a 7,548-effLOC/129-file fixture measured 34,613
    re.compile calls (~3.27s, ~42% of total preprocessing time) with this
    exact call site as the dominant source. maxsize=2048 comfortably covers
    every distinct state-variable name in a single job (574 state variables
    total, well under 2048 even before accounting for name reuse across
    contracts) while keeping worst-case memory bounded in a long-lived
    process, rather than caching unboundedly."""
    return re.compile(r"\b" + re.escape(name) + r"\b(\s*\[[^\]]*\])*(\s*\.\w+)*\s*(=(?!=)|\+=|-=|\*=|/=|\|=|&=|\+\+|--)|\bdelete\s+" + re.escape(name) + r"\b|\b" + re.escape(name) + r"\s*\.\s*(push|pop)\s*\(")


def find_state_writes(body: str, body_start: int, after_offset: int, state_names: List[str], line_index: LineIndex) -> Tuple[List[int], List[str]]:
    writes: List[int] = []
    internal_calls: List[str] = []
    rel = after_offset - body_start
    tail = body[rel:]
    for name in state_names:
        pattern = _state_write_pattern(name)
        for match in pattern.finditer(tail):
            writes.append(line_index.line_of(after_offset + match.start()))
    for match in INTERNAL_STATE_CALL_RE.finditer(tail):
        internal_calls.append(match.group(1))
    return sorted(set(writes)), sorted(set(internal_calls))


def loop_spans(masked: str, start: int, end: int, pairs: Dict[int, int]) -> List[Dict[str, Any]]:
    from text_utils import matching_paren
    loops: List[Dict[str, Any]] = []
    for match in LOOP_RE.finditer(masked, start, end):
        open_paren = match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        if close_paren == -1 or close_paren > end:
            continue
        header = collapse_ws(masked[open_paren + 1:close_paren])
        idx = close_paren + 1
        while idx < end and masked[idx] in " \t\n":
            idx += 1
        if idx < end and masked[idx] == "{":
            body_end = pairs.get(idx, end)
            body_start = idx
        else:
            body_start = idx
            body_end = masked.find(";", idx, end)
            if body_end == -1:
                body_end = end
        loops.append({"kind": match.group(1), "start": match.start(), "header": header, "bodyStart": body_start, "bodyEnd": body_end})
    return loops


def classify_call_hint(method: str) -> List[str]:
    hints: List[str] = []
    if re.match(r"^(latestRoundData|latestAnswer|getReserves|slot0|observe|consult|getPrice\w*|price|getAmountsOut|getAmountOut|getRate\w*|exchangeRate\w*|pricePerShare|getPricePerFullShare)$", method):
        hints.append("SC03")
    if re.match(r"^(flashLoan\w*|flash|flashSwap|maxFlashLoan|flashFee)$", method):
        hints.append("SC04")
    if re.match(r"^(swap\w*|exactInput\w*|exactOutput\w*)$", method):
        hints.append("EXTRA-front-running-mev")
    return hints


def in_assembly(ctx: Dict[str, Any], offset: int) -> bool:
    return any(s <= offset <= e for s, _match_start, e in ctx["assembly_spans"])


def fn_at(ctx: Dict[str, Any], offset: int) -> Optional[Dict[str, Any]]:
    for fn in ctx["contract"]["functions"]:
        if fn["_bodyStart"] is not None and fn["_bodyEnd"] is not None and fn["_bodyStart"] <= offset <= fn["_bodyEnd"]:
            return fn
    return None


def param_names(fn: Optional[Dict[str, Any]]) -> List[str]:
    if not fn:
        return []
    return [p["name"] for p in fn["params"] if p.get("name")]


def find_assembly_spans(ctx: Dict[str, Any]) -> List[Tuple[int, int, int]]:
    """(match_start, open_brace, close_brace) for every `assembly { ... }`
    block in this scope. Must run before anything calls in_assembly()."""
    masked, span_start, span_end, pairs = ctx["masked"], ctx["span_start"], ctx["span_end"], ctx["pairs"]
    spans = []
    for match in re.finditer(r"\bassembly\b[^{]*\{", masked[span_start:span_end]):
        open_brace = span_start + match.end() - 1
        close_brace = pairs.get(open_brace, span_end)
        spans.append((span_start + match.start(), open_brace, close_brace))
    return spans


def build_file_context(entry: Dict[str, Any], declared_types: Dict[str, str], registry: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    line_index = entry["lineIndex"]
    return {
        "masked": entry["masked"],
        "original": entry["text"],
        "line_index": line_index,
        "structure": entry["structure"],
        "pairs": entry["structure"]["pairs"],
        "declared_types": declared_types,
        "path": entry["path"],
        "entry": entry,
        "collector": SignalCollector(entry["path"], line_index, registry),
        "calls": [],
    }


def build_scope_context(file_ctx: Dict[str, Any], contract: Dict[str, Any], span_start: int, span_end: int) -> Dict[str, Any]:
    masked = file_ctx["masked"]
    ctx = dict(file_ctx)
    ctx.update({
        "contract": contract,
        "cname": contract["name"],
        "span_start": span_start,
        "span_end": span_end,
        "body": masked[span_start:span_end],
        "state_names": [var["name"] for var in contract["stateVariables"]],
        "state_types": {var["name"]: var["type"] for var in contract["stateVariables"]},
        "state_user_types": {var["name"]: var["userType"] for var in contract["stateVariables"] if var.get("userType")},
        "external_call_offsets": [],
    })
    ctx["assembly_spans"] = find_assembly_spans(ctx)
    return ctx


def build_scopes(structure: Dict[str, Any]) -> List[Tuple[Dict[str, Any], int, int]]:
    """Same scope list as the pre-V2.1 monolith: one entry per contract, plus
    one synthetic pseudo-contract per free function."""
    all_scopes: List[Tuple[Dict[str, Any], int, int]] = []
    for contract in structure["contracts"]:
        all_scopes.append((contract, contract["_bodyStart"], contract["_bodyEnd"]))
    for fn in structure["freeFunctions"]:
        if fn["_bodyStart"] is not None and fn["_bodyEnd"] is not None:
            all_scopes.append(({"name": None, "functions": [fn], "modifiers": [], "stateVariables": [], "usingFor": [], "bases": []}, fn["_bodyStart"], fn["_bodyEnd"]))
    return all_scopes


def enrich_function(fn: Dict[str, Any], access: Dict[str, Any]) -> None:
    """Sets the non-signal structural fields (accessControl/stateChanging/
    reentrancyGuarded) every function carries in the report's own inventory.
    Not a detector - this is inventory enrichment, computed once per function
    alongside (but independent of) the function-level detectors below, since
    both need the same `access` value."""
    fn["accessControl"] = access
    fn["stateChanging"] = fn["mutability"] not in ("view", "pure") and fn["hasBody"]
    fn["reentrancyGuarded"] = is_reentrancy_guarded(fn)
