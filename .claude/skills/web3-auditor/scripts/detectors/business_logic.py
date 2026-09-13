# -*- coding: utf-8 -*-
"""Contract-level Business Logic / Invariants checks (phase="contract"),
V2.4 (docs/decisiones.md D-046). New module: this is a new logical group
(cross-function state/guard relationships), not Access Control or
Proxy/Upgradeability, so it does not live in access_control.py.

Per the V2.4 audit (docs/decisiones.md), most of what "business logic"
usually means - broken invariants, impossible states, inconsistent
economic conditions, incomplete workflows, call-sequence abuse beyond
reentrancy - has no reliable mechanical signal, the same documented
limitation checklist.md already states for SC02/SC03/SC04, and stays
IA's job (Step 6). Only a narrow, purely structural slice is mechanical
without guessing intent: which functions write which state variable, and
whether their guards are clearly inconsistent (at least one guarded, at
least one not) - a cross-function generalization of the same "at least
one guarded, at least one not" definition
initializer-reinitializer-inconsistency.general (access_control.py)
already established for initializers specifically.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .context import find_state_writes, function_access_info

# Fresh, independent copy of access_control.py's own INITIALIZER_NAME_RE -
# not a cross-module import, to keep these two detector modules decoupled
# (same reasoning already documented for hardcoded-role-holder.general's
# own address-literal regex).
INITIALIZER_NAME_RE = re.compile(r"^(initialize|initialise|init|__\w+_init(?:_unchained)?|setUp|setup)$", re.I)

# D-047: structural (never name-based) shapes of a write to `{name}` that
# must never count as a relevant "unguarded" writer for
# state-write-guard-inconsistency.general - see that function's own
# docstring for why each one is safe regardless of what the function or
# variable is called.
SELF_SCOPED_WRITE_RE_TEMPLATE = r"\b{name}\b\s*\[\s*msg\.sender\s*\](?:\s*\[[^\]]*\])*\s*(=(?!=)|\+=|-=|\*=|/=|\|=|&=|\+\+|--)"
PAYABLE_FUNDED_WRITE_RE_TEMPLATE = r"\b{name}\b\s*(=(?!=)|\+=)\s*[^;]*\bmsg\.value\b[^;]*;"


def _excluded_write_lines(fn: Dict[str, Any], name: str, line_index: Any) -> set:
    """Lines where `fn` writes `name` in one of the two structural shapes
    D-047 excludes: indexed by msg.sender (the index IS the caller's own
    economic scope - `credits[msg.sender] -= amount` can only ever affect
    the caller's own slot, no matter who calls it or what it is named),
    or - only in a function that is actually `payable` - accumulating
    msg.value itself into `name` (`totalDeposits += msg.value` records
    exactly what the caller chose to send, not an arbitrary mutation).
    Both are matched directly against the write statement's own shape,
    never against the function's or variable's name. Uses the same
    body-relative offset convention find_state_writes itself uses
    (offsets are relative to `fn["_bodyStart"] + 1`) so line numbers line
    up with find_state_writes's own result for the same function."""
    body = fn["_body"]
    base_offset = fn["_bodyStart"] + 1
    lines: set = set()
    for match in re.finditer(SELF_SCOPED_WRITE_RE_TEMPLATE.format(name=re.escape(name)), body):
        lines.add(line_index.line_of(base_offset + match.start()))
    if fn.get("mutability") == "payable":
        for match in re.finditer(PAYABLE_FUNDED_WRITE_RE_TEMPLATE.format(name=re.escape(name)), body):
            lines.add(line_index.line_of(base_offset + match.start()))
    return lines


def detect_state_write_guard_inconsistency(ctx: Dict[str, Any]) -> None:
    """V2.4, Business Logic / Invariants, first check (docs/decisiones.md
    D-046). Purely structural signal: the SAME non-constant, non-immutable
    state variable is written by 2+ functions where at least one is
    guarded and at least one is completely unguarded - a restriction
    enforced through one function can be bypassed by calling another that
    reaches the same state with no check at all. Reuses find_state_writes
    called once PER (function, single variable) pair - not with the full
    state_names list at once, the way admin-function-unprotected.general
    does, since that combined-list shape only answers "did this function
    write ANY of these", losing which specific variable was written;
    INTERNAL_STATE_CALL_RE's own matches (the second element
    find_state_writes returns) are deliberately never used here for the
    same reason - that regex is not variable-specific, so it would mark
    every state variable as "written" by any function calling _mint/
    _burn/etc. anywhere, regardless of relevance.

    Reuses function_access_info's own modifiers/bodyGuards fields (already
    distinguishes actual modifier-based guards from inline
    msg.sender/require/hasRole-shaped checks - see context.py) rather than
    collapsing to one boolean, and surfaces both in this signal's details.

    Constructors and initializer-shaped functions are excluded entirely -
    neither counted as guarded nor unguarded writers. A constructor or
    initializer legitimately sets state with no role check by design
    (deployment/one-time-init IS the guard); counting them would make
    nearly every stateful contract "inconsistent" against its own
    constructor, which is exactly the kind of noise this check must not
    produce. Potential signal only, never an automatic vulnerability - a
    deliberately public initializer-style setter used only during a
    documented bootstrap window, or two writers gated by genuinely
    equivalent but differently-spelled checks this heuristic cannot prove
    equivalent, are both legitimate designs.

    fpRisk medium (D-047 refinement): an initial version of this check
    found 2/16 real evals/cases/*.sol fixtures firing, both confirmed
    false positives of the same class already documented for
    admin-function-unprotected.general - CreditLedger.spendCredit's
    `credits[msg.sender] -= amount` (self-service indexed by msg.sender,
    the index IS the authorization) and UpgradeableVaultLogic.deposit's
    `deposit() external payable { totalDeposits += msg.value; }` (a
    deliberately permissionless inflow paired with a guarded
    `sweepToOwner()` outflow - an ordinary pool/ledger design, not a
    bypassed restriction). Both are now excluded structurally by
    _excluded_write_lines (matched against the write statement's own
    shape - msg.sender indexing, or msg.value flowing into a payable
    function's own state - never against the function's or variable's
    name), not by special-casing the function names observed in those
    two fixtures. A write to a variable is only ever counted as a
    relevant writer (guarded or unguarded) here when at least one of its
    write lines in that function falls outside both exclusion shapes;
    residual uncertainty (e.g. two writers gated by genuinely equivalent
    but differently-spelled checks this heuristic cannot prove
    equivalent, or a real vulnerability this narrower detection now
    misses) is why this stays medium rather than low."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    state_names = [v["name"] for v in contract["stateVariables"] if not v.get("constant") and not v.get("immutable")]
    if not state_names:
        return
    writers: Dict[str, List[Dict[str, Any]]] = {}
    for fn in contract["functions"]:
        if fn["_bodyStart"] is None or fn["_bodyEnd"] is None:
            continue
        if fn["kind"] == "constructor" or INITIALIZER_NAME_RE.match(fn["name"] or ""):
            continue
        access = function_access_info(fn)
        for name in state_names:
            writes, _internal_calls = find_state_writes(fn["_body"], fn["_bodyStart"] + 1, fn["_bodyStart"] + 1, [name], ctx["line_index"])
            if not writes:
                continue
            if set(writes) <= _excluded_write_lines(fn, name, ctx["line_index"]):
                continue
            writers.setdefault(name, []).append({"fn": fn, "guarded": access["guarded"], "modifiers": access["modifiers"], "bodyGuards": access["bodyGuards"]})
    for name in sorted(writers):
        entries = writers[name]
        if len(entries) < 2:
            continue
        guarded_entries = [e for e in entries if e["guarded"]]
        unguarded_entries = [e for e in entries if not e["guarded"]]
        if not guarded_entries or not unguarded_entries:
            continue
        anchor_fn = unguarded_entries[0]["fn"]
        scope = {"function": anchor_fn["name"] or anchor_fn["kind"], "modifier": None, "kind": anchor_fn["kind"]}
        ctx["collector"].add("state-write-guard-inconsistency.general", anchor_fn["_headStart"], cname, scope, {
            "variable": name,
            "guardedWriters": [{"function": e["fn"]["name"] or e["fn"]["kind"], "modifiers": e["modifiers"], "bodyGuards": e["bodyGuards"]} for e in guarded_entries],
            "unguardedWriters": sorted(e["fn"]["name"] or e["fn"]["kind"] for e in unguarded_entries),
        })


CONTRACT_CHECKS = [
    ("state-write-guard-inconsistency.general", detect_state_write_guard_inconsistency),
]
