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

    fpRisk high (revised from an initial medium estimate, based on
    empirical evidence from the 16 real evals/cases/*.sol fixtures, not
    just reasoning about it): the SAME two confirmed false positives
    already documented for admin-function-unprotected.general apply
    here too, since both checks rely on the same function_access_info
    notion of "guarded". (1) A self-service function indexed by
    msg.sender (e.g. `credits[msg.sender] -= amount`) needs no owner-style
    guard - the mapping index IS the authorization - but this heuristic
    has no notion of "guarded by its own indexing", so it looks
    unguarded next to an admin-only `credits[to] += amount` writer.
    (2) A deliberately permissionless inflow function (e.g.
    `deposit() external payable { totalDeposits += msg.value; }`) paired
    with an admin-gated outflow function on the same counter (e.g.
    `sweepToOwner()`) is a completely ordinary pool/ledger pattern, not a
    bypassed restriction - `deposit` was never supposed to be gated in
    the first place. Both were observed directly on real fixtures
    (CreditLedger.spendCredit, UpgradeableVaultLogic.deposit) during this
    check's own verification, not merely anticipated."""
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
