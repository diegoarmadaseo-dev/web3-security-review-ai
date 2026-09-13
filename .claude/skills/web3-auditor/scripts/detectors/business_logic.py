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

# D-048: write-shape regexes reused by both state-pair-write-mismatch.general
# and state-write-operator-inconsistency.general. Both allow the same
# optional bracket/dot suffixes between the name and the operator so a
# mapping/array write (`credits[msg.sender] = v`) is matched exactly like
# a plain variable write (`x = v`) - D-049 found ABSOLUTE_WRITE_RE_TEMPLATE
# missing this (RELATIVE_WRITE_RE_TEMPLATE already had it), which silently
# made every indexed overwrite invisible to
# state-write-operator-inconsistency.general regardless of the D-047
# exclusion-scope question that prompted the fix.
RELATIVE_WRITE_RE_TEMPLATE = r"\b{name}\b\s*(?:\[[^\]]*\])*(?:\.\w+)*\s*(?:\+=|-=|\*=|/=|\|=|&=|\+\+|--)"
ABSOLUTE_WRITE_RE_TEMPLATE = r"\b{name}\b\s*(?:\[[^\]]*\])*(?:\.\w+)*\s*=(?!=)\s*([^;]*);"

# D-050: structural signature of a deliberate "close out and clear" reset
# (liquidation/sweep/claim), as opposed to a genuinely suspicious
# arbitrary overwrite - see _has_closeout_signal.
ZERO_LITERAL_RE = re.compile(r"^(0+|0x0+)$")
VALUE_TRANSFER_RE = re.compile(r"\.\s*transfer\s*\(|\.\s*send\s*\(|\.\s*call\s*\{[^}]*\bvalue\b")


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


def _written_vars_by_function(contract: Dict[str, Any], state_names: List[str], line_index: Any) -> Dict[int, Dict[str, Any]]:
    """Shared scan for D-048's two checks: per non-constructor,
    non-initializer function, which of `state_names` it genuinely writes.

    D-049: deliberately does NOT apply D-047's self-scoped/payable-funded
    exclusions, unlike state-write-guard-inconsistency.general. Those
    exclusions were designed and justified for one specific question - is
    the lack of an access-control guard actually dangerous, given the
    write's own shape already bounds who it can affect - which has no
    bearing on the two questions this shared scan feeds: does a write
    participate in an established co-occurrence pattern
    (state-pair-write-mismatch.general), or is it relative vs. an
    absolute overwrite (state-write-operator-inconsistency.general). A
    self-scoped withdraw that skips a paired totalSupply write, or a
    self-scoped overwrite breaking an otherwise-relative pattern, are
    exactly the kind of case those two checks exist to catch - excluding
    them silently hid real cases, confirmed empirically during the V2.4
    second-block audit (docs/decisiones.md D-049). Reuses
    find_state_writes exactly as state-write-guard-inconsistency.general
    does (once per (function, single variable) pair, never the combined
    state_names shape) - only the D-047 filtering step is skipped here.
    Keyed by `id(fn)` since function dicts aren't hashable by value and
    two functions can share a name (overloads)."""
    written_by: Dict[int, Dict[str, Any]] = {}
    for fn in contract["functions"]:
        if fn["_bodyStart"] is None or fn["_bodyEnd"] is None:
            continue
        if fn["kind"] == "constructor" or INITIALIZER_NAME_RE.match(fn["name"] or ""):
            continue
        written_vars = set()
        for name in state_names:
            writes, _internal_calls = find_state_writes(fn["_body"], fn["_bodyStart"] + 1, fn["_bodyStart"] + 1, [name], line_index)
            if writes:
                written_vars.add(name)
        if written_vars:
            written_by[id(fn)] = {"fn": fn, "vars": written_vars}
    return written_by


def detect_state_pair_write_mismatch(ctx: Dict[str, Any]) -> None:
    """V2.4, Business Logic / Invariants, second block (docs/decisiones.md
    D-048). Purely structural co-occurrence signal: two state variables
    are written together (both, in the same function) by 2+ functions -
    establishing an apparent pattern that these two move as a pair (e.g.
    `balances[to] += amount; totalSupply += amount;` in both a mint and
    an airdrop function) - but a further function writes only ONE of the
    two. Never asserts what the "correct" relationship between the two
    variables actually is (no guess at mint/burn/supply semantics); it
    only observes that an established co-occurrence, seen in 2+ places,
    is broken in one more. Deliberately does NOT try to detect an
    "opposite direction" violation (e.g. one increases while the
    established pattern has both increase) - determining a consistent
    "expected sign" per pair across functions that may use different
    operators adds real complexity and its own FP surface for a signal
    that is already only informational; out of scope for this first
    version. Reuses the exact same per-(function, variable)
    find_state_writes call as state-write-guard-inconsistency.general,
    but - unlike that check - does NOT apply D-047's self-scoped/
    payable-funded exclusions (see _written_vars_by_function's own
    docstring, D-049): a self-scoped write can still break or establish a
    co-occurrence pattern like any other write. Constructors and
    initializer-shaped functions are excluded entirely (see
    _written_vars_by_function) - a constructor's one-time genesis writes
    should not, by themselves as a single data point, define what
    "normal" co-occurrence looks like for ongoing operational functions.
    fpRisk medium: some functions legitimately touch only one side of an
    otherwise-paired relationship on purpose (e.g. an explicit admin
    correction tool), and a 2-function sample is a thin basis for
    "established" - both are real, accepted limitations of a heuristic
    that deliberately never asks what the variables mean."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    state_names = sorted(v["name"] for v in contract["stateVariables"] if not v.get("constant") and not v.get("immutable"))
    if len(state_names) < 2:
        return
    written_by = _written_vars_by_function(contract, state_names, ctx["line_index"])
    if len(written_by) < 2:
        return
    entries = list(written_by.values())
    for i, a in enumerate(state_names):
        for b in state_names[i + 1:]:
            together = [e for e in entries if a in e["vars"] and b in e["vars"]]
            if len(together) < 2:
                continue
            only_a = [e for e in entries if a in e["vars"] and b not in e["vars"]]
            only_b = [e for e in entries if b in e["vars"] and a not in e["vars"]]
            deviators = only_a + only_b
            if not deviators:
                continue
            anchor_fn = deviators[0]["fn"]
            scope = {"function": anchor_fn["name"] or anchor_fn["kind"], "modifier": None, "kind": anchor_fn["kind"]}
            ctx["collector"].add("state-pair-write-mismatch.general", anchor_fn["_headStart"], cname, scope, {
                "variables": [a, b],
                "writtenTogether": sorted(e["fn"]["name"] or e["fn"]["kind"] for e in together),
                "onlyFirst": sorted(e["fn"]["name"] or e["fn"]["kind"] for e in only_a),
                "onlySecond": sorted(e["fn"]["name"] or e["fn"]["kind"] for e in only_b),
            })


def _has_closeout_signal(body: str, name: str, match: Any) -> bool:
    """D-050: structural evidence that an absolute `name = 0` overwrite is
    a deliberate "close out this position and clear it" reset rather than
    a blind, unexplained stomp - never inferred from the function's or
    variable's name. Either of two independent, purely syntactic signals
    is enough: (a) `name` is referenced somewhere else in the SAME
    function body, outside this exact write's own span - the classic
    `uint256 seized = collateralDeposited[account]; collateralDeposited[account] = 0;`
    read-then-clear idiom; or (b) the function contains a value-transfer-
    shaped call anywhere (`.transfer(`/`.send(`/`.call{value...`) - a
    liquidation/sweep that reads the OLD value of a *different* variable
    (e.g. `borrowed[account] = 0;` in the same function that transfers
    out `collateralDeposited`) still needs a closeout signal to exclude
    it, and (a) alone would miss that case since `borrowed` itself is
    never re-read in that function."""
    other_refs = [
        m for m in re.finditer(r"\b" + re.escape(name) + r"\b", body)
        if not (match.start() <= m.start() < match.end())
    ]
    if other_refs:
        return True
    return bool(VALUE_TRANSFER_RE.search(body))


def _write_operator_kinds(fn: Dict[str, Any], name: str) -> Dict[str, bool]:
    """Whether `fn` writes `name` in a relative (self-referencing) shape,
    a true absolute overwrite, or a deliberate zero-reset (D-050).
    `+=`/`-=`/`++`/`--`-shaped writes are unambiguously relative from
    their own syntax. A bare `name = <rhs>` is first checked for
    self-reference - `x = x + amount` is a disguised increment (a common
    long-form style) and must not be misread as a reset just because it
    uses `=`. Only once a write is confirmed to genuinely discard the
    previous value (RHS never mentions `name`) does its shape matter: an
    overwrite to a literal zero (`x = 0`) WITH a closeout signal
    (_has_closeout_signal) is a `safeReset`, not counted as `absolute` -
    everything else (a non-zero overwrite, or a zero overwrite with no
    closeout evidence at all) still counts as `absolute`, so a genuinely
    unexpected operator change is never hidden just because it happens to
    assign zero."""
    body = fn["_body"]
    has_relative = bool(re.search(RELATIVE_WRITE_RE_TEMPLATE.format(name=re.escape(name)), body))
    has_absolute = False
    has_safe_reset = False
    for match in re.finditer(ABSOLUTE_WRITE_RE_TEMPLATE.format(name=re.escape(name)), body):
        rhs = match.group(1).strip()
        if re.search(r"\b" + re.escape(name) + r"\b", rhs):
            has_relative = True
            continue
        if ZERO_LITERAL_RE.match(rhs) and _has_closeout_signal(body, name, match):
            has_safe_reset = True
        else:
            has_absolute = True
    return {"relative": has_relative, "absolute": has_absolute, "safeReset": has_safe_reset}


def detect_state_write_operator_inconsistency(ctx: Dict[str, Any]) -> None:
    """V2.4, Business Logic / Invariants, second block (docs/decisiones.md
    D-048). A state variable adjusted only relatively (`+=`/`-=`/`++`/
    `--`, or the disguised-relative `x = x + amount` style - see
    _write_operator_kinds) by every writer but one, where that one
    function instead overwrites it outright (`x = <expr not mentioning
    x>`) - informational regardless of that function's own guard status:
    even a properly `onlyOwner`-gated reset can silently discard
    accounting a purely-relative sibling set of functions assumed would
    only ever be adjusted incrementally. Fires only when exactly one
    writer overwrites and at least one other is relative-only, keeping
    this to the narrow "one outlier among an established pattern" shape
    rather than flagging any variable with a mix of styles. Constructors
    and initializer-shaped functions are excluded (see
    _written_vars_by_function) - a constructor's `x = INITIAL` is the
    universal, expected way to set a variable's genesis value and would
    otherwise make this fire on nearly every stateful contract. Does NOT
    apply D-047's self-scoped/payable-funded exclusions (D-049) - a
    self-scoped overwrite (`credits[msg.sender] = v`) breaking an
    otherwise-relative pattern is exactly the kind of case this check
    exists to catch, not something to filter out before even asking which
    operator was used.

    D-050 refinement: an initial version found 3/16 real evals/cases/*.sol
    fixtures firing once D-049 stopped excluding self-scoped/payable-funded
    writes - SpotPriceLending.liquidate (`collateralDeposited[account] = 0;
    borrowed[account] = 0;` after seizing collateral, transferring the
    seized amount out) and UpgradeableVaultLogic.sweepToOwner
    (`totalDeposits = 0;` after transferring the swept total to the owner,
    the same function already identified as legitimate in D-046), all
    confirmed false positives - resetting a per-account balance to
    literal zero as part of a legitimate close-out is exactly as common
    and correct a pattern as D-046/D-047's self-scoped/payable-funded
    ones, just a different shape. Fixed structurally (never by function/
    variable name) via _write_operator_kinds' new `safeReset` category:
    an overwrite to a literal zero WITH a closeout signal
    (_has_closeout_signal - the variable read elsewhere in the same
    function, or the function containing any value-transfer-shaped call)
    is excluded from the writer's own classification entirely, the same
    treatment constructors already get. A non-zero overwrite, or a zero
    overwrite with no closeout evidence at all, is deliberately NOT
    excluded - a genuinely unexpected operator change is never hidden
    just because it happens to assign zero. fpRisk medium (reverted from
    the D-049 high once the confirmed false positives were excluded
    structurally) - residual risk is a deliberate, documented "reset"
    admin function with no read/transfer nearby, or a genuinely
    suspicious zero-write that happens to share a function with an
    unrelated transfer, both of which this heuristic still cannot
    perfectly distinguish."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    state_names = [v["name"] for v in contract["stateVariables"] if not v.get("constant") and not v.get("immutable")]
    if not state_names:
        return
    written_by = _written_vars_by_function(contract, state_names, ctx["line_index"])
    writers: Dict[str, List[Dict[str, Any]]] = {}
    for entry in written_by.values():
        fn = entry["fn"]
        for name in entry["vars"]:
            kinds = _write_operator_kinds(fn, name)
            if kinds["safeReset"] and not kinds["relative"] and not kinds["absolute"]:
                continue
            writers.setdefault(name, []).append({"fn": fn, "hasAbsolute": kinds["absolute"]})
    for name in sorted(writers):
        entries = writers[name]
        if len(entries) < 2:
            continue
        relative_only = [e for e in entries if not e["hasAbsolute"]]
        overwriters = [e for e in entries if e["hasAbsolute"]]
        if len(relative_only) < 1 or len(overwriters) != 1:
            continue
        anchor_fn = overwriters[0]["fn"]
        scope = {"function": anchor_fn["name"] or anchor_fn["kind"], "modifier": None, "kind": anchor_fn["kind"]}
        ctx["collector"].add("state-write-operator-inconsistency.general", anchor_fn["_headStart"], cname, scope, {
            "variable": name,
            "relativeWriters": sorted(e["fn"]["name"] or e["fn"]["kind"] for e in relative_only),
            "overwriteFunction": anchor_fn["name"] or anchor_fn["kind"],
        })


CONTRACT_CHECKS = [
    ("state-write-guard-inconsistency.general", detect_state_write_guard_inconsistency),
    ("state-pair-write-mismatch.general", detect_state_pair_write_mismatch),
    ("state-write-operator-inconsistency.general", detect_state_write_operator_inconsistency),
]
