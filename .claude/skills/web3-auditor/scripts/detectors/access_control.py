# -*- coding: utf-8 -*-
"""Function-level and contract-level access-control/upgradeability checks.
Moved verbatim from the pre-V2.1 detect_solidity_signals monolith.

Function-phase checks receive a per-function context (see registry.py's
orchestrator) that already has `fn`, `access` (function_access_info(fn),
computed once per function alongside enrich_function - see context.py) and
`scope` filled in, so none of them recompute access info independently.
reentrancy-pattern additionally needs ctx["external_call_offsets"], already
fully populated by the scope-phase checks in calls_and_transfers.py by the
time function-phase checks run (enforced by orchestration order, not by
this module).
"""
from __future__ import annotations

import re
from typing import Any, Dict

from .context import INTERNAL_STATE_CALL_RE, REENTRANCY_GUARD_RE, find_state_writes, function_access_info, locate_scope
from text_utils import matching_paren

ADMIN_NAME_RE = re.compile(r"^(set|update|change|configure|withdraw|sweep|rescue|drain|emergency|pause|unpause|mint|burn|upgrade|migrate|whitelist|blacklist|add|remove|grant|revoke|kill|destroy|transferOwnership|renounce|register|unregister|enable|disable|toggle|reset|claim(All|Fees)?)", re.I)
ADMIN_NAME_EXCLUDE_RE = re.compile(r"^(addLiquidity|removeLiquidity|mintTo|burnFrom|setApprovalForAll|withdrawTo)$")
INITIALIZER_NAME_RE = re.compile(r"^(initialize|initialise|init|__\w+_init(?:_unchained)?|setUp|setup)$", re.I)
INITIALIZER_GUARD_RE = re.compile(r"^(initializer|reinitializer|onlyInitializing|only\w+|auth\w*|when\w+)$")
INITIALIZED_BODY_RE = re.compile(r"\binitializ(?:ed|ing)\b|_initialized|_initializing|AlreadyInitialized|alreadyInit|require\s*\(\s*!\s*init", re.I)
UPGRADE_FUNCTION_RE = re.compile(r"^(upgradeTo|upgradeToAndCall|_authorizeUpgrade|_upgradeTo|_upgradeToAndCall|setImplementation|_setImplementation|changeAdmin|_changeAdmin|upgrade|migrate|upgradeBeaconToAndCall)$")
PROXY_BASE_RE = re.compile(r"upgradeable|uups|proxy|initializable|erc1967|beacon", re.I)
PROXY_FUNCTION_RE = re.compile(r"^(upgradeTo|upgradeToAndCall|_authorizeUpgrade|_upgradeTo|_setImplementation|setImplementation|changeAdmin|_changeAdmin|implementation|_implementation|proxiableUUID|_getImplementation)$")
TWO_STEP_RE = re.compile(r"Ownable2Step|acceptOwnership|pendingOwner", re.I)
OWNERSHIP_TRANSFER_RE = re.compile(r"^(transferOwnership|setOwner|changeOwner|_transferOwnership)$")
ZERO_ADDRESS_RE_TEMPLATE = r"\b{p}\b\s*[!=]=\s*(address\s*\(\s*0x?0*\s*\)|ZERO_ADDRESS|address\s*\(\s*0x0+\s*\))|(address\s*\(\s*0x?0*\s*\)|ZERO_ADDRESS)\s*[!=]=\s*\b{p}\b|_?(check|require|validate|nonZero|notZero|assert|ensure|verify)\w*\s*\([^;]*\b{p}\b"
KNOWN_PUBLIC_SLOTS = {
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # EIP-1967 implementation
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",  # EIP-1967 admin
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",  # EIP-1967 beacon
    "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",  # EIP-1822 proxiable
}

# --- V2.1 detector-expansion, first block (docs/decisiones.md D-032) ---
CALLBACK_NAME_RE = re.compile(r"^(onFlashLoan|executeOperation|uniswapV2Call|uniswapV3FlashCallback|receiveFlashLoan|onERC721Received|onERC1155Received|onERC1155BatchReceived|tokensReceived|onTokenTransfer)$")
ARRAY_TYPE_RE = re.compile(r"\[\s*\d*\s*\]\s*$")
GAP_VAR_RE = re.compile(r"^_{0,2}(storage)?gap\d*$", re.I)

# --- V2.1 detector-expansion, second block (docs/decisiones.md D-033) ---
ROLE_GRANT_RE = re.compile(r"\b(_setupRole|_grantRole|grantRole)\s*\(")
HARDCODED_ADDRESS_IN_ROLE_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
EXTERNAL_CALL_IN_MODIFIER_RE = re.compile(r"\.(call|send|staticcall|callcode|delegatecall)\s*(\{[^}]*\})?\s*\(")

# --- V2.3, Access Control + Proxy/Upgradeability, first block (docs/decisiones.md D-038) ---
# Same 4 hex values as KNOWN_PUBLIC_SLOTS above, verbatim, mapped to which EIP-1967/EIP-1822
# slot each one is - a fresh, independent constant rather than restructuring
# KNOWN_PUBLIC_SLOTS itself (which detect_proxy_pattern already relies on as a plain set).
EIP1967_SLOT_KIND = {
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "implementation",
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "admin",
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "beacon",
    "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7": "eip1822-proxiable",
}
REINITIALIZER_MODIFIER_RE = re.compile(r"^reinitializer$")

# --- V2.3, Access Control + Proxy/Upgradeability, second block (docs/decisiones.md D-040) ---
GOVERNANCE_REFERENCE_RE = re.compile(r"TimelockController|Governor|GnosisSafe|\bSafe\b|MultiSig", re.I)
ADMIN_ROLE_GRANT_RE = re.compile(r"\bgrantRole\s*\(\s*([^,()]+?)\s*,")
ADMIN_ROLE_REVOKE_RE_TEMPLATE = r"\b(?:revokeRole|renounceRole)\s*\(\s*{role}\s*,"

# --- V2.3, Access Control + Proxy/Upgradeability, third block (docs/decisiones.md D-041) ---
DIAMOND_CUT_NAME_RE = re.compile(r"^diamondCut$")
AUTH_MODIFIER_NAME_RE = re.compile(r"^(only\w+|auth\w*)$", re.I)
MODIFIER_HAS_ANY_CHECK_RE = re.compile(r"msg\.sender|tx\.origin|\w+\s*\(")
SET_ROLE_ADMIN_RE = re.compile(r"\b_?setRoleAdmin\s*\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)")
DEFAULT_ADMIN_ROLE_LITERAL_RE = re.compile(r"^(DEFAULT_ADMIN_ROLE|0x0+|bytes32\s*\(\s*0x?0*\s*\))$")
ROLE_GRANT_TO_SELF_RE = re.compile(r"\b(?:_setupRole|_grantRole|grantRole)\s*\(\s*([^,()]+?)\s*,\s*(address\s*\(\s*this\s*\)|this)\s*\)")


# --- scope-phase checks -----------------------------------------------------

def detect_hardcoded_role_holder(ctx: Dict[str, Any]) -> None:
    """A role granted directly to a literal address (rather than a
    constructor/function parameter) is a centralization signal: the holder
    can never be changed without a contract upgrade or a separate admin
    call. Reuses the same 20-byte hex literal shape as arithmetic_and_gas.py's
    `hardcoded-address` (a fresh local constant, not a cross-module import,
    to avoid coupling two independent detector modules for one regex)."""
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in ROLE_GRANT_RE.finditer(body):
        offset = span_start + match.start()
        open_paren = span_start + match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        if close_paren == -1:
            continue
        args_text = masked[open_paren + 1:close_paren]
        addr = HARDCODED_ADDRESS_IN_ROLE_RE.search(args_text)
        if not addr:
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("hardcoded-role-holder.general", offset, ctx["cname"], scope, {"call": match.group(1), "address": addr.group(0)})


def detect_admin_function_uses_tx_origin_check(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, second block
    (docs/decisiones.md D-040). Narrows tx-origin.general's own
    already-computed `inCondition` detail into a gate, further restricted to
    functions whose name matches the same ADMIN_NAME_RE/ADMIN_NAME_EXCLUDE_RE
    heuristic admin-function-unprotected.general already uses. Reads the
    tx-origin signal already emitted earlier in this same scope-phase pass
    (calls_and_transfers.CHECKS runs before access_control.CHECKS in
    registry.py's SCOPE_CHECKS - see that module's docstring) - zero new
    regex over raw text, zero re-scan. tx.origin used in a condition on an
    admin-named function is a well-known, essentially always-wrong pattern
    (any contract can relay the call and pass the check), so fpRisk is low."""
    cname = ctx["cname"]
    for s in ctx["collector"].signals:
        if s["family"] != "tx-origin" or s["contract"] != cname or not s["details"].get("inCondition"):
            continue
        fn_name = s.get("function") or ""
        if not ADMIN_NAME_RE.match(fn_name) or ADMIN_NAME_EXCLUDE_RE.match(fn_name):
            continue
        offset = ctx["line_index"].offset_of_line(s["line"])
        scope = {"function": s["function"], "modifier": s["modifier"], "kind": None}
        ctx["collector"].add("admin-function-uses-tx-origin-check.general", offset, cname, scope, {})


def detect_role_admin_reassigned_non_default(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, third block
    (docs/decisiones.md D-041). `_setRoleAdmin(role, newAdminRole)`
    reassigns which role is allowed to grant/revoke `role` - by default
    every role (including DEFAULT_ADMIN_ROLE itself) is administered by
    DEFAULT_ADMIN_ROLE. Reassigning that to anything else delegates
    grant/revoke power away from the top-level admin role, raising the
    stakes of whoever holds the new admin role - a structural fact worth
    surfacing, not an automatic vulnerability (a deliberate multi-tier RBAC
    hierarchy is a legitimate design), hence fpRisk medium. Skips the
    common no-op spelling (reassigning to DEFAULT_ADMIN_ROLE itself, or an
    equivalent zero-literal spelling) to avoid flagging what is really the
    OZ default restated explicitly."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in SET_ROLE_ADMIN_RE.finditer(body):
        role_expr, new_admin_expr = match.group(1).strip(), match.group(2).strip()
        if DEFAULT_ADMIN_ROLE_LITERAL_RE.match(new_admin_expr):
            continue
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        ctx["collector"].add("role-admin-reassigned-non-default.general", offset, ctx["cname"], scope, {"role": role_expr, "newAdminRole": new_admin_expr})


def detect_role_granted_to_self_contract(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, third block
    (docs/decisiones.md D-041). A role-granting call whose account argument
    is the contract's own address (`address(this)`/`this`) means the
    CONTRACT is now a holder of that role - if it can also be told to make
    arbitrary calls or delegatecalls elsewhere, this can become a
    self-service privilege-escalation path a plain address-holder review
    would miss. Restricted to ADMIN-named roles (same substring gate as
    access-control-admin-transfer-no-two-step.general) to stay narrow -
    routine operational roles (e.g. a contract registering itself as its
    own MINTER_ROLE for an internal mint-and-distribute step) are common
    and not the target here."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in ROLE_GRANT_TO_SELF_RE.finditer(body):
        role_expr = match.group(1).strip()
        if not re.search(r"ADMIN", role_expr, re.I):
            continue
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        ctx["collector"].add("role-granted-to-self-contract.general", offset, ctx["cname"], scope, {"role": role_expr})


CHECKS = [
    ("hardcoded-role-holder.general", detect_hardcoded_role_holder),
    ("admin-function-uses-tx-origin-check.general", detect_admin_function_uses_tx_origin_check),
    ("role-admin-reassigned-non-default.general", detect_role_admin_reassigned_non_default),
    ("role-granted-to-self-contract.general", detect_role_granted_to_self_contract),
]


# --- function-phase checks -------------------------------------------------

def detect_initializer_unprotected(fctx: Dict[str, Any]) -> None:
    fn, access, scope = fctx["fn"], fctx["access"], fctx["scope"]
    name = fn["name"] or ""
    public = fn["visibility"] in ("public", "external")
    if not (public and INITIALIZER_NAME_RE.match(name) and fn["stateChanging"]):
        return
    guarded_by_modifier = any(INITIALIZER_GUARD_RE.match(m["name"]) for m in fn["modifiers"])
    guarded_by_body = bool(INITIALIZED_BODY_RE.search(fn["_body"])) or access["guarded"]
    if guarded_by_modifier or guarded_by_body:
        return
    fctx["collector"].add("initializer-unprotected.general", fn["_headStart"], fctx["cname"], scope, {"name": name, "visibility": fn["visibility"], "modifiers": [m["name"] for m in fn["modifiers"]]})


def detect_zero_address_unchecked(fctx: Dict[str, Any]) -> None:
    fn, scope = fctx["fn"], fctx["scope"]
    public = fn["visibility"] in ("public", "external")
    if not (public and fn["stateChanging"] and fn["kind"] in ("function", "constructor")):
        return
    unchecked_params = []
    modifier_args = " ".join((m["args"] or "") for m in fn["modifiers"])
    for param in fn["params"]:
        pname = param.get("name")
        if not pname or not param.get("isAddress"):
            continue
        pattern = re.compile(ZERO_ADDRESS_RE_TEMPLATE.format(p=re.escape(pname)))
        if pattern.search(fn["_body"]) or re.search(r"\b" + re.escape(pname) + r"\b", modifier_args):
            continue
        unchecked_params.append(pname)
    if unchecked_params:
        fctx["collector"].add("zero-address-unchecked.general", fn["_headStart"], fctx["cname"], scope, {"params": unchecked_params, "kind": fn["kind"]})


def detect_admin_function_unprotected(fctx: Dict[str, Any]) -> None:
    fn, access, scope = fctx["fn"], fctx["access"], fctx["scope"]
    name = fn["name"] or ""
    public = fn["visibility"] in ("public", "external")
    if not (public and fn["stateChanging"] and fn["kind"] == "function" and UPGRADE_FUNCTION_RE.match(name) is None
            and INITIALIZER_NAME_RE.match(name) is None and ADMIN_NAME_RE.match(name)
            and not ADMIN_NAME_EXCLUDE_RE.match(name) and not access["guarded"]):
        return
    writes_state = bool(find_state_writes(fn["_body"], fn["_bodyStart"] + 1, fn["_bodyStart"] + 1, fctx["state_names"], fctx["line_index"])[0]) or bool(INTERNAL_STATE_CALL_RE.search(fn["_body"]))
    fctx["collector"].add("admin-function-unprotected.general", fn["_headStart"], fctx["cname"], scope, {"name": name, "visibility": fn["visibility"], "modifiers": [m["name"] for m in fn["modifiers"]], "writesState": writes_state})


def detect_upgrade_function(fctx: Dict[str, Any]) -> None:
    fn, access, scope = fctx["fn"], fctx["access"], fctx["scope"]
    name = fn["name"] or ""
    if not UPGRADE_FUNCTION_RE.match(name):
        return
    body_stripped = re.sub(r"\s+", "", fn["_body"])
    fctx["collector"].add("upgrade-function.general", fn["_headStart"], fctx["cname"], scope, {"name": name, "visibility": fn["visibility"], "guarded": access["guarded"], "guards": access["modifiers"] + access["bodyGuards"], "emptyBody": body_stripped == "" or body_stripped == "{}"})


def detect_upgrade_function_unprotected(fctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, third block (docs/decisiones.md D-035).
    Narrows upgrade-function.general's own gating condition
    (UPGRADE_FUNCTION_RE.match(name), access["guarded"]) into a signal by
    evaluating THIS function's own already-computed `fctx["fn"]`/
    `fctx["access"]` directly - not by reading back detect_upgrade_function's
    emitted signal from ctx["collector"].signals filtered by function name.

    An earlier version did read the signal history by name, which broke on
    overloaded functions sharing a name (`upgradeTo(address)` and
    `upgradeTo(address,bytes)`): processing the second overload re-scanned
    ALL prior same-named signals, including the first overload's, and could
    fire (mis-attributed to the second overload's location) even when the
    second overload was itself properly guarded. Evaluating `fn`/`access`
    directly is immune to this by construction - each overload is its own
    object, never confused with a sibling. Found and fixed during review
    (docs/decisiones.md D-036); see
    test_upgrade_function_overload_only_unguarded_one_flagged. Still
    reuses UPGRADE_FUNCTION_RE and access["guarded"] verbatim - same
    already-computed pieces detect_upgrade_function itself uses, just read
    directly instead of round-tripped through a signal."""
    fn, access, scope, cname = fctx["fn"], fctx["access"], fctx["scope"], fctx["cname"]
    name = fn["name"] or ""
    if not UPGRADE_FUNCTION_RE.match(name):
        return
    if access["guarded"]:
        return
    fctx["collector"].add("upgrade-function-unprotected.general", fn["_headStart"], cname, scope, {"name": name})


def detect_reentrancy_pattern(fctx: Dict[str, Any]) -> None:
    fn, scope = fctx["fn"], fctx["scope"]
    if not (fn["stateChanging"] and not fn["reentrancyGuarded"]):
        return
    in_fn = sorted(off for off, kind in fctx["external_call_offsets"] if fn["_bodyStart"] <= off <= fn["_bodyEnd"] and kind != "eth-transfer")
    if not in_fn:
        return
    first_call = in_fn[0]
    writes, internal_calls = find_state_writes(fctx["masked"][fn["_bodyStart"]:fn["_bodyEnd"]], fn["_bodyStart"], first_call, fctx["state_names"], fctx["line_index"])
    if not (writes or internal_calls):
        return
    fctx["collector"].add("reentrancy-pattern.general", first_call, fctx["cname"], scope, {
        "callLine": fctx["line_index"].line_of(first_call),
        "stateWritesAfterCall": writes,
        "internalCallsAfterCall": internal_calls,
        "guarded": False,
        "externalCallCount": len(in_fn),
    })


def detect_unprotected_callback_handler(fctx: Dict[str, Any]) -> None:
    """External-facing callback entry points (flash-loan callbacks, token
    receiver hooks) are meant to be invoked by a specific caller (the lending
    pool, the token contract); one with no visible caller check at all is a
    classic "anyone can pretend to be the pool" access-control gap. Reuses
    `access["guarded"]` (function_access_info, computed once per function
    alongside enrich_function - see context.py) rather than re-scanning the
    body: a genuine caller check that uses a non-standard modifier name or
    validates a passed-in parameter instead of `msg.sender` directly (e.g.
    Aave's `initiator` argument) will not be recognized here, which is why
    this family is fpRisk high, same as the other name-heuristic checks."""
    fn, access, scope = fctx["fn"], fctx["access"], fctx["scope"]
    name = fn["name"] or ""
    if not CALLBACK_NAME_RE.match(name):
        return
    if fn["visibility"] not in ("public", "external") or access["guarded"]:
        return
    fctx["collector"].add("unprotected-callback-handler.general", fn["_headStart"], fctx["cname"], scope, {"name": name, "visibility": fn["visibility"], "modifiers": [m["name"] for m in fn["modifiers"]]})


def detect_mismatched_array_length(fctx: Dict[str, Any]) -> None:
    """Two or more array parameters indexed together (a batch-processing
    pattern) with no `a.length == b.length`-shaped check anywhere in the
    body is a well-known source of out-of-bounds reads/reverts or silently
    dropped entries. Only fires when the arrays are actually indexed (`name[`
    somewhere in the body), not merely declared, to keep this narrow."""
    fn, scope = fctx["fn"], fctx["scope"]
    if fn["visibility"] not in ("public", "external"):
        return
    array_params = [p["name"] for p in fn["params"] if p.get("name") and ARRAY_TYPE_RE.search(p.get("type") or "")]
    if len(array_params) < 2:
        return
    body = fn.get("_body", "")
    indexed = [name for name in array_params if re.search(r"\b" + re.escape(name) + r"\s*\[", body)]
    if len(indexed) < 2:
        return
    checked = False
    for i in range(len(indexed)):
        for j in range(i + 1, len(indexed)):
            a, b = indexed[i], indexed[j]
            pair_re = re.compile(r"\b" + re.escape(a) + r"\.length\b\s*[!=]=\s*" + re.escape(b) + r"\.length\b|\b" + re.escape(b) + r"\.length\b\s*[!=]=\s*" + re.escape(a) + r"\.length\b")
            if pair_re.search(body):
                checked = True
                break
        if checked:
            break
    if checked:
        return
    fctx["collector"].add("mismatched-array-length.general", fn["_headStart"], fctx["cname"], scope, {"name": fn["name"], "arrayParams": indexed})


def detect_access_control_admin_transfer_no_two_step(fctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, second block
    (docs/decisiones.md D-040). AccessControl's analogue of
    single-step-ownership-transfer.general (which only covers Ownable):
    a `grantRole(X, ...)` and a `revokeRole(X, ...)`/`renounceRole(X, ...)`
    on the SAME role expression X inside the SAME function, with no
    on-chain acceptance step from the new holder. Restricted to role
    expressions whose text contains "ADMIN" (case-insensitive) to keep this
    narrow to the highest-stakes role rather than firing on routine
    same-function role rotations (e.g. MINTER_ROLE). Potential signal only,
    not an automatic vulnerability - an atomic grant+revoke behind an
    already well-guarded caller (e.g. a timelock) can be a perfectly
    reasonable design; fpRisk is medium, not high, since the pattern itself
    is specific (same role, same function)."""
    fn, scope, cname = fctx["fn"], fctx["scope"], fctx["cname"]
    body = fn.get("_body", "")
    grant_match = ADMIN_ROLE_GRANT_RE.search(body)
    if not grant_match:
        return
    role_expr = grant_match.group(1).strip()
    if not re.search(r"ADMIN", role_expr, re.I):
        return
    revoke_re = re.compile(ADMIN_ROLE_REVOKE_RE_TEMPLATE.format(role=re.escape(role_expr)))
    if not revoke_re.search(body):
        return
    fctx["collector"].add("access-control-admin-transfer-no-two-step.general", fn["_headStart"], cname, scope, {"role": role_expr})


def detect_diamond_cut_unprotected(fctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, third block
    (docs/decisiones.md D-041). EIP-2535 Diamond pattern: `diamondCut`
    (add/replace/remove facets) controls the entire contract's logic - the
    same blast radius as an UUPS/Transparent upgrade entry point, but not
    covered by UPGRADE_FUNCTION_RE (a distinct, EIP-mandated exact name,
    not related to that family's proxy-shaped names). Same structure as
    detect_upgrade_function_unprotected: evaluate this function's own
    already-computed `fn`/`access` directly. fpRisk low - this exact name
    is essentially only ever used for the EIP-2535 entry point."""
    fn, access, scope, cname = fctx["fn"], fctx["access"], fctx["scope"], fctx["cname"]
    name = fn["name"] or ""
    if not DIAMOND_CUT_NAME_RE.match(name):
        return
    if access["guarded"]:
        return
    fctx["collector"].add("diamond-cut-unprotected.general", fn["_headStart"], cname, scope, {"name": name})


def detect_disable_initializers_outside_constructor_unprotected(fctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, third block
    (docs/decisiones.md D-041). `_disableInitializers()` is meant to be
    called once, at deployment, from the constructor - the standard
    pattern implementation-not-disabled.general already checks for. A
    public/external function OTHER than the constructor that also contains
    this call and carries no guard lets anyone permanently lock the
    contract out of ever being initialized/re-initialized (a griefing
    surface on a not-yet-initialized proxy, or a DoS on a future
    upgrade path that expects a fresh reinitializer to run). Restricted to
    public/external functions (like admin-function-unprotected.general) so
    an internal helper only reachable from an already-guarded caller
    elsewhere in the same contract is not flagged in isolation."""
    fn, access, scope, cname = fctx["fn"], fctx["access"], fctx["scope"], fctx["cname"]
    if fn["kind"] == "constructor" or fn["visibility"] not in ("public", "external"):
        return
    if "_disableInitializers" not in fn.get("_body", ""):
        return
    if access["guarded"]:
        return
    fctx["collector"].add("disable-initializers-outside-constructor-unprotected.general", fn["_headStart"], cname, scope, {"name": fn["name"] or fn["kind"], "visibility": fn["visibility"]})


# --- contract-phase checks --------------------------------------------------

def detect_proxy_pattern(ctx: Dict[str, Any]) -> None:
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    function_names = [fn["name"] for fn in contract["functions"] if fn["name"]]
    indicators = []
    for base in contract["bases"]:
        if PROXY_BASE_RE.search(base):
            indicators.append("base:" + base)
    contract_original = ctx["original"][contract["_start"]:contract["_bodyEnd"]]
    for slot in KNOWN_PUBLIC_SLOTS:
        if slot in contract_original.lower():
            indicators.append("storage-slot-constant")
            break
    for item in ctx["entry"]["strings"]:
        if contract["_start"] <= item["start"] <= contract["_bodyEnd"] and re.search(r"eip1967|org\.zeppelinos|PROXIABLE|eip1822", item["text"], re.I):
            indicators.append("storage-slot-string")
            break
    for fname in function_names:
        if PROXY_FUNCTION_RE.match(fname):
            indicators.append("function:" + fname)
    for fn in contract["functions"]:
        if fn["kind"] == "fallback" and re.search(r"delegatecall", fn.get("_body", "")):
            indicators.append("fallback-delegatecall")
    if re.search(r"\bsstore\s*\(", ctx["body"]) and ctx["assembly_spans"]:
        indicators.append("assembly-sstore")
    if not indicators:
        return
    has_initializer = any(INITIALIZER_NAME_RE.match(n) for n in function_names)
    ctor = next((fn for fn in contract["functions"] if fn["kind"] == "constructor"), None)
    ctx["collector"].add("proxy-pattern.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {
        "indicators": sorted(set(indicators)),
        "hasInitializer": has_initializer,
        "constructorDisablesInitializers": bool(ctor and "_disableInitializers" in ctor.get("_body", "")),
    })


def detect_single_step_ownership_transfer(ctx: Dict[str, Any]) -> None:
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    function_names = [fn["name"] for fn in contract["functions"] if fn["name"]]
    transfer_fn = next((n for n in function_names if OWNERSHIP_TRANSFER_RE.match(n)), None)
    inherits_ownable = any(re.match(r"^Ownable(Upgradeable)?$", b) for b in contract["bases"])
    two_step = any(TWO_STEP_RE.search(b) for b in contract["bases"]) or any(TWO_STEP_RE.search(n) for n in function_names) or any(TWO_STEP_RE.search(v["name"]) for v in contract["stateVariables"])
    if not ((transfer_fn or inherits_ownable) and not two_step):
        return
    fn = next((f for f in contract["functions"] if f["name"] == transfer_fn), None)
    offset = fn["_headStart"] if fn else contract["_start"]
    ctx["collector"].add("single-step-ownership-transfer.general", offset, cname, locate_scope(contract, offset), {"function": transfer_fn, "inherited": transfer_fn is None and inherits_ownable})


def detect_storage_gap_missing(ctx: Dict[str, Any]) -> None:
    """Upgradeable base contracts conventionally reserve a trailing
    `uint256[N] private __gap;`-shaped array so a future version can add
    state without shifting storage slots for derived contracts. Only checks
    contracts that already show an upgradeable-named base (same `PROXY_BASE_RE`
    used by detect_proxy_pattern, applied to the already-parsed `bases` list -
    no new text scan). Absence is a potential gap, not a defect by itself:
    a contract using namespaced/ERC-7201 storage instead of the OZ `__gap`
    convention, or one that is never actually inherited further, needs no
    gap at all - hence fpRisk high."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None or not any(PROXY_BASE_RE.search(base) for base in contract["bases"]):
        return
    if any(GAP_VAR_RE.match(var["name"]) for var in contract["stateVariables"]):
        return
    ctx["collector"].add("storage-gap-missing.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {"bases": contract["bases"]})


def detect_reentrancy_inconsistent_guarding(ctx: Dict[str, Any]) -> None:
    """Corroborating evidence for reentrancy-pattern.general: if this
    contract already has a guarded, state-changing function that itself
    makes a real external call (kind != eth-transfer), the contract's author
    clearly knows the nonReentrant pattern - so a *different*, already-flagged
    function in the same contract missing that same guard is a more likely
    genuine gap than an isolated reentrancy-pattern hit. Reads only
    already-computed data (ctx["collector"].signals so far, fn["reentrancyGuarded"]/
    fn["stateChanging"] set by enrich_function, ctx["external_call_offsets"]
    populated by the scope-phase checks) - no new regex scan of source text."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    flagged = [s for s in ctx["collector"].signals if s["checkId"] == "reentrancy-pattern.general" and s["contract"] == cname]
    if not flagged:
        return
    guarded_names = sorted({
        fn["name"] or fn["kind"]
        for fn in contract["functions"]
        if fn.get("reentrancyGuarded") and fn.get("stateChanging")
        and fn["_bodyStart"] is not None and fn["_bodyEnd"] is not None
        and any(fn["_bodyStart"] <= off <= fn["_bodyEnd"] for off, kind in ctx["external_call_offsets"] if kind != "eth-transfer")
    })
    if not guarded_names:
        return
    by_name = {(fn["name"] or fn["kind"]): fn for fn in contract["functions"]}
    for s in flagged:
        fn = by_name.get(s["function"])
        offset = fn["_headStart"] if fn else contract["_start"]
        ctx["collector"].add("reentrancy-inconsistent-guarding.general", offset, cname, {"function": s["function"], "modifier": None, "kind": None}, {"guardedSiblingFunctions": guarded_names})


def detect_implementation_not_disabled(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, second block (docs/decisiones.md D-033).
    An upgradeable-indicated contract (same `PROXY_BASE_RE` gate as
    storage-gap-missing, applied to the already-parsed `bases` list) that
    declares an `initialize`-shaped function should disable initializers on
    the implementation itself (`_disableInitializers()` in its constructor,
    or in a no-constructor default) so nobody can call `initialize` directly
    on the deployed logic contract. Potential signal only: an abstract base
    never deployed on its own does not need this - hence fpRisk high, same
    caveat class as storage-gap-missing."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None or not any(PROXY_BASE_RE.search(base) for base in contract["bases"]):
        return
    function_names = [fn["name"] for fn in contract["functions"] if fn["name"]]
    if not any(INITIALIZER_NAME_RE.match(n) for n in function_names):
        return
    ctor = next((fn for fn in contract["functions"] if fn["kind"] == "constructor"), None)
    if ctor and "_disableInitializers" in ctor.get("_body", ""):
        return
    ctx["collector"].add("implementation-not-disabled.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {"hasConstructor": ctor is not None})


def detect_external_call_in_modifier(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, second block (docs/decisiones.md D-033).
    A modifier's code runs *before* the function body it guards - an
    external call inside a modifier is a distinct reentrancy-adjacent
    surface from reentrancy-pattern.general (which only looks at function
    bodies). `contract["modifiers"]` entries carry `_start`/`_end` offsets
    (preprocess.py's parse_modifiers) but no pre-sliced `_body` string like
    functions do, so the span is sliced here directly from `ctx["masked"]` -
    confirmed reliable before implementing (docs/decisiones.md D-033)."""
    contract, cname, masked = ctx["contract"], ctx["cname"], ctx["masked"]
    if cname is None:
        return
    for mod in contract["modifiers"]:
        span = masked[mod["_start"]:mod["_end"]]
        match = EXTERNAL_CALL_IN_MODIFIER_RE.search(span)
        if not match:
            continue
        offset = mod["_start"] + match.start()
        ctx["collector"].add("external-call-in-modifier.general", offset, cname, {"function": None, "modifier": mod["name"], "kind": None}, {"modifier": mod["name"], "call": match.group(1)})


def detect_reentrancy_guard_not_first_modifier(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, third block (docs/decisiones.md D-035).
    Modifiers run in the order listed, each wrapping the next - a
    `nonReentrant`-style guard that is not the FIRST modifier leaves
    whatever runs in an earlier modifier outside the guard. Only fires when
    an earlier modifier is one this same contract's own
    external-call-in-modifier.general already flagged as making a real
    external call (read from ctx["collector"].signals, populated earlier in
    this same CONTRACT_CHECKS pass by list order below) - a plain
    access-control modifier before the guard is not flagged. No new text
    scan; reuses REENTRANCY_GUARD_RE (context.py) and the already-parsed,
    ordered fn["modifiers"]."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    risky_modifier_names = {
        s["details"]["modifier"]
        for s in ctx["collector"].signals
        if s["checkId"] == "external-call-in-modifier.general" and s["contract"] == cname
    }
    if not risky_modifier_names:
        return
    for fn in contract["functions"]:
        mods = fn["modifiers"]
        guard_idx = next((i for i, m in enumerate(mods) if REENTRANCY_GUARD_RE.match(m["name"])), None)
        if guard_idx is None or guard_idx == 0:
            continue
        earlier_risky = [m["name"] for m in mods[:guard_idx] if m["name"] in risky_modifier_names]
        if not earlier_risky:
            continue
        scope = {"function": fn["name"] or fn["kind"], "modifier": None, "kind": fn["kind"]}
        ctx["collector"].add("reentrancy-guard-not-first-modifier.general", fn["_headStart"], cname, scope, {"guard": mods[guard_idx]["name"], "earlierModifiers": earlier_risky})


def detect_eip1967_slot_specific(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, first block
    (docs/decisiones.md D-038). proxy-pattern.general already checks the
    same 4 known slot values but collapses them into one generic
    "storage-slot-constant" indicator regardless of which slot matched.
    This narrows that into a specific fact per slot found (implementation/
    admin/beacon/eip1822-proxiable) - a pure fact, not a defect, so fpRisk
    is low, same as proxy-pattern itself. Does not modify proxy-pattern."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    contract_original = ctx["original"][contract["_start"]:contract["_bodyEnd"]].lower()
    for slot, kind in sorted(EIP1967_SLOT_KIND.items()):
        if slot in contract_original:
            ctx["collector"].add("eip1967-slot-specific.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {"slotKind": kind})


def detect_naive_proxy_storage_collision(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, first block
    (docs/decisiones.md D-038; broadened in D-039). A contract that
    delegatecalls anywhere in its body (reusing the delegatecall.general
    signal already emitted earlier in this same scope-phase pass - see the
    module docstring on ordering) but shows none of the known EIP-1967/
    EIP-1822 slots is using "naive" storage: its own state variables sit at
    the same slots (0, 1, 2, ...) the delegated-to contract's variables
    would use, risking a collision. Only fires when the contract also
    declares at least one non-constant, non-immutable state variable
    (constants/immutables consume no storage slot, so cannot collide).
    Potential signal only, not an automatic vulnerability - a
    namespaced-storage pattern this heuristic does not recognize could
    still be collision-free - hence fpRisk high, same caveat class as
    storage-gap-missing.

    D-039: not restricted to a delegatecall inside fallback() specifically
    - a named-function-based forwarder (`function forward(bytes calldata d)
    external { impl.delegatecall(d); }`) carries the identical
    storage-collision risk and is a realistic, non-fallback proxy shape.
    The original inFallback-only filter missed it, inconsistent with
    compute_system_graph's own proxy-pairing heuristic (which already
    falls back to any delegatecall site in the contract when none is in
    fallback - see its module-level comment). See
    test_delegatecall_in_named_function_is_flagged_naive_proxy_storage_collision."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    delegate_hits = [s for s in ctx["collector"].signals if s["family"] == "delegatecall" and s["contract"] == cname]
    if not delegate_hits:
        return
    contract_original = ctx["original"][contract["_start"]:contract["_bodyEnd"]].lower()
    if any(slot in contract_original for slot in EIP1967_SLOT_KIND):
        return
    storage_vars = [v["name"] for v in contract["stateVariables"] if not v.get("constant") and not v.get("immutable")]
    if not storage_vars:
        return
    ctx["collector"].add("naive-proxy-storage-collision.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {"stateVariables": storage_vars})


def _is_initializer_guarded(fn: Dict[str, Any]) -> bool:
    guarded_by_modifier = any(INITIALIZER_GUARD_RE.match(m["name"]) for m in fn["modifiers"])
    guarded_by_body = bool(INITIALIZED_BODY_RE.search(fn.get("_body", ""))) or function_access_info(fn)["guarded"]
    return guarded_by_modifier or guarded_by_body


def detect_initializer_reinitializer_inconsistency(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, first block
    (docs/decisiones.md D-038). Complements initializer-unprotected.general
    (which flags a single unguarded initializer standalone) by comparing
    protection ACROSS every initializer-shaped function in the same
    contract: the primary initializer (INITIALIZER_NAME_RE, same as
    initializer-unprotected) plus any function carrying a `reinitializer`
    modifier (a later, versioned re-initialization entry point - the
    modifier's own presence is not, by itself, proof of protection, since a
    guard could still be missing from an unrelated function that also
    matches). Fires only when at least one candidate is guarded and at
    least one is not - a plain, uniformly-unprotected set is already fully
    covered by initializer-unprotected.general on its own."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    candidates = []
    for fn in contract["functions"]:
        name = fn["name"] or ""
        is_primary = bool(INITIALIZER_NAME_RE.match(name)) and fn["visibility"] in ("public", "external") and fn.get("stateChanging")
        has_reinit_modifier = any(REINITIALIZER_MODIFIER_RE.match(m["name"]) for m in fn["modifiers"])
        if is_primary or has_reinit_modifier:
            candidates.append((fn, _is_initializer_guarded(fn)))
    if len(candidates) < 2:
        return
    guarded_names = sorted(fn["name"] for fn, guarded in candidates if guarded)
    unguarded_names = sorted(fn["name"] for fn, guarded in candidates if not guarded)
    if not guarded_names or not unguarded_names:
        return
    unguarded_fn = next(fn for fn, guarded in candidates if not guarded)
    scope = {"function": unguarded_fn["name"], "modifier": None, "kind": unguarded_fn["kind"]}
    ctx["collector"].add("initializer-reinitializer-inconsistency.general", unguarded_fn["_headStart"], cname, scope, {"guarded": guarded_names, "unguarded": unguarded_names})


def detect_reinitializer_version_not_increasing(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, second block
    (docs/decisiones.md D-040). `reinitializer(N)` is meant to be a single,
    monotonically increasing per-contract counter (each version usable only
    once, and only after all lower versions). Walks every reinitializer-
    tagged function in declaration order (already-parsed `fn["modifiers"]`,
    including each modifier's own already-parsed `args` text - no new
    scan) and flags any version that is not strictly greater than the
    previous one seen: a duplicate or out-of-order version number would let
    an already-used re-initialization entry point run again, or run out of
    the intended sequence."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    versions = []
    for fn in contract["functions"]:
        for m in fn["modifiers"]:
            if m["name"] != "reinitializer":
                continue
            args = (m.get("args") or "").strip()
            if re.match(r"^\d+$", args):
                versions.append((fn, int(args)))
            break
    if len(versions) < 2:
        return
    last_version = versions[0][1]
    for fn, version in versions[1:]:
        if version <= last_version:
            scope = {"function": fn["name"] or fn["kind"], "modifier": None, "kind": fn["kind"]}
            ctx["collector"].add("reinitializer-version-not-increasing.general", fn["_headStart"], cname, scope, {"version": version, "previousVersion": last_version})
        last_version = version


def detect_constructor_sets_state_in_upgradeable(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, second block
    (docs/decisiones.md D-040). An upgradeable-indicated contract (same
    `PROXY_BASE_RE` gate as storage-gap-missing/implementation-not-disabled)
    that also defines an initializer function but sets non-constant,
    non-immutable state in its constructor: constructor code runs once at
    the IMPLEMENTATION's own deployment, never in the proxy's storage
    context, so any such write is invisible to every proxy delegating to
    it. Immutable/constant variables are excluded - they are compiled into
    the implementation's bytecode, not storage, so setting them in a
    constructor is the standard, correct pattern precisely because it works
    under delegatecall. Skipped entirely if the constructor already calls
    `_disableInitializers()`, same as implementation-not-disabled - that
    call is itself evidence the constructor is deliberately
    deployment-time-only. Reuses find_state_writes (context.py), already
    used the same way by admin-function-unprotected.general."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None or not any(PROXY_BASE_RE.search(base) for base in contract["bases"]):
        return
    function_names = [fn["name"] for fn in contract["functions"] if fn["name"]]
    if not any(INITIALIZER_NAME_RE.match(n) for n in function_names):
        return
    ctor = next((fn for fn in contract["functions"] if fn["kind"] == "constructor"), None)
    if not ctor or ctor["_bodyStart"] is None or ctor["_bodyEnd"] is None:
        return
    if "_disableInitializers" in ctor.get("_body", ""):
        return
    state_names = [v["name"] for v in contract["stateVariables"] if not v.get("constant") and not v.get("immutable")]
    if not state_names:
        return
    writes, internal_calls = find_state_writes(ctor["_body"], ctor["_bodyStart"] + 1, ctor["_bodyStart"] + 1, state_names, ctx["line_index"])
    if not writes and not internal_calls:
        return
    scope = {"function": ctor["name"] or ctor["kind"], "modifier": None, "kind": ctor["kind"]}
    ctx["collector"].add("constructor-sets-state-in-upgradeable.general", ctor["_headStart"], cname, scope, {})


def detect_multiple_upgradeable_bases(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, second block
    (docs/decisiones.md D-040). Purely structural fact, reusing PROXY_BASE_RE
    against the already-parsed `bases` list (no new scan): inheriting 2+
    upgradeable-indicated bases makes Solidity's C3 linearization order of
    those bases significant for the final storage layout - reordering the
    `is A, B` list can silently change slot assignment. Informational, not
    a defect by itself, hence fpRisk low."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    matching_bases = [base for base in contract["bases"] if PROXY_BASE_RE.search(base)]
    if len(matching_bases) < 2:
        return
    ctx["collector"].add("multiple-upgradeable-bases.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {"bases": matching_bases})


def detect_governance_reference(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, second block
    (docs/decisiones.md D-040). Presence-only signal: a base or a state
    variable's already-resolved `userType` naming a known
    timelock/governor/multisig shape (TimelockController, Governor,
    GnosisSafe/Safe, MultiSig). Fires ONLY when such a reference is found -
    there is no "absence" branch anywhere in this function, by design: not
    finding a governance-shaped name is not evidence a contract lacks
    governance (it could be an externally-owned multisig address with no
    on-chain type trace at all), so this family must never be read as
    "no timelock/multisig detected = risk"."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None:
        return
    matches = set()
    for base in contract["bases"]:
        if GOVERNANCE_REFERENCE_RE.search(base):
            matches.add(base)
    for var in contract["stateVariables"]:
        user_type = var.get("userType")
        if user_type and GOVERNANCE_REFERENCE_RE.search(user_type):
            matches.add(user_type)
    if not matches:
        return
    ctx["collector"].add("governance-reference-detected.general", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {"references": sorted(matches)})


def detect_auth_modifier_empty_guard(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, third block
    (docs/decisiones.md D-041). An access-control-named modifier
    (`only*`/`auth*`) whose body contains neither `msg.sender`/`tx.origin`
    NOR any function call at all before its `_;` placeholder is a no-op
    guard - it compiles and runs but enforces nothing. Deliberately
    excludes OpenZeppelin v5's own delegation pattern
    (`modifier onlyOwner() { _checkOwner(); _; }`), which contains a
    function call and therefore does not match "no function call at all" -
    this is what keeps fpRisk low despite the very common `only*` naming
    convention. Reuses the same `contract["modifiers"]` `_start`/`_end`
    span slicing external-call-in-modifier.general already relies on;
    isolates the actual body (after the first `{`) so the modifier's own
    name+params (e.g. `onlyOwner(` itself) can never self-match the
    function-call shape being searched for."""
    contract, cname, masked = ctx["contract"], ctx["cname"], ctx["masked"]
    if cname is None:
        return
    for mod in contract["modifiers"]:
        if not AUTH_MODIFIER_NAME_RE.match(mod["name"]):
            continue
        span = masked[mod["_start"]:mod["_end"]]
        brace_idx = span.find("{")
        if brace_idx == -1:
            continue
        body = span[brace_idx + 1:]
        if MODIFIER_HAS_ANY_CHECK_RE.search(body):
            continue
        ctx["collector"].add("auth-modifier-empty-guard.general", mod["_start"], cname, {"function": None, "modifier": mod["name"], "kind": None}, {"modifier": mod["name"]})


def detect_upgradeable_contract_has_selfdestruct(ctx: Dict[str, Any]) -> None:
    """V2.3, Access Control + Proxy/Upgradeability, third block
    (docs/decisiones.md D-041). Single-file, all-modes complement to
    preprocess.py's cross-contract, pro-only
    implementation-selfdestruct-reachable.general: that one needs a
    systemGraph-resolved proxy pairing to confirm a real proxy delegates to
    this exact contract; this one fires on the cheaper, always-available
    structural fact alone - an upgradeable-indicated contract (same
    PROXY_BASE_RE gate as storage-gap-missing/implementation-not-disabled)
    that already carries a selfdestruct.general or
    selfdestruct-unprotected.general signal (both reused verbatim, no new
    scan) - worth a second look in quick/standard mode too, where
    systemGraph is never computed."""
    contract, cname = ctx["contract"], ctx["cname"]
    if cname is None or not any(PROXY_BASE_RE.search(base) for base in contract["bases"]):
        return
    hits = [s for s in ctx["collector"].signals if s["family"] in ("selfdestruct", "selfdestruct-unprotected") and s["contract"] == cname]
    for hit in hits:
        offset = ctx["line_index"].offset_of_line(hit["line"])
        scope = {"function": hit.get("function"), "modifier": hit.get("modifier"), "kind": None}
        ctx["collector"].add("upgradeable-contract-has-selfdestruct.general", offset, cname, scope, {"baseSignalFamily": hit["family"]})


FUNCTION_CHECKS = [
    ("initializer-unprotected.general", detect_initializer_unprotected),
    ("zero-address-unchecked.general", detect_zero_address_unchecked),
    ("admin-function-unprotected.general", detect_admin_function_unprotected),
    ("upgrade-function.general", detect_upgrade_function),
    ("reentrancy-pattern.general", detect_reentrancy_pattern),
    ("unprotected-callback-handler.general", detect_unprotected_callback_handler),
    ("mismatched-array-length.general", detect_mismatched_array_length),
    ("upgrade-function-unprotected.general", detect_upgrade_function_unprotected),
    ("access-control-admin-transfer-no-two-step.general", detect_access_control_admin_transfer_no_two_step),
    ("diamond-cut-unprotected.general", detect_diamond_cut_unprotected),
    ("disable-initializers-outside-constructor-unprotected.general", detect_disable_initializers_outside_constructor_unprotected),
]

CONTRACT_CHECKS = [
    ("proxy-pattern.general", detect_proxy_pattern),
    ("single-step-ownership-transfer.general", detect_single_step_ownership_transfer),
    ("storage-gap-missing.general", detect_storage_gap_missing),
    ("reentrancy-inconsistent-guarding.general", detect_reentrancy_inconsistent_guarding),
    ("implementation-not-disabled.general", detect_implementation_not_disabled),
    ("external-call-in-modifier.general", detect_external_call_in_modifier),
    ("reentrancy-guard-not-first-modifier.general", detect_reentrancy_guard_not_first_modifier),
    ("eip1967-slot-specific.general", detect_eip1967_slot_specific),
    ("naive-proxy-storage-collision.general", detect_naive_proxy_storage_collision),
    ("initializer-reinitializer-inconsistency.general", detect_initializer_reinitializer_inconsistency),
    ("reinitializer-version-not-increasing.general", detect_reinitializer_version_not_increasing),
    ("constructor-sets-state-in-upgradeable.general", detect_constructor_sets_state_in_upgradeable),
    ("multiple-upgradeable-bases.general", detect_multiple_upgradeable_bases),
    ("governance-reference-detected.general", detect_governance_reference),
    ("auth-modifier-empty-guard.general", detect_auth_modifier_empty_guard),
    ("upgradeable-contract-has-selfdestruct.general", detect_upgradeable_contract_has_selfdestruct),
]
