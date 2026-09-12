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

from .context import INTERNAL_STATE_CALL_RE, find_state_writes, locate_scope

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


FUNCTION_CHECKS = [
    ("initializer-unprotected.general", detect_initializer_unprotected),
    ("zero-address-unchecked.general", detect_zero_address_unchecked),
    ("admin-function-unprotected.general", detect_admin_function_unprotected),
    ("upgrade-function.general", detect_upgrade_function),
    ("reentrancy-pattern.general", detect_reentrancy_pattern),
    ("unprotected-callback-handler.general", detect_unprotected_callback_handler),
    ("mismatched-array-length.general", detect_mismatched_array_length),
]

CONTRACT_CHECKS = [
    ("proxy-pattern.general", detect_proxy_pattern),
    ("single-step-ownership-transfer.general", detect_single_step_ownership_transfer),
    ("storage-gap-missing.general", detect_storage_gap_missing),
    ("reentrancy-inconsistent-guarding.general", detect_reentrancy_inconsistent_guarding),
]
