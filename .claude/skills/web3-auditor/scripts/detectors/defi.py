# -*- coding: utf-8 -*-
"""Scope-level DeFi/finance-shaped checks (phase="scope"), independent of
each other and of external_call_offsets. Moved verbatim from the pre-V2.1
detect_solidity_signals monolith.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from .context import collapse_ws, fn_at, locate_scope, loop_spans, statement_at
from text_utils import matching_paren, split_top_level

ORACLE_METHOD_RE = re.compile(r"\.(latestRoundData|latestAnswer|getReserves|slot0|observe|consult|getPrice\w*|price|getAmountsOut|getAmountOut|getAmountsIn|quote\w*|getRate\w*|exchangeRate\w*|pricePerShare|getPricePerFullShare|convertToAssets|convertToShares|totalAssets)\s*\(")
FLASH_RE = re.compile(r"\b(flashLoan\w*|onFlashLoan|executeOperation|uniswapV2Call|uniswapV3FlashCallback|receiveFlashLoan|IERC3156\w*|IFlashLoan\w*|flashSwap|flash|maxFlashLoan|flashFee)\b")
SWAP_CALL_RE = re.compile(r"\b(swap\w*|exactInput\w*|exactOutput\w*|addLiquidity\w*|removeLiquidity\w*)\s*\(")
MIN_AMOUNT_ZERO_RE = re.compile(r"\b(amountOutMin\w*|amountOutMinimum|minAmountOut|amountAMin|amountBMin|minReturn\w*|minOut\w*|minimumAmount\w*|sqrtPriceLimitX96)\s*:\s*0\b")
SIGNATURE_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|\.tryRecover\s*\(|\bECDSA\.|\bSignatureChecker\.|\bisValidSignature\s*\(")
# --- V2.1 detector-expansion, first block (docs/decisiones.md D-032) ---
ECRECOVER_RE = re.compile(r"\becrecover\s*\(")
ECRECOVER_ASSIGN_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*=\s*$")
LATEST_ROUND_DATA_RE = re.compile(r"\.latestRoundData\s*\(\s*\)")
ANSWER_VALIDATION_RE = re.compile(r"\banswer\b\s*[<>]=?\s*0\b|\b0\b\s*[<>]=?\s*\banswer\b|require\s*\([^;]*\banswer\b[^;]*\)|\bupdatedAt\b|\bansweredInRound\b|\broundId\b|\bstale\b|\bheartbeat\b|\bmaxAge\b|\bMAX_DELAY\b")
# --- V2.1 detector-expansion, third block (docs/decisiones.md D-035) ---
APPROVE_METHOD_RE = re.compile(r"\.(approve|safeApprove|forceApprove|increaseAllowance)\s*\(")
MAX_APPROVAL_ARG_RE = re.compile(r"type\s*\(\s*uint(256)?\s*\)\s*\.max|2\s*\*\*\s*256\s*-\s*1|uint256\s*\(\s*-\s*1\s*\)|MAX_UINT|MAX_INT|0x[fF]{64}")
PERMIT_CALL_RE = re.compile(r"([A-Za-z_$][\w$.\[\]()]*?)\s*\.\s*permit\s*(?:\{[^}]*\})?\s*\(")
TRY_BEFORE_CALL_RE = re.compile(r"\btry\s+$")
DOMAIN_SEPARATOR_RE = re.compile(r"DOMAIN_SEPARATOR|_domainSeparator|EIP712|_hashTypedData|typedDataHash", re.I)
DOMAIN_SEPARATOR_BASE_RE = re.compile(r"EIP712|Permit", re.I)


def detect_oracle_usage(ctx: Dict[str, Any]) -> None:
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in ORACLE_METHOD_RE.finditer(body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        fn = fn_at(ctx, offset)
        fbody = fn.get("_body", "") if fn else body
        method = match.group(1)
        provider = "generic"
        if method in ("latestRoundData", "latestAnswer"):
            provider = "chainlink"
        elif method == "getReserves":
            provider = "uniswap-v2"
        elif method in ("slot0", "observe"):
            provider = "uniswap-v3"
        ctx["collector"].add("oracle-usage.general", offset, ctx["cname"], scope, {
            "method": method,
            "provider": provider,
            "stalenessCheckInFunction": bool(re.search(r"updatedAt|answeredInRound|roundId|stale|heartbeat|maxAge|MAX_DELAY|timestamp\s*[<>]", fbody, re.I)),
            "balanceOfThisInFunction": bool(re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", fbody)),
            "spotSource": method in ("getReserves", "slot0"),
        })


def detect_flash_loan_surface(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in FLASH_RE.finditer(body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        preceding = masked[max(span_start, offset - 12):offset]
        role = "reference"
        if re.search(r"function\s+$", preceding):
            role = "provider" if match.group(1).startswith("flash") else "receiver"
        elif preceding.rstrip().endswith("."):
            role = "caller"
        ctx["collector"].add("flash-loan-surface.general", offset, ctx["cname"], scope, {"identifier": match.group(1), "role": role})


def detect_slippage_unprotected(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in SWAP_CALL_RE.finditer(body):
        offset = span_start + match.start()
        open_paren = span_start + match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        if close_paren == -1:
            continue
        preceding = masked[max(span_start, offset - 10):offset]
        if re.search(r"function\s+$", preceding):
            continue
        args_text = masked[open_paren + 1:close_paren]
        args = [collapse_ws(part) for part in split_top_level(args_text)]
        zero_min = any(arg == "0" for arg in args) or MIN_AMOUNT_ZERO_RE.search(args_text) is not None
        deadline_now = any(arg == "block.timestamp" for arg in args) or re.search(r"deadline\s*:\s*block\.timestamp\b", args_text) is not None
        if zero_min or deadline_now:
            scope = locate_scope(contract, offset)
            ctx["collector"].add("slippage-unprotected.general", offset, ctx["cname"], scope, {"call": match.group(1), "zeroMinAmount": zero_min, "deadlineIsBlockTimestamp": deadline_now})


def detect_unlimited_approval(ctx: Dict[str, Any]) -> None:
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in re.finditer(r"\.(approve|safeApprove|forceApprove|increaseAllowance)\s*\(", body):
        offset = span_start + match.start()
        open_paren = span_start + match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        if close_paren == -1:
            continue
        args_text = collapse_ws(masked[open_paren + 1:close_paren])
        if re.search(r"type\s*\(\s*uint(256)?\s*\)\s*\.max|2\s*\*\*\s*256\s*-\s*1|uint256\s*\(\s*-\s*1\s*\)|MAX_UINT|MAX_INT|0x[fF]{64}", args_text):
            scope = locate_scope(contract, offset)
            ctx["collector"].add("unlimited-approval.general", offset, ctx["cname"], scope, {"method": match.group(1), "spender": split_top_level(args_text)[0] if split_top_level(args_text) else None})


def detect_signature_replay_surface(ctx: Dict[str, Any]) -> None:
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in SIGNATURE_RE.finditer(body):
        offset = span_start + match.start()
        scope = locate_scope(contract, offset)
        fn = fn_at(ctx, offset)
        fbody = fn.get("_body", "") if fn else ""
        ctx["collector"].add("signature-replay-surface.general", offset, ctx["cname"], scope, {
            "api": collapse_ws(match.group(0)).rstrip("("),
            "nonceFound": bool(re.search(r"\bnonces?\b", body, re.I)),
            "chainIdFound": bool(re.search(r"chainid|DOMAIN_SEPARATOR|EIP712|_domainSeparator|_hashTypedData|typedData", body, re.I)),
            "deadlineFound": bool(re.search(r"deadline|expir|validUntil|validBefore|notAfter", body, re.I)),
            "zeroAddressCheckInFunction": bool(re.search(r"address\s*\(\s*0\s*\)", fbody)),
            "usedSignatureTracking": bool(re.search(r"usedSignatures|_usedNonces|executed\s*\[|signatures\s*\[|usedHashes|processed\s*\[", body)),
        })


def detect_ecrecover_zero_address_unchecked(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, first block (docs/decisiones.md D-032).
    `ecrecover` returns `address(0)` on a malformed signature instead of
    reverting; using its result (directly, or via the variable it was
    assigned to) without ever comparing it to `address(0)` is a distinct,
    narrower defect than signature-replay-surface's broader nonce/chainId/
    deadline inventory. Stays within one function body (statement_at +
    a bounded tail scan to the enclosing function's end) - no file-wide scan."""
    contract, span_start, body, masked = ctx["contract"], ctx["span_start"], ctx["body"], ctx["masked"]
    for match in ECRECOVER_RE.finditer(body):
        offset = span_start + match.start()
        stmt, stmt_start = statement_at(masked, offset, span_start, ctx["span_end"])
        if re.search(r"address\s*\(\s*0x?0*\s*\)", stmt):
            continue
        prefix = collapse_ws(masked[stmt_start:offset])
        assign = ECRECOVER_ASSIGN_RE.search(re.sub(r"^address\s+", "", prefix))
        fn = fn_at(ctx, offset)
        checked_later = False
        if assign and fn and fn["_bodyEnd"] is not None:
            varname = assign.group(1)
            tail = masked[offset:fn["_bodyEnd"]]
            checked_later = bool(re.search(r"\b" + re.escape(varname) + r"\b\s*[!=]=\s*address\s*\(\s*0x?0*\s*\)|address\s*\(\s*0x?0*\s*\)\s*[!=]=\s*\b" + re.escape(varname) + r"\b", tail))
        if checked_later:
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("ecrecover-zero-address-unchecked.general", offset, ctx["cname"], scope, {"assignedTo": assign.group(1) if assign else None})


def detect_oracle_answer_unchecked(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, first block (docs/decisiones.md D-032).
    Narrows oracle-usage's informational `stalenessCheckInFunction` flag into
    its own gated signal specifically for Chainlink's `latestRoundData()`:
    fires only when the enclosing function shows neither a staleness/round
    check nor an `answer` sanity check. Independent regex against the
    already-extracted function body, same bounded-cost pattern as the
    module's other detectors - does not modify detect_oracle_usage."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in LATEST_ROUND_DATA_RE.finditer(body):
        offset = span_start + match.start()
        fn = fn_at(ctx, offset)
        fbody = fn.get("_body", "") if fn else body
        if ANSWER_VALIDATION_RE.search(fbody):
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("oracle-answer-unchecked.general", offset, ctx["cname"], scope, {"method": "latestRoundData"})


def detect_signature_missing_nonce_or_deadline(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, second block (docs/decisiones.md D-033).
    Narrows signature-replay-surface's informational, whole-file
    `nonceFound`/`deadlineFound` flags into a gated signal scoped to the
    *enclosing function* only - a nonce or deadline check elsewhere in the
    file (e.g. in an unrelated function) does not protect this one. Reuses
    `SIGNATURE_RE` verbatim (same constant, not a re-derived pattern) and
    the same nonce/deadline keyword shapes as the existing check, applied to
    `fn["_body"]` instead of the whole scope body. Does not modify
    detect_signature_replay_surface."""
    contract, span_start, body = ctx["contract"], ctx["span_start"], ctx["body"]
    for match in SIGNATURE_RE.finditer(body):
        offset = span_start + match.start()
        fn = fn_at(ctx, offset)
        fbody = fn.get("_body", "") if fn else ""
        if not fbody:
            continue
        nonce_found = bool(re.search(r"\bnonces?\b", fbody, re.I))
        deadline_found = bool(re.search(r"deadline|expir|validUntil|validBefore|notAfter", fbody, re.I))
        if nonce_found or deadline_found:
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("signature-missing-nonce-or-deadline.general", offset, ctx["cname"], scope, {"api": collapse_ws(match.group(0)).rstrip("(")})


def detect_unlimited_approval_in_loop(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, third block (docs/decisiones.md D-035).
    Granting a max-value approval repeatedly inside a loop (one per
    loop-controlled spender/token) multiplies unlimited-approval's own
    exposure surface across every iteration. Reuses loop_spans (already in
    context.py, used by arithmetic_and_gas.py's loop analysis) and the same
    max-approval literal shapes as unlimited-approval, applied only within
    each loop's own body span - no new file-wide scan.

    loop_spans() returns one entry per loop keyword found, so a nested loop
    (for inside for) yields an outer entry whose body span physically
    contains the inner loop's own span too - the same approve() call site
    would then be visited once per enclosing loop level. `seen_offsets`
    dedupes by exact match position so each call site is only ever flagged
    once regardless of nesting depth; found and fixed during review
    (docs/decisiones.md D-035), see
    test_nested_loop_reports_unlimited_approval_only_once."""
    contract, span_start, span_end, masked, pairs = ctx["contract"], ctx["span_start"], ctx["span_end"], ctx["masked"], ctx["pairs"]
    seen_offsets = set()
    for loop in loop_spans(masked, span_start, span_end, pairs):
        loop_body = masked[loop["bodyStart"]:loop["bodyEnd"]]
        for match in APPROVE_METHOD_RE.finditer(loop_body):
            offset = loop["bodyStart"] + match.start()
            if offset in seen_offsets:
                continue
            open_paren = loop["bodyStart"] + match.end() - 1
            close_paren = matching_paren(masked, open_paren)
            if close_paren == -1:
                continue
            args_text = masked[open_paren + 1:close_paren]
            if not MAX_APPROVAL_ARG_RE.search(args_text):
                continue
            seen_offsets.add(offset)
            scope = locate_scope(contract, offset)
            ctx["collector"].add("unlimited-approval-in-loop.general", offset, ctx["cname"], scope, {"method": match.group(1), "loopLine": ctx["line_index"].line_of(loop["start"])})


def detect_permit_not_wrapped_in_try_catch(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, third block (docs/decisiones.md D-035).
    `IERC20Permit.permit(...)` reverts if the signature was already used or
    front-run - calling it unwrapped means that revert propagates and can
    block the whole transaction; `try token.permit(...) { ... } catch { ...
    }` is the documented mitigation. Checks a window of `masked` immediately
    before the call for a literal `try` token (TRY_BEFORE_CALL_RE below):
    the pattern already requires everything between "try" and the call to
    be whitespace, so a generous window is safe - it cannot pick up an
    unrelated, more distant `try` that has other tokens (a statement
    terminator, another call) in between. A 10-char window was tried first
    and missed the common multi-line-argument style (`try` on its own line
    before a long call), a false positive found and fixed during review
    (docs/decisiones.md D-035); see
    test_permit_wrapped_in_multiline_try_is_not_flagged. PERMIT_CALL_RE
    also accepts an optional `{...}` call-options block between `permit`
    and `(` (e.g. `token.permit{gas: 50000}(...)`), a coverage gap found
    and closed during the D-036 review; see
    test_permit_with_gas_call_options_is_flagged_unwrapped."""
    contract, span_start, masked = ctx["contract"], ctx["span_start"], ctx["masked"]
    body = ctx["body"]
    for match in PERMIT_CALL_RE.finditer(body):
        offset = span_start + match.start()
        window_start = max(span_start, offset - 100)
        preceding = masked[window_start:offset]
        if TRY_BEFORE_CALL_RE.search(preceding):
            continue
        scope = locate_scope(contract, offset)
        ctx["collector"].add("permit-not-wrapped-in-try-catch.general", offset, ctx["cname"], scope, {"callee": match.group(1)})


def detect_signature_domain_separator_missing(ctx: Dict[str, Any]) -> None:
    """V2.1 detector-expansion, third block (docs/decisiones.md D-035).
    A contract using ecrecover/ECDSA-shaped signature verification
    (SIGNATURE_RE, reused verbatim) with no EIP-712 domain-separator
    construction anywhere in the same contract risks the same signature
    being replayed against a different contract or chain. Fires once per
    contract, not per signature site.

    Also checks contract["bases"] (already parsed, no new scan) for an
    EIP712/Permit-shaped base name: `ctx["body"]` is only the text inside
    the contract's own braces, so a contract that gets its domain separator
    by inheriting OpenZeppelin's EIP712/ERC20Permit - the standard,
    correct, extremely common way to do this - would never spell
    "DOMAIN_SEPARATOR" anywhere in its own body. An earlier version missed
    this and false-positived on exactly that pattern; found and fixed
    during review (docs/decisiones.md D-035), see
    test_eip712_permit_base_suppresses_domain_separator_missing."""
    contract, cname, body = ctx["contract"], ctx["cname"], ctx["body"]
    if cname is None:
        return
    if not SIGNATURE_RE.search(body):
        return
    if DOMAIN_SEPARATOR_RE.search(body):
        return
    if any(DOMAIN_SEPARATOR_BASE_RE.search(base) for base in contract["bases"]):
        return
    ctx["collector"].add("signature-domain-separator-missing.general", ctx["span_start"], cname, {"function": None, "modifier": None, "kind": None}, {})


CHECKS = [
    ("oracle-usage.general", detect_oracle_usage),
    ("flash-loan-surface.general", detect_flash_loan_surface),
    ("slippage-unprotected.general", detect_slippage_unprotected),
    ("unlimited-approval.general", detect_unlimited_approval),
    ("signature-replay-surface.general", detect_signature_replay_surface),
    ("ecrecover-zero-address-unchecked.general", detect_ecrecover_zero_address_unchecked),
    ("oracle-answer-unchecked.general", detect_oracle_answer_unchecked),
    ("signature-missing-nonce-or-deadline.general", detect_signature_missing_nonce_or_deadline),
    ("unlimited-approval-in-loop.general", detect_unlimited_approval_in_loop),
    ("permit-not-wrapped-in-try-catch.general", detect_permit_not_wrapped_in_try_catch),
    ("signature-domain-separator-missing.general", detect_signature_domain_separator_missing),
]
