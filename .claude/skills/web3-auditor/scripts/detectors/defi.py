# -*- coding: utf-8 -*-
"""Scope-level DeFi/finance-shaped checks (phase="scope"), independent of
each other and of external_call_offsets. Moved verbatim from the pre-V2.1
detect_solidity_signals monolith.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from .context import collapse_ws, fn_at, locate_scope
from text_utils import matching_paren, split_top_level

ORACLE_METHOD_RE = re.compile(r"\.(latestRoundData|latestAnswer|getReserves|slot0|observe|consult|getPrice\w*|price|getAmountsOut|getAmountOut|getAmountsIn|quote\w*|getRate\w*|exchangeRate\w*|pricePerShare|getPricePerFullShare|convertToAssets|convertToShares|totalAssets)\s*\(")
FLASH_RE = re.compile(r"\b(flashLoan\w*|onFlashLoan|executeOperation|uniswapV2Call|uniswapV3FlashCallback|receiveFlashLoan|IERC3156\w*|IFlashLoan\w*|flashSwap|flash|maxFlashLoan|flashFee)\b")
SWAP_CALL_RE = re.compile(r"\b(swap\w*|exactInput\w*|exactOutput\w*|addLiquidity\w*|removeLiquidity\w*)\s*\(")
MIN_AMOUNT_ZERO_RE = re.compile(r"\b(amountOutMin\w*|amountOutMinimum|minAmountOut|amountAMin|amountBMin|minReturn\w*|minOut\w*|minimumAmount\w*|sqrtPriceLimitX96)\s*:\s*0\b")
SIGNATURE_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|\.tryRecover\s*\(|\bECDSA\.|\bSignatureChecker\.|\bisValidSignature\s*\(")


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


CHECKS = [
    ("oracle-usage.general", detect_oracle_usage),
    ("flash-loan-surface.general", detect_flash_loan_surface),
    ("slippage-unprotected.general", detect_slippage_unprotected),
    ("unlimited-approval.general", detect_unlimited_approval),
    ("signature-replay-surface.general", detect_signature_replay_surface),
]
