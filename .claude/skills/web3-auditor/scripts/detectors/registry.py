# -*- coding: utf-8 -*-
"""Single source of truth for every check's metadata and dispatch (V2.1,
docs/decisiones.md). Extends the pre-V2.1 SIGNAL_FAMILIES dict with:

- checkId: the "family.variant" scheme Diego approved. Every check migrated
  in V2.1 keeps its exact pre-V2.1 behavior under the ".general" variant -
  the not-yet-split, base case of that family. A future subfase that
  actually decomposes a family into specialized checks adds sibling
  variants (e.g. "admin-function-unprotected.withdraw-arbitrary-recipient")
  alongside ".general", never by renaming or removing it.
- groupHint: reserved, unused placeholder for future signal
  grouping/prioritization (Diego's decision: prepare the field now, no
  reduction-of-noise system yet - see docs/decisiones.md).

`family` (unchanged, still what every signal's "family" JSON field reports)
and `checkId` (new, additive) are both present on every emitted signal - see
context.py's SignalCollector.

Orchestration order within each phase is significant for a handful of
checks (see calls_and_transfers.py's and access_control.py's module
docstrings) and is fixed by the order checks are registered below, not by
any priority field - this mirrors the exact order the pre-V2.1 monolith
executed them in, so behavior is unchanged.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

from . import access_control, arithmetic_and_gas, calls_and_transfers, defi, file_level, vyper

CHECK_METADATA: Dict[str, Dict[str, Any]] = {
    "tx-origin.general": {"family": "tx-origin", "categories": ["SC01", "EXTRA-tx-origin"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "delegatecall.general": {"family": "delegatecall", "categories": ["SC10", "EXTRA-delegatecall"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "selfdestruct.general": {"family": "selfdestruct", "categories": ["SC01", "EXTRA-selfdestruct"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "low-level-call.general": {"family": "low-level-call", "categories": ["SC06", "SC08"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "token-transfer-unchecked.general": {"family": "token-transfer-unchecked", "categories": ["SC06"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "external-call.general": {"family": "external-call", "categories": ["SC06", "SC08"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "reentrancy-pattern.general": {"family": "reentrancy-pattern", "categories": ["SC08"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "unchecked-block.general": {"family": "unchecked-block", "categories": ["SC09"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "assembly-block.general": {"family": "assembly-block", "categories": ["EXTRA-assembly", "SC06", "SC10"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "timestamp-dependence.general": {"family": "timestamp-dependence", "categories": ["EXTRA-weak-randomness", "SC02"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "weak-randomness.general": {"family": "weak-randomness", "categories": ["EXTRA-weak-randomness"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "unbounded-loop.general": {"family": "unbounded-loop", "categories": ["EXTRA-dos-gas"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "msg-value-in-loop.general": {"family": "msg-value-in-loop", "categories": ["SC02", "EXTRA-dos-gas"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "initializer-unprotected.general": {"family": "initializer-unprotected", "categories": ["SC10", "SC01"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "zero-address-unchecked.general": {"family": "zero-address-unchecked", "categories": ["SC05"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "floating-pragma.general": {"family": "floating-pragma", "categories": ["EXTRA-floating-pragma"], "needsContext": False, "fpRisk": "low", "groupHint": None},
    "pragma-missing.general": {"family": "pragma-missing", "categories": ["EXTRA-floating-pragma"], "needsContext": False, "fpRisk": "low", "groupHint": None},
    "obsolete-compiler.general": {"family": "obsolete-compiler", "categories": ["EXTRA-obsolete-compiler", "SC09"], "needsContext": False, "fpRisk": "low", "groupHint": None},
    "legacy-arithmetic.general": {"family": "legacy-arithmetic", "categories": ["SC09"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "proxy-pattern.general": {"family": "proxy-pattern", "categories": ["SC10"], "needsContext": True, "fpRisk": "low", "groupHint": None},
    "upgrade-function.general": {"family": "upgrade-function", "categories": ["SC10", "SC01"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "admin-function-unprotected.general": {"family": "admin-function-unprotected", "categories": ["SC01"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "single-step-ownership-transfer.general": {"family": "single-step-ownership-transfer", "categories": ["SC01", "EXTRA-ownership"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "arbitrary-from-transfer.general": {"family": "arbitrary-from-transfer", "categories": ["SC01", "SC02"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "arbitrary-external-call.general": {"family": "arbitrary-external-call", "categories": ["SC06", "SC01"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "unlimited-approval.general": {"family": "unlimited-approval", "categories": ["SC02", "SC01"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "signature-replay-surface.general": {"family": "signature-replay-surface", "categories": ["EXTRA-replay-permit"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "slippage-unprotected.general": {"family": "slippage-unprotected", "categories": ["EXTRA-front-running-mev", "SC03"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "oracle-usage.general": {"family": "oracle-usage", "categories": ["SC03", "SC04"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "flash-loan-surface.general": {"family": "flash-loan-surface", "categories": ["SC04"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "division-before-multiplication.general": {"family": "division-before-multiplication", "categories": ["SC07"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "hardcoded-address.general": {"family": "hardcoded-address", "categories": ["SC05", "EXTRA-config"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    # --- V2.1 detector-expansion, first block (docs/decisiones.md D-032) ---
    "unprotected-callback-handler.general": {"family": "unprotected-callback-handler", "categories": ["SC01"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "reentrancy-inconsistent-guarding.general": {"family": "reentrancy-inconsistent-guarding", "categories": ["SC08"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "external-call-in-loop.general": {"family": "external-call-in-loop", "categories": ["EXTRA-dos-gas"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "storage-gap-missing.general": {"family": "storage-gap-missing", "categories": ["SC10"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "mismatched-array-length.general": {"family": "mismatched-array-length", "categories": ["SC05"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "ecrecover-zero-address-unchecked.general": {"family": "ecrecover-zero-address-unchecked", "categories": ["SC05"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "oracle-answer-unchecked.general": {"family": "oracle-answer-unchecked", "categories": ["SC03", "SC04"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "gas-unbounded-storage-array-push.general": {"family": "gas-unbounded-storage-array-push", "categories": ["EXTRA-dos-gas"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    # --- V2.1 detector-expansion, second block (docs/decisiones.md D-033) ---
    "hardcoded-role-holder.general": {"family": "hardcoded-role-holder", "categories": ["SC01"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "external-call-in-modifier.general": {"family": "external-call-in-modifier", "categories": ["SC08"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "call-value-from-parameter.general": {"family": "call-value-from-parameter", "categories": ["SC06", "SC01"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "implementation-not-disabled.general": {"family": "implementation-not-disabled", "categories": ["SC10"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "signature-missing-nonce-or-deadline.general": {"family": "signature-missing-nonce-or-deadline", "categories": ["EXTRA-replay-permit"], "needsContext": True, "fpRisk": "high", "groupHint": None},
    "unsafe-downcast.general": {"family": "unsafe-downcast", "categories": ["SC09"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    # --- V2.1 detector-expansion, third block (docs/decisiones.md D-035) ---
    "selfdestruct-unprotected.general": {"family": "selfdestruct-unprotected", "categories": ["SC01"], "needsContext": True, "fpRisk": "low", "groupHint": None},
    "upgrade-function-unprotected.general": {"family": "upgrade-function-unprotected", "categories": ["SC10", "SC01"], "needsContext": True, "fpRisk": "low", "groupHint": None},
    "delegatecall-arbitrary-unprotected.general": {"family": "delegatecall-arbitrary-unprotected", "categories": ["SC06", "SC01"], "needsContext": True, "fpRisk": "low", "groupHint": None},
    "reentrancy-guard-not-first-modifier.general": {"family": "reentrancy-guard-not-first-modifier", "categories": ["SC08"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "unlimited-approval-in-loop.general": {"family": "unlimited-approval-in-loop", "categories": ["SC02", "SC01"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "permit-not-wrapped-in-try-catch.general": {"family": "permit-not-wrapped-in-try-catch", "categories": ["EXTRA-replay-permit"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "signature-domain-separator-missing.general": {"family": "signature-domain-separator-missing", "categories": ["EXTRA-replay-permit"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "chained-division-precision-loss.general": {"family": "chained-division-precision-loss", "categories": ["SC07"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
    "low-level-call-return-data-unbounded-decode.general": {"family": "low-level-call-return-data-unbounded-decode", "categories": ["SC06"], "needsContext": True, "fpRisk": "medium", "groupHint": None},
}

# Phase order matters (see module docstring). Do not alphabetize or reorder
# without re-running the before/after preprocess.py regression diff.
FILE_CHECKS: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = list(file_level.CHECKS)

SCOPE_CHECKS: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = (
    list(calls_and_transfers.CHECKS)
    + list(defi.CHECKS)
    + list(arithmetic_and_gas.CHECKS)
    + list(access_control.CHECKS)
)

FUNCTION_CHECKS: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = list(access_control.FUNCTION_CHECKS)

CONTRACT_CHECKS: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = list(access_control.CONTRACT_CHECKS)

VYPER_CHECKS: List[Callable[[Dict[str, Any]], None]] = list(vyper.CHECKS)


def _verify_registry() -> None:
    """Every checkId referenced by a phase list must have metadata, and
    every check_id used by SignalCollector.add() across all phases must
    resolve. Run at import time (cheap, ~32 entries) so a typo fails loudly
    at startup instead of silently dropping a check's metadata at runtime."""
    all_check_ids = {cid for cid, _fn in FILE_CHECKS + SCOPE_CHECKS + FUNCTION_CHECKS + CONTRACT_CHECKS}
    missing = all_check_ids - set(CHECK_METADATA)
    if missing:
        raise RuntimeError("detectors.registry: check(s) with no CHECK_METADATA entry: %s" % sorted(missing))
    unused = set(CHECK_METADATA) - all_check_ids
    if unused:
        raise RuntimeError("detectors.registry: CHECK_METADATA entry with no registered check function: %s" % sorted(unused))


_verify_registry()
