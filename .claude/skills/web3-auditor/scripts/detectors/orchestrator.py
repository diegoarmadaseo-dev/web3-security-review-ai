# -*- coding: utf-8 -*-
"""Entry points preprocess.py calls to run every registered check against
one parsed file. Replaces the pre-V2.1 detect_solidity_signals /
detect_vyper_signals monoliths: same control flow, same order of operations,
now driven by the registry instead of inlined per-family code.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from . import registry
from .context import build_file_context, build_scopes, build_scope_context, enrich_function, function_access_info


def detect_solidity_signals(entry: Dict[str, Any], declared_types: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run every registered detector family over one Solidity file.

    Returns (signals, calls), exactly like the pre-V2.1 monolith.
    """
    file_ctx = build_file_context(entry, declared_types, registry.CHECK_METADATA)

    for _check_id, check in registry.FILE_CHECKS:
        check(file_ctx)

    for contract, span_start, span_end in build_scopes(file_ctx["structure"]):
        scope_ctx = build_scope_context(file_ctx, contract, span_start, span_end)

        for _check_id, check in registry.SCOPE_CHECKS:
            check(scope_ctx)

        for fn in contract["functions"]:
            if fn["_bodyStart"] is None or fn["_bodyEnd"] is None:
                continue
            access = function_access_info(fn)
            enrich_function(fn, access)
            fctx = dict(scope_ctx)
            fctx.update({
                "fn": fn,
                "access": access,
                "scope": {"function": fn["name"] or fn["kind"], "modifier": None, "kind": fn["kind"]},
            })
            for _check_id, check in registry.FUNCTION_CHECKS:
                check(fctx)

        for _check_id, check in registry.CONTRACT_CHECKS:
            check(scope_ctx)

    collector = file_ctx["collector"]
    collector.signals.sort(key=lambda s: (s["line"], s["column"], s["family"]))
    return collector.signals, file_ctx["calls"]


def detect_vyper_signals(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run Vyper's limited check set over one Vyper file. Returns signals
    only - Vyper has no cross-file `calls[]` tracking (checklist.md)."""
    from . import vyper as vyper_module
    ctx = vyper_module.build_vyper_context(entry, registry.CHECK_METADATA)
    for check in registry.VYPER_CHECKS:
        check(ctx)
    ctx["collector"].signals.sort(key=lambda s: (s["line"], s["column"], s["family"]))
    return ctx["collector"].signals
