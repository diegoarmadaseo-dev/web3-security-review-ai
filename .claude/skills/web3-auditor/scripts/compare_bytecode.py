#!/usr/bin/env python3
"""Deterministic bytecode comparison for deployed contracts (V2.7,
docs/decisiones.md D-057).

Compares:
  1. sourceVsRuntime   - source-compiled bytecode vs deployed runtime bytecode
  2. constructorVsRuntime - deployment (init) bytecode vs runtime bytecode;
                            optionally separates constructor args via ABI
  3. proxyComparisons  - for each proxy in systemGraph.proxies[], compares
                         the implementation's source vs runtime bytecode;
                         unresolved proxies stay UNRESOLVED, never guessed

Input: a JSON object that EXTENDS the V2.6.1 ingest record produced by
scripts/ingest_onchain.py with optional extra fields (see rawInput definition
in bytecode-compare-schema.json).  This script NEVER makes a network call
and NEVER modifies preprocess.py, score.py, registry.py, detectors/ or
systemGraph itself.

Verdicts (exactly these five, no others):
  MATCH        Normalized bytecodes are byte-identical after CBOR stripping.
  MISMATCH     Normalized bytecodes differ.
  UNAVAILABLE  A required field is absent, null, or invalid (e.g. no
               runtimeBytecode, unverified contract, empty bytecode).
  INCOMPLETE   Data present but insufficient (e.g. unlinked library
               placeholders, non-elementary ABI type preventing arg
               length computation, or init-code layout prevents prefix
               separation without an ABI).
  UNRESOLVED   Structural ambiguity that cannot be resolved deterministically
               (e.g. proxy implementation not resolved in systemGraph).

MISMATCH is NEVER a finding.  It is a technical fact reported in comparisons[]
and propagated to limitations[] for the AI analysis step to interpret in context.
This script has no code path that emits findings or signals of any kind.

CBOR metadata stripping (D-C):
  Solidity appends CBOR-encoded metadata to the end of bytecode:
    [runtime_code][cbor_map][2-byte big-endian length of cbor_map]
  We strip exactly those trailing bytes when ALL of the following hold:
    (a) len(bytecode) >= 4 (minimum for 1-byte map + 2-byte length)
    (b) declared length > 0 and < len(bytecode) - 2
    (c) the first byte of the CBOR region is a fixmap marker: 0xa0..0xb7
        (fixmap with 0..23 entries; covers all real Solidity outputs)
  When any condition fails, raw bytes are compared unchanged and the detail
  field explains which condition was not met.  No other bytes are removed.

Constructor arg separation (D-D):
  Requires ABI OR a deployment bytecode that starts with the runtime bytecode
  (most common Solidity layout: [init_preamble+runtime][args]).
  Without either condition met, verdict is INCOMPLETE, never guessed.
  Non-elementary ABI parameter types (tuple, string, arrays) make the
  expected byte-length incalculable; the function returns None rather than
  estimating.

Standard library only.  No network access, no LLM calls.  Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

COMPARE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

MISMATCH_NOTE = (
    "MISMATCH (and every non-MATCH verdict) is a technical fact about bytecode "
    "differences or analysis limitations, never an automatic vulnerability finding. "
    "This script has no code path that emits findings or signals. Interpreting a "
    "MISMATCH requires understanding the compilation pipeline, CBOR metadata, "
    "constructor arguments, library linking, and deployment context - that is the "
    "analysis step's (AI's) job, informed by this record, never this script's."
)

# ---------------------------------------------------------------------------
# Regex constants
# ---------------------------------------------------------------------------

# Unlinked library placeholders in hex bytecode.
# Modern solc: __$<34-char-keccak-prefix>$__ (38 chars total, but the __...__
# wrapper is what we match).  Legacy solc: __LibraryName__ (variable length).
# Both contain literal '__' which is not valid hex, so presence = INCOMPLETE.
_UNLINKED_PLACEHOLDER_RE = re.compile(r"__[\$a-zA-Z0-9_]{1,40}__")

# Static elementary ABI types (each occupies exactly 32 bytes when ABI-encoded).
# Matches: uint, uint8..uint256, int, int8..int256, bool, address, bytes1..bytesN.
# Does NOT match: bytes (dynamic), string, tuple, any array type.
_STATIC_ABI_TYPE_RE = re.compile(r"^(u?int\d*|bytes\d+|address|bool)$")


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class CompareError(Exception):
    """Raised when the input is too malformed to attempt any comparison
    (not a dict, or missing required top-level structure).  Normal per-field
    issues (missing bytecode, invalid hex, unresolved proxy, etc.) are always
    reported via verdict/detail, never raised."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CompareError(message)


# ---------------------------------------------------------------------------
# Bytecode normalization helpers
# ---------------------------------------------------------------------------

def normalize_hex(raw: Any, field_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (normalized_lowercase_hex_without_0x, error_or_None).
    Accepts '0x'-prefixed or bare hex strings.  None or absent → error.
    Empty ('0x' or '') → returns ('', None) — valid empty bytecode."""
    if raw is None:
        return None, "%s is absent or null" % field_name
    if not isinstance(raw, str):
        return None, "%s must be a string, got %s" % (field_name, type(raw).__name__)
    s = raw.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if s == "" or s == "0":
        return "", None
    if len(s) % 2 != 0:
        return None, "%s has odd hex length (%d chars)" % (field_name, len(s))
    try:
        bytes.fromhex(s)
    except ValueError:
        return None, "%s contains non-hex characters" % field_name
    return s.lower(), None


def has_unlinked_libraries(hex_str: str) -> bool:
    """True if hex_str contains unlinked library placeholder patterns."""
    return bool(_UNLINKED_PLACEHOLDER_RE.search(hex_str))


# ---------------------------------------------------------------------------
# CBOR metadata stripping (D-C)
# ---------------------------------------------------------------------------

def strip_cbor_metadata(data: bytes) -> Tuple[bytes, bool, str]:
    """Strip Solidity CBOR metadata suffix from bytecode bytes.

    Returns (result_bytes, was_stripped, detail_string).

    Stripping conditions (all must hold):
      (a) len(data) >= 4
      (b) declared_length = int.from_bytes(data[-2:], 'big') > 0
      (c) declared_length < len(data) - 2  (CBOR cannot consume entire bytecode)
      (d) data[-(declared_length+2)] is in 0xa0..0xb7  (CBOR fixmap marker)

    When any condition fails, data is returned unchanged with an explanation.
    """
    if len(data) < 4:
        return data, False, (
            "bytecode too short to contain CBOR metadata (%d bytes < 4)" % len(data)
        )
    cbor_len = int.from_bytes(data[-2:], "big")
    if cbor_len == 0:
        return data, False, "declared CBOR length is zero; skipping strip"
    remaining = len(data) - 2
    if cbor_len >= remaining:
        return data, False, (
            "declared CBOR length %d >= remaining bytecode %d; likely not CBOR metadata"
            % (cbor_len, remaining)
        )
    cbor_start = len(data) - 2 - cbor_len
    first_byte = data[cbor_start]
    # 0xa0 = fixmap(0), 0xb7 = fixmap(23) — all Solidity CBOR maps fall here
    if not (0xa0 <= first_byte <= 0xb7):
        return data, False, (
            "CBOR region first byte 0x%02x is not a fixmap marker (0xa0..0xb7); "
            "skipping strip" % first_byte
        )
    stripped = data[:cbor_start]
    return stripped, True, (
        "stripped %d bytes of CBOR metadata (map marker 0x%02x, "
        "%d-byte CBOR body + 2-byte length word)"
        % (cbor_len + 2, first_byte, cbor_len)
    )


def _normalize_bytecode_hex(hex_str: str) -> Tuple[str, bool, str]:
    """Convert normalized hex string to bytes, strip CBOR, return normalized hex.

    Returns (normalized_hex, cbor_was_stripped, detail).
    Input must be a valid lowercase hex string without 0x prefix (from normalize_hex).
    """
    if not hex_str:
        return "", False, "empty bytecode"
    data = bytes.fromhex(hex_str)
    stripped, was_stripped, detail = strip_cbor_metadata(data)
    return stripped.hex(), was_stripped, detail


# ---------------------------------------------------------------------------
# ABI helpers (D-D)
# ---------------------------------------------------------------------------

def _abi_constructor_input_types(abi: Any) -> Optional[List[str]]:
    """Return list of constructor parameter type strings from an ABI array.
    Returns [] if no constructor entry found.  Returns None if abi is not a list."""
    if not isinstance(abi, list):
        return None
    for entry in abi:
        if isinstance(entry, dict) and entry.get("type") == "constructor":
            inputs = entry.get("inputs", [])
            if not isinstance(inputs, list):
                return None
            return [
                inp.get("type", "") for inp in inputs if isinstance(inp, dict)
            ]
    return []  # no constructor entry → no constructor args


def _abi_encoded_length(types: List[str]) -> Optional[int]:
    """Compute expected ABI-encoded byte length for a list of elementary type strings.

    Each static elementary type occupies exactly 32 bytes in ABI encoding
    (bool, address, uintN, intN, bytesN — all padded to 32 bytes).
    Returns None if any type is non-elementary (tuple, string, dynamic bytes,
    array, or unrecognized) — prevents guessing length for complex args.
    Returns 0 for an empty list (no-arg constructor).
    """
    for t in types:
        if not _STATIC_ABI_TYPE_RE.match(t.strip()):
            return None
    return len(types) * 32


# ---------------------------------------------------------------------------
# Constructor arg separation (D-D)
# ---------------------------------------------------------------------------

def separate_constructor_args(
    deployment_hex: str,
    runtime_hex: str,
    abi: Optional[Any],
) -> Tuple[Optional[str], str]:
    """Try to separate constructor args from deployment (init) bytecode.

    Returns (constructor_args_hex_or_None, detail_string).
    Returns ('', ...) when deployment == runtime (no args, trivial match).
    Returns (None, ...) when separation is not possible → caller yields INCOMPLETE.

    Strategy:
    1. Strip CBOR from both sides to get normalized hex.
    2. If dep_norm == rt_norm → no constructor args (exact match).
    3. If dep_norm.startswith(rt_norm) → args = dep_norm[len(rt_norm):]
       Optionally validated against ABI if provided.
    4. If prefix match fails and ABI provides a computable arg length →
       try suffix extraction: dep[-expected_len*2:].  Fallback only; detail
       notes that prefix-match failed, so treat with extra caution.
    5. Otherwise → (None, reason) = INCOMPLETE.

    Never guesses lengths or argument values without structural evidence.
    """
    if not deployment_hex and deployment_hex != "":
        return None, "deploymentBytecode is absent"
    if not runtime_hex and runtime_hex != "":
        return None, "runtimeBytecode is absent"

    dep_norm, _, _ = _normalize_bytecode_hex(deployment_hex)
    rt_norm, _, _ = _normalize_bytecode_hex(runtime_hex)

    if not rt_norm:
        return None, "runtimeBytecode is empty after CBOR normalization"

    # Case 1: deployment IS the runtime (no constructor args at all)
    if dep_norm == rt_norm:
        return "", "deployment bytecode matches runtime exactly (no constructor args)"

    # Case 2: deployment starts with runtime -> args are the suffix
    if dep_norm.startswith(rt_norm):
        args_hex = dep_norm[len(rt_norm):]
        if abi is None:
            return None, (
                "deployment bytecode has %d trailing byte(s) after runtime bytecode, "
                "but no ABI was provided to verify constructor arguments"
                % (len(args_hex) // 2)
            )
        types = _abi_constructor_input_types(abi)
        if types is None:
            return None, "ABI constructor inputs is not a valid list"
        if len(types) == 0:
            return None, (
                "ABI declares no constructor args, but deployment bytecode contains "
                "%d trailing byte(s)" % (len(args_hex) // 2)
            )
        expected_len = _abi_encoded_length(types)
        if expected_len is None:
            return None, (
                "ABI constructor contains non-elementary parameter type(s) "
                "(tuple/string/dynamic bytes/array); expected length cannot be computed deterministically"
            )
        actual_bytes = len(args_hex) // 2
        if actual_bytes == expected_len:
            return args_hex, (
                "ABI-confirmed: %d bytes of constructor args (%d param(s))"
                % (actual_bytes, len(types))
            )
        return None, (
            "ABI expected %d bytes of constructor args but found %d"
            % (expected_len, actual_bytes)
        )

    # Case 3: prefix match failed; check if ABI provides computable arg length
    if abi is not None:
        types = _abi_constructor_input_types(abi)
        if types is not None and len(types) > 0:
            expected_len = _abi_encoded_length(types)
            if expected_len is not None and expected_len > 0:
                expected_hex_chars = expected_len * 2
                if len(dep_norm) > expected_hex_chars:
                    candidate = dep_norm[-expected_hex_chars:]
                    prefix = dep_norm[:-expected_hex_chars]
                    if rt_norm in prefix or prefix.startswith(rt_norm) or prefix == rt_norm:
                        return candidate, (
                            "ABI-confirmed suffix extraction: %d bytes of constructor args (%d param(s))"
                            % (expected_len, len(types))
                        )
                    return None, (
                        "deployment bytecode does not contain runtime bytecode even after "
                        "accounting for %d bytes of ABI constructor args" % expected_len
                    )
            elif expected_len is None:
                return None, (
                    "ABI constructor contains non-elementary parameter type(s); "
                    "cannot compute expected argument length"
                )

    return None, (
        "cannot separate constructor args: deployment bytecode does not start "
        "with the normalized runtime bytecode and no usable ABI was provided"
    )


# ---------------------------------------------------------------------------
# Verdict builder
# ---------------------------------------------------------------------------

def _verdict(
    code: str,
    detail: str,
    normalized_a: Optional[str] = None,
    normalized_b: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {"verdict": code, "detail": detail}
    if normalized_a is not None:
        result["normalizedA"] = normalized_a
    if normalized_b is not None:
        result["normalizedB"] = normalized_b
    if extra:
        result.update(extra)
    return result


# ---------------------------------------------------------------------------
# Individual comparison functions
# ---------------------------------------------------------------------------

def compare_source_vs_runtime(
    source_bytecode: Optional[str],
    runtime_bytecode: Optional[str],
    verified: bool,
) -> Dict[str, Any]:
    """Compare source-compiled bytecode against deployed runtime bytecode.

    Both sides are CBOR-stripped before comparison.  Neither side generates
    a finding; MISMATCH is a technical result only.
    """
    if not verified:
        return _verdict(
            "UNAVAILABLE",
            "source is not verified; sourceBytecode cannot be trusted for comparison",
        )
    if source_bytecode is None:
        return _verdict("UNAVAILABLE", "sourceBytecode field absent or null in input")
    if runtime_bytecode is None:
        return _verdict("UNAVAILABLE", "runtimeBytecode field absent or null in input")

    if isinstance(source_bytecode, str) and has_unlinked_libraries(source_bytecode):
        return _verdict(
            "INCOMPLETE",
            "sourceBytecode contains unlinked library placeholder(s) (__$...$__ or "
            "__Name__); comparison cannot proceed until all libraries are linked",
        )
    if isinstance(runtime_bytecode, str) and has_unlinked_libraries(runtime_bytecode):
        return _verdict(
            "INCOMPLETE",
            "runtimeBytecode contains unlinked library placeholder(s); "
            "comparison cannot proceed until all libraries are linked",
        )

    src_raw, src_err = normalize_hex(source_bytecode, "sourceBytecode")
    rt_raw, rt_err = normalize_hex(runtime_bytecode, "runtimeBytecode")

    if src_err:
        return _verdict("UNAVAILABLE", "sourceBytecode invalid: %s" % src_err)
    if rt_err:
        return _verdict("UNAVAILABLE", "runtimeBytecode invalid: %s" % rt_err)

    assert src_raw is not None
    assert rt_raw is not None

    if rt_raw == "":
        return _verdict(
            "UNAVAILABLE",
            "runtimeBytecode is empty (deployed address has no code; "
            "may have self-destructed or never deployed)",
        )

    # Strip CBOR from both sides
    src_norm, src_stripped, src_cbor_detail = _normalize_bytecode_hex(src_raw)
    rt_norm, rt_stripped, rt_cbor_detail = _normalize_bytecode_hex(rt_raw)

    cbor_info: Dict[str, Any] = {
        "sourceCborStripped": src_stripped,
        "sourceCborDetail": src_cbor_detail,
        "runtimeCborStripped": rt_stripped,
        "runtimeCborDetail": rt_cbor_detail,
    }

    if src_norm == rt_norm:
        return _verdict(
            "MATCH",
            "source and runtime bytecode are byte-identical after CBOR normalization",
            src_norm, rt_norm, cbor_info,
        )
    return _verdict(
        "MISMATCH",
        "source and runtime bytecode differ after CBOR normalization; "
        "see normalizedA (source) and normalizedB (runtime)",
        src_norm, rt_norm, cbor_info,
    )


def compare_constructor_vs_runtime(
    deployment_bytecode: Optional[str],
    runtime_bytecode: Optional[str],
    abi: Optional[Any],
) -> Dict[str, Any]:
    """Separate constructor args from deployment (init) bytecode and account
    for all bytes.  MATCH means we could account for the deployment structure;
    it does not compare the content of constructor args against expected values.
    """
    if deployment_bytecode is None:
        return _verdict("UNAVAILABLE", "deploymentBytecode field absent or null in input")
    if runtime_bytecode is None:
        return _verdict("UNAVAILABLE", "runtimeBytecode field absent or null in input")

    if isinstance(deployment_bytecode, str) and has_unlinked_libraries(deployment_bytecode):
        return _verdict(
            "INCOMPLETE",
            "deploymentBytecode contains unlinked library placeholder(s); "
            "cannot separate constructor args from an unlinked deployment",
        )
    if isinstance(runtime_bytecode, str) and has_unlinked_libraries(runtime_bytecode):
        return _verdict(
            "INCOMPLETE",
            "runtimeBytecode contains unlinked library placeholder(s); "
            "cannot separate constructor args from an unlinked runtime",
        )

    dep_raw, dep_err = normalize_hex(deployment_bytecode, "deploymentBytecode")
    rt_raw, rt_err = normalize_hex(runtime_bytecode, "runtimeBytecode")

    if dep_err:
        return _verdict("UNAVAILABLE", "deploymentBytecode invalid: %s" % dep_err)
    if rt_err:
        return _verdict("UNAVAILABLE", "runtimeBytecode invalid: %s" % rt_err)

    assert dep_raw is not None
    assert rt_raw is not None

    if rt_raw == "":
        return _verdict(
            "UNAVAILABLE",
            "runtimeBytecode is empty; cannot use it to locate the runtime code "
            "within the deployment bytecode",
        )

    abi_used = abi is not None
    args_hex, args_detail = separate_constructor_args(dep_raw, rt_raw, abi)

    if args_hex is None:
        return _verdict(
            "INCOMPLETE",
            "constructor arg separation not possible: %s" % args_detail,
            extra={"abiUsed": abi_used, "separationDetail": args_detail},
        )

    return _verdict(
        "MATCH",
        "constructor args accounted for: %s" % args_detail,
        extra={
            "constructorArgs": args_hex if args_hex else None,
            "constructorArgBytes": len(args_hex) // 2,
            "abiUsed": abi_used,
            "separationDetail": args_detail,
        },
    )


def compare_proxy_vs_implementation(
    system_graph: Optional[Dict[str, Any]],
    source_bytecode_map: Optional[Dict[str, str]],
    runtime_bytecode_map: Optional[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Compare each proxy's implementation source vs runtime bytecode using
    systemGraph.proxies[] (already computed by preprocess.py; never modified here).

    Proxy ↔ implementation is NOT itself a MISMATCH — only the implementation's
    source vs runtime comparison produces a verdict.  Unresolved proxies remain
    UNRESOLVED; their implementation is never guessed.

    Returns a list (possibly empty) of per-proxy verdict dicts.
    """
    if system_graph is None:
        return []
    proxies = system_graph.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        return []

    results: List[Dict[str, Any]] = []
    for entry in proxies:
        if not isinstance(entry, dict):
            continue
        proxy_key = entry.get("proxy", "unknown")
        impl_key = entry.get("implementation")
        status = entry.get("status", "unresolved")
        reason = entry.get("reason", "")

        if status != "resolved" or not impl_key:
            results.append({
                "proxyKey": proxy_key,
                "implementationKey": impl_key,
                "verdict": "UNRESOLVED",
                "detail": (
                    "proxy implementation not resolved in systemGraph"
                    + (": %s" % reason if reason else "")
                ),
            })
            continue

        impl_source = (source_bytecode_map or {}).get(impl_key) if source_bytecode_map else None
        impl_runtime = (runtime_bytecode_map or {}).get(impl_key) if runtime_bytecode_map else None

        if impl_source is None and impl_runtime is None:
            results.append({
                "proxyKey": proxy_key,
                "implementationKey": impl_key,
                "verdict": "UNAVAILABLE",
                "detail": (
                    "no bytecodes provided for implementation key %r; "
                    "add entries to sourceBytecodeMap and runtimeBytecodeMap" % impl_key
                ),
            })
            continue

        if impl_source is None:
            results.append({
                "proxyKey": proxy_key,
                "implementationKey": impl_key,
                "verdict": "UNAVAILABLE",
                "detail": "sourceBytecodeMap has no entry for implementation key %r" % impl_key,
            })
            continue

        if impl_runtime is None:
            results.append({
                "proxyKey": proxy_key,
                "implementationKey": impl_key,
                "verdict": "UNAVAILABLE",
                "detail": "runtimeBytecodeMap has no entry for implementation key %r" % impl_key,
            })
            continue

        # Both available — compare source vs runtime for the implementation
        sub = compare_source_vs_runtime(
            source_bytecode=impl_source,
            runtime_bytecode=impl_runtime,
            verified=True,  # source was explicitly provided in sourceBytecodeMap
        )
        item: Dict[str, Any] = {
            "proxyKey": proxy_key,
            "implementationKey": impl_key,
            "verdict": sub["verdict"],
            "detail": "implementation %r: %s" % (impl_key, sub.get("detail", "")),
        }
        # Carry CBOR info through for forensic traceability
        for k in ("sourceCborStripped", "runtimeCborStripped",
                   "sourceCborDetail", "runtimeCborDetail"):
            if k in sub:
                item[k] = sub[k]
        results.append(item)

    return results


# ---------------------------------------------------------------------------
# Top-level compare function
# ---------------------------------------------------------------------------

def compare(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Run all bytecode comparisons on an extended V2.6.1 ingest record.

    Reads from the record:
      Core V2.6.1 fields : address, network, verified, hasCode
      New V2.7 fields    : runtimeBytecode, deploymentBytecode, sourceBytecode,
                           abi, systemGraph, sourceBytecodeMap, runtimeBytecodeMap

    Returns a structured result with verdicts, limitations[], provenance{},
    and a fixed note restating the no-finding rule.
    """
    _require(isinstance(raw, dict), "input must be a JSON object")

    raw_address = raw.get("address")
    address = None
    if isinstance(raw_address, str):
        s = raw_address.strip()
        address = s.lower() if re.match(r"^0x[0-9a-fA-F]{40}$", s) else s
    network = raw.get("network")
    # Identity check (same pattern as ingest_onchain.py D-056): string 'true' is NOT True
    verified = raw.get("verified") is True
    has_code = raw.get("hasCode")

    limitations: List[str] = []

    # Empty bytecode early detection
    if has_code is False:
        limitations.append(
            "hasCode is false: the queried address has no deployed bytecode; "
            "all comparisons will be UNAVAILABLE"
        )

    raw_runtime = raw.get("runtimeBytecode")
    raw_deployment = raw.get("deploymentBytecode")
    raw_source = raw.get("sourceBytecode")
    abi = raw.get("abi")
    system_graph = raw.get("systemGraph")
    source_map = raw.get("sourceBytecodeMap")
    runtime_map = raw.get("runtimeBytecodeMap")

    # Detect empty runtimeBytecode field
    if raw_runtime is not None:
        rt_check, rt_err = normalize_hex(raw_runtime, "runtimeBytecode")
        if rt_check == "" and rt_err is None:
            limitations.append(
                "runtimeBytecode field is present but empty (zero-length bytecode); "
                "deployed address may have self-destructed"
            )

    comparisons: Dict[str, Any] = {}

    # 1. Source vs runtime
    comparisons["sourceVsRuntime"] = compare_source_vs_runtime(
        source_bytecode=raw_source,
        runtime_bytecode=raw_runtime,
        verified=verified,
    )

    # 2. Constructor vs runtime
    if raw_deployment is None:
        comparisons["constructorVsRuntime"] = _verdict(
            "UNAVAILABLE", "deploymentBytecode field not provided in input"
        )
    else:
        comparisons["constructorVsRuntime"] = compare_constructor_vs_runtime(
            deployment_bytecode=raw_deployment,
            runtime_bytecode=raw_runtime,
            abi=abi,
        )

    # 3. Proxy comparisons (reads systemGraph.proxies[], never modifies it)
    comparisons["proxyComparisons"] = compare_proxy_vs_implementation(
        system_graph=system_graph,
        source_bytecode_map=source_map,
        runtime_bytecode_map=runtime_map,
    )

    # Propagate non-MATCH verdicts to limitations[] for the analysis step
    for comp_name, verdict_obj in comparisons.items():
        if comp_name == "proxyComparisons":
            continue
        if not isinstance(verdict_obj, dict):
            continue
        v = verdict_obj.get("verdict")
        if v in ("MISMATCH", "INCOMPLETE"):
            limitations.append(
                "%s: %s — %s" % (comp_name, v, verdict_obj.get("detail", ""))
            )

    for proxy_item in comparisons["proxyComparisons"]:
        if not isinstance(proxy_item, dict):
            continue
        v = proxy_item.get("verdict")
        if v in ("MISMATCH", "INCOMPLETE", "UNRESOLVED"):
            limitations.append(
                "proxyComparisons[%s]: %s — %s"
                % (proxy_item.get("proxyKey", "?"), v, proxy_item.get("detail", ""))
            )

    # Provenance: per-field origin, same pattern as ingest_onchain.py
    provenance: Dict[str, str] = {}
    if raw_runtime is not None:
        provenance["runtimeBytecode"] = "on-chain"
    if raw_deployment is not None:
        provenance["deploymentBytecode"] = "on-chain"
    if raw_source is not None:
        provenance["sourceBytecode"] = "explorer-or-compiler"
    if abi is not None:
        provenance["abi"] = "explorer-or-user"
    if system_graph is not None:
        provenance["systemGraph"] = "preprocess-computed"
    if source_map is not None:
        provenance["sourceBytecodeMap"] = "explorer-or-compiler"
    if runtime_map is not None:
        provenance["runtimeBytecodeMap"] = "on-chain"

    return {
        "compareVersion": COMPARE_VERSION,
        "address": address,
        "network": network,
        "verified": verified,
        "comparisons": comparisons,
        "limitations": limitations,
        "provenance": provenance,
        "note": MISMATCH_NOTE,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _read_json_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CompareError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compare_bytecode.py",
        description=(
            "Deterministic bytecode comparison for deployed contracts (V2.7). "
            "Reads an extended V2.6.1 ingest record (with optional runtimeBytecode, "
            "deploymentBytecode, sourceBytecode, abi, systemGraph, sourceBytecodeMap, "
            "runtimeBytecodeMap fields) from a file or stdin. "
            "Produces MATCH/MISMATCH/UNAVAILABLE/INCOMPLETE/UNRESOLVED verdicts. "
            "Never fetches anything itself; never emits findings or signals."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to the extended ingest JSON file. Reads stdin if omitted.",
    )
    parser.add_argument(
        "--out", default=None,
        help="Write the comparison result to this file instead of stdout.",
    )
    parser.add_argument(
        "--indent", type=int, default=2,
        help="JSON indentation (0 = compact output).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        raw = _read_json_file(args.path) if args.path else json.loads(sys.stdin.read())
        result = compare(raw)
    except (CompareError, OSError, json.JSONDecodeError) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False),
            file=sys.stdout,
        )
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
