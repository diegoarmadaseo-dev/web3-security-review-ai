#!/usr/bin/env python3
"""Deterministic bytecode comparison for deployed contracts (V2.7/V2.8 Blocks 2-3,
docs/decisiones.md D-057/D-059/D-060/D-061).

Compares:
  1. sourceVsRuntime   - source-compiled bytecode vs deployed runtime bytecode
  2. constructorVsRuntime - deployment (init) bytecode vs runtime bytecode;
                            optionally separates constructor args via ABI
  3. proxyComparisons  - for each proxy in systemGraph.proxies[], compares
                         the implementation's source vs runtime bytecode;
                         unresolved proxies stay UNRESOLVED, never guessed
  4. capabilityChecks  - whether PUSH0/transient-storage/MCOPY opcodes
                         actually used in the bytecode are supported by the
                         target chain's catalog capabilities (chains.py)
  5. compilerVersionCheck - explorer-reported compilerVersion vs the solc
                         version byte-encoded in the runtime bytecode's own
                         CBOR metadata trailer; gated on verified (D-060)
  6. crossChainImplementationDrift - when 2+ resolved proxies on DIFFERENT
                         chains delegate to implementations that share a
                         reliable, content-based identity (the CBOR-embedded
                         source metadata hash, never bare name or address),
                         compares their runtime bytecode; a MISMATCH also
                         carries a purely descriptive divergenceProfile
                         (V2.8 Block 3, C-10 - never changes the verdict)
  7. crossChainProvenanceConsistency - for implementations already grouped
                         by #6's identity, whether their caller-supplied
                         verifiedMap/compilerVersionMap agree across chains
                         (V2.8 Block 3, C-09)

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

# EVM opcodes gated by chains.py's tracked capability flags (V2.8 Block 2/3).
_OPCODE_PUSH0 = 0x5F        # EIP-3855
_OPCODE_TLOAD = 0x5C        # EIP-1153
_OPCODE_TSTORE = 0x5D       # EIP-1153
_OPCODE_MCOPY = 0x5E        # EIP-5656 (Cancun)
_PUSH1, _PUSH32 = 0x60, 0x7F


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
# Opcode capability checks (V2.8 Block 2, C-01/C-05)
# ---------------------------------------------------------------------------

def _walk_opcodes(data: bytes) -> "set":
    """Linear single-pass scan of EVM bytecode that treats PUSH-data bytes as
    data, never as instructions - a naive substring/byte search would
    false-positive whenever a PUSH argument happens to equal an opcode byte.
    Does not validate JUMPDEST reachability or any other control-flow
    property; only opcode presence is needed here."""
    seen = set()
    i, n = 0, len(data)
    while i < n:
        op = data[i]
        seen.add(op)
        if _PUSH1 <= op <= _PUSH32:
            i += 1 + (op - _PUSH1 + 1)
        else:
            i += 1
    return seen


def check_capability_compatibility(
    runtime_bytecode: Optional[str],
    deployment_bytecode: Optional[str],
    chain_id: Optional[int],
) -> List[Dict[str, Any]]:
    """For each EVM-version-gated opcode chains.py's catalog tracks (PUSH0,
    transient storage), check whether it is actually used in the available
    bytecode and, if so, whether the target chain's catalog capability
    supports it.  Never infers a vulnerability - an incompatibility is a
    deployability/technical fact, reported the same way a bytecode MISMATCH
    is (R-C2's rule applies here too).  An unknown chain (isKnown=False) or
    a broken chains.json maps to UNAVAILABLE with an explicit detail stating
    that capability compatibility cannot be assessed - this is this
    function's equivalent of report-schema.json's NOT_ASSESSED concept, but
    reuses the existing UNAVAILABLE verdict rather than adding a 6th verdict
    token (D-060 corrective fix: this substitution is deliberate and was
    explicitly confirmed, never a silent change - compare_bytecode.py has a
    hard "exactly five verdicts" constraint that predates this feature).
    "opcode used, capability compatibility cannot be assessed" is
    fundamentally different from "opcode used, compatible" and must never
    be conflated.

    Only emits one entry per tracked capability that is used or checkable;
    if BOTH bytecode fields are absent, still emits one UNAVAILABLE entry
    per capability - never silently skips (same discipline as proxyComparisons,
    which returns [] only when there is genuinely nothing to check, i.e. no
    proxies at all)."""
    hex_candidates = []
    for field_name, hex_str in (("runtimeBytecode", runtime_bytecode), ("deploymentBytecode", deployment_bytecode)):
        if hex_str is None:
            continue
        norm, err = normalize_hex(hex_str, field_name)
        if norm:
            hex_candidates.append(norm)

    capability_specs = [
        ("supportsPush0", "PUSH0", frozenset([_OPCODE_PUSH0])),
        ("supportsTransientStorage", "TLOAD/TSTORE", frozenset([_OPCODE_TLOAD, _OPCODE_TSTORE])),
        ("supportsCancun", "MCOPY", frozenset([_OPCODE_MCOPY])),
    ]

    if not hex_candidates:
        return [
            _verdict(
                "UNAVAILABLE",
                "no runtimeBytecode or deploymentBytecode available to scan for %s usage" % opcode_label,
                extra={"capability": cap_key},
            )
            for cap_key, opcode_label, _ in capability_specs
        ]

    used_opcodes: "set" = set()
    for hex_str in hex_candidates:
        try:
            used_opcodes |= _walk_opcodes(bytes.fromhex(hex_str))
        except ValueError:
            continue

    chain_meta: Optional[Dict[str, Any]] = None
    chain_meta_error: Optional[str] = None
    if isinstance(chain_id, int) and not isinstance(chain_id, bool):
        try:
            import chains as _chains
            chain_meta = _chains.get_chain_capabilities(chain_id)
        except Exception as exc:  # noqa: BLE001 - catalog/lookup failure must never abort the whole comparison
            chain_meta_error = str(exc)

    results: List[Dict[str, Any]] = []
    for cap_key, opcode_label, opcode_bytes in capability_specs:
        is_used = bool(used_opcodes & opcode_bytes)
        if not is_used:
            results.append(_verdict(
                "MATCH",
                "%s not used in the scanned bytecode; no chain-compatibility concern" % opcode_label,
                extra={"capability": cap_key, "opcodeUsed": False},
            ))
            continue
        if chain_id is None or not isinstance(chain_id, int) or isinstance(chain_id, bool):
            results.append(_verdict(
                "UNAVAILABLE",
                "%s is used, but no valid chainId was available to check compatibility" % opcode_label,
                extra={"capability": cap_key, "opcodeUsed": True},
            ))
            continue
        if chain_meta_error is not None:
            results.append(_verdict(
                "UNAVAILABLE",
                "%s is used, but chain capabilities could not be loaded (%s); "
                "capability compatibility cannot be assessed" % (opcode_label, chain_meta_error),
                extra={"capability": cap_key, "opcodeUsed": True, "chainId": chain_id},
            ))
            continue
        if chain_meta is None or not chain_meta.get("isKnown"):
            results.append(_verdict(
                "UNAVAILABLE",
                "%s is used, but chainId %r is not in the known chain catalog; "
                "capability compatibility cannot be assessed" % (opcode_label, chain_id),
                extra={"capability": cap_key, "opcodeUsed": True, "chainId": chain_id, "chainKnown": False},
            ))
            continue
        supported = bool(chain_meta.get("capabilities", {}).get(cap_key))
        chain_name = chain_meta.get("name") or ("chain %s" % chain_id)
        if supported:
            results.append(_verdict(
                "MATCH",
                "%s is used and %s (chainId %d) supports it" % (opcode_label, chain_name, chain_id),
                extra={"capability": cap_key, "opcodeUsed": True, "chainId": chain_id, "chainKnown": True},
            ))
        else:
            results.append(_verdict(
                "MISMATCH",
                "%s is used, but %s (chainId %d) does not support it - the contract as "
                "compiled cannot run as intended on this chain" % (opcode_label, chain_name, chain_id),
                extra={"capability": cap_key, "opcodeUsed": True, "chainId": chain_id, "chainKnown": True},
            ))
    return results


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
# CBOR solc-version decoding (V2.8 Block 2, C-02) - NOT a general CBOR parser.
# Scoped ONLY to the shapes Solidity's own metadata encoder emits: a
# definite-length fixmap (already located by strip_cbor_metadata) of short
# text-string keys to short byte-string or text-string values. Any encoding
# outside this narrow scope returns None rather than guessing.
# ---------------------------------------------------------------------------

def _read_cbor_bytes_or_text(cbor_body: bytes, pos: int) -> Optional[Tuple[Any, int]]:
    """Read one CBOR byte-string (major type 2) or text-string (major type 3)
    item starting at pos.  Supports exactly two length encodings - short form
    (length 0..23 embedded in the initial byte: 0x40..0x57 / 0x60..0x77) and
    1-byte-length-follows form (length 24..255: 0x58 / 0x78) - which together
    cover every value Solidity's own metadata encoder actually emits (short
    "solc" version bytes, longer ipfs/bzzr1 hash byte strings, always well
    under 255 bytes).  Returns (value, new_pos) or None for any other
    encoding (2-byte+ length, indefinite length, other major types) - never
    guessed."""
    marker = cbor_body[pos]
    is_bytes = 0x40 <= marker <= 0x5B
    is_text = 0x60 <= marker <= 0x7B
    if not (is_bytes or is_text):
        return None
    base = 0x40 if is_bytes else 0x60
    minor = marker - base
    if minor <= 0x17:  # 0..23: short form, length embedded directly
        length = minor
        pos += 1
    elif minor == 0x18:  # 1-byte length follows (covers 24..255)
        pos += 1
        length = cbor_body[pos]
        pos += 1
    else:
        return None  # 2-byte+ length or indefinite-length - out of scope
    raw = cbor_body[pos:pos + length]
    if len(raw) != length:
        return None
    pos += length
    value: Any = raw.decode("utf-8") if is_text else raw
    return value, pos


def _decode_cbor_solc_metadata(cbor_body: bytes) -> Tuple[Optional[Dict[str, Any]], str]:
    """Decode a Solidity-emitted CBOR fixmap body (the bytes between the map
    marker and the trailing 2-byte length word). Returns (dict_or_None, detail).
    Keys are always short text strings (solc never emits a long key name);
    values (the ipfs/bzzr1 hash, the solc version bytes) may use either
    length form - see _read_cbor_bytes_or_text."""
    try:
        pos = 0
        first = cbor_body[pos]
        if not (0xA0 <= first <= 0xB7):
            return None, "not a definite-length fixmap (0x%02x)" % first
        n_entries = first - 0xA0
        pos += 1
        result: Dict[str, Any] = {}
        for _ in range(n_entries):
            key_byte = cbor_body[pos]
            if not (0x60 <= key_byte <= 0x77):
                return None, "unsupported CBOR key encoding (not a short text string)"
            key_len = key_byte - 0x60
            pos += 1
            key = cbor_body[pos:pos + key_len].decode("utf-8")
            pos += key_len
            read = _read_cbor_bytes_or_text(cbor_body, pos)
            if read is None:
                return None, "unsupported CBOR value encoding for key %r" % key
            value, pos = read
            result[key] = value
        return result, "decoded %d top-level key(s)" % n_entries
    except (IndexError, UnicodeDecodeError):
        return None, "CBOR structure truncated or malformed"


def _solc_version_from_metadata(meta: Dict[str, Any]) -> Optional[str]:
    """Solidity's 'solc' metadata key is 3 raw bytes (major, minor, patch) in
    the common case, e.g. b'\\x00\\x08\\x14' -> '0.8.20'.  Returns None
    (never guesses) when the value is not exactly 3 bytes."""
    value = meta.get("solc")
    if isinstance(value, (bytes, bytearray)) and len(value) == 3:
        return "%d.%d.%d" % (value[0], value[1], value[2])
    return None


def check_compiler_version_consistency(
    reported_compiler_version: Optional[str],
    runtime_bytecode: Optional[str],
    verified: bool,
) -> Dict[str, Any]:
    """Compare the explorer-reported compilerVersion against the version
    byte-encoded in the runtime bytecode's own CBOR metadata trailer
    (reusing strip_cbor_metadata's existing boundary detection, never
    duplicating it).  A disagreement is a data-integrity/provenance fact -
    stale or wrong explorer metadata - NEVER a vulnerability signal.

    D-060 corrective fix: gates on verified first, exactly like
    compare_source_vs_runtime (D-056) - an unverified record's
    explorer-reported compilerVersion is just as untrustworthy as its
    sourceBytecode and must never be compared as if it were reliable."""
    if not verified:
        return _verdict(
            "UNAVAILABLE",
            "source is not verified; compilerVersion cannot be trusted for comparison",
        )
    if not reported_compiler_version or not isinstance(reported_compiler_version, str):
        return _verdict("UNAVAILABLE", "compilerVersion not provided in input; nothing to cross-check")
    if not runtime_bytecode:
        return _verdict("UNAVAILABLE", "runtimeBytecode not provided; cannot locate embedded CBOR metadata")

    rt_hex, rt_err = normalize_hex(runtime_bytecode, "runtimeBytecode")
    if rt_err or not rt_hex:
        return _verdict("UNAVAILABLE", "runtimeBytecode invalid or empty: %s" % (rt_err or "empty"))

    data = bytes.fromhex(rt_hex)
    stripped, was_stripped, strip_detail = strip_cbor_metadata(data)
    if not was_stripped:
        return _verdict("INCOMPLETE", "no CBOR metadata block found in runtimeBytecode: %s" % strip_detail)

    cbor_body = data[len(stripped):len(data) - 2]
    meta, decode_detail = _decode_cbor_solc_metadata(cbor_body)
    if meta is None:
        return _verdict("INCOMPLETE", "CBOR metadata found but could not be decoded: %s" % decode_detail)

    embedded_version = _solc_version_from_metadata(meta)
    if embedded_version is None:
        return _verdict("INCOMPLETE", "CBOR metadata decoded but contains no recognizable 'solc' version field")

    reported_match = re.search(r"(\d+)\.(\d+)\.(\d+)", reported_compiler_version)
    if not reported_match:
        return _verdict(
            "INCOMPLETE",
            "reported compilerVersion %r has no recognizable X.Y.Z version" % reported_compiler_version,
        )
    reported_normalized = "%s.%s.%s" % reported_match.groups()

    if reported_normalized == embedded_version:
        return _verdict(
            "MATCH",
            "reported compilerVersion (%s) matches version embedded in bytecode metadata" % reported_normalized,
            extra={"reportedVersion": reported_normalized, "embeddedVersion": embedded_version},
        )
    return _verdict(
        "MISMATCH",
        "reported compilerVersion (%s) does NOT match version embedded in bytecode metadata (%s) - "
        "explorer metadata may be stale or incorrect" % (reported_normalized, embedded_version),
        extra={"reportedVersion": reported_normalized, "embeddedVersion": embedded_version},
    )


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
# Cross-chain implementation drift (V2.8 Block 2, C-03)
# ---------------------------------------------------------------------------

def _extract_chain_id_from_key(key: Optional[str]) -> Optional[str]:
    """Independent re-derivation of preprocess.py's onchain-key chain-id
    extraction (preprocess.py's _onchain_chain_id is a private helper and is
    never imported across modules - same rationale diff_reports.py already
    documents for its own independent re-derivations)."""
    if not isinstance(key, str) or not key.startswith("onchain:/"):
        return None
    stripped = key[9:]
    if stripped.startswith("/"):
        stripped = stripped[1:]
    parts = stripped.split("/", 1)
    if parts and parts[0].isdigit():
        return parts[0]
    return None


def _cbor_metadata_identity_hash(runtime_bytecode: Optional[str]) -> Optional[str]:
    """Extract a reliable, content-based cross-chain identity from runtime
    bytecode's own CBOR metadata trailer (reuses check_compiler_version_
    consistency's existing CBOR boundary detection and decoder - never a
    second parser).  Returns the hex-encoded 'ipfs' (or, for older solc,
    'bzzr1'/'bzzr0') hash Solidity's own compiler embeds as a content
    fingerprint of the exact source + compiler settings that produced this
    bytecode - two deployments sharing this hash are provably compiled from
    the same source, unlike a bare contract name or an address, which prove
    nothing on their own.  Returns None (no identity - never guessed) when
    bytecode is absent/invalid, CBOR metadata is absent or undecodable, or
    the decoded metadata carries none of these keys."""
    if not runtime_bytecode:
        return None
    rt_hex, rt_err = normalize_hex(runtime_bytecode, "runtimeBytecode")
    if rt_err or not rt_hex:
        return None
    data = bytes.fromhex(rt_hex)
    stripped, was_stripped, _ = strip_cbor_metadata(data)
    if not was_stripped:
        return None
    cbor_body = data[len(stripped):len(data) - 2]
    meta, _ = _decode_cbor_solc_metadata(cbor_body)
    if meta is None:
        return None
    for key in ("ipfs", "bzzr1", "bzzr0"):
        value = meta.get(key)
        if isinstance(value, (bytes, bytearray)) and len(value) > 0:
            return "%s:%s" % (key, value.hex())
    return None


def _group_resolved_proxies_by_identity(
    system_graph: Optional[Dict[str, Any]],
    runtime_bytecode_map: Optional[Dict[str, str]],
    key_field: str = "implementation",
) -> Dict[str, Dict[str, str]]:
    """Shared grouping step for check_cross_chain_implementation_drift (C-03),
    check_cross_chain_provenance_consistency (C-09), check_cross_chain_proxy_drift
    (V2.8 Block 4, C-11), and compute_cross_chain_coverage_summary (C-13) -
    all need the EXACT same "2+ resolved proxies on different chains sharing
    a reliable metadata identity" grouping, so it is computed once here
    rather than re-derived per caller.  key_field selects which systemGraph
    proxy-entry field to group by - 'implementation' (default, C-03/C-09) or
    'proxy' (C-11) - the grouping algorithm itself is identical either way.
    Returns {identityHash: {chainId: key}}; an entry whose metadata identity
    cannot be established never appears in any group (see
    _cbor_metadata_identity_hash - never guessed from name or address)."""
    if system_graph is None or not runtime_bytecode_map:
        return {}
    proxies = system_graph.get("proxies")
    if not isinstance(proxies, list):
        return {}

    groups: Dict[str, Dict[str, str]] = {}
    for entry in proxies:
        if not isinstance(entry, dict) or entry.get("status") != "resolved":
            continue
        target_key = entry.get(key_field)
        chain_id = _extract_chain_id_from_key(target_key)
        if chain_id is None:
            continue
        identity = _cbor_metadata_identity_hash(runtime_bytecode_map.get(target_key))
        if identity is None:
            continue
        groups.setdefault(identity, {})[chain_id] = target_key
    return groups


def _chains_known_map(chain_ids: List[str]) -> Dict[str, bool]:
    """V2.8 Block 4, C-14.  Purely descriptive: whether each chainId in a
    cross-chain group is in chains.py's known catalog.  NEVER blocks or
    changes a comparison - identity is content-based, not chain-dependent,
    so an uncatalogued chain's bytecode is still compared exactly the same
    way - this only adds context for interpreting the result, since an
    uncatalogued chain's type/trust profile is itself unknown.  A broken or
    missing chains.json degrades every entry to False (never guessed as
    known) rather than aborting the comparison - same precedent as
    check_capability_compatibility's own chain_meta_error handling."""
    import chains
    result: Dict[str, bool] = {}
    for cid in chain_ids:
        try:
            chain_id_int = int(cid)
        except (TypeError, ValueError):
            result[cid] = False
            continue
        try:
            meta = chains.get_chain_capabilities(chain_id_int)
            result[cid] = bool(meta.get("isKnown"))
        except Exception:  # noqa: BLE001 - catalog/lookup failure must never abort the comparison
            result[cid] = False
    return result


# V2.8 Block 3, C-10: purely descriptive byte-diff characterization of an
# ALREADY-DECIDED MISMATCH.  Thresholds are generous, named constants, never
# used to change a verdict - see byte_divergence_profile's own docstring.
_DIVERGENCE_LOCALIZED_MAX_BYTES = 128      # ~4 32-byte slots (immutables/library addresses)
_DIVERGENCE_LOCALIZED_MAX_REGIONS = 8


def byte_divergence_profile(hex_a: str, hex_b: str) -> Dict[str, Any]:
    """Purely descriptive byte-level characterization of two ALREADY-DIFFERENT
    normalized (CBOR-stripped) bytecode hex strings.  Never asserts a cause -
    an immutable value, a linked library address, and a genuine functional
    change are all indistinguishable from raw bytes alone - and NEVER
    changes a MATCH/MISMATCH verdict or constitutes a finding by itself;
    MISMATCH_NOTE/R-C2 already govern how every verdict in this script must
    be interpreted, and this is no exception.  'localized' means few, small,
    clustered differing byte-ranges (consistent with, but never confirmed
    as, a handful of immutable/library-address substitutions); 'structural'
    means the differences are larger or more widespread; different-length
    inputs are their own bucket ('different-length'), never guessed into
    either of the other two.

    PUBLIC (V2.9, D-063): promoted from a private helper so monitor_diff.py
    (M1, temporal snapshot drift) can reuse it for the SAME characterization
    across time instead of across chains - the byte-level math is identical
    either way, so this is deliberately NOT re-derived in the new script."""
    len_a, len_b = len(hex_a) // 2, len(hex_b) // 2
    if len_a != len_b:
        return {
            "sameLength": False,
            "totalBytes": max(len_a, len_b),
            "differingBytes": None,
            "differingRegions": None,
            "characterization": "different-length",
        }
    bytes_a, bytes_b = bytes.fromhex(hex_a), bytes.fromhex(hex_b)
    differing_bytes = 0
    differing_regions = 0
    in_region = False
    for byte_a, byte_b in zip(bytes_a, bytes_b):
        if byte_a != byte_b:
            differing_bytes += 1
            if not in_region:
                differing_regions += 1
                in_region = True
        else:
            in_region = False
    if differing_bytes <= _DIVERGENCE_LOCALIZED_MAX_BYTES and differing_regions <= _DIVERGENCE_LOCALIZED_MAX_REGIONS:
        characterization = "localized"
    else:
        characterization = "structural"
    return {
        "sameLength": True,
        "totalBytes": len_a,
        "differingBytes": differing_bytes,
        "differingRegions": differing_regions,
        "characterization": characterization,
    }


def _cross_chain_bytecode_drift(
    groups: Dict[str, Dict[str, str]],
    runtime_bytecode_map: Dict[str, str],
    keys_field_name: str,
    subject_label: str,
) -> List[Dict[str, Any]]:
    """Shared comparison step for check_cross_chain_implementation_drift
    (C-03) and check_cross_chain_proxy_drift (V2.8 Block 4, C-11) - both need
    the exact same "normalize, compare, attach divergenceProfile/chainsKnown"
    logic once a reliable identity grouping already exists (from
    _group_resolved_proxies_by_identity); only the output key name
    (implementationKeys vs proxyKeys) and detail wording differ.

    A MISMATCH carries a purely descriptive 'divergenceProfile' (C-10)
    comparing every other chain's bytecode against the first (lowest
    chainId) as reference, and every item carries 'chainsKnown' (C-14) -
    both are informational only and NEVER change the verdict itself."""
    results: List[Dict[str, Any]] = []
    for identity in sorted(groups):
        by_chain = groups[identity]
        if len(by_chain) < 2:
            continue
        chain_ids = sorted(by_chain, key=int)
        normalized: Dict[str, str] = {}
        for cid in chain_ids:
            norm_hex, _ = normalize_hex(runtime_bytecode_map[by_chain[cid]], "runtimeBytecode")
            normalized[cid], _, _ = _normalize_bytecode_hex(norm_hex)
        distinct = set(normalized.values())
        keys_by_chain = {cid: by_chain[cid] for cid in chain_ids}
        chains_known = _chains_known_map(chain_ids)
        if len(distinct) == 1:
            results.append(_verdict(
                "MATCH",
                "%s sharing verified metadata identity %s are byte-identical "
                "(after CBOR normalization) across chains %s"
                % (subject_label, identity, ", ".join(chain_ids)),
                extra={
                    "metadataIdentity": identity, "chainIds": chain_ids,
                    keys_field_name: keys_by_chain, "chainsKnown": chains_known,
                },
            ))
        else:
            reference_cid = chain_ids[0]
            reference_hex = normalized[reference_cid]
            divergence_profile = {
                "referenceChainId": reference_cid,
                "perChain": {
                    cid: byte_divergence_profile(reference_hex, normalized[cid])
                    for cid in chain_ids[1:]
                    if normalized[cid] != reference_hex
                },
            }
            results.append(_verdict(
                "MISMATCH",
                "%s sharing verified metadata identity %s have DIFFERENT bytecode "
                "(after CBOR normalization) across chains %s - multi-chain rollout "
                "appears out of sync"
                % (subject_label, identity, ", ".join(chain_ids)),
                extra={
                    "metadataIdentity": identity, "chainIds": chain_ids,
                    keys_field_name: keys_by_chain, "chainsKnown": chains_known,
                    "divergenceProfile": divergence_profile,
                },
            ))
    return results


def check_cross_chain_implementation_drift(
    system_graph: Optional[Dict[str, Any]],
    runtime_bytecode_map: Optional[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """When 2+ RESOLVED proxies on DIFFERENT chains delegate to
    implementations that share a reliable, content-based identity (the
    CBOR-embedded source metadata hash - see _cbor_metadata_identity_hash),
    compare their runtime bytecodes after CBOR normalization.  A drift is a
    technical fact (a multi-chain rollout is out of sync) - NEVER a
    vulnerability signal.

    D-060 corrective fix: this function previously grouped candidates by
    bare contract name alone, which could false-group two entirely
    unrelated contracts that merely share a common name (audit finding).
    Bare-name (and address) grouping has been REMOVED entirely.  An
    implementation whose metadata identity cannot be established (bytecode
    missing, CBOR metadata absent/undecodable, or no ipfs/bzzr key) never
    contributes to any group - no relationship is ever inferred from name
    or address alone, and no comparison is emitted for it.  Never compares
    within the same chain (compare_source_vs_runtime already covers that)
    and never fires for a single-chain deployment.

    V2.8 Block 3 (C-10/C-14): see _cross_chain_bytecode_drift for the shared
    divergenceProfile/chainsKnown behavior - both purely descriptive, never
    changing the verdict."""
    groups = _group_resolved_proxies_by_identity(system_graph, runtime_bytecode_map)
    return _cross_chain_bytecode_drift(groups, runtime_bytecode_map or {}, "implementationKeys", "implementations")


def check_cross_chain_proxy_drift(
    system_graph: Optional[Dict[str, Any]],
    runtime_bytecode_map: Optional[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """V2.8 Block 4, C-11.  Same mechanism as check_cross_chain_implementation_drift
    (C-03) - reuses _group_resolved_proxies_by_identity/_cross_chain_bytecode_drift
    verbatim - but grouped on the PROXY's own key/bytecode instead of the
    implementation's (key_field='proxy'; runtimeBytecodeMap must ALSO carry
    an entry for the proxy key itself for this to find anything - no new
    top-level input field, just an additional expected key in the SAME
    existing map).

    Proxies are expected to be structurally STABLE across a multi-chain
    rollout (unlike implementations, which are legitimately upgraded) - a
    drift here is at least as strong a signal, often stronger, that
    something about the deployment mechanism itself (not just its logic)
    differs unexpectedly across chains.  Never a vulnerability signal - same
    MISMATCH_NOTE/R-C2 discipline as every other verdict in this script."""
    groups = _group_resolved_proxies_by_identity(system_graph, runtime_bytecode_map, key_field="proxy")
    return _cross_chain_bytecode_drift(groups, runtime_bytecode_map or {}, "proxyKeys", "proxies")


def check_cross_chain_provenance_consistency(
    system_graph: Optional[Dict[str, Any]],
    runtime_bytecode_map: Optional[Dict[str, str]],
    verified_map: Optional[Dict[str, bool]],
    compiler_version_map: Optional[Dict[str, str]],
    contract_name_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """V2.8 Block 3, C-09; extended in Block 4 (C-12) with contractNameMap.
    For implementations already proven to share a reliable cross-chain
    identity (reuses C-03's exact grouping via
    _group_resolved_proxies_by_identity - never re-derived), check whether
    their caller-supplied verifiedMap/compilerVersionMap/contractNameMap
    agree across chains.  A disagreement is a provenance/integrity fact -
    different explorers (or the same explorer at different times)
    disagreeing about the same underlying compiled artifact - NEVER a
    vulnerability signal, same discipline as C-04's duplicate-identity
    conflicts (never chooses a side).  contractNameMap disagreement in
    particular is integrity metadata only (e.g. mismatched per-chain
    labeling for a proven-identical artifact) - it is never itself evidence
    of anything malicious, and this function has no code path or wording
    that claims otherwise.

    verifiedMap/compilerVersionMap/contractNameMap are optional inputs,
    parallel to sourceBytecodeMap/runtimeBytecodeMap (D-057's own precedent
    for adding a per-key map without touching systemGraph).  Without ANY of
    them, nothing can be checked and no entry is produced - this NEVER
    falls back to the single primary record's own top-level
    verified/compilerVersion/contractName field, which describes only the
    one address being analyzed, never the whole cross-chain group.  A
    malformed (non-dict) map is treated exactly like an absent one - never
    guessed, never crashes.  Every item also carries 'chainsKnown' (C-14),
    purely descriptive."""
    verified_map = verified_map if isinstance(verified_map, dict) else None
    compiler_version_map = compiler_version_map if isinstance(compiler_version_map, dict) else None
    contract_name_map = contract_name_map if isinstance(contract_name_map, dict) else None
    if not verified_map and not compiler_version_map and not contract_name_map:
        return []
    groups = _group_resolved_proxies_by_identity(system_graph, runtime_bytecode_map)

    results: List[Dict[str, Any]] = []
    for identity in sorted(groups):
        by_chain = groups[identity]
        if len(by_chain) < 2:
            continue
        chain_ids = sorted(by_chain, key=int)
        implementation_keys = {cid: by_chain[cid] for cid in chain_ids}

        verified_values: Dict[str, bool] = {}
        for cid in chain_ids:
            value = (verified_map or {}).get(by_chain[cid])
            if isinstance(value, bool):
                verified_values[cid] = value

        compiler_values: Dict[str, str] = {}
        for cid in chain_ids:
            raw_version = (compiler_version_map or {}).get(by_chain[cid])
            if isinstance(raw_version, str):
                match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw_version)
                if match:
                    compiler_values[cid] = "%s.%s.%s" % match.groups()

        contract_name_values: Dict[str, str] = {}
        for cid in chain_ids:
            raw_name = (contract_name_map or {}).get(by_chain[cid])
            if isinstance(raw_name, str) and raw_name.strip():
                contract_name_values[cid] = raw_name.strip()

        disagreements: Dict[str, Dict[str, Any]] = {}
        if len(set(verified_values.values())) > 1:
            disagreements["verified"] = dict(verified_values)
        if len(set(compiler_values.values())) > 1:
            disagreements["compilerVersion"] = dict(compiler_values)
        if len(set(contract_name_values.values())) > 1:
            disagreements["contractName"] = dict(contract_name_values)

        extra = {
            "metadataIdentity": identity, "chainIds": chain_ids,
            "implementationKeys": implementation_keys, "chainsKnown": _chains_known_map(chain_ids),
        }
        has_any_data = verified_values or compiler_values or contract_name_values
        if disagreements:
            results.append(_verdict(
                "MISMATCH",
                "implementations sharing verified metadata identity %s disagree on %s across "
                "chains %s - a provenance/integrity fact about explorer-reported metadata, "
                "never a vulnerability signal"
                % (identity, " and ".join(sorted(disagreements)), ", ".join(chain_ids)),
                extra={**extra, "disagreements": disagreements},
            ))
        elif has_any_data:
            results.append(_verdict(
                "MATCH",
                "implementations sharing verified metadata identity %s agree on all checked "
                "provenance field(s) across chains %s" % (identity, ", ".join(chain_ids)),
                extra={**extra, "disagreements": {}},
            ))
        else:
            results.append(_verdict(
                "UNAVAILABLE",
                "implementations sharing verified metadata identity %s found across chains %s, "
                "but verifiedMap/compilerVersionMap/contractNameMap provide no comparable data "
                "for them" % (identity, ", ".join(chain_ids)),
                extra={**extra, "disagreements": {}},
            ))
    return results


def compute_cross_chain_coverage_summary(
    system_graph: Optional[Dict[str, Any]],
    runtime_bytecode_map: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    """V2.8 Block 4, C-13.  Purely descriptive aggregation over the SAME
    resolved-proxy population check_cross_chain_implementation_drift (C-03)
    and check_cross_chain_proxy_drift (C-11) already group via
    _group_resolved_proxies_by_identity - adds NO new detection logic and
    NEVER affects any verdict.  Exists because a resolved proxy whose
    implementation (or proxy) bytecode carries no reliable CBOR metadata
    identity is currently INVISIBLE elsewhere - it silently contributes no
    comparison anywhere, with nothing in the rest of the output signaling
    that it was even considered.  This is a NOT_ASSESSED-style transparency
    aggregate, not itself a finding: counts only, never a claim about why a
    given proxy lacks an identity (missing bytecode, undecodable CBOR, and
    a genuinely non-Solidity/minimal-proxy target are all indistinguishable
    from counts alone).  A malformed (non-dict) runtimeBytecodeMap is
    treated exactly like an absent one - never guessed, never crashes."""
    safe_runtime_map = runtime_bytecode_map if isinstance(runtime_bytecode_map, dict) else {}
    if system_graph is None:
        resolved: List[Dict[str, Any]] = []
    else:
        proxies_raw = system_graph.get("proxies")
        proxies = proxies_raw if isinstance(proxies_raw, list) else []
        resolved = [p for p in proxies if isinstance(p, dict) and p.get("status") == "resolved"]

    def _with_identity_count(key_field: str) -> int:
        count = 0
        for entry in resolved:
            target_key = entry.get(key_field)
            if _extract_chain_id_from_key(target_key) is None:
                continue
            if _cbor_metadata_identity_hash(safe_runtime_map.get(target_key)) is not None:
                count += 1
        return count

    def _group_stats(key_field: str, with_identity: int) -> Dict[str, int]:
        groups = _group_resolved_proxies_by_identity(system_graph, safe_runtime_map, key_field=key_field)
        return {
            "withIdentityCount": with_identity,
            "withoutIdentityCount": len(resolved) - with_identity,
            "groupCount": len(groups),
            "comparableGroupCount": sum(1 for by_chain in groups.values() if len(by_chain) >= 2),
        }

    return {
        "resolvedProxyCount": len(resolved),
        "implementationIdentity": _group_stats("implementation", _with_identity_count("implementation")),
        "proxyIdentity": _group_stats("proxy", _with_identity_count("proxy")),
    }


# ---------------------------------------------------------------------------
# Top-level compare function
# ---------------------------------------------------------------------------

def compare(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Run all bytecode comparisons on an extended V2.6.1 ingest record.

    Reads from the record:
      Core V2.6.1 fields : address, network, verified, hasCode
      New V2.7 fields    : runtimeBytecode, deploymentBytecode, sourceBytecode,
                           abi, systemGraph, sourceBytecodeMap, runtimeBytecodeMap
      New V2.8 Block 3   : verifiedMap, compilerVersionMap (optional, keyed like
                           runtimeBytecodeMap - feed check_cross_chain_provenance_consistency)
      New V2.8 Block 4   : contractNameMap (optional, same keying, C-12); runtimeBytecodeMap
                           may ALSO carry proxy-key entries (feeds check_cross_chain_proxy_drift, C-11)

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
    compiler_version = raw.get("compilerVersion")
    verified_map = raw.get("verifiedMap")
    compiler_version_map = raw.get("compilerVersionMap")
    contract_name_map = raw.get("contractNameMap")
    chain_id = network.get("chainId") if isinstance(network, dict) else None

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

    # 4. Opcode capability checks (V2.8 Block 2, C-01/C-05)
    comparisons["capabilityChecks"] = check_capability_compatibility(
        runtime_bytecode=raw_runtime,
        deployment_bytecode=raw_deployment,
        chain_id=chain_id,
    )

    # 5. Explorer compilerVersion vs CBOR-embedded solc version (C-02)
    comparisons["compilerVersionCheck"] = check_compiler_version_consistency(
        reported_compiler_version=compiler_version,
        runtime_bytecode=raw_runtime,
        verified=verified,
    )

    # 6. Cross-chain implementation drift (C-03), incl. divergenceProfile (C-10)
    comparisons["crossChainImplementationDrift"] = check_cross_chain_implementation_drift(
        system_graph=system_graph,
        runtime_bytecode_map=runtime_map,
    )

    # 7. Cross-chain provenance consistency for C-03 identity-linked implementations (C-09/C-12)
    comparisons["crossChainProvenanceConsistency"] = check_cross_chain_provenance_consistency(
        system_graph=system_graph,
        runtime_bytecode_map=runtime_map,
        verified_map=verified_map,
        compiler_version_map=compiler_version_map,
        contract_name_map=contract_name_map,
    )

    # 8. Cross-chain proxy bytecode drift (V2.8 Block 4, C-11)
    comparisons["crossChainProxyDrift"] = check_cross_chain_proxy_drift(
        system_graph=system_graph,
        runtime_bytecode_map=runtime_map,
    )

    # 9. Cross-chain coverage summary (V2.8 Block 4, C-13) - descriptive only
    comparisons["crossChainCoverageSummary"] = compute_cross_chain_coverage_summary(
        system_graph=system_graph,
        runtime_bytecode_map=runtime_map,
    )

    # Propagate non-MATCH verdicts to limitations[] for the analysis step
    _LIST_SHAPED_COMPARISONS = (
        "proxyComparisons", "capabilityChecks",
        "crossChainImplementationDrift", "crossChainProvenanceConsistency",
        "crossChainProxyDrift",
    )
    for comp_name, verdict_obj in comparisons.items():
        if comp_name in _LIST_SHAPED_COMPARISONS:
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

    for cap_item in comparisons["capabilityChecks"]:
        if not isinstance(cap_item, dict):
            continue
        v = cap_item.get("verdict")
        if v in ("MISMATCH", "INCOMPLETE"):
            limitations.append(
                "capabilityChecks[%s]: %s — %s"
                % (cap_item.get("capability", "?"), v, cap_item.get("detail", ""))
            )

    for drift_item in comparisons["crossChainImplementationDrift"]:
        if not isinstance(drift_item, dict):
            continue
        v = drift_item.get("verdict")
        if v in ("MISMATCH", "INCOMPLETE"):
            limitations.append(
                "crossChainImplementationDrift[%s]: %s — %s"
                % (drift_item.get("metadataIdentity", "?"), v, drift_item.get("detail", ""))
            )

    for provenance_item in comparisons["crossChainProvenanceConsistency"]:
        if not isinstance(provenance_item, dict):
            continue
        v = provenance_item.get("verdict")
        if v in ("MISMATCH", "INCOMPLETE"):
            limitations.append(
                "crossChainProvenanceConsistency[%s]: %s — %s"
                % (provenance_item.get("metadataIdentity", "?"), v, provenance_item.get("detail", ""))
            )

    for proxy_drift_item in comparisons["crossChainProxyDrift"]:
        if not isinstance(proxy_drift_item, dict):
            continue
        v = proxy_drift_item.get("verdict")
        if v in ("MISMATCH", "INCOMPLETE"):
            limitations.append(
                "crossChainProxyDrift[%s]: %s — %s"
                % (proxy_drift_item.get("metadataIdentity", "?"), v, proxy_drift_item.get("detail", ""))
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
    if compiler_version is not None:
        provenance["compilerVersion"] = "explorer"
    if verified_map is not None:
        provenance["verifiedMap"] = "explorer"
    if compiler_version_map is not None:
        provenance["compilerVersionMap"] = "explorer"
    if contract_name_map is not None:
        provenance["contractNameMap"] = "explorer"

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
