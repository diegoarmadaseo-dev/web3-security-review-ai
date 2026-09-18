#!/usr/bin/env python3
"""Deployed-contract ingestion, verified-only (V2.6.1, docs/decisiones.md
D-055). Turns an ALREADY-FETCHED JSON blob describing one (address, network)
pair into (a) a normalized ingestion record and (b) - only when the input
says the contract is verified and carries usable source - a multi-file
"bundle" string in preprocess.py's OWN existing `=== FILE: ... ===` /
`=== END FILE ===` format, ready to be piped to preprocess.py's stdin
UNCHANGED (see collect_inputs/parse_bundle in preprocess.py).

THIS SCRIPT NEVER MAKES A NETWORK CALL. It has no HTTP client, no RPC
client, and no notion of "fetch this address" - by design (D-055): whoever
already obtained the raw JSON (an MCP blockchain/explorer connector, a
manual paste from Etherscan/Sourcify, any other tool) did so with their own
credentials and their own error/timeout/rate-limit handling, entirely
OUTSIDE this Skill. This script only reads and reshapes data that already
exists as a local JSON file - the exact same posture diff_reports.py already
established for comparing two already-produced reports.

Bytecode-only (unverified) analysis is explicitly OUT OF SCOPE for this
version - see the V2.6 audit (docs/decisiones.md D-055): an unverified
contract's `sourceFiles` are simply absent, ingestion reports
completeness "failed" with a neutral, non-accusatory reason, and nothing
further is attempted. `verified: false` is a TRANSPARENCY fact about what
we could recover, NEVER a vulnerability signal on its own - this script has
no code path capable of producing a finding/signal at all, verified or not.

Contract identity for a verified contract's recovered source files is a
virtual path under "onchain://<chainId>/<address>/<relative-file-name>" -
chosen so preprocess.py's OWN, UNMODIFIED `key = "%s#%s" % (path, name)`
(scripts/preprocess.py, systemGraph node key) naturally produces an
onchain-namespaced key with zero changes to preprocess.py or
compute_system_graph. Caveat, unavoidable without touching preprocess.py:
its own `normalize_path()` collapses any doubled "/" (including the "//"
in "onchain://") down to a single "/", since consecutive slashes produce
an empty path segment that normalize_path already filters out - so the
REALIZED path/key ends up "onchain:/<chainId>/<address>/<file>", not
byte-identical to the "onchain://" scheme used to construct it. This is
disclosed here and in the schema rather than silently accepted.

Address/network normalization is deliberately shallow: addresses are
validated for basic well-formedness (0x + 40 hex chars) and canonicalized
to lowercase - EIP-55 mixed-case checksum verification is NOT performed.
Computing an EIP-55 checksum requires Keccak-256, which Python's stdlib
does not provide: hashlib.sha3_256 is the NIST-finalized SHA3-256, which
differs from Ethereum's (pre-standardization) Keccak-256 in its padding
and would silently produce a WRONG checksum if used naively. Rather than
hand-roll a Keccak-256 implementation (a large, error-prone undertaking
far beyond "normalize an address", and explicitly out of scope for this
block) or silently mislabel SHA3-256 output as an EIP-55 checksum, this
script simply does not claim checksum validation at all.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

INGEST_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

NEVER_A_VULNERABILITY_NOTE = (
    "verified=false (or any other completeness limitation recorded here) is "
    "a TRANSPARENCY fact about what could be recovered, never a "
    "vulnerability finding or signal by itself - this script has no code "
    "path that emits findings/signals at all. Judging an unverified "
    "contract's trustworthiness, if attempted at all, is the analysis "
    "step's (AI's) job, informed by this record, never this script's."
)
RUNTIME_STATE_NOTE = (
    "This record describes a deployed contract's identity and (if "
    "verified) its recovered SOURCE CODE only. It carries no live storage "
    "values, balances, or transaction history - deployed RUNTIME state "
    "remains out of scope (see docs/legal-risk-register.md RISK-014, "
    "docs/decisiones.md D-055)."
)

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Deliberately small, explicit table of well-known EVM chain ids - an
# unrecognized chainId is still accepted (name stays null); only a
# genuinely unparseable `network` value (neither a number nor a known
# name) fails ingestion, since new chains launch constantly and this
# script must never block on an incomplete registry.
_KNOWN_CHAINS = {
    1: "ethereum", 5: "goerli", 10: "optimism", 56: "bsc", 100: "gnosis",
    137: "polygon", 250: "fantom", 8453: "base", 42161: "arbitrum",
    43114: "avalanche", 11155111: "sepolia",
}
_NETWORK_ALIASES = {
    "ethereum": 1, "mainnet": 1, "eth": 1, "goerli": 5, "optimism": 10, "op": 10,
    "bsc": 56, "binance": 56, "bnb": 56, "gnosis": 100, "xdai": 100,
    "polygon": 137, "matic": 137, "fantom": 250, "ftm": 250, "base": 8453,
    "arbitrum": 42161, "arb": 42161, "avalanche": 43114, "avax": 43114,
    "sepolia": 11155111,
}

_BUNDLE_MARKER_RE = re.compile(r"^\s*(=== FILE: .+? ===|=== END FILE ===)\s*$", re.MULTILINE)


class IngestError(Exception):
    """Raised when the input is too malformed to even attempt ingestion
    (not a dict, or missing a required top-level key) - distinct from a
    per-contract completeness limitation (unverified, empty, unsafe
    filename, ...), which is always reported via `completeness`/`reasons`,
    never raised."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IngestError(message)


def normalize_address(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """Returns (normalized_lowercase_address, error_reason_or_None). Never
    raises - a malformed address is a completeness concern, not a caller
    contract violation."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "address is missing or not a string"
    candidate = raw.strip()
    if not ADDRESS_RE.match(candidate):
        return None, "address is not a well-formed 0x-prefixed 20-byte hex string"
    return candidate.lower(), None


def normalize_network(raw: Any) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Returns (chainId, name_or_None, error_reason_or_None). (V2.8: uses chains.py)"""
    import chains
    try:
        return chains.resolve_chain(raw)
    except chains.ChainsConfigError:
        # Only a broken/missing/malformed chains.json falls back to the
        # legacy hardcoded table below - any OTHER exception (a real bug in
        # chains.py) must propagate, never be silently swallowed.
        pass

    if isinstance(raw, dict):
        raw = raw.get("chainId")
    if isinstance(raw, bool):
        return None, None, "network must be a chain id or network name, not a boolean"
    if isinstance(raw, int):
        return raw, _KNOWN_CHAINS.get(raw), None
    if isinstance(raw, str):
        text = raw.strip()
        if text.isdigit():
            chain_id = int(text)
            return chain_id, _KNOWN_CHAINS.get(chain_id), None
        alias = _NETWORK_ALIASES.get(text.lower())
        if alias is not None:
            return alias, _KNOWN_CHAINS.get(alias), None
        return None, None, "network %r is not a recognized name and is not numeric" % text
    return None, None, "network is missing or of an unsupported type"


def _sanitize_relative_path(raw_path: Any) -> Tuple[Optional[str], Optional[str]]:
    """Returns (safe_relative_path, rejection_reason_or_None). Source file
    paths originate from a THIRD-PARTY explorer response, not from the
    user directly - defense in depth against path traversal / absolute
    paths, same posture as any other untrusted external input."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "source file path is missing or empty"
    candidate = raw_path.strip().replace("\\", "/")
    if any(ord(ch) < 0x20 for ch in candidate):
        return None, "source file path contains a control character"
    if candidate.startswith("/") or re.match(r"^[A-Za-z]:", candidate):
        return None, "source file path is absolute, rejected"
    # Filter "." segments too (not just empty ones), mirroring
    # preprocess.py's own normalize_path exactly - this is the same
    # function that will normalize this same path again once it reaches
    # the bundle parser, so pre-normalizing identically here is what makes
    # OUR OWN duplicate-path detection (below) actually catch
    # "./A.sol" vs "A.sol" before it ever reaches preprocess.py.
    segments = [s for s in candidate.split("/") if s not in ("", ".")]
    if not segments:
        return None, "source file path is empty after normalization"
    if any(s == ".." for s in segments):
        return None, "source file path contains a '..' traversal segment, rejected"
    return "/".join(segments), None


def _reason(code: str, detail: str) -> Dict[str, str]:
    return {"code": code, "detail": detail}


def build_bundle(virtual_prefix: str, source_files: List[Dict[str, Any]]) -> Tuple[Optional[str], int, List[Dict[str, Any]]]:
    """Returns (bundle_text_or_None, accepted_count, skipped[{path,reason}]).
    Rejects (never silently drops without recording) any file whose
    sanitized path collides with one already accepted, or whose own
    content contains a line shaped like a bundle boundary marker - such
    content would corrupt preprocess.py's own bundle parser, which has no
    escaping mechanism for it (it was designed for trusted, self-assembled
    bundles, not third-party explorer content)."""
    accepted: List[Tuple[str, str]] = []
    seen_paths: Dict[str, bool] = {}
    skipped: List[Dict[str, Any]] = []
    for entry in source_files:
        if not isinstance(entry, dict):
            skipped.append({"path": None, "reason": "source file entry is not an object"})
            continue
        safe_path, reason = _sanitize_relative_path(entry.get("path"))
        content = entry.get("content")
        if reason:
            skipped.append({"path": entry.get("path"), "reason": reason})
            continue
        if safe_path in seen_paths:
            skipped.append({"path": safe_path, "reason": "duplicate path after sanitization"})
            continue
        if not isinstance(content, str):
            skipped.append({"path": safe_path, "reason": "source file content is missing or not a string"})
            continue
        if _BUNDLE_MARKER_RE.search(content):
            skipped.append({"path": safe_path, "reason": "content contains a line shaped like a bundle boundary marker (=== FILE: ... === or === END FILE ===); would corrupt the multi-file bundle"})
            continue
        seen_paths[safe_path] = True
        accepted.append((safe_path, content))
    if not accepted:
        return None, 0, skipped
    parts = []
    for path, content in accepted:
        body = content if content.endswith("\n") else content + "\n"
        parts.append("=== FILE: %s%s ===\n%s=== END FILE ===\n" % (virtual_prefix, path, body))
    return "".join(parts), len(accepted), skipped


def find_contradictory_duplicate_identities(raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Given multiple raw ingestion inputs meant to be combined into one
    multi-contract analysis bundle, detect when two or more records claim
    the SAME (chainId, address) identity but disagree on fields that
    identity should determine (verified, contractName, compilerVersion).

    Never silently picks a side and never mutates or combines the records
    itself - every conflict is reported, the caller (the workflow that
    assembles the combined bundle) decides what to do with it. Same
    discipline build_bundle already applies one level down for duplicate
    source file paths within a single ingestion (V2.6.1, D-055): a
    collision is always recorded with a reason, never silently resolved.

    Records whose own (address, network) cannot be resolved are skipped
    here entirely - that is ingest()'s own INVALID_ADDRESS/UNRECOGNIZED_NETWORK
    concern, not a duplicate-identity concern."""
    by_identity: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}
    for idx, raw in enumerate(raw_records):
        if not isinstance(raw, dict):
            continue
        address, _addr_err = normalize_address(raw.get("address"))
        chain_id, _name, _net_err = normalize_network(raw.get("network"))
        if address is None or chain_id is None:
            continue
        by_identity.setdefault((chain_id, address), []).append({"index": idx, "raw": raw})

    conflicts: List[Dict[str, Any]] = []
    for (chain_id, address), records in by_identity.items():
        if len(records) < 2:
            continue
        disagreements: Dict[str, List[Any]] = {}
        for field in ("verified", "contractName", "compilerVersion"):
            distinct: List[Any] = []
            for r in records:
                value = r["raw"].get(field)
                if value not in distinct:
                    distinct.append(value)
            if len(distinct) > 1:
                disagreements[field] = distinct
        if disagreements:
            conflicts.append({
                "chainId": chain_id,
                "address": address,
                "recordIndices": [r["index"] for r in records],
                "disagreements": disagreements,
            })
    return conflicts


def check_network_identity_consistency(raw_network: Any) -> Optional[Dict[str, Any]]:
    """V2.8 Block 3, C-08.  When the raw network field is a dict supplying
    BOTH a chainId AND a "name" string, cross-check the supplied name
    against the catalog's canonical name/aliases for that chainId.

    chains.resolve_chain() itself only ever reads "chainId" from a dict
    form and silently discards any other key - so a caller that ALSO
    includes a (possibly contradictory) "name" for its own bookkeeping
    would otherwise have that mismatch go completely unnoticed everywhere
    downstream. This is exactly the kind of config/copy-paste error that
    is realistic in a multi-chain workflow (e.g. a per-chain template
    where the chainId was updated but the name label was not).

    Returns None (nothing to check - never guessed) when raw_network is
    not a dict, carries no usable "name" string, or resolves to a chainId
    the catalog does not know (isKnown=False) - there is nothing reliable
    to compare an unknown chain's "canonical" name against. Uses ONLY
    chains.py's existing PUBLIC resolve_chain()/load_chains_config() - it
    never imports a private helper and never modifies chains.py itself.

    Input-integrity signal ONLY, NEVER a security finding: a mismatched
    name is far more likely a copy-paste/config error in the caller's own
    tooling than an attack, and this function has no code path, and its
    detail text uses no wording, that asserts otherwise."""
    if not isinstance(raw_network, dict):
        return None
    declared_name = raw_network.get("name")
    if not isinstance(declared_name, str) or not declared_name.strip():
        return None

    import chains
    try:
        resolved_chain_id, canonical_name, _err = chains.resolve_chain(raw_network)
    except chains.ChainsConfigError:
        return None  # broken/missing catalog - nothing can be verified, never guessed
    if resolved_chain_id is None or canonical_name is None:
        return None  # chainId unresolvable, or unknown to the catalog - not this check's concern

    try:
        catalog = chains.load_chains_config()
    except chains.ChainsConfigError:
        return None

    accepted_identifiers = {canonical_name}
    for entry in catalog.get("chains", []):
        if entry.get("chainId") == resolved_chain_id:
            accepted_identifiers.update(entry.get("aliases", []) or [])
            break

    declared_normalized = declared_name.strip().lower()
    consistent = declared_normalized in accepted_identifiers
    return {
        "chainId": resolved_chain_id,
        "canonicalName": canonical_name,
        "declaredName": declared_name,
        "consistent": consistent,
        "detail": (
            "declared network name %r matches the catalog identity for chainId %d"
            % (declared_name, resolved_chain_id)
        ) if consistent else (
            "declared network name %r does not match the catalog identity for chainId %d "
            "(canonical: %r) - an input-integrity signal such as a config/copy-paste "
            "mismatch, never a security finding"
            % (declared_name, resolved_chain_id, canonical_name)
        ),
    }


def ingest(raw: Dict[str, Any]) -> Dict[str, Any]:
    _require(isinstance(raw, dict), "input must be a JSON object")
    _require("address" in raw, "input.address is required")
    _require("network" in raw, "input.network is required")

    reasons: List[Dict[str, str]] = []
    address, address_error = normalize_address(raw.get("address"))
    if address_error:
        reasons.append(_reason("INVALID_ADDRESS", address_error))
    chain_id, chain_name, network_error = normalize_network(raw.get("network"))
    if network_error:
        reasons.append(_reason("UNRECOGNIZED_NETWORK", network_error))

    # Identity check, never bool() coercion (same pattern hasCode already
    # uses below): bool("false") is True in Python, so a malformed input
    # that serializes the boolean as a string would otherwise be silently
    # treated as verified - exactly the direction the hard rule (verified
    # never implies trust it hasn't earned) must never fail in.
    verified = raw.get("verified") is True
    has_code = raw.get("hasCode")
    provenance: Dict[str, str] = {"verified": "explorer"}

    bundle: Optional[str] = None
    source_file_count = 0
    skipped_source_files: List[Dict[str, Any]] = []
    virtual_prefix = None

    if address is None or chain_id is None:
        reasons.append(_reason("IDENTITY_INCOMPLETE", "cannot build a virtual path or systemGraph key without both a valid address and a resolvable network"))
    else:
        virtual_prefix = "onchain://%d/%s/" % (chain_id, address)
        provenance["virtualPathPrefix"] = "analyzer-inferred"

    if has_code is False:
        reasons.append(_reason("EMPTY_BYTECODE", "the queried address reports no deployed code (empty bytecode) - there is no contract to analyze here, regardless of any verified-source claim"))
        provenance["hasCode"] = "on-chain"
    elif has_code is True:
        provenance["hasCode"] = "on-chain"

    if has_code is not False:
        if not verified:
            reasons.append(_reason("UNVERIFIED_CONTRACT", "source code for this contract has not been verified by the queried explorer; static source analysis cannot be performed without source - this is a transparency limitation, not a vulnerability"))
        elif virtual_prefix is None:
            reasons.append(_reason("SOURCE_NOT_INGESTED", "verified source was reported but could not be placed under a virtual path (see IDENTITY_INCOMPLETE)"))
        else:
            source_files = raw.get("sourceFiles")
            if not isinstance(source_files, list) or not source_files:
                reasons.append(_reason("NO_SOURCE_FILES", "verified=true but no source files were supplied"))
            else:
                bundle, source_file_count, skipped_source_files = build_bundle(virtual_prefix, source_files)
                provenance["sourceFiles"] = "explorer"
                if bundle is None:
                    reasons.append(_reason("NO_USABLE_SOURCE_FILES", "verified=true and source files were supplied, but none survived path/content safety checks"))
                elif skipped_source_files:
                    reasons.append(_reason("PARTIAL_SOURCE_RECOVERY", "%d of %d supplied source file(s) were rejected (see skippedSourceFiles) and excluded from the bundle" % (len(skipped_source_files), len(source_files))))

    if any(r["code"] in ("INVALID_ADDRESS", "UNRECOGNIZED_NETWORK", "IDENTITY_INCOMPLETE", "EMPTY_BYTECODE", "UNVERIFIED_CONTRACT", "SOURCE_NOT_INGESTED", "NO_SOURCE_FILES", "NO_USABLE_SOURCE_FILES") for r in reasons):
        status = "failed"
    elif reasons:
        status = "partial"
    else:
        status = "complete"

    for field in ("contractName", "compilerVersion"):
        if raw.get(field) is not None:
            provenance[field] = "explorer"

    return {
        "ingestVersion": INGEST_VERSION,
        "address": address,
        "network": {"chainId": chain_id, "name": chain_name},
        "verified": verified,
        "hasCode": has_code if isinstance(has_code, bool) else None,
        "contractName": raw.get("contractName"),
        "compilerVersion": raw.get("compilerVersion"),
        "virtualPathPrefix": virtual_prefix,
        "bundle": bundle,
        "sourceFileCount": source_file_count,
        "skippedSourceFiles": skipped_source_files,
        "completeness": {"status": status, "reasons": reasons},
        "provenance": provenance,
        "note": NEVER_A_VULNERABILITY_NOTE,
        "runtimeStateNote": RUNTIME_STATE_NOTE,
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
        raise IngestError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ingest_onchain.py",
        description="Normalize an already-fetched deployed-contract JSON blob (address+network+verification+source) into an ingestion record and, if verified, a preprocess.py-ready bundle. Never fetches anything itself.",
    )
    parser.add_argument("path", nargs="?", default=None, help="Path to the already-fetched input JSON file. Reads stdin if omitted.")
    parser.add_argument("--out", default=None, help="Write the ingestion record to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        raw = _read_json_file(args.path) if args.path else json.loads(sys.stdin.read())
        record = ingest(raw)
    except (IngestError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(record, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
