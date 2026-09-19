#!/usr/bin/env python3
"""Continuous on-chain monitoring: temporal snapshot drift, finding lifecycle
across repeated scans, and a completeness/idempotency gate for monitoring
windows (V2.9, docs/decisiones.md D-063).

Three independent capabilities:

  M1 (compute_temporal_snapshot_drift) - given TWO already-fetched snapshots
     of the SAME (address, network) taken at different times, reports
     structural facts: verified/hasCode flips, adminAddress/ownerAddress
     changes (only when the caller supplies both - never guessed), runtime
     bytecode drift, and proxy-to-implementation resolution drift.  Reuses
     compare_bytecode.py's existing normalize_hex/strip_cbor_metadata/
     byte_divergence_profile (V2.7/C-10) rather than re-deriving bytecode
     comparison logic - the math is identical whether the two things being
     compared are separated by CHAIN (V2.8) or by TIME (this module).

  M2 (compute_finding_lifecycle) - given an ORDERED sequence of already-
     scored reports (each report-schema.json shaped), tracks each finding's
     stableKey across scans: new / present / resolved / regressed.  Reuses
     diff_reports.py's existing diff_reports() (V2.5/D-054) UNCHANGED for
     each consecutive pair; the only new logic here is the small reducer
     that folds a SEQUENCE of pairwise diffs into a per-key status history
     and flags a resolved finding that reappears later as 'regressed'.

  M3 (compute_snapshot_coverage_status / compute_snapshot_content_hash) -
     a monitoring WINDOW can only be trusted as far as the ingestion behind
     it was complete.  compute_snapshot_coverage_status gates on the
     caller-supplied completeness.status (ingest_onchain.py, V2.6.1/D-055)
     of each snapshot and returns ASSESSED or NOT_ASSESSED for the WINDOW
     as a whole - this is a coverage/window status ONLY, never a 6th
     bytecode verdict; compare_bytecode.py's five verdicts (MATCH/MISMATCH/
     UNAVAILABLE/INCOMPLETE/UNRESOLVED) are completely untouched by this
     module and by this status.  A failed snapshot NEVER silently reads as
     "no change" - see NEVER_SAFE_BY_SILENCE_NOTE.  compute_snapshot_content_hash
     gives a deterministic idempotency key (excluding snapshotTimestamp
     itself) so a caller can recognize "this snapshot's on-chain state is
     identical to the last one already recorded" and skip a redundant
     comparison/alert.

M4 - statelessness boundary (enforced by this module's own design, not a
     function): snapshotTimestamp is ALWAYS caller-supplied on every
     snapshot/scan passed in - this module NEVER calls datetime.now() or
     any clock, which would make its output non-reproducible given the
     same inputs (the same invariant this whole project has held since
     Subfase 0).  This module has NO database, NO cron/scheduling, NO
     alerting, and NO RPC/network calls of any kind - exactly like every
     other script in this Skill (D-055's "network calls happen OUTSIDE the
     Skill" precedent, extended here to "snapshot storage and alerting
     happen OUTSIDE the Skill" too).  A calling workflow is responsible for
     fetching on-chain data, persisting snapshots/reports over time, and
     deciding what to do with a change once this module reports it as a
     fact; retention/scalability of that history is entirely the caller's
     concern, not this module's.

M1/M2 never author a finding and never call a model: a bytecode/proxy/
finding-lifecycle change is a TECHNICAL FACT for the analysis step (or a
human) to interpret in context, exactly like every comparison in
compare_bytecode.py and diff_reports.py already works (R-C2/STRUCTURAL_ONLY_NOTE).
"No change detected" is never treated, by this module or its callers, as
proof of safety - see NEVER_SAFE_BY_SILENCE_NOTE and M3's explicit gate.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from diff_reports import diff_reports, DiffError, STRUCTURAL_ONLY_NOTE  # noqa: E402
from score import compute_stable_key  # noqa: E402
from compare_bytecode import normalize_hex, strip_cbor_metadata, byte_divergence_profile  # noqa: E402

MONITOR_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

NEVER_SAFE_BY_SILENCE_NOTE = (
    "A drift/lifecycle result of MATCH, an empty flagChanges/proxyDrift list, "
    "or a currentStatus of 'resolved' describes only what THIS comparison "
    "could determine from the snapshots/reports it was given. It is never "
    "proof of safety on its own: a NOT_ASSESSED window (see coverageStatus) "
    "means the underlying data was incomplete, and even an ASSESSED window "
    "only covers the specific fields this module compares - it says nothing "
    "about state or code paths outside that scope."
)

TEMPORAL_DRIFT_NOTE = (
    "flagChanges/bytecodeDrift/proxyDrift describe STRUCTURAL differences "
    "between two already-fetched snapshots of the same on-chain target over "
    "time. They are not, by themselves, security conclusions: a bytecode or "
    "proxy-implementation change may be a completely legitimate, intentional "
    "deployment action. Judging significance requires reviewing the "
    "underlying change in context (see SKILL.md Step 6)."
)

STATELESSNESS_NOTE = (
    "This module has no database, no cron/scheduling, no alerting, and no "
    "RPC/network calls. snapshotTimestamp/scan ordering are always supplied "
    "by the caller, never generated here, so output stays a pure, "
    "reproducible function of its inputs. Persisting snapshot/scan history "
    "over time and deciding how to act on a reported change are entirely "
    "the calling workflow's responsibility."
)


class MonitorDiffError(Exception):
    """Raised when an input is too malformed/incomplete to compare (e.g. a
    missing snapshotTimestamp, or the two snapshots plainly describe
    different (address, network) targets). Per-field data gaps within an
    otherwise valid pair are never raised - they are reported as UNAVAILABLE,
    exactly like compare_bytecode.py's own CompareError/verdict split."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MonitorDiffError(message)


def _require_snapshot_timestamp(snapshot: Dict[str, Any], label: str) -> str:
    _require(isinstance(snapshot, dict), "%s must be a JSON object" % label)
    ts = snapshot.get("snapshotTimestamp")
    _require(
        isinstance(ts, str) and ts.strip() != "",
        "%s.snapshotTimestamp is required and must be a non-empty caller-supplied "
        "string (M4: this module never generates timestamps itself)" % label,
    )
    return ts


def _fact(**fields: Any) -> Dict[str, Any]:
    return dict(fields)


# ---------------------------------------------------------------------------
# M1: temporal snapshot drift
# ---------------------------------------------------------------------------

def _normalize_verified(value: Any) -> bool:
    # Identity check, never bool() coercion - same pattern as D-056/ingest_onchain.py.
    return value is True


def _normalize_has_code(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _normalize_address_like(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


# field -> normalizer. adminAddress/ownerAddress are OPTIONAL: only compared
# when BOTH snapshots supply a usable value - never guessed when one is absent.
_SCALAR_FIELD_NORMALIZERS = {
    "verified": _normalize_verified,
    "hasCode": _normalize_has_code,
    "adminAddress": _normalize_address_like,
    "ownerAddress": _normalize_address_like,
}
_OPTIONAL_SCALAR_FIELDS = frozenset(["adminAddress", "ownerAddress"])


def _compute_flag_changes(snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> List[Dict[str, Any]]:
    changes = []
    for field, normalizer in _SCALAR_FIELD_NORMALIZERS.items():
        v1 = normalizer(snapshot1.get(field))
        v2 = normalizer(snapshot2.get(field))
        if field in _OPTIONAL_SCALAR_FIELDS and (v1 is None or v2 is None):
            continue
        if v1 != v2:
            changes.append({"field": field, "from": v1, "to": v2})
    return changes


def _strip_cbor_hex(hex_str: str) -> str:
    return strip_cbor_metadata(bytes.fromhex(hex_str))[0].hex() if hex_str else ""


def _compute_bytecode_drift(runtime1: Any, runtime2: Any) -> Dict[str, Any]:
    norm1, err1 = normalize_hex(runtime1, "runtimeBytecode") if runtime1 is not None else (None, "absent")
    norm2, err2 = normalize_hex(runtime2, "runtimeBytecode") if runtime2 is not None else (None, "absent")
    if err1 or norm1 is None or err2 or norm2 is None:
        return _fact(status="UNAVAILABLE", detail="runtimeBytecode missing or invalid on one or both snapshots")
    stripped1, stripped2 = _strip_cbor_hex(norm1), _strip_cbor_hex(norm2)
    if stripped1 == stripped2:
        return _fact(status="MATCH", detail="runtimeBytecode is byte-identical (after CBOR normalization) across both snapshots")
    return _fact(
        status="MISMATCH",
        detail="runtimeBytecode differs (after CBOR normalization) between the two snapshots - a technical fact, never a vulnerability signal",
        divergenceProfile=byte_divergence_profile(stripped1, stripped2),
    )


def _index_proxies(system_graph: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(system_graph, dict):
        return {}
    proxies = system_graph.get("proxies")
    if not isinstance(proxies, list):
        return {}
    return {p["proxy"]: p for p in proxies if isinstance(p, dict) and isinstance(p.get("proxy"), str)}


def _compute_proxy_drift(snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_proxy1 = _index_proxies(snapshot1.get("systemGraph"))
    by_proxy2 = _index_proxies(snapshot2.get("systemGraph"))
    results: List[Dict[str, Any]] = []
    for proxy_key in sorted(set(by_proxy1) | set(by_proxy2)):
        entry1, entry2 = by_proxy1.get(proxy_key), by_proxy2.get(proxy_key)
        if entry1 is None or entry2 is None:
            results.append(_fact(
                proxyKey=proxy_key, status="UNAVAILABLE",
                detail="this proxy is present in only one of the two snapshots' systemGraph",
            ))
            continue
        resolved1 = entry1.get("status") == "resolved"
        resolved2 = entry2.get("status") == "resolved"
        if not (resolved1 and resolved2):
            results.append(_fact(
                proxyKey=proxy_key, status="UNAVAILABLE",
                detail="proxy resolution status is not 'resolved' on one or both snapshots; implementation cannot be compared",
            ))
            continue
        impl1, impl2 = entry1.get("implementation"), entry2.get("implementation")
        if impl1 == impl2:
            results.append(_fact(proxyKey=proxy_key, status="MATCH", implementationKey=impl1,
                                  detail="resolved implementation key is unchanged across snapshots"))
        else:
            results.append(_fact(
                proxyKey=proxy_key, status="MISMATCH",
                implementationKeyFrom=impl1, implementationKeyTo=impl2,
                detail="resolved implementation key changed between snapshots - a technical fact (e.g. a proxy upgrade), never a vulnerability signal",
            ))
    return results


def _resolve_canonical_chain_id(network: Any) -> Optional[int]:
    """V2.9 corrective fix (D-064).  Canonical NUMERIC chainId only - a
    network NAME/alias is never identity by itself (two snapshots declaring
    "ethereum" and 1 must still be recognized as the SAME chain, never as
    different just because one used a name and the other a number). Reuses
    chains.py's existing PUBLIC resolve_chain() - never re-derives chain
    resolution, never modifies chains.py. Returns None (never guessed) for
    anything that does not resolve to a concrete integer chainId:
    unresolvable/missing network, or a broken/missing chains.json catalog -
    a numeric-but-uncatalogued chainId (isKnown=False) still resolves fine,
    matching this project's established "unknown numeric chain is always
    accepted" rule (it is the NAME/alias resolution, not the catalog
    lookup, that can fail)."""
    import chains
    try:
        chain_id, _canonical_name, _err = chains.resolve_chain(network)
    except chains.ChainsConfigError:
        return None
    return chain_id if isinstance(chain_id, int) and not isinstance(chain_id, bool) else None


def compute_temporal_snapshot_drift(snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> Dict[str, Any]:
    """M1.  snapshot1 is assumed to be the EARLIER snapshot and snapshot2 the
    LATER one, by argument order alone - this module never parses or compares
    snapshotTimestamp VALUES to determine chronology (they are opaque,
    caller-supplied labels), exactly matching diff_reports.py's own v1/v2
    convention (D-054): the caller's declared order is authoritative, never
    inferred.

    Snapshot identity is (chainId, address), BOTH required to match exactly
    (D-064 corrective fix): a same-address-different-chain pair is NEVER
    treated as "the same target over time" - that is a coincidence (or a
    deliberate deterministic multi-chain deployment) at best, and comparing
    it as if temporal would silently reintroduce exactly the cross-chain
    contamination V2.8's chain isolation (D-058) exists to prevent. chainId
    is resolved to its canonical numeric form via chains.py (never guessed);
    an unresolvable/missing chainId on either side means the identity itself
    cannot be established, so no comparison is attempted.

    All results here are STRUCTURAL FACTS, never security verdicts - a
    proxy upgrade or a bytecode change may be a completely legitimate,
    intentional deployment action. Interpreting significance is the
    analysis step's (or a human's) job, exactly like every other comparison
    in this Skill (see STRUCTURAL_ONLY_NOTE/R-C2)."""
    ts1 = _require_snapshot_timestamp(snapshot1, "snapshot1")
    ts2 = _require_snapshot_timestamp(snapshot2, "snapshot2")

    chain_id1 = _resolve_canonical_chain_id(snapshot1.get("network"))
    chain_id2 = _resolve_canonical_chain_id(snapshot2.get("network"))
    _require(
        chain_id1 is not None and chain_id2 is not None,
        "snapshot1.network and snapshot2.network must both resolve to a concrete numeric "
        "chainId - temporal drift requires a resolvable chain identity, never guessed",
    )
    _require(
        chain_id1 == chain_id2,
        "snapshot1 (chainId %r) and snapshot2 (chainId %r) are on DIFFERENT chains - temporal "
        "drift compares the SAME (chainId, address) target over time; a shared address across "
        "different chains is never treated as the same target" % (chain_id1, chain_id2),
    )

    addr1 = _normalize_address_like(snapshot1.get("address"))
    addr2 = _normalize_address_like(snapshot2.get("address"))
    _require(
        addr1 is not None and addr1 == addr2,
        "snapshot1.address and snapshot2.address must both be present and identical - "
        "temporal drift compares the SAME on-chain target over time, never two different addresses",
    )

    return {
        "monitorVersion": MONITOR_VERSION,
        "chainId": chain_id1,
        "address": addr1,
        "snapshot1Timestamp": ts1,
        "snapshot2Timestamp": ts2,
        "flagChanges": _compute_flag_changes(snapshot1, snapshot2),
        "bytecodeDrift": _compute_bytecode_drift(snapshot1.get("runtimeBytecode"), snapshot2.get("runtimeBytecode")),
        "proxyDrift": _compute_proxy_drift(snapshot1, snapshot2),
        "note": TEMPORAL_DRIFT_NOTE,
    }


# ---------------------------------------------------------------------------
# M3: completeness/idempotency gate
# ---------------------------------------------------------------------------

def compute_snapshot_coverage_status(snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> Dict[str, Any]:
    """M3.  A WINDOW/coverage status for the pair as a whole - NOT_ASSESSED
    here is deliberately a DIFFERENT vocabulary from compare_bytecode.py's
    five bytecode verdicts (MATCH/MISMATCH/UNAVAILABLE/INCOMPLETE/UNRESOLVED),
    which remain completely unchanged; this function never touches or is
    consulted by compare_bytecode.py.

    ASSESSED unless either snapshot's caller-supplied completeness.status
    (ingest_onchain.py, D-055) is literally 'failed' - a 'partial' snapshot
    still yields ASSESSED at the window level (the specific fields it is
    missing simply surface as UNAVAILABLE within compute_temporal_snapshot_drift
    itself, never silently as "no change"). completeness is optional input;
    when absent on a snapshot, that snapshot is treated as unconstrained by
    this gate (never guessed as failed, never guessed as complete)."""
    reasons: List[str] = []
    for label, snapshot in (("snapshot1", snapshot1), ("snapshot2", snapshot2)):
        completeness = snapshot.get("completeness") if isinstance(snapshot, dict) else None
        status = completeness.get("status") if isinstance(completeness, dict) else None
        if status == "failed":
            reasons.append("%s.completeness.status is 'failed' - its ingestion was incomplete enough that "
                           "comparisons involving it cannot be trusted" % label)
    if reasons:
        return {"status": "NOT_ASSESSED", "reasons": reasons}
    return {"status": "ASSESSED", "reasons": []}


def compute_snapshot_content_hash(snapshot: Dict[str, Any]) -> str:
    """M3 idempotency key.  Deterministic SHA-256 over the comparison-relevant
    subset of a snapshot - EXCLUDES snapshotTimestamp itself (and any
    completeness/provenance metadata) so that two snapshots taken at
    different times but describing IDENTICAL on-chain state hash identically,
    letting a caller recognize a redundant, no-op monitoring run and skip a
    repeat comparison/alert. Never used to compare across DIFFERENT
    addresses - it is an identity fingerprint of one target's state, not a
    cross-target identity like compare_bytecode.py's metadata-hash grouping."""
    _require(isinstance(snapshot, dict), "snapshot must be a JSON object")
    resolved_proxies = sorted(
        (p.get("proxy"), p.get("implementation"))
        for p in ((snapshot.get("systemGraph") or {}).get("proxies") or [])
        if isinstance(p, dict) and p.get("status") == "resolved"
    )
    relevant = {
        "address": _normalize_address_like(snapshot.get("address")),
        "network": snapshot.get("network"),
        "verified": _normalize_verified(snapshot.get("verified")),
        "hasCode": _normalize_has_code(snapshot.get("hasCode")),
        "runtimeBytecode": (snapshot.get("runtimeBytecode") or "").strip().lower(),
        "adminAddress": _normalize_address_like(snapshot.get("adminAddress")),
        "ownerAddress": _normalize_address_like(snapshot.get("ownerAddress")),
        "resolvedProxies": resolved_proxies,
    }
    canonical = json.dumps(relevant, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def snapshots_are_identical(snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> bool:
    """M3 idempotency check: True when the two snapshots' comparison-relevant
    content hashes match, regardless of their (different) snapshotTimestamp."""
    return compute_snapshot_content_hash(snapshot1) == compute_snapshot_content_hash(snapshot2)


def monitor_snapshot_pair(snapshot1: Dict[str, Any], snapshot2: Dict[str, Any]) -> Dict[str, Any]:
    """Top-level M1+M3 entry point used by the CLI's snapshot-drift mode.
    The drift comparison is ALWAYS attempted regardless of coverageStatus -
    NOT_ASSESSED is an explicit, additional window-level flag layered on
    top, never a reason to skip reporting what CAN be determined (same
    "always report what's known, explicitly flag what isn't" discipline as
    every comparison in compare_bytecode.py)."""
    coverage = compute_snapshot_coverage_status(snapshot1, snapshot2)
    drift = compute_temporal_snapshot_drift(snapshot1, snapshot2)
    identical = snapshots_are_identical(snapshot1, snapshot2)
    return {
        "monitorVersion": MONITOR_VERSION,
        "coverageStatus": coverage,
        "identicalToLastSnapshot": identical,
        "drift": drift,
        "note": NEVER_SAFE_BY_SILENCE_NOTE,
    }


# ---------------------------------------------------------------------------
# M2: finding lifecycle across N scans
# ---------------------------------------------------------------------------

def compute_finding_lifecycle(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """M2.  scans must be given in chronological order (caller-declared,
    never inferred - same convention as M1/diff_reports.py); each entry is
    {"snapshotTimestamp": <caller-supplied str>, "report": <report-schema.json-shaped dict>}.

    Reuses diff_reports.diff_reports() UNCHANGED for every consecutive pair
    (V2.5/D-054) - the only new logic is folding that SEQUENCE of pairwise
    diffs into a per-stableKey history, so a finding that was resolved and
    later reappears is explicitly tagged 'regressed' rather than silently
    re-reported as merely 'new' (which would hide that it had already been
    seen and fixed once). A single scan is valid (the monitoring baseline):
    every finding in it is 'new' as of that scan, nothing can yet be
    resolved or regressed."""
    _require(isinstance(scans, list) and len(scans) >= 1, "scans must be a non-empty array")
    for idx, scan in enumerate(scans):
        _require(isinstance(scan, dict), "scans[%d] must be a JSON object" % idx)
        _require_snapshot_timestamp(scan, "scans[%d]" % idx)
        _require(isinstance(scan.get("report"), dict), "scans[%d].report must be a JSON object" % idx)

    history: Dict[str, List[Dict[str, Any]]] = {}

    def _record(key: str, status: str, timestamp: str) -> None:
        history.setdefault(key, []).append({"status": status, "timestamp": timestamp})

    first_report = scans[0]["report"]
    _require(isinstance(first_report.get("findings"), list), "scans[0].report.findings must be an array")
    for finding in first_report["findings"]:
        _record(compute_stable_key(finding), "new", scans[0]["snapshotTimestamp"])

    for i in range(1, len(scans)):
        step_diff = diff_reports(scans[i - 1]["report"], scans[i]["report"])
        timestamp = scans[i]["snapshotTimestamp"]
        for finding in step_diff["resolvedFindings"]:
            _record(compute_stable_key(finding), "resolved", timestamp)
        for finding in step_diff["newFindings"]:
            key = compute_stable_key(finding)
            was_ever_resolved = any(h["status"] == "resolved" for h in history.get(key, []))
            _record(key, "regressed" if was_ever_resolved else "new", timestamp)

    final_keys = {compute_stable_key(f) for f in scans[-1]["report"].get("findings", [])}
    per_finding: Dict[str, Any] = {}
    for key, events in history.items():
        per_finding[key] = {
            "history": events,
            "currentStatus": "present" if key in final_keys else "resolved",
            "everRegressed": any(e["status"] == "regressed" for e in events),
        }

    return {
        "monitorVersion": MONITOR_VERSION,
        "scanCount": len(scans),
        "perFinding": per_finding,
        "regressedFindingCount": sum(1 for f in per_finding.values() if f["everRegressed"]),
        "note": STRUCTURAL_ONLY_NOTE,
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


def _read_json_file(path: Optional[str]) -> Any:
    """path=None reads stdin instead (V2.11, A-04) - same fallback already
    established by ingest_onchain.py/score.py/validate_report.py/
    render_report.py/compare_bytecode.py. Only "finding-lifecycle" (a single
    JSON input) exposes this; "snapshot-drift" keeps 2 required file
    arguments, which has no single-optional-positional precedent to copy
    without inventing a new convention."""
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MonitorDiffError("%s is not valid JSON: %s" % (path or "stdin", exc)) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monitor_diff.py",
        description=(
            "Continuous on-chain monitoring: temporal snapshot drift and finding "
            "lifecycle across repeated scans (V2.9). Never fetches anything itself; "
            "never stores history; never alerts."
        ),
    )
    subparsers = parser.add_subparsers(dest="monitor_mode", required=True)

    drift_parser = subparsers.add_parser("snapshot-drift", help="Diff two already-fetched on-chain snapshots of the same target over time.")
    drift_parser.add_argument("snapshot1", help="Path to the EARLIER snapshot JSON.")
    drift_parser.add_argument("snapshot2", help="Path to the LATER snapshot JSON.")
    drift_parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    drift_parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")

    lifecycle_parser = subparsers.add_parser("finding-lifecycle", help="Track finding new/resolved/regressed status across an ordered sequence of scans.")
    lifecycle_parser.add_argument("scans", nargs="?", default=None, help="Path to a JSON file containing {\"scans\": [...]} in chronological order. Reads stdin if omitted.")
    lifecycle_parser.add_argument("--out", default=None, help="Write the result to this file instead of stdout.")
    lifecycle_parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        if args.monitor_mode == "snapshot-drift":
            snapshot1 = _read_json_file(args.snapshot1)
            snapshot2 = _read_json_file(args.snapshot2)
            result = monitor_snapshot_pair(snapshot1, snapshot2)
        else:
            payload = _read_json_file(args.scans)
            _require(isinstance(payload, dict) and isinstance(payload.get("scans"), list),
                      "%s must contain a JSON object with a 'scans' array" % (args.scans or "stdin"))
            result = compute_finding_lifecycle(payload["scans"])
    except (MonitorDiffError, DiffError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
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
