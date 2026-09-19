"""Tests for scripts/monitor_diff.py (V2.9 - Continuous Monitoring: temporal
snapshot drift, finding lifecycle, completeness/idempotency gate,
docs/decisiones.md D-063).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import monitor_diff  # noqa: E402
from score import compute_stable_key  # noqa: E402

REFERENCES_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "references"

ADDR = "0x" + "aa" * 20
CBOR = "a26469706673582212200123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef64736f6c6343000814" + "0033"
RT_CODE = "6080604052348015600f57600080fd5b506004361060285760003560e01c"
RT_A = "0x" + RT_CODE + CBOR
RT_A_DIFF = "0x" + RT_CODE + "ff" + CBOR


def make_snapshot(timestamp, **overrides):
    base = {
        "snapshotTimestamp": timestamp,
        "address": ADDR,
        "network": {"chainId": 1},
        "verified": True,
        "hasCode": True,
        "runtimeBytecode": RT_A,
    }
    base.update(overrides)
    return base


def make_finding(finding_id, category="SC01", severity="HIGH", function="f"):
    # compute_stable_key does not use 'id' - two findings must differ in
    # category/severity/locations (not just 'id') to get distinct stableKeys.
    return {
        "id": finding_id,
        "category": category,
        "severity": severity,
        "confidence": "HIGH",
        "locations": [{"file": "A.sol", "contract": "A", "function": function}],
    }


# ---------------------------------------------------------------------------
# M1: temporal snapshot drift
# ---------------------------------------------------------------------------

class TemporalSnapshotDriftTests(unittest.TestCase):
    def test_missing_snapshot_timestamp_raises(self):
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_temporal_snapshot_drift({"address": ADDR}, make_snapshot("t2"))

    def test_blank_snapshot_timestamp_raises(self):
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_temporal_snapshot_drift(make_snapshot("   "), make_snapshot("t2"))

    def test_mismatched_address_raises_never_silently_compared(self):
        # Adversarial: comparing two DIFFERENT on-chain targets as if they
        # were the same one over time must never be silently allowed.
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_temporal_snapshot_drift(
                make_snapshot("t1"), make_snapshot("t2", address="0x" + "bb" * 20)
            )

    # -- D-064 corrective fix: (chainId, address) identity, not address alone --

    def test_same_chain_id_same_address_compares_normally(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", network={"chainId": 1}), make_snapshot("t2", network={"chainId": 1})
        )
        self.assertEqual(drift["chainId"], 1)

    def test_different_chain_id_same_address_is_rejected(self):
        # THE confirmed bug from the final audit: same address on a
        # DIFFERENT chain must never be treated as "the same target over
        # time" - this is exactly the cross-chain contamination V2.8's
        # chain isolation (D-058) exists to prevent.
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_temporal_snapshot_drift(
                make_snapshot("t1", network={"chainId": 1}),
                make_snapshot("t2", network={"chainId": 137}),
            )

    def test_same_chain_id_different_address_is_rejected(self):
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_temporal_snapshot_drift(
                make_snapshot("t1", network={"chainId": 1}),
                make_snapshot("t2", network={"chainId": 1}, address="0x" + "bb" * 20),
            )

    def test_malformed_or_missing_chain_id_yields_no_comparison(self):
        # Adversarial: an unresolvable chainId on either side means identity
        # itself cannot be established - never guessed as "probably the same".
        for bad_network in (None, "not-a-real-chain-name", True, {}, {"chainId": "not-a-number"}):
            with self.subTest(bad_network=bad_network):
                with self.assertRaises(monitor_diff.MonitorDiffError):
                    monitor_diff.compute_temporal_snapshot_drift(
                        make_snapshot("t1", network=bad_network), make_snapshot("t2")
                    )

    def test_chain_name_and_numeric_id_for_the_same_chain_are_recognized_as_identical(self):
        # Network name/alias is NOT a separate identity - only the CANONICAL
        # resolved chainId matters, so "ethereum" and 1 must match.
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", network="ethereum"), make_snapshot("t2", network=1)
        )
        self.assertEqual(drift["chainId"], 1)

    def test_broken_chains_catalog_never_crashes_and_never_guesses_a_match(self):
        from unittest import mock
        import chains
        with mock.patch.object(chains, "load_chains_config", side_effect=chains.ChainsConfigError("broken")):
            with self.assertRaises(monitor_diff.MonitorDiffError):
                monitor_diff.compute_temporal_snapshot_drift(make_snapshot("t1"), make_snapshot("t2"))

    def test_no_change_is_match_with_empty_flag_changes(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(make_snapshot("t1"), make_snapshot("t2"))
        self.assertEqual(drift["bytecodeDrift"]["status"], "MATCH")
        self.assertEqual(drift["flagChanges"], [])
        self.assertEqual(drift["proxyDrift"], [])

    def test_verified_flip_is_recorded_as_a_fact(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", verified=True), make_snapshot("t2", verified=False)
        )
        self.assertIn({"field": "verified", "from": True, "to": False}, drift["flagChanges"])

    def test_verified_coercion_protection_matches_d056(self):
        # Adversarial: string "true"/"false" must never be treated as a
        # real boolean flip - same discipline as D-056.
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", verified="true"), make_snapshot("t2", verified="false")
        )
        self.assertEqual(drift["flagChanges"], [])  # both normalize to False -> no change

    def test_has_code_flip_is_recorded(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", hasCode=True), make_snapshot("t2", hasCode=False)
        )
        self.assertIn({"field": "hasCode", "from": True, "to": False}, drift["flagChanges"])

    def test_bytecode_upgrade_drift_is_mismatch_with_divergence_profile(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1"), make_snapshot("t2", runtimeBytecode=RT_A_DIFF)
        )
        self.assertEqual(drift["bytecodeDrift"]["status"], "MISMATCH")
        self.assertIn("divergenceProfile", drift["bytecodeDrift"])
        self.assertIn("never a vulnerability signal", drift["bytecodeDrift"]["detail"].lower())

    def test_bytecode_match_never_carries_a_divergence_profile(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(make_snapshot("t1"), make_snapshot("t2"))
        self.assertNotIn("divergenceProfile", drift["bytecodeDrift"])

    def test_missing_runtime_bytecode_is_unavailable_never_guessed(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", runtimeBytecode=None), make_snapshot("t2")
        )
        self.assertEqual(drift["bytecodeDrift"]["status"], "UNAVAILABLE")

    def test_proxy_implementation_upgrade_is_mismatch(self):
        sg1 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I1.sol#Impl"}]}
        sg2 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I2.sol#Impl"}]}
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", systemGraph=sg1), make_snapshot("t2", systemGraph=sg2)
        )
        self.assertEqual(drift["proxyDrift"][0]["status"], "MISMATCH")
        self.assertEqual(drift["proxyDrift"][0]["implementationKeyFrom"], "onchain:/1/0xaa/I1.sol#Impl")
        self.assertEqual(drift["proxyDrift"][0]["implementationKeyTo"], "onchain:/1/0xaa/I2.sol#Impl")

    def test_proxy_implementation_unchanged_is_match(self):
        sg = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I1.sol#Impl"}]}
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", systemGraph=sg), make_snapshot("t2", systemGraph=sg)
        )
        self.assertEqual(drift["proxyDrift"][0]["status"], "MATCH")

    def test_proxy_unresolved_on_either_side_is_unavailable(self):
        sg1 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "unresolved", "implementation": None}]}
        sg2 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I1.sol#Impl"}]}
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", systemGraph=sg1), make_snapshot("t2", systemGraph=sg2)
        )
        self.assertEqual(drift["proxyDrift"][0]["status"], "UNAVAILABLE")

    def test_proxy_present_only_on_one_side_is_unavailable_never_guessed(self):
        sg1 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I1.sol#Impl"}]}
        sg2 = {"proxies": []}
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", systemGraph=sg1), make_snapshot("t2", systemGraph=sg2)
        )
        self.assertEqual(drift["proxyDrift"][0]["status"], "UNAVAILABLE")

    def test_admin_address_only_compared_when_both_sides_supply_it(self):
        # Adversarial: one-sided data must never be guessed as "unchanged".
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", adminAddress="0x" + "11" * 20), make_snapshot("t2")
        )
        self.assertFalse(any(c["field"] == "adminAddress" for c in drift["flagChanges"]))

    def test_admin_address_change_detected_when_both_supplied(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", adminAddress="0x" + "11" * 20),
            make_snapshot("t2", adminAddress="0x" + "22" * 20),
        )
        self.assertTrue(any(c["field"] == "adminAddress" for c in drift["flagChanges"]))

    def test_admin_address_same_case_insensitive_is_no_change(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", adminAddress="0x" + "AA" * 20),
            make_snapshot("t2", adminAddress="0x" + "aa" * 20),
        )
        self.assertFalse(any(c["field"] == "adminAddress" for c in drift["flagChanges"]))

    def test_owner_address_change_detected_independently_of_admin(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1", ownerAddress="0x" + "11" * 20),
            make_snapshot("t2", ownerAddress="0x" + "22" * 20),
        )
        self.assertTrue(any(c["field"] == "ownerAddress" for c in drift["flagChanges"]))

    def test_never_emits_findings_or_signals(self):
        drift = monitor_diff.compute_temporal_snapshot_drift(
            make_snapshot("t1"), make_snapshot("t2", runtimeBytecode=RT_A_DIFF)
        )
        self.assertNotIn("findings", drift)
        self.assertNotIn("signals", drift)
        self.assertNotIn("vulnerabilities", drift)


# ---------------------------------------------------------------------------
# M3: completeness/idempotency gate
# ---------------------------------------------------------------------------

class CoverageAndIdempotencyTests(unittest.TestCase):
    def test_failed_snapshot_yields_not_assessed_window(self):
        s1 = make_snapshot("t1", completeness={"status": "failed", "reasons": [{"code": "X", "detail": "y"}]})
        result = monitor_diff.monitor_snapshot_pair(s1, make_snapshot("t2"))
        self.assertEqual(result["coverageStatus"]["status"], "NOT_ASSESSED")

    def test_not_assessed_never_skips_the_drift_computation(self):
        # Diego's explicit rule: NOT_ASSESSED must never mean "no change" by
        # omission - the comparison itself is still always attempted.
        s1 = make_snapshot("t1", completeness={"status": "failed", "reasons": []})
        result = monitor_diff.monitor_snapshot_pair(s1, make_snapshot("t2", runtimeBytecode=RT_A_DIFF))
        self.assertEqual(result["coverageStatus"]["status"], "NOT_ASSESSED")
        self.assertEqual(result["drift"]["bytecodeDrift"]["status"], "MISMATCH")

    def test_partial_snapshot_still_assessed_at_window_level(self):
        s1 = make_snapshot("t1", completeness={"status": "partial", "reasons": []})
        result = monitor_diff.monitor_snapshot_pair(s1, make_snapshot("t2"))
        self.assertEqual(result["coverageStatus"]["status"], "ASSESSED")

    def test_absent_completeness_is_never_guessed_as_failed(self):
        result = monitor_diff.monitor_snapshot_pair(make_snapshot("t1"), make_snapshot("t2"))
        self.assertEqual(result["coverageStatus"]["status"], "ASSESSED")

    def test_not_assessed_never_becomes_a_sixth_bytecode_verdict(self):
        # R-C1 (compare_bytecode.py): exactly MATCH/MISMATCH/UNAVAILABLE/
        # INCOMPLETE/UNRESOLVED. NOT_ASSESSED must appear ONLY as coverageStatus.
        s1 = make_snapshot("t1", completeness={"status": "failed", "reasons": []})
        result = monitor_diff.monitor_snapshot_pair(s1, make_snapshot("t2"))
        self.assertIn(result["drift"]["bytecodeDrift"]["status"], ("MATCH", "MISMATCH", "UNAVAILABLE"))
        self.assertNotEqual(result["drift"]["bytecodeDrift"]["status"], "NOT_ASSESSED")

    def test_identical_snapshots_are_recognized_despite_different_timestamps(self):
        result = monitor_diff.monitor_snapshot_pair(make_snapshot("t1"), make_snapshot("t2"))
        self.assertTrue(result["identicalToLastSnapshot"])

    def test_content_change_breaks_idempotency(self):
        result = monitor_diff.monitor_snapshot_pair(make_snapshot("t1"), make_snapshot("t2", verified=False))
        self.assertFalse(result["identicalToLastSnapshot"])

    def test_content_hash_ignores_snapshot_timestamp_itself(self):
        h1 = monitor_diff.compute_snapshot_content_hash(make_snapshot("t1"))
        h2 = monitor_diff.compute_snapshot_content_hash(make_snapshot("completely-different-label"))
        self.assertEqual(h1, h2)

    def test_content_hash_changes_with_proxy_resolution(self):
        sg1 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I1.sol#Impl"}]}
        sg2 = {"proxies": [{"proxy": "onchain:/1/0xaa/P.sol#P", "status": "resolved", "implementation": "onchain:/1/0xaa/I2.sol#Impl"}]}
        h1 = monitor_diff.compute_snapshot_content_hash(make_snapshot("t1", systemGraph=sg1))
        h2 = monitor_diff.compute_snapshot_content_hash(make_snapshot("t1", systemGraph=sg2))
        self.assertNotEqual(h1, h2)


# ---------------------------------------------------------------------------
# M2: finding lifecycle
# ---------------------------------------------------------------------------

class FindingLifecycleTests(unittest.TestCase):
    def test_single_scan_baseline_is_new_and_present(self):
        report = {"findings": [make_finding("f1")], "categoryCoverage": []}
        lifecycle = monitor_diff.compute_finding_lifecycle([{"snapshotTimestamp": "t1", "report": report}])
        key = compute_stable_key(make_finding("f1"))
        self.assertEqual(lifecycle["perFinding"][key]["history"][0]["status"], "new")
        self.assertEqual(lifecycle["perFinding"][key]["currentStatus"], "present")
        self.assertFalse(lifecycle["perFinding"][key]["everRegressed"])

    def test_resolved_then_regressed_is_tagged_regressed_not_new(self):
        # Adversarial (the exact capability Diego required): a finding must
        # never be silently re-reported as merely "new" after reappearing.
        key = compute_stable_key(make_finding("f1"))
        scans = [
            {"snapshotTimestamp": "t1", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
            {"snapshotTimestamp": "t2", "report": {"findings": [], "categoryCoverage": []}},
            {"snapshotTimestamp": "t3", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
        ]
        lifecycle = monitor_diff.compute_finding_lifecycle(scans)
        statuses = [h["status"] for h in lifecycle["perFinding"][key]["history"]]
        self.assertEqual(statuses, ["new", "resolved", "regressed"])
        self.assertTrue(lifecycle["perFinding"][key]["everRegressed"])
        self.assertEqual(lifecycle["perFinding"][key]["currentStatus"], "present")
        self.assertEqual(lifecycle["regressedFindingCount"], 1)

    def test_resolved_and_never_returning_stays_resolved(self):
        key = compute_stable_key(make_finding("f1"))
        scans = [
            {"snapshotTimestamp": "t1", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
            {"snapshotTimestamp": "t2", "report": {"findings": [], "categoryCoverage": []}},
        ]
        lifecycle = monitor_diff.compute_finding_lifecycle(scans)
        self.assertEqual(lifecycle["perFinding"][key]["currentStatus"], "resolved")
        self.assertFalse(lifecycle["perFinding"][key]["everRegressed"])
        self.assertEqual(lifecycle["regressedFindingCount"], 0)

    def test_genuinely_new_finding_never_confused_with_regressed(self):
        # Negative control: a finding that was NEVER seen before, appearing
        # for the first time at a later scan, must stay "new" - regression
        # requires a PRIOR "resolved" event for that exact stableKey.
        key_f2 = compute_stable_key(make_finding("f2", function="g"))
        scans = [
            {"snapshotTimestamp": "t1", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
            {"snapshotTimestamp": "t2", "report": {"findings": [make_finding("f1"), make_finding("f2", function="g")], "categoryCoverage": []}},
        ]
        lifecycle = monitor_diff.compute_finding_lifecycle(scans)
        self.assertEqual(lifecycle["perFinding"][key_f2]["history"][0]["status"], "new")
        self.assertFalse(lifecycle["perFinding"][key_f2]["everRegressed"])

    def test_present_across_all_scans_has_single_new_event(self):
        key = compute_stable_key(make_finding("f1"))
        scans = [
            {"snapshotTimestamp": "t1", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
            {"snapshotTimestamp": "t2", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
            {"snapshotTimestamp": "t3", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}},
        ]
        lifecycle = monitor_diff.compute_finding_lifecycle(scans)
        self.assertEqual(len(lifecycle["perFinding"][key]["history"]), 1)
        self.assertEqual(lifecycle["perFinding"][key]["currentStatus"], "present")

    def test_missing_snapshot_timestamp_on_a_scan_raises(self):
        scans = [{"report": {"findings": [], "categoryCoverage": []}}]
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_finding_lifecycle(scans)

    def test_empty_scans_list_raises(self):
        with self.assertRaises(monitor_diff.MonitorDiffError):
            monitor_diff.compute_finding_lifecycle([])

    def test_malformed_report_raises_diff_error_via_reused_diff_reports(self):
        # Adversarial: a scan whose report has no 'findings' array must
        # surface diff_reports.py's OWN existing validation, never crash
        # with an unrelated exception.
        from diff_reports import DiffError
        scans = [
            {"snapshotTimestamp": "t1", "report": {"findings": [], "categoryCoverage": []}},
            {"snapshotTimestamp": "t2", "report": {"categoryCoverage": []}},  # no findings key
        ]
        with self.assertRaises(DiffError):
            monitor_diff.compute_finding_lifecycle(scans)

    def test_never_emits_a_new_finding_or_signal_itself(self):
        scans = [{"snapshotTimestamp": "t1", "report": {"findings": [make_finding("f1")], "categoryCoverage": []}}]
        lifecycle = monitor_diff.compute_finding_lifecycle(scans)
        self.assertNotIn("findings", lifecycle)
        self.assertNotIn("signals", lifecycle)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = monitor_diff.main(argv)
        return exit_code, stdout.getvalue()

    def test_snapshot_drift_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "s1.json"
            p2 = Path(tmp) / "s2.json"
            p1.write_text(json.dumps(make_snapshot("t1")), encoding="utf-8")
            p2.write_text(json.dumps(make_snapshot("t2", verified=False)), encoding="utf-8")
            exit_code, out = self._run_cli(["snapshot-drift", str(p1), str(p2)])
            self.assertEqual(exit_code, monitor_diff.EXIT_OK)
            result = json.loads(out)
            self.assertEqual(result["coverageStatus"]["status"], "ASSESSED")

    def test_finding_lifecycle_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "scans.json"
            payload = {"scans": [{"snapshotTimestamp": "t1", "report": {"findings": [], "categoryCoverage": []}}]}
            p.write_text(json.dumps(payload), encoding="utf-8")
            exit_code, out = self._run_cli(["finding-lifecycle", str(p)])
            self.assertEqual(exit_code, monitor_diff.EXIT_OK)
            result = json.loads(out)
            self.assertEqual(result["scanCount"], 1)

    def test_malformed_json_yields_clean_error_envelope_never_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            good = Path(tmp) / "good.json"
            good.write_text(json.dumps(make_snapshot("t2")), encoding="utf-8")
            exit_code, out = self._run_cli(["snapshot-drift", str(bad), str(good)])
            self.assertEqual(exit_code, monitor_diff.EXIT_FAILED)
            envelope = json.loads(out)
            self.assertFalse(envelope["ok"])
            self.assertIn("error", envelope)

    def test_mismatched_address_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "s1.json"
            p2 = Path(tmp) / "s2.json"
            p1.write_text(json.dumps(make_snapshot("t1")), encoding="utf-8")
            p2.write_text(json.dumps(make_snapshot("t2", address="0x" + "bb" * 20)), encoding="utf-8")
            exit_code, out = self._run_cli(["snapshot-drift", str(p1), str(p2)])
            self.assertEqual(exit_code, monitor_diff.EXIT_FAILED)
            self.assertFalse(json.loads(out)["ok"])


# ---------------------------------------------------------------------------
# Schema drift
# ---------------------------------------------------------------------------

class SchemaDriftTests(unittest.TestCase):
    def test_snapshot_pair_result_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "monitor-diff-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["snapshotPairResult"]["required"])
        result = monitor_diff.monitor_snapshot_pair(make_snapshot("t1"), make_snapshot("t2"))
        self.assertEqual(required, set(result.keys()))

    def test_temporal_drift_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "monitor-diff-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["temporalDrift"]["required"])
        drift = monitor_diff.compute_temporal_snapshot_drift(make_snapshot("t1"), make_snapshot("t2"))
        self.assertEqual(required, set(drift.keys()))

    def test_finding_lifecycle_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "monitor-diff-schema.json").read_text(encoding="utf-8"))
        required = set(schema["definitions"]["findingLifecycleResult"]["required"])
        report = {"findings": [], "categoryCoverage": []}
        lifecycle = monitor_diff.compute_finding_lifecycle([{"snapshotTimestamp": "t1", "report": report}])
        self.assertEqual(required, set(lifecycle.keys()))


if __name__ == "__main__":
    unittest.main()
