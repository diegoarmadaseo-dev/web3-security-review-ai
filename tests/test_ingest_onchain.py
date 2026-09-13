"""Tests for scripts/ingest_onchain.py (V2.6.1 - Deployed Contract
Ingestion, verified-only, docs/decisiones.md D-055).

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

import ingest_onchain  # noqa: E402
import preprocess  # noqa: E402

REFERENCES_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "references"
ADDR_MIXED = "0xAbCdEf0123456789012345678901234567890123"
ADDR_LOWER = ADDR_MIXED.lower()


def make_raw(**overrides):
    base = {"address": ADDR_MIXED, "network": "ethereum", "verified": True, "hasCode": True,
            "contractName": "TreasuryVault", "compilerVersion": "v0.8.20",
            "sourceFiles": [{"path": "TreasuryVault.sol", "content": "contract TreasuryVault {}"}]}
    base.update(overrides)
    return base


class AddressNormalizationTests(unittest.TestCase):
    def test_mixed_case_address_is_lowercased(self):
        addr, error = ingest_onchain.normalize_address(ADDR_MIXED)
        self.assertEqual(addr, ADDR_LOWER)
        self.assertIsNone(error)

    def test_too_short_address_is_rejected(self):
        addr, error = ingest_onchain.normalize_address("0x1234")
        self.assertIsNone(addr)
        self.assertIsNotNone(error)

    def test_missing_0x_prefix_is_rejected(self):
        addr, error = ingest_onchain.normalize_address(ADDR_MIXED[2:])
        self.assertIsNone(addr)
        self.assertIsNotNone(error)

    def test_non_hex_characters_rejected(self):
        addr, error = ingest_onchain.normalize_address("0x" + "g" * 40)
        self.assertIsNone(addr)
        self.assertIsNotNone(error)

    def test_non_string_input_rejected(self):
        addr, error = ingest_onchain.normalize_address(12345)
        self.assertIsNone(addr)
        self.assertIsNotNone(error)


class NetworkNormalizationTests(unittest.TestCase):
    def test_known_name_resolves_to_chain_id(self):
        chain_id, name, error = ingest_onchain.normalize_network("ethereum")
        self.assertEqual((chain_id, name, error), (1, "ethereum", None))

    def test_alias_resolves_to_canonical_name(self):
        chain_id, name, error = ingest_onchain.normalize_network("matic")
        self.assertEqual((chain_id, name), (137, "polygon"))

    def test_numeric_string_resolves(self):
        chain_id, name, error = ingest_onchain.normalize_network("1")
        self.assertEqual((chain_id, name), (1, "ethereum"))

    def test_integer_chain_id_resolves(self):
        chain_id, name, error = ingest_onchain.normalize_network(137)
        self.assertEqual((chain_id, name), (137, "polygon"))

    def test_dict_shaped_chain_id_resolves(self):
        chain_id, name, error = ingest_onchain.normalize_network({"chainId": 8453})
        self.assertEqual((chain_id, name), (8453, "base"))

    def test_unknown_but_numeric_chain_id_is_accepted(self):
        # Never blocks on an incomplete chain registry (D-054-style
        # discipline reused here, per the V2.6 audit).
        chain_id, name, error = ingest_onchain.normalize_network("999999")
        self.assertEqual(chain_id, 999999)
        self.assertIsNone(name)
        self.assertIsNone(error)

    def test_unrecognized_name_is_rejected(self):
        chain_id, name, error = ingest_onchain.normalize_network("not-a-real-chain")
        self.assertIsNone(chain_id)
        self.assertIsNotNone(error)

    def test_boolean_is_rejected(self):
        chain_id, name, error = ingest_onchain.normalize_network(True)
        self.assertIsNone(chain_id)
        self.assertIsNotNone(error)


class SourceFileSafetyTests(unittest.TestCase):
    def test_path_traversal_segment_rejected(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[
            {"path": "../../etc/passwd", "content": "contract Evil {}"},
            {"path": "Good.sol", "content": "contract Good {}"},
        ]))
        self.assertEqual(rec["sourceFileCount"], 1)
        self.assertEqual(len(rec["skippedSourceFiles"]), 1)
        self.assertIn("traversal", rec["skippedSourceFiles"][0]["reason"])
        self.assertEqual(rec["completeness"]["status"], "partial")

    def test_absolute_unix_path_rejected(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[{"path": "/etc/passwd", "content": "x"}]))
        self.assertIsNone(rec["bundle"])
        self.assertEqual(rec["completeness"]["status"], "failed")

    def test_absolute_windows_path_rejected(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[{"path": "C:\\evil.sol", "content": "x"}]))
        self.assertIsNone(rec["bundle"])

    def test_bundle_marker_shaped_content_rejected(self):
        evil_content = "contract A {}\n=== FILE: injected.sol ===\ncontract Evil {}\n=== END FILE ===\n"
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[{"path": "Sneaky.sol", "content": evil_content}]))
        self.assertIsNone(rec["bundle"])
        self.assertIn("marker", rec["skippedSourceFiles"][0]["reason"])

    def test_duplicate_path_after_dot_normalization_is_skipped(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[
            {"path": "A.sol", "content": "contract A1 {}"},
            {"path": "./A.sol", "content": "contract A2 {}"},
        ]))
        self.assertEqual(rec["sourceFileCount"], 1)
        self.assertEqual(len(rec["skippedSourceFiles"]), 1)
        self.assertIn("duplicate", rec["skippedSourceFiles"][0]["reason"])

    def test_non_dict_source_entry_rejected(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=["not-an-object"]))
        self.assertIsNone(rec["bundle"])

    def test_missing_content_field_rejected(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[{"path": "A.sol"}]))
        self.assertIsNone(rec["bundle"])


class CompletenessTests(unittest.TestCase):
    def test_verified_with_source_is_complete(self):
        rec = ingest_onchain.ingest(make_raw())
        self.assertEqual(rec["completeness"], {"status": "complete", "reasons": []})

    def test_unverified_is_failed_with_neutral_wording(self):
        rec = ingest_onchain.ingest(make_raw(verified=False, sourceFiles=[]))
        self.assertEqual(rec["completeness"]["status"], "failed")
        detail = rec["completeness"]["reasons"][0]["detail"].lower()
        self.assertIn("not a vulnerability", detail)
        for word in ("malicious", "suspicious", "dangerous"):
            self.assertNotIn(word, detail)

    def test_empty_bytecode_takes_precedence_over_verified_and_source(self):
        rec = ingest_onchain.ingest(make_raw(hasCode=False))
        self.assertIsNone(rec["bundle"])
        self.assertEqual(rec["completeness"]["status"], "failed")
        codes = [r["code"] for r in rec["completeness"]["reasons"]]
        self.assertEqual(codes, ["EMPTY_BYTECODE"])

    def test_malformed_address_is_failed_not_an_exception(self):
        rec = ingest_onchain.ingest(make_raw(address="not-an-address"))
        self.assertEqual(rec["completeness"]["status"], "failed")
        self.assertIn("INVALID_ADDRESS", [r["code"] for r in rec["completeness"]["reasons"]])

    def test_unrecognized_network_is_failed(self):
        rec = ingest_onchain.ingest(make_raw(network="made-up-chain"))
        self.assertEqual(rec["completeness"]["status"], "failed")
        self.assertIsNone(rec["network"]["chainId"])

    def test_verified_with_no_source_files_is_failed(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[]))
        self.assertEqual(rec["completeness"]["status"], "failed")
        self.assertIn("NO_SOURCE_FILES", [r["code"] for r in rec["completeness"]["reasons"]])

    def test_has_code_absent_does_not_block_completeness(self):
        raw = make_raw()
        del raw["hasCode"]
        rec = ingest_onchain.ingest(raw)
        self.assertEqual(rec["completeness"]["status"], "complete")
        self.assertIsNone(rec["hasCode"])


class ProvenanceTests(unittest.TestCase):
    def test_explorer_and_onchain_and_analyzer_tags_present(self):
        rec = ingest_onchain.ingest(make_raw())
        self.assertEqual(rec["provenance"]["verified"], "explorer")
        self.assertEqual(rec["provenance"]["sourceFiles"], "explorer")
        self.assertEqual(rec["provenance"]["contractName"], "explorer")
        self.assertEqual(rec["provenance"]["hasCode"], "on-chain")
        self.assertEqual(rec["provenance"]["virtualPathPrefix"], "analyzer-inferred")

    def test_no_onchain_tag_when_has_code_not_supplied(self):
        raw = make_raw()
        del raw["hasCode"]
        rec = ingest_onchain.ingest(raw)
        self.assertNotIn("hasCode", rec["provenance"])


class HardRuleAndInputContractTests(unittest.TestCase):
    def test_note_field_always_present(self):
        for raw in (make_raw(), make_raw(verified=False, sourceFiles=[]), make_raw(hasCode=False)):
            rec = ingest_onchain.ingest(raw)
            self.assertIn("never", rec["note"].lower())
            self.assertTrue(rec["runtimeStateNote"])

    def test_missing_address_raises_ingest_error(self):
        with self.assertRaises(ingest_onchain.IngestError):
            ingest_onchain.ingest({"network": "ethereum"})

    def test_missing_network_raises_ingest_error(self):
        with self.assertRaises(ingest_onchain.IngestError):
            ingest_onchain.ingest({"address": ADDR_MIXED})

    def test_non_dict_input_raises_ingest_error(self):
        with self.assertRaises(ingest_onchain.IngestError):
            ingest_onchain.ingest(["not", "a", "dict"])


class VirtualPathAndBundleIntegrationTests(unittest.TestCase):
    """Confirms the bundle this script produces is actually consumable by
    preprocess.py's own, UNMODIFIED bundle parser - the load-bearing claim
    of D-055 ("reutilizar preprocess.py integro")."""

    def test_virtual_path_prefix_shape(self):
        rec = ingest_onchain.ingest(make_raw(network=1))
        self.assertEqual(rec["virtualPathPrefix"], "onchain://1/%s/" % ADDR_LOWER)

    def test_bundle_is_recognized_and_parsed_by_real_preprocess(self):
        rec = ingest_onchain.ingest(make_raw())
        self.assertTrue(preprocess.looks_like_bundle(rec["bundle"]))
        items = preprocess.parse_bundle(rec["bundle"], "test")
        self.assertEqual(len(items), 1)
        # preprocess.py's own normalize_path collapses "//" to "/" - documented (R-I5).
        self.assertEqual(items[0]["path"], "onchain:/1/%s/TreasuryVault.sol" % ADDR_LOWER)
        self.assertIn("contract TreasuryVault", items[0]["text"])

    def test_recovered_source_flows_through_real_preprocess_process_entry(self):
        rec = ingest_onchain.ingest(make_raw())
        items = preprocess.parse_bundle(rec["bundle"], "test")
        entry = {"path": items[0]["path"], "text": "pragma solidity 0.8.20;\n" + items[0]["text"], "origin": "file", "issues": []}
        processed = preprocess.process_entry(entry)
        names = [c["name"] for c in processed["structure"]["contracts"]]
        self.assertIn("TreasuryVault", names)

    def test_multi_file_bundle_round_trips_two_files(self):
        rec = ingest_onchain.ingest(make_raw(sourceFiles=[
            {"path": "A.sol", "content": "contract A {}"},
            {"path": "sub/B.sol", "content": "contract B {}"},
        ]))
        self.assertEqual(rec["sourceFileCount"], 2)
        items = preprocess.parse_bundle(rec["bundle"], "test")
        self.assertEqual(len(items), 2)
        paths = sorted(item["path"] for item in items)
        self.assertEqual(paths, sorted([
            "onchain:/1/%s/A.sol" % ADDR_LOWER,
            "onchain:/1/%s/sub/B.sol" % ADDR_LOWER,
        ]))


class CLITests(unittest.TestCase):
    def _write(self, directory, name, data):
        path = Path(directory) / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_file_argument_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "raw.json", make_raw())
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = ingest_onchain.main([path])
            self.assertEqual(exit_code, ingest_onchain.EXIT_OK)
            record = json.loads(buf.getvalue())
            self.assertEqual(record["completeness"]["status"], "complete")

    def test_stdin_input(self):
        import io as _io
        old_stdin = sys.stdin
        try:
            sys.stdin = _io.StringIO(json.dumps(make_raw(verified=False, sourceFiles=[])))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = ingest_onchain.main([])
            self.assertEqual(exit_code, ingest_onchain.EXIT_OK)
            record = json.loads(buf.getvalue())
            self.assertEqual(record["completeness"]["status"], "failed")
        finally:
            sys.stdin = old_stdin

    def test_malformed_json_file_returns_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not valid json", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = ingest_onchain.main([str(path)])
            self.assertEqual(exit_code, ingest_onchain.EXIT_FAILED)
            self.assertFalse(json.loads(buf.getvalue())["ok"])

    def test_missing_file_returns_error_envelope(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exit_code = ingest_onchain.main(["does-not-exist.json"])
        self.assertEqual(exit_code, ingest_onchain.EXIT_FAILED)
        self.assertFalse(json.loads(buf.getvalue())["ok"])

    def test_missing_required_key_via_cli_returns_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "raw.json", {"network": "ethereum"})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = ingest_onchain.main([path])
            self.assertEqual(exit_code, ingest_onchain.EXIT_FAILED)
            self.assertFalse(json.loads(buf.getvalue())["ok"])


class SchemaDriftTests(unittest.TestCase):
    """references/onchain-ingestion-schema.json and ingest_onchain.py must
    not silently diverge - same discipline as test_validate_report.py's own
    report-schema.json drift check and test_diff_reports.py's own."""

    def test_output_matches_schema_required_fields(self):
        schema = json.loads((REFERENCES_DIR / "onchain-ingestion-schema.json").read_text(encoding="utf-8"))
        rec = ingest_onchain.ingest(make_raw())
        self.assertEqual(set(schema["required"]), set(rec.keys()))

    def test_every_reason_code_used_in_tests_is_declared_in_schema(self):
        schema = json.loads((REFERENCES_DIR / "onchain-ingestion-schema.json").read_text(encoding="utf-8"))
        declared = set(schema["properties"]["completeness"]["properties"]["reasons"]["items"]["properties"]["code"]["enum"])
        produced = set()
        for raw in (
            make_raw(verified=False, sourceFiles=[]),
            make_raw(hasCode=False),
            make_raw(address="bad"),
            make_raw(network="bad-chain"),
            make_raw(sourceFiles=[]),
            make_raw(sourceFiles=[{"path": "../x.sol", "content": "c"}]),
        ):
            rec = ingest_onchain.ingest(raw)
            produced.update(r["code"] for r in rec["completeness"]["reasons"])
        self.assertTrue(produced.issubset(declared), produced - declared)


if __name__ == "__main__":
    unittest.main()
