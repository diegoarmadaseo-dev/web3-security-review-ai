"""Tests for scripts/compare_bytecode.py (V2.7 - Source vs Deployed Bytecode,
docs/decisiones.md D-057).

Run from repository root: python -m unittest
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

import compare_bytecode  # noqa: E402

REFERENCES_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "references"

ADDR_MIXED = "0xAbCdEf0123456789012345678901234567890123"
ADDR_LOWER = ADDR_MIXED.lower()

# Realistic CBOR trailer (0xa2 = fixmap(2), keys "ipfs" and "solc", followed by 2-byte length 0x0033)
# 51 bytes of CBOR body (starts with 0xa2) + 2 bytes length (0x0033 = 51)
SAMPLE_CBOR_MAP_HEX = "a26469706673582212200123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef64736f6c6343000814"
SAMPLE_CBOR_HEX = SAMPLE_CBOR_MAP_HEX + "0033"
SAMPLE_RUNTIME_CODE_HEX = "6080604052348015600f57600080fd5b506004361060285760003560e01c"


def make_raw_record(**overrides):
    base = {
        "address": ADDR_LOWER,
        "network": "ethereum",
        "verified": True,
        "hasCode": True,
        "sourceBytecode": "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX,
        "runtimeBytecode": "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX,
    }
    base.update(overrides)
    return base


class HexNormalizationTests(unittest.TestCase):
    def test_normalize_valid_hex_with_0x_prefix(self):
        norm, err = compare_bytecode.normalize_hex("0xAbCd", "field")
        self.assertEqual(norm, "abcd")
        self.assertIsNone(err)

    def test_normalize_valid_hex_without_prefix(self):
        norm, err = compare_bytecode.normalize_hex("1234ef", "field")
        self.assertEqual(norm, "1234ef")
        self.assertIsNone(err)

    def test_normalize_empty_strings(self):
        self.assertEqual(compare_bytecode.normalize_hex("", "field"), ("", None))
        self.assertEqual(compare_bytecode.normalize_hex("0x", "field"), ("", None))
        self.assertEqual(compare_bytecode.normalize_hex("0", "field"), ("", None))

    def test_normalize_rejects_odd_length(self):
        norm, err = compare_bytecode.normalize_hex("0x123", "field")
        self.assertIsNone(norm)
        self.assertIn("odd hex length", err)

    def test_normalize_rejects_non_hex(self):
        norm, err = compare_bytecode.normalize_hex("0x123g", "field")
        self.assertIsNone(norm)
        self.assertIn("non-hex", err)

    def test_normalize_rejects_non_string(self):
        norm, err = compare_bytecode.normalize_hex(12345, "field")
        self.assertIsNone(norm)
        self.assertIn("must be a string", err)

    def test_normalize_rejects_none(self):
        norm, err = compare_bytecode.normalize_hex(None, "field")
        self.assertIsNone(norm)
        self.assertIn("absent or null", err)


class CborStrippingTests(unittest.TestCase):
    def test_strip_real_solidity_cbor(self):
        raw_bytes = bytes.fromhex(SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX)
        stripped, was_stripped, detail = compare_bytecode.strip_cbor_metadata(raw_bytes)
        self.assertTrue(was_stripped)
        self.assertEqual(stripped.hex(), SAMPLE_RUNTIME_CODE_HEX)
        self.assertIn("stripped 53 bytes", detail)

    def test_strip_too_short_bytecode(self):
        raw_bytes = bytes.fromhex("1234")
        stripped, was_stripped, detail = compare_bytecode.strip_cbor_metadata(raw_bytes)
        self.assertFalse(was_stripped)
        self.assertEqual(stripped, raw_bytes)
        self.assertIn("too short", detail)

    def test_strip_zero_declared_length(self):
        raw_bytes = bytes.fromhex(SAMPLE_RUNTIME_CODE_HEX + "0000")
        stripped, was_stripped, detail = compare_bytecode.strip_cbor_metadata(raw_bytes)
        self.assertFalse(was_stripped)
        self.assertEqual(stripped, raw_bytes)
        self.assertIn("declared CBOR length is zero", detail)

    def test_strip_excessive_declared_length(self):
        # declared length 0x0100 (256 bytes) exceeds length of 10-byte bytecode
        raw_bytes = bytes.fromhex("6080604052348015" + "0100")
        stripped, was_stripped, detail = compare_bytecode.strip_cbor_metadata(raw_bytes)
        self.assertFalse(was_stripped)
        self.assertEqual(stripped, raw_bytes)
        self.assertIn("likely not CBOR metadata", detail)

    def test_strip_non_fixmap_marker(self):
        # 0x82 is array(2) in CBOR, not fixmap (0xa0..0xb7)
        cbor_body = "826469706673582212200123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        cbor_len = "%04x" % (len(cbor_body) // 2)
        raw_bytes = bytes.fromhex(SAMPLE_RUNTIME_CODE_HEX + cbor_body + cbor_len)
        stripped, was_stripped, detail = compare_bytecode.strip_cbor_metadata(raw_bytes)
        self.assertFalse(was_stripped)
        self.assertEqual(stripped, raw_bytes)
        self.assertIn("not a fixmap marker", detail)


class UnlinkedLibrariesTests(unittest.TestCase):
    def test_detects_modern_solc_library_placeholder(self):
        placeholder = "__$64736f6c63430008140123456789abcdef012$__"
        hex_with_lib = "6080" + placeholder + "6040"
        self.assertTrue(compare_bytecode.has_unlinked_libraries(hex_with_lib))

    def test_detects_legacy_library_placeholder(self):
        placeholder = "__SafeMathLib___________________________"
        hex_with_lib = "6080" + placeholder + "6040"
        self.assertTrue(compare_bytecode.has_unlinked_libraries(hex_with_lib))

    def test_plain_hex_has_no_unlinked_libraries(self):
        self.assertFalse(compare_bytecode.has_unlinked_libraries(SAMPLE_RUNTIME_CODE_HEX))


class SourceVsRuntimeTests(unittest.TestCase):
    def test_match_identical_bytecode(self):
        result = compare_bytecode.compare_source_vs_runtime(
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            verified=True,
        )
        self.assertEqual(result["verdict"], "MATCH")
        self.assertEqual(result["normalizedA"], SAMPLE_RUNTIME_CODE_HEX)
        self.assertEqual(result["normalizedB"], SAMPLE_RUNTIME_CODE_HEX)

    def test_match_with_different_cbor_metadata_hashes(self):
        # Different IPFS metadata hashes in CBOR should be stripped, resulting in MATCH
        alt_cbor_map = "a2646970667358221220" + "ff" * 32 + "64736f6c6343000814"
        alt_cbor = alt_cbor_map + "0033"
        src = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX + alt_cbor

        result = compare_bytecode.compare_source_vs_runtime(src, rt, verified=True)
        self.assertEqual(result["verdict"], "MATCH")
        self.assertTrue(result["sourceCborStripped"])
        self.assertTrue(result["runtimeCborStripped"])
        self.assertEqual(result["normalizedA"], result["normalizedB"])

    def test_mismatch_differing_runtime_code(self):
        src = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX + "ff" + SAMPLE_CBOR_HEX
        result = compare_bytecode.compare_source_vs_runtime(src, rt, verified=True)
        self.assertEqual(result["verdict"], "MISMATCH")
        self.assertNotEqual(result["normalizedA"], result["normalizedB"])

    def test_unverified_yields_unavailable(self):
        result = compare_bytecode.compare_source_vs_runtime(
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            verified=False,
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")
        self.assertIn("not verified", result["detail"])

    def test_missing_source_yields_unavailable(self):
        result = compare_bytecode.compare_source_vs_runtime(
            None,
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            verified=True,
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")
        self.assertIn("sourceBytecode", result["detail"])

    def test_missing_runtime_yields_unavailable(self):
        result = compare_bytecode.compare_source_vs_runtime(
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            None,
            verified=True,
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")
        self.assertIn("runtimeBytecode", result["detail"])

    def test_empty_runtime_yields_unavailable(self):
        result = compare_bytecode.compare_source_vs_runtime(
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            "0x",
            verified=True,
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")
        self.assertIn("empty", result["detail"])

    def test_unlinked_source_yields_incomplete(self):
        src_unlinked = "0x" + SAMPLE_RUNTIME_CODE_HEX + "__$1234567890abcdef1234567890abcdef12$__"
        result = compare_bytecode.compare_source_vs_runtime(
            src_unlinked,
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            verified=True,
        )
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertIn("unlinked library", result["detail"])


class ConstructorVsRuntimeTests(unittest.TestCase):
    def test_match_identical_deployment_and_runtime(self):
        result = compare_bytecode.compare_constructor_vs_runtime(
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            abi=None,
        )
        self.assertEqual(result["verdict"], "MATCH")
        self.assertIsNone(result["constructorArgs"])
        self.assertEqual(result["constructorArgBytes"], 0)
        self.assertFalse(result["abiUsed"])

    def test_match_with_abi_confirmed_constructor_args(self):
        # 1 static address arg = 32 bytes (64 hex chars)
        arg_hex = "000000000000000000000000abcdef0123456789abcdef0123456789abcdef01"
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        abi = [
            {"type": "constructor", "inputs": [{"name": "owner", "type": "address"}]}
        ]
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=abi)
        self.assertEqual(result["verdict"], "MATCH")
        self.assertEqual(result["constructorArgs"], arg_hex)
        self.assertEqual(result["constructorArgBytes"], 32)
        self.assertTrue(result["abiUsed"])
        self.assertIn("ABI-confirmed", result["separationDetail"])

    def test_match_with_multiple_elementary_args(self):
        # 2 elementary args: address + uint256 = 64 bytes (128 hex chars)
        arg_hex = ("00" * 31 + "01") + ("00" * 31 + "02")
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        abi = [
            {
                "type": "constructor",
                "inputs": [
                    {"name": "owner", "type": "address"},
                    {"name": "initialSupply", "type": "uint256"},
                ],
            }
        ]
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=abi)
        self.assertEqual(result["verdict"], "MATCH")
        self.assertEqual(result["constructorArgBytes"], 64)

    def test_suffix_extraction_match_when_preamble_present(self):
        # Deployment has init preamble before runtime bytecode
        preamble = "6080604052348015600f57600080fd5b50"
        arg_hex = "00" * 31 + "42"  # 32 bytes
        dep = "0x" + preamble + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        abi = [
            {"type": "constructor", "inputs": [{"name": "val", "type": "uint256"}]}
        ]
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=abi)
        self.assertEqual(result["verdict"], "MATCH")
        self.assertEqual(result["constructorArgs"], arg_hex)
        self.assertEqual(result["constructorArgBytes"], 32)

    def test_incomplete_when_no_abi_and_trailing_args_present(self):
        arg_hex = "00" * 32
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=None)
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertIn("no ABI was provided", result["detail"])

    def test_incomplete_when_abi_has_non_elementary_type(self):
        arg_hex = "00" * 64
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        abi = [
            {"type": "constructor", "inputs": [{"name": "name", "type": "string"}]}
        ]
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=abi)
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertIn("non-elementary", result["detail"])

    def test_incomplete_when_abi_declared_no_args_but_trailing_bytes_exist(self):
        arg_hex = "00" * 32
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        abi = [{"type": "constructor", "inputs": []}]
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=abi)
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertIn("declares no constructor args", result["detail"])

    def test_incomplete_when_abi_length_mismatches_trailing_bytes(self):
        # ABI expects 32 bytes (1 param), but 64 trailing bytes provided
        arg_hex = "00" * 64
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + arg_hex
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        abi = [
            {"type": "constructor", "inputs": [{"name": "val", "type": "uint256"}]}
        ]
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=abi)
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertIn("ABI expected 32 bytes of constructor args but found 64", result["detail"])

    def test_incomplete_when_unlinked_libraries_in_deployment(self):
        dep = "0x" + SAMPLE_RUNTIME_CODE_HEX + "__$1234567890abcdef1234567890abcdef12$__"
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX
        result = compare_bytecode.compare_constructor_vs_runtime(dep, rt, abi=None)
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertIn("unlinked library", result["detail"])

    def test_unavailable_when_missing_deployment_bytecode(self):
        result = compare_bytecode.compare_constructor_vs_runtime(
            None,
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            abi=None,
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")

    def test_unavailable_when_missing_runtime_bytecode(self):
        result = compare_bytecode.compare_constructor_vs_runtime(
            "0x" + SAMPLE_RUNTIME_CODE_HEX,
            None,
            abi=None,
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")


class ProxyVsImplementationTests(unittest.TestCase):
    def test_unresolved_proxy_stays_unresolved(self):
        system_graph = {
            "proxies": [
                {
                    "proxy": "onchain:/1/0xproxy#Proxy",
                    "implementation": None,
                    "status": "unresolved",
                    "reason": "storage slot read returned zero address",
                }
            ]
        }
        results = compare_bytecode.compare_proxy_vs_implementation(
            system_graph, {}, {}
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "UNRESOLVED")
        self.assertIn("not resolved", results[0]["detail"])

    def test_resolved_proxy_with_missing_bytecodes_is_unavailable(self):
        impl_key = "onchain:/1/0ximpl#Impl"
        system_graph = {
            "proxies": [
                {
                    "proxy": "onchain:/1/0xproxy#Proxy",
                    "implementation": impl_key,
                    "status": "resolved",
                }
            ]
        }
        results = compare_bytecode.compare_proxy_vs_implementation(
            system_graph, {}, {}
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "UNAVAILABLE")

    def test_resolved_proxy_matching_implementation_source_vs_runtime(self):
        impl_key = "onchain:/1/0ximpl#Impl"
        system_graph = {
            "proxies": [
                {
                    "proxy": "onchain:/1/0xproxy#Proxy",
                    "implementation": impl_key,
                    "status": "resolved",
                }
            ]
        }
        src_map = {impl_key: "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX}
        rt_map = {impl_key: "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX}

        results = compare_bytecode.compare_proxy_vs_implementation(
            system_graph, src_map, rt_map
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "MATCH")
        self.assertEqual(results[0]["proxyKey"], "onchain:/1/0xproxy#Proxy")
        self.assertEqual(results[0]["implementationKey"], impl_key)

    def test_resolved_proxy_mismatch_implementation_source_vs_runtime(self):
        impl_key = "onchain:/1/0ximpl#Impl"
        system_graph = {
            "proxies": [
                {
                    "proxy": "onchain:/1/0xproxy#Proxy",
                    "implementation": impl_key,
                    "status": "resolved",
                }
            ]
        }
        src_map = {impl_key: "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX}
        rt_map = {impl_key: "0x" + SAMPLE_RUNTIME_CODE_HEX + "ff" + SAMPLE_CBOR_HEX}

        results = compare_bytecode.compare_proxy_vs_implementation(
            system_graph, src_map, rt_map
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "MISMATCH")


class TopLevelCompareTests(unittest.TestCase):
    def test_complete_match_record(self):
        raw = make_raw_record(
            deploymentBytecode="0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX,
        )
        res = compare_bytecode.compare(raw)
        self.assertEqual(res["compareVersion"], "2026.1")
        self.assertEqual(res["address"], ADDR_LOWER)
        self.assertTrue(res["verified"])
        self.assertEqual(res["comparisons"]["sourceVsRuntime"]["verdict"], "MATCH")
        self.assertEqual(res["comparisons"]["constructorVsRuntime"]["verdict"], "MATCH")
        self.assertEqual(res["limitations"], [])
        self.assertIn("MISMATCH", res["note"])

    def test_limitations_propagation_for_mismatch(self):
        raw = make_raw_record(
            sourceBytecode="0x" + SAMPLE_RUNTIME_CODE_HEX + "aa" + SAMPLE_CBOR_HEX,
        )
        res = compare_bytecode.compare(raw)
        self.assertEqual(res["comparisons"]["sourceVsRuntime"]["verdict"], "MISMATCH")
        self.assertTrue(any("sourceVsRuntime: MISMATCH" in lim for lim in res["limitations"]))

    def test_hascode_false_adds_limitation(self):
        raw = make_raw_record(hasCode=False)
        res = compare_bytecode.compare(raw)
        self.assertTrue(any("hasCode is false" in lim for lim in res["limitations"]))

    def test_verified_coercion_protection_d056(self):
        # String "true" or "false" must NOT be treated as verified=True
        for bad_v in ["true", "false", 1, 0, None]:
            raw = make_raw_record(verified=bad_v)
            res = compare_bytecode.compare(raw)
            self.assertFalse(res["verified"])
            self.assertEqual(res["comparisons"]["sourceVsRuntime"]["verdict"], "UNAVAILABLE")

    def test_address_normalization_lowercases_mixed_case(self):
        raw = make_raw_record(address=ADDR_MIXED)
        res = compare_bytecode.compare(raw)
        self.assertEqual(res["address"], ADDR_LOWER)

    def test_never_emits_findings_or_signals(self):
        raw = make_raw_record(
            sourceBytecode="0x112233",
            runtimeBytecode="0x445566",
        )
        res = compare_bytecode.compare(raw)
        self.assertNotIn("findings", res)
        self.assertNotIn("signals", res)
        self.assertNotIn("vulnerabilities", res)


class CliTests(unittest.TestCase):
    def test_cli_reading_file_and_writing_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            in_path = Path(tmp) / "input.json"
            out_path = Path(tmp) / "output.json"
            raw = make_raw_record(
                deploymentBytecode="0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX,
            )
            in_path.write_text(json.dumps(raw), encoding="utf-8")

            exit_code = compare_bytecode.main([str(in_path), "--out", str(out_path)])
            self.assertEqual(exit_code, compare_bytecode.EXIT_OK)
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["comparisons"]["sourceVsRuntime"]["verdict"], "MATCH")

    def test_cli_invalid_json_returns_failed_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text("{broken json", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = compare_bytecode.main([str(bad_path)])
            self.assertEqual(exit_code, compare_bytecode.EXIT_FAILED)
            out = json.loads(buf.getvalue())
            self.assertFalse(out["ok"])

    def test_cli_non_dict_json_returns_failed_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "list.json"
            bad_path.write_text("[]", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                exit_code = compare_bytecode.main([str(bad_path)])
            self.assertEqual(exit_code, compare_bytecode.EXIT_FAILED)
            out = json.loads(buf.getvalue())
            self.assertFalse(out["ok"])


class SchemaDriftTests(unittest.TestCase):
    def test_output_matches_schema_required_fields(self):
        schema = json.loads(
            (REFERENCES_DIR / "bytecode-compare-schema.json").read_text(encoding="utf-8")
        )
        rec = compare_bytecode.compare(make_raw_record())
        self.assertEqual(set(schema["required"]), set(rec.keys()))

    def test_comparisons_object_matches_schema_required_fields(self):
        schema = json.loads(
            (REFERENCES_DIR / "bytecode-compare-schema.json").read_text(encoding="utf-8")
        )
        required_comps = set(schema["properties"]["comparisons"]["required"])
        rec = compare_bytecode.compare(make_raw_record())
        self.assertEqual(required_comps, set(rec["comparisons"].keys()))

    def test_every_verdict_is_one_of_allowed_five(self):
        allowed = {"MATCH", "MISMATCH", "UNAVAILABLE", "INCOMPLETE", "UNRESOLVED"}
        verdicts_found = set()

        # Run various cases to sample verdicts
        v1 = compare_bytecode.compare_source_vs_runtime("0x12", "0x12", verified=True)["verdict"]
        v2 = compare_bytecode.compare_source_vs_runtime("0x12", "0x34", verified=True)["verdict"]
        v3 = compare_bytecode.compare_source_vs_runtime("0x12", "0x12", verified=False)["verdict"]
        v4 = compare_bytecode.compare_source_vs_runtime("0x12__$lib$__", "0x12", verified=True)["verdict"]
        v5 = compare_bytecode.compare_proxy_vs_implementation(
            {"proxies": [{"proxy": "p", "status": "unresolved"}]}, {}, {}
        )[0]["verdict"]

        verdicts_found.update([v1, v2, v3, v4, v5])
        self.assertEqual(verdicts_found, allowed)


if __name__ == "__main__":
    unittest.main()
