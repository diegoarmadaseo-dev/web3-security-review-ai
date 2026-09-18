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
from unittest import mock

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


# ---------------------------------------------------------------------------
# V2.8 Block 2
# ---------------------------------------------------------------------------

_PUSH0_RUNTIME = "0x5f00"           # PUSH0, STOP
_NO_PUSH0_RUNTIME = "0x60000000"    # PUSH1 0x00, STOP, STOP (no PUSH0 opcode)
_PUSH0_AS_DATA_RUNTIME = "0x605f00"  # PUSH1 0x5f (data, not an opcode), STOP


class CapabilityCompatibilityTests(unittest.TestCase):
    def test_push0_used_on_incompatible_chain_is_mismatch(self):
        results = compare_bytecode.check_capability_compatibility(_PUSH0_RUNTIME, None, 250)  # fantom
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertEqual(push0["verdict"], "MISMATCH")
        self.assertTrue(push0["opcodeUsed"])

    def test_push0_used_on_compatible_chain_is_match(self):
        results = compare_bytecode.check_capability_compatibility(_PUSH0_RUNTIME, None, 1)  # ethereum
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertEqual(push0["verdict"], "MATCH")

    def test_push0_not_used_is_match_regardless_of_chain(self):
        # Negative control: absence of the opcode is trivially fine even on
        # a chain that does not support it.
        results = compare_bytecode.check_capability_compatibility(_NO_PUSH0_RUNTIME, None, 250)
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertEqual(push0["verdict"], "MATCH")
        self.assertFalse(push0["opcodeUsed"])

    def test_push_data_byte_is_never_mistaken_for_push0_opcode(self):
        # Adversarial: PUSH1 0x5f pushes the literal byte 0x5f as DATA - a
        # naive substring/byte search would false-positive here.
        results = compare_bytecode.check_capability_compatibility(_PUSH0_AS_DATA_RUNTIME, None, 250)
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertFalse(push0["opcodeUsed"])
        self.assertEqual(push0["verdict"], "MATCH")

    def test_tload_and_tstore_both_detected_as_transient_storage(self):
        for opcode_hex in ("5c", "5d"):  # TLOAD, TSTORE
            with self.subTest(opcode=opcode_hex):
                runtime = "0x" + opcode_hex + "00"
                results = compare_bytecode.check_capability_compatibility(runtime, None, 250)  # fantom: unsupported
                ts = next(r for r in results if r["capability"] == "supportsTransientStorage")
                self.assertEqual(ts["verdict"], "MISMATCH")

    def test_unknown_chain_is_unavailable_never_silently_compatible(self):
        # Adversarial (unknown chains, required): absence of a warning must
        # never be misread as "compatible" - this is this script's
        # NOT_ASSESSED equivalent.
        results = compare_bytecode.check_capability_compatibility(_PUSH0_RUNTIME, None, 999999999)
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertEqual(push0["verdict"], "UNAVAILABLE")
        self.assertFalse(push0.get("chainKnown", False))

    def test_no_chain_id_is_unavailable(self):
        results = compare_bytecode.check_capability_compatibility(_PUSH0_RUNTIME, None, None)
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertEqual(push0["verdict"], "UNAVAILABLE")

    def test_no_bytecode_at_all_yields_two_unavailable_entries(self):
        results = compare_bytecode.check_capability_compatibility(None, None, 1)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["verdict"] == "UNAVAILABLE" for r in results))

    def test_broken_chains_catalog_yields_unavailable_never_crashes(self):
        # Adversarial: a broken chains.json must degrade to UNAVAILABLE, not
        # raise and abort the whole comparison.
        import chains
        with mock.patch.object(chains, "get_chain_capabilities", side_effect=chains.ChainsConfigError("broken")):
            results = compare_bytecode.check_capability_compatibility(_PUSH0_RUNTIME, None, 1)
        push0 = next(r for r in results if r["capability"] == "supportsPush0")
        self.assertEqual(push0["verdict"], "UNAVAILABLE")

    def test_verdicts_stay_within_the_five_allowed(self):
        allowed = {"MATCH", "MISMATCH", "UNAVAILABLE", "INCOMPLETE", "UNRESOLVED"}
        for chain_id, runtime in ((1, _PUSH0_RUNTIME), (250, _PUSH0_RUNTIME), (None, _PUSH0_RUNTIME), (1, _NO_PUSH0_RUNTIME)):
            for r in compare_bytecode.check_capability_compatibility(runtime, None, chain_id):
                self.assertIn(r["verdict"], allowed)


def _encode_solc_cbor(version_bytes: bytes) -> str:
    """Minimal single-key {"solc": <3 bytes>} CBOR fixmap, hex-encoded,
    WITHOUT the trailing 2-byte length word (caller appends it, matching
    strip_cbor_metadata's own contract)."""
    key = b"solc"
    body = bytes([0xA1, 0x60 + len(key)]) + key + bytes([0x40 + len(version_bytes)]) + version_bytes
    return body.hex()


class CompilerVersionConsistencyTests(unittest.TestCase):
    def test_matching_versions_is_match(self):
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        result = compare_bytecode.check_compiler_version_consistency(
            "v0.8.20+commit.a1b79de6", runtime, verified=True
        )
        self.assertEqual(result["verdict"], "MATCH")
        self.assertEqual(result["embeddedVersion"], "0.8.20")

    def test_mismatched_versions_is_mismatch(self):
        # Adversarial (misleading metadata, required): explorer claims a
        # DIFFERENT version than what is actually embedded in the bytecode.
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        result = compare_bytecode.check_compiler_version_consistency(
            "v0.8.19+commit.7dd6d404", runtime, verified=True
        )
        self.assertEqual(result["verdict"], "MISMATCH")
        self.assertEqual(result["reportedVersion"], "0.8.19")
        self.assertEqual(result["embeddedVersion"], "0.8.20")

    def test_long_form_cbor_value_length_is_decoded_correctly(self):
        # The realistic case: an "ipfs" hash long enough (34 bytes) to
        # require CBOR's 1-byte-length-follows encoding (0x58), which a
        # short-form-only decoder would reject as unsupported. Reuses this
        # file's own SAMPLE_CBOR_HEX fixture, which already has this shape.
        meta_body = bytes.fromhex(SAMPLE_CBOR_MAP_HEX)
        decoded, detail = compare_bytecode._decode_cbor_solc_metadata(meta_body)
        self.assertIsNotNone(decoded, detail)
        self.assertEqual(compare_bytecode._solc_version_from_metadata(decoded), "0.8.20")

    def test_no_compiler_version_provided_is_unavailable(self):
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        result = compare_bytecode.check_compiler_version_consistency(None, runtime, verified=True)
        self.assertEqual(result["verdict"], "UNAVAILABLE")

    def test_no_runtime_bytecode_is_unavailable(self):
        result = compare_bytecode.check_compiler_version_consistency("v0.8.20", None, verified=True)
        self.assertEqual(result["verdict"], "UNAVAILABLE")

    def test_no_cbor_metadata_present_is_incomplete_never_guessed(self):
        result = compare_bytecode.check_compiler_version_consistency(
            "v0.8.20", "0x" + SAMPLE_RUNTIME_CODE_HEX, verified=True
        )
        self.assertEqual(result["verdict"], "INCOMPLETE")

    def test_malformed_truncated_cbor_never_crashes(self):
        # Adversarial: a CBOR region that looks like a fixmap but is cut off
        # mid-value must degrade to INCOMPLETE, never raise.
        truncated_body = bytes.fromhex(_encode_solc_cbor(b"\x00\x08"))  # claims 3 bytes, only 2 present
        truncated_hex = truncated_body.hex() + ("%04x" % len(truncated_body))
        result = compare_bytecode.check_compiler_version_consistency(
            "v0.8.20", "0x" + SAMPLE_RUNTIME_CODE_HEX + truncated_hex, verified=True
        )
        self.assertIn(result["verdict"], ("INCOMPLETE", "UNAVAILABLE"))

    def test_reported_version_without_semver_is_incomplete(self):
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        result = compare_bytecode.check_compiler_version_consistency("nightly-build", runtime, verified=True)
        self.assertEqual(result["verdict"], "INCOMPLETE")

    def test_verdicts_stay_within_the_five_allowed(self):
        allowed = {"MATCH", "MISMATCH", "UNAVAILABLE", "INCOMPLETE", "UNRESOLVED"}
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        for version in (None, "v0.8.20", "v0.8.19", "garbage"):
            r = compare_bytecode.check_compiler_version_consistency(version, runtime, verified=True)
            self.assertIn(r["verdict"], allowed)

    def test_unverified_yields_unavailable_even_with_matching_version(self):
        # D-060 corrective fix (Critical Item 3): a coincidentally- or
        # maliciously-matching compilerVersion on an UNVERIFIED record must
        # never be reported as a confirmed MATCH.
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        result = compare_bytecode.check_compiler_version_consistency(
            "v0.8.20+commit.a1b79de6", runtime, verified=False
        )
        self.assertEqual(result["verdict"], "UNAVAILABLE")

    def test_full_compare_gates_compiler_version_check_on_verified_field(self):
        # Same coercion matrix as D-056's VerifiedFieldCoercionTests
        # (ingest_onchain.py): false (bool), "false"/"true" (string), 1
        # (int) must ALL be treated as NOT verified - only literal True
        # (identity check) may produce a MATCH/MISMATCH verdict.
        runtime = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        for non_true_verified in (False, "false", "true", 1, None):
            with self.subTest(verified=non_true_verified):
                raw = make_raw_record(
                    verified=non_true_verified,
                    runtimeBytecode=runtime,
                    compilerVersion="v0.8.20+commit.a1b79de6",
                )
                result = compare_bytecode.compare(raw)
                self.assertEqual(result["comparisons"]["compilerVersionCheck"]["verdict"], "UNAVAILABLE")
        raw_true = make_raw_record(
            verified=True, runtimeBytecode=runtime, compilerVersion="v0.8.20+commit.a1b79de6"
        )
        self.assertEqual(
            compare_bytecode.compare(raw_true)["comparisons"]["compilerVersionCheck"]["verdict"], "MATCH"
        )


class CrossChainImplementationDriftTests(unittest.TestCase):
    """D-060 corrective fix: identity is now the CBOR-embedded source
    metadata hash (ipfs/bzzr), never bare contract name or address."""

    _RT_WITH_IDENTITY = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
    _RT_WITH_IDENTITY_DIFFERENT_CODE = "0x" + SAMPLE_RUNTIME_CODE_HEX + "ff" + SAMPLE_CBOR_HEX

    def _system_graph(self, resolved_pairs):
        proxies = []
        for chain_id, addr, status, impl_chain, impl_addr, impl_name in resolved_pairs:
            entry = {
                "proxy": "onchain:/%s/%s/P.sol#P" % (chain_id, addr),
                "status": status,
                "implementation": (
                    "onchain:/%s/%s/I.sol#%s" % (impl_chain, impl_addr, impl_name)
                    if status == "resolved" else None
                ),
            }
            proxies.append(entry)
        return {"proxies": proxies}

    def test_shared_metadata_identity_identical_bytecode_is_match(self):
        sg = self._system_graph([
            (1, "0xaa", "resolved", 1, "0xaa", "Impl"),
            (137, "0xbb", "resolved", 137, "0xbb", "Impl"),
        ])
        rt_map = {
            "onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY,
            "onchain:/137/0xbb/I.sol#Impl": self._RT_WITH_IDENTITY,
        }
        results = compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "MATCH")
        self.assertTrue(results[0]["metadataIdentity"].startswith("ipfs:"))
        self.assertEqual(set(results[0]["chainIds"]), {"1", "137"})

    def test_shared_metadata_identity_different_bytecode_is_mismatch(self):
        # Adversarial test 2 (D-060): a RELIABLE identity (matching CBOR
        # metadata hash) exists on both chains, but the actual runtime
        # bytecode differs - a genuine drifted rollout, not a guess.
        sg = self._system_graph([
            (1, "0xaa", "resolved", 1, "0xaa", "Impl"),
            (137, "0xbb", "resolved", 137, "0xbb", "Impl"),
        ])
        rt_map = {
            "onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY,
            "onchain:/137/0xbb/I.sol#Impl": self._RT_WITH_IDENTITY_DIFFERENT_CODE,
        }
        results = compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "MISMATCH")

    def test_unrelated_same_name_contracts_without_shared_identity_produce_no_drift(self):
        # Adversarial test 1 (D-060 / audit finding): two UNRELATED
        # contracts that merely share the bare name "Impl" across chains,
        # with no shared CBOR metadata identity, must NEVER be reported as
        # a drifted rollout - this is the exact false-match the final audit
        # confirmed under the old bare-name grouping.
        sg = self._system_graph([
            (1, "0xaa", "resolved", 1, "0xaa", "Impl"),
            (137, "0xbb", "resolved", 137, "0xbb", "Impl"),
        ])
        rt_map = {
            "onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY,  # has an "ipfs" identity
            "onchain:/137/0xbb/I.sol#Impl": "0x6099",  # no CBOR metadata at all - genuinely unrelated
        }
        self.assertEqual(compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map), [])

    def test_missing_identity_on_one_chain_yields_no_drift(self):
        # Adversarial test 3 (D-060): one chain's implementation carries no
        # decodable metadata identity at all (absent from the map entirely)
        # -> excluded from grouping, never guessed, never a false UNAVAILABLE.
        sg = self._system_graph([
            (1, "0xaa", "resolved", 1, "0xaa", "Impl"),
            (137, "0xbb", "resolved", 137, "0xbb", "Impl"),
        ])
        rt_map = {"onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY}  # chain 137 entirely absent
        self.assertEqual(compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map), [])

    def test_single_chain_deployment_produces_no_entry(self):
        sg = self._system_graph([(1, "0xaa", "resolved", 1, "0xaa", "Impl")])
        rt_map = {"onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY}
        self.assertEqual(compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map), [])

    def test_unresolved_proxy_is_excluded_never_guessed_into_a_group(self):
        # Adversarial (chain isolation, required): an unresolved proxy on a
        # second chain must never be paired with a resolved one elsewhere.
        sg = self._system_graph([
            (1, "0xaa", "resolved", 1, "0xaa", "Impl"),
            (137, "0xbb", "unresolved", None, None, None),
        ])
        rt_map = {"onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY}
        self.assertEqual(compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map), [])

    def test_no_system_graph_or_no_map_returns_empty(self):
        self.assertEqual(compare_bytecode.check_cross_chain_implementation_drift(None, {"x": "0x00"}), [])
        self.assertEqual(compare_bytecode.check_cross_chain_implementation_drift({"proxies": []}, None), [])

    def test_verdicts_stay_within_the_five_allowed(self):
        allowed = {"MATCH", "MISMATCH", "UNAVAILABLE", "INCOMPLETE", "UNRESOLVED"}
        sg = self._system_graph([
            (1, "0xaa", "resolved", 1, "0xaa", "Impl"),
            (137, "0xbb", "resolved", 137, "0xbb", "Impl"),
        ])
        rt_map = {
            "onchain:/1/0xaa/I.sol#Impl": self._RT_WITH_IDENTITY,
            "onchain:/137/0xbb/I.sol#Impl": self._RT_WITH_IDENTITY,
        }
        for r in compare_bytecode.check_cross_chain_implementation_drift(sg, rt_map):
            self.assertIn(r["verdict"], allowed)


class CborMetadataIdentityHashTests(unittest.TestCase):
    def test_identity_extracted_from_ipfs_key(self):
        identity = compare_bytecode._cbor_metadata_identity_hash(
            "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        )
        self.assertIsNotNone(identity)
        self.assertTrue(identity.startswith("ipfs:"))

    def test_same_bytecode_yields_same_identity(self):
        rt = "0x" + SAMPLE_RUNTIME_CODE_HEX + SAMPLE_CBOR_HEX
        self.assertEqual(
            compare_bytecode._cbor_metadata_identity_hash(rt),
            compare_bytecode._cbor_metadata_identity_hash(rt),
        )

    def test_no_bytecode_yields_no_identity(self):
        self.assertIsNone(compare_bytecode._cbor_metadata_identity_hash(None))
        self.assertIsNone(compare_bytecode._cbor_metadata_identity_hash(""))

    def test_bytecode_without_cbor_metadata_yields_no_identity(self):
        self.assertIsNone(compare_bytecode._cbor_metadata_identity_hash("0x" + SAMPLE_RUNTIME_CODE_HEX))

    def test_metadata_without_ipfs_or_bzzr_key_yields_no_identity(self):
        # Only a "solc" key present - a compiler version alone is far too
        # weak a signal to serve as a cross-chain identity (many unrelated
        # contracts share a compiler version).
        solc_only_body = bytes.fromhex(_encode_solc_cbor(b"\x00\x08\x14"))
        solc_only_hex = solc_only_body.hex() + ("%04x" % len(solc_only_body))
        self.assertIsNone(
            compare_bytecode._cbor_metadata_identity_hash("0x" + SAMPLE_RUNTIME_CODE_HEX + solc_only_hex)
        )


class ComparisonsSchemaDriftTests(unittest.TestCase):
    def test_comparisons_keys_match_schema_required(self):
        schema = json.loads((REFERENCES_DIR / "bytecode-compare-schema.json").read_text(encoding="utf-8"))
        required = set(schema["properties"]["comparisons"]["required"])
        result = compare_bytecode.compare(make_raw_record())
        self.assertEqual(required, set(result["comparisons"].keys()))


if __name__ == "__main__":
    unittest.main()
