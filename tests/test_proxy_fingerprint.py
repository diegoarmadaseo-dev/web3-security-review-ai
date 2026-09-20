"""Tests for scripts/proxy_fingerprint.py (V3 Block 4, C1, docs/decisiones.md
D-072): deterministic bytecode-only proxy-pattern fingerprinting.

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

import proxy_fingerprint as pf  # noqa: E402
import preprocess  # noqa: E402

_IMPL_ADDR = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # 20 bytes, arbitrary


def _eip1167_bytecode(addr_hex=_IMPL_ADDR):
    return "0x" + pf._EIP1167_PREFIX.hex() + addr_hex.lower() + pf._EIP1167_SUFFIX.hex()


def _eip1967_bytecode():
    # The slot constant surrounded by unrelated opcodes - real EIP-1967
    # proxies PUSH32 this constant, never store it as a bare literal
    # outside an instruction, but presence-detection doesn't require a
    # specific surrounding opcode, only the 32 literal bytes.
    return "0x60" + pf.PROXIABLE_IMPLEMENTATION_SLOT.hex() + "5560"


class ReusesPreprocessSlotConstantTests(unittest.TestCase):
    def test_slot_constant_is_identical_to_preprocess_single_source_of_truth(self):
        # Proves this module never redeclares its own copy of the EIP-1967
        # slot - the exact bug this fix closes (two independently-typed
        # values silently disagreeing at one hex character).
        self.assertEqual(pf.PROXIABLE_IMPLEMENTATION_SLOT.hex(), preprocess.EIP1967_IMPLEMENTATION_SLOT_HEX)

    def test_slot_constant_is_still_a_member_of_known_public_slots(self):
        # preprocess.py's own secrets-scanner behavior for this exact value
        # must be unaffected by the refactor.
        self.assertIn(preprocess.EIP1967_IMPLEMENTATION_SLOT_HEX, preprocess.KNOWN_PUBLIC_SLOTS)
        self.assertEqual(len(preprocess.KNOWN_PUBLIC_SLOTS), 4)


class ComputeProxyFingerprintTests(unittest.TestCase):
    def test_positive_eip1167_exact_template_matches_and_extracts_address(self):
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": _eip1167_bytecode()})
        self.assertEqual(result["status"], "matched")
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["pattern"], "EIP-1167")
        self.assertEqual(result["matches"][0]["implementation"], "0x" + _IMPL_ADDR.lower())
        self.assertEqual(result["matches"][0]["confidence"], "low")

    def test_adversarial_one_byte_off_in_prefix_never_matches(self):
        # Change the very first byte of the canonical prefix - a real
        # false-template-match probe, not just a length/shape check.
        mutated_prefix = bytes([pf._EIP1167_PREFIX[0] ^ 0xFF]) + pf._EIP1167_PREFIX[1:]
        addr = bytes.fromhex(_IMPL_ADDR)
        data = mutated_prefix + addr + pf._EIP1167_SUFFIX
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": "0x" + data.hex()})
        self.assertEqual(result["status"], "no_match")

    def test_adversarial_one_byte_off_in_suffix_never_matches(self):
        mutated_suffix = pf._EIP1167_SUFFIX[:-1] + bytes([pf._EIP1167_SUFFIX[-1] ^ 0xFF])
        addr = bytes.fromhex(_IMPL_ADDR)
        data = pf._EIP1167_PREFIX + addr + mutated_suffix
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": "0x" + data.hex()})
        self.assertEqual(result["status"], "no_match")

    def test_adversarial_wrong_length_never_matches(self):
        # One extra trailing byte - must never be treated as "close enough".
        data = pf._EIP1167_PREFIX + bytes.fromhex(_IMPL_ADDR) + pf._EIP1167_SUFFIX + b"\x00"
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": "0x" + data.hex()})
        self.assertEqual(result["status"], "no_match")

    def test_positive_eip1967_slot_presence_never_extracts_a_target(self):
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": _eip1967_bytecode()})
        self.assertEqual(result["status"], "matched")
        eip1967 = [m for m in result["matches"] if m["pattern"] == "EIP-1967"][0]
        self.assertIsNone(eip1967["implementation"])  # never guessed - lives in storage, not bytecode.

    def test_negative_absent_slot_constant_never_matches_eip1967(self):
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": "0x6000600055"})
        self.assertEqual([m["pattern"] for m in result["matches"]], [])

    def test_negative_no_pattern_matched_at_all(self):
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": "0x6000"})
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["matches"], [])

    def test_never_returns_a_severity_field(self):
        result = pf.compute_proxy_fingerprint({"runtimeBytecode": _eip1167_bytecode()})
        self.assertNotIn("severity", result)
        for m in result["matches"]:
            self.assertNotIn("severity", m)

    def test_malformed_missing_runtime_bytecode_raises(self):
        with self.assertRaises(pf.ProxyFingerprintError):
            pf.compute_proxy_fingerprint({})

    def test_malformed_non_hex_raises(self):
        with self.assertRaises(pf.ProxyFingerprintError):
            pf.compute_proxy_fingerprint({"runtimeBytecode": "zzz"})

    def test_never_mutates_input(self):
        payload = {"runtimeBytecode": _eip1167_bytecode()}
        before = json.loads(json.dumps(payload))
        pf.compute_proxy_fingerprint(payload)
        self.assertEqual(payload, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = pf.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"runtimeBytecode": _eip1167_bytecode()}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, pf.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "matched")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, pf.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_proxy_fingerprint_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["proxy-fingerprint"], "proxy_fingerprint")


if __name__ == "__main__":
    unittest.main()
