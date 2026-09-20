"""Tests for scripts/bytecode_advisory.py (V3 Block 3, B3, docs/decisiones.md
D-071): deterministic opcode-presence advisory scan.

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

import bytecode_advisory as ba  # noqa: E402


class ComputeBytecodeAdvisoriesTests(unittest.TestCase):
    def test_positive_delegatecall_as_real_instruction_is_flagged(self):
        # 0xf4 as the very first byte is a real DELEGATECALL instruction.
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0xf4"})
        labels = {a["opcode"] for a in result["advisories"]}
        self.assertIn("DELEGATECALL", labels)
        self.assertEqual(result["advisories"][0]["confidence"], "low")

    def test_positive_selfdestruct_as_real_instruction_is_flagged(self):
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0xff"})
        labels = {a["opcode"] for a in result["advisories"]}
        self.assertIn("SELFDESTRUCT", labels)

    def test_positive_callcode_as_real_instruction_is_flagged(self):
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0xf2"})
        labels = {a["opcode"] for a in result["advisories"]}
        self.assertIn("CALLCODE", labels)

    def test_adversarial_opcode_byte_only_as_push_data_is_never_flagged(self):
        # PUSH1 0xF4 (bytes 60 F4): the byte 0xf4 here is DATA for the PUSH,
        # never an executed DELEGATECALL instruction - the textbook false
        # positive a naive substring scan would produce.
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0x60f4"})
        self.assertEqual(result["advisories"], [])

    def test_adversarial_all_three_opcode_bytes_as_push_data_never_flagged(self):
        # PUSH3 0xF2 0xF4 0xFF: three consecutive advisory-opcode byte
        # values, all consumed as one PUSH3's data, none executed.
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0x62f2f4ff"})
        self.assertEqual(result["advisories"], [])

    def test_negative_bytecode_with_no_advisory_opcodes(self):
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0x6000"})  # PUSH1 0x00
        self.assertEqual(result["advisories"], [])
        self.assertEqual(result["advisoryCount"], 0)

    def test_never_returns_a_severity_field(self):
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0xf4"})
        self.assertNotIn("severity", result)
        for entry in result["advisories"]:
            self.assertNotIn("severity", entry)

    def test_empty_bytecode_yields_no_advisories(self):
        result = ba.compute_bytecode_advisories({"runtimeBytecode": "0x"})
        self.assertEqual(result["advisories"], [])

    def test_malformed_missing_runtime_bytecode_raises(self):
        with self.assertRaises(ba.BytecodeAdvisoryError):
            ba.compute_bytecode_advisories({})

    def test_malformed_non_hex_raises(self):
        with self.assertRaises(ba.BytecodeAdvisoryError):
            ba.compute_bytecode_advisories({"runtimeBytecode": "not-hex-zzz"})

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(ba.BytecodeAdvisoryError):
            ba.compute_bytecode_advisories("not-a-dict")

    def test_never_mutates_input(self):
        payload = {"runtimeBytecode": "0xf4"}
        before = json.loads(json.dumps(payload))
        ba.compute_bytecode_advisories(payload)
        self.assertEqual(payload, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ba.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"runtimeBytecode": "0xf4"}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, ba.EXIT_OK)
        self.assertEqual(json.loads(out)["advisoryCount"], 1)

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps({"runtimeBytecode": "0x6000"}))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, ba.EXIT_OK)
        self.assertEqual(json.loads(out)["advisories"], [])

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, ba.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_bytecode_advisory_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["bytecode-advisory"], "bytecode_advisory")


if __name__ == "__main__":
    unittest.main()
