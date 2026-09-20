"""Tests for scripts/bytecode_metamorphic_signal.py (V3 Block 7, F2,
docs/decisiones.md D-075): deterministic CREATE2+SELFDESTRUCT
co-occurrence signal.

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

import bytecode_metamorphic_signal as bms  # noqa: E402

_CREATE2 = "f5"
_SELFDESTRUCT = "ff"
_STOP = "00"
_PUSH1 = "60"
_ADD = "01"


class ComputeBytecodeMetamorphicSignalTests(unittest.TestCase):
    def test_positive_create2_and_selfdestruct_co_occurrence_is_signaled(self):
        result = bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0x" + _CREATE2 + _SELFDESTRUCT})
        self.assertEqual(result["status"], "signal_present")
        self.assertTrue(result["hasCreate2"])
        self.assertTrue(result["hasSelfdestruct"])
        self.assertEqual(result["confidence"], "low")

    def test_negative_create2_alone_is_not_signaled(self):
        result = bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0x" + _CREATE2 + _STOP})
        self.assertEqual(result["status"], "no_signal")
        self.assertTrue(result["hasCreate2"])
        self.assertFalse(result["hasSelfdestruct"])

    def test_negative_selfdestruct_alone_is_not_signaled(self):
        result = bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0x" + _SELFDESTRUCT})
        self.assertEqual(result["status"], "no_signal")
        self.assertFalse(result["hasCreate2"])
        self.assertTrue(result["hasSelfdestruct"])

    def test_negative_neither_opcode_is_not_signaled(self):
        result = bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0x" + _PUSH1 + "01" + _PUSH1 + "01" + _ADD})
        self.assertEqual(result["status"], "no_signal")
        self.assertFalse(result["hasCreate2"])
        self.assertFalse(result["hasSelfdestruct"])

    def test_adversarial_both_opcode_bytes_only_as_push_data_is_not_signaled(self):
        # PUSH1 0xf5, PUSH1 0xff - both bytes appear only as PUSH operands,
        # never as real instructions; _walk_opcodes must skip them as data.
        bytecode = _PUSH1 + _CREATE2 + _PUSH1 + _SELFDESTRUCT + _STOP
        result = bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0x" + bytecode})
        self.assertEqual(result["status"], "no_signal")
        self.assertFalse(result["hasCreate2"])
        self.assertFalse(result["hasSelfdestruct"])

    def test_adversarial_missing_runtime_bytecode_raises(self):
        with self.assertRaises(bms.BytecodeMetamorphicSignalError):
            bms.compute_bytecode_metamorphic_signal({})

    def test_adversarial_non_hex_runtime_bytecode_raises(self):
        with self.assertRaises(bms.BytecodeMetamorphicSignalError):
            bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0xZZZZ"})

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(bms.BytecodeMetamorphicSignalError):
            bms.compute_bytecode_metamorphic_signal("not-a-dict")

    def test_never_returns_a_severity_field(self):
        result = bms.compute_bytecode_metamorphic_signal({"runtimeBytecode": "0x" + _CREATE2 + _SELFDESTRUCT})
        self.assertNotIn("severity", result)

    def test_never_mutates_payload(self):
        payload = {"runtimeBytecode": "0x" + _CREATE2 + _SELFDESTRUCT}
        before = json.loads(json.dumps(payload))
        bms.compute_bytecode_metamorphic_signal(payload)
        self.assertEqual(payload, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = bms.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"runtimeBytecode": "0x" + _CREATE2 + _SELFDESTRUCT}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, bms.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "signal_present")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, bms.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_bytecode_metamorphic_signal_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["bytecode-metamorphic-signal"], "bytecode_metamorphic_signal")


if __name__ == "__main__":
    unittest.main()
