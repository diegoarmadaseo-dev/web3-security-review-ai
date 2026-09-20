"""Tests for scripts/bytecode_size.py (V3 Block 5, D2, docs/decisiones.md
D-073): deterministic EIP-170 runtime-bytecode size check.

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

import bytecode_size as bs  # noqa: E402


def _hex_of_n_bytes(n):
    return "0x" + ("00" * n)


class ComputeBytecodeSizeReportTests(unittest.TestCase):
    def test_positive_small_bytecode_is_within_limit(self):
        result = bs.compute_bytecode_size_report({"runtimeBytecode": "0x6000"})
        self.assertEqual(result["status"], "within_limit")
        self.assertEqual(result["sizeBytes"], 2)
        self.assertEqual(result["bytesOverLimit"], 0)

    def test_boundary_exactly_at_limit_is_within(self):
        result = bs.compute_bytecode_size_report({"runtimeBytecode": _hex_of_n_bytes(bs.EIP170_MAX_RUNTIME_BYTES)})
        self.assertEqual(result["status"], "within_limit")
        self.assertEqual(result["sizeBytes"], bs.EIP170_MAX_RUNTIME_BYTES)
        self.assertEqual(result["bytesOverLimit"], 0)

    def test_boundary_one_byte_over_limit_exceeds(self):
        result = bs.compute_bytecode_size_report({"runtimeBytecode": _hex_of_n_bytes(bs.EIP170_MAX_RUNTIME_BYTES + 1)})
        self.assertEqual(result["status"], "exceeds_limit")
        self.assertEqual(result["bytesOverLimit"], 1)

    def test_adversarial_well_over_limit(self):
        result = bs.compute_bytecode_size_report({"runtimeBytecode": _hex_of_n_bytes(bs.EIP170_MAX_RUNTIME_BYTES + 10000)})
        self.assertEqual(result["status"], "exceeds_limit")
        self.assertEqual(result["bytesOverLimit"], 10000)

    def test_empty_bytecode_is_within_limit(self):
        result = bs.compute_bytecode_size_report({"runtimeBytecode": "0x"})
        self.assertEqual(result["sizeBytes"], 0)
        self.assertEqual(result["status"], "within_limit")

    def test_never_returns_a_severity_field(self):
        result = bs.compute_bytecode_size_report({"runtimeBytecode": _hex_of_n_bytes(bs.EIP170_MAX_RUNTIME_BYTES + 1)})
        self.assertNotIn("severity", result)

    def test_malformed_missing_runtime_bytecode_raises(self):
        with self.assertRaises(bs.BytecodeSizeError):
            bs.compute_bytecode_size_report({})

    def test_malformed_non_hex_raises(self):
        with self.assertRaises(bs.BytecodeSizeError):
            bs.compute_bytecode_size_report({"runtimeBytecode": "zzz"})

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(bs.BytecodeSizeError):
            bs.compute_bytecode_size_report("not-a-dict")

    def test_never_mutates_input(self):
        payload = {"runtimeBytecode": "0x6000"}
        before = json.loads(json.dumps(payload))
        bs.compute_bytecode_size_report(payload)
        self.assertEqual(payload, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = bs.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"runtimeBytecode": _hex_of_n_bytes(bs.EIP170_MAX_RUNTIME_BYTES + 1)}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, bs.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "exceeds_limit")

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps({"runtimeBytecode": "0x6000"}))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, bs.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "within_limit")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, bs.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_bytecode_size_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["bytecode-size"], "bytecode_size")


if __name__ == "__main__":
    unittest.main()
