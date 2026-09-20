"""Tests for scripts/bytecode_compiler_bugs.py (V3 Block 5, D3,
docs/decisiones.md D-073): CBOR solc-version extraction bridged into
compiler_bugs.py's existing matcher.

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

import bytecode_compiler_bugs as bcb  # noqa: E402
import compiler_bugs as cb  # noqa: E402

# Real, independently-verified CBOR trailer (built and round-tripped through
# the actual compare_bytecode.py decode chain before being hardcoded here -
# see docs/decisiones.md D-073) embedding solc 0.8.20: a fixmap {"solc":
# b"\x00\x08\x14"} (10-byte CBOR body) plus its 2-byte length word, appended
# after 4 bytes of arbitrary "code".
_BYTECODE_WITH_SOLC_0_8_20 = "0x60006000a164736f6c6343000814000a"

FIXTURE_DATASET = {
    "datasetVersion": "test-fixture-1",
    "sourceUrl": "https://example.invalid/bugs",
    "provenance": "test fixture",
    "bugs": [
        {"uid": "TEST-0001", "name": "Fixture bug", "introducedVersion": "0.8.13", "fixedVersion": "0.8.21", "severity": "medium", "summary": "s", "verified": True},
    ],
}


class ExtractSolcVersionFromBytecodeTests(unittest.TestCase):
    def test_positive_extracts_exact_version_from_real_cbor_trailer(self):
        version, detail = bcb.extract_solc_version_from_bytecode(_BYTECODE_WITH_SOLC_0_8_20)
        self.assertEqual(version, "0.8.20")
        self.assertIn("CBOR", detail)

    def test_negative_no_cbor_metadata_present(self):
        version, detail = bcb.extract_solc_version_from_bytecode("0x6000")
        self.assertIsNone(version)
        self.assertIn("no CBOR metadata", detail)

    def test_adversarial_malformed_cbor_never_crashes_or_guesses(self):
        # A trailing length word that claims more CBOR than is actually there.
        version, detail = bcb.extract_solc_version_from_bytecode("0x600060000000ff")
        self.assertIsNone(version)


class ComputeBytecodeCompilerBugReportTests(unittest.TestCase):
    def test_positive_version_extracted_and_matched_against_dataset(self):
        result = bcb.compute_bytecode_compiler_bug_report({"runtimeBytecode": _BYTECODE_WITH_SOLC_0_8_20}, FIXTURE_DATASET)
        self.assertEqual(result["status"], "version_extracted")
        self.assertEqual(result["extractedVersion"], "0.8.20")
        self.assertEqual(result["compilerBugReport"]["status"], "affected")
        self.assertEqual(result["compilerBugReport"]["matches"][0]["uid"], "TEST-0001")

    def test_negative_no_version_found_yields_null_bug_report(self):
        result = bcb.compute_bytecode_compiler_bug_report({"runtimeBytecode": "0x6000"}, FIXTURE_DATASET)
        self.assertEqual(result["status"], "version_not_found")
        self.assertIsNone(result["compilerBugReport"])
        self.assertIsNone(result["extractedVersion"])

    def test_reuses_compiler_bugs_matcher_unmodified(self):
        # Independently confirms this module delegates to the SAME function
        # compiler_bugs.py's own tests exercise, rather than reimplementing
        # version matching.
        direct = cb.check_compiler_version("0.8.20", FIXTURE_DATASET)
        bridged = bcb.compute_bytecode_compiler_bug_report({"runtimeBytecode": _BYTECODE_WITH_SOLC_0_8_20}, FIXTURE_DATASET)
        self.assertEqual(bridged["compilerBugReport"]["matches"], direct["matches"])

    def test_malformed_missing_runtime_bytecode_raises(self):
        with self.assertRaises(bcb.BytecodeCompilerBugsError):
            bcb.compute_bytecode_compiler_bug_report({}, FIXTURE_DATASET)

    def test_malformed_not_a_dict_raises(self):
        with self.assertRaises(bcb.BytecodeCompilerBugsError):
            bcb.compute_bytecode_compiler_bug_report("not-a-dict", FIXTURE_DATASET)

    def test_real_bundled_dataset_end_to_end(self):
        result = bcb.compute_bytecode_compiler_bug_report({"runtimeBytecode": _BYTECODE_WITH_SOLC_0_8_20})
        self.assertEqual(result["status"], "version_extracted")
        self.assertIn(result["compilerBugReport"]["status"], ("affected", "not_affected"))


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = bcb.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end_with_custom_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset_path = Path(tmp) / "dataset.json"
            dataset_path.write_text(json.dumps(FIXTURE_DATASET), encoding="utf-8")
            input_path = Path(tmp) / "input.json"
            input_path.write_text(json.dumps({"runtimeBytecode": _BYTECODE_WITH_SOLC_0_8_20}), encoding="utf-8")
            exit_code, out = self._run_cli([str(input_path), "--dataset", str(dataset_path)])
        self.assertEqual(exit_code, bcb.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "version_extracted")

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, bcb.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_bytecode_compiler_bugs_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["bytecode-compiler-bugs"], "bytecode_compiler_bugs")


if __name__ == "__main__":
    unittest.main()
