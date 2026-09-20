"""Tests for scripts/compiler_bugs.py (V3 Block 4, C2, docs/decisiones.md
D-072): deterministic known-Solidity-compiler-bug cross-reference against a
bundled, offline dataset.

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

import compiler_bugs as cb  # noqa: E402

# A small, self-contained fixture dataset - tests are isolated from the
# real bundled config/solc-known-bugs.json's actual content, which may be
# replaced with a verified snapshot later without breaking these tests.
FIXTURE_DATASET = {
    "datasetVersion": "test-fixture-1",
    "sourceUrl": "https://example.invalid/bugs",
    "provenance": "test fixture, not the real bundled dataset",
    "bugs": [
        {
            "uid": "TEST-0001",
            "name": "Fixture bug",
            "introducedVersion": "0.5.0",
            "fixedVersion": "0.5.10",
            "severity": "medium",
            "summary": "A fixture entry for boundary testing.",
            "verified": True,
        }
    ],
}


class CheckCompilerVersionTests(unittest.TestCase):
    def test_boundary_introduced_version_is_affected_inclusive(self):
        result = cb.check_compiler_version("0.5.0", FIXTURE_DATASET)
        self.assertEqual(result["status"], "affected")
        self.assertEqual(result["matches"][0]["uid"], "TEST-0001")

    def test_boundary_fixed_version_is_not_affected_exclusive(self):
        result = cb.check_compiler_version("0.5.10", FIXTURE_DATASET)
        self.assertEqual(result["status"], "not_affected")

    def test_positive_version_inside_range_is_affected(self):
        result = cb.check_compiler_version("0.5.5", FIXTURE_DATASET)
        self.assertEqual(result["status"], "affected")

    def test_negative_version_before_introduced_is_not_affected(self):
        result = cb.check_compiler_version("0.4.26", FIXTURE_DATASET)
        self.assertEqual(result["status"], "not_affected")

    def test_negative_version_well_after_fixed_is_not_affected(self):
        result = cb.check_compiler_version("0.8.20", FIXTURE_DATASET)
        self.assertEqual(result["status"], "not_affected")

    def test_semver_numeric_comparison_not_string_comparison(self):
        # 0.5.9 vs 0.5.10 - a naive string compare would get this backwards.
        wide_dataset = {"bugs": [{"uid": "X", "name": "n", "introducedVersion": "0.5.9", "fixedVersion": "0.5.11", "severity": "low", "summary": "s", "verified": True}]}
        self.assertEqual(cb.check_compiler_version("0.5.10", wide_dataset)["status"], "affected")
        self.assertEqual(cb.check_compiler_version("0.5.9", wide_dataset)["status"], "affected")
        self.assertEqual(cb.check_compiler_version("0.5.11", wide_dataset)["status"], "not_affected")

    def test_unknown_unparseable_version_format(self):
        for bad in ["not-a-version", "0.8", "1.2.3.4", "", None]:
            with self.subTest(bad=bad):
                result = cb.check_compiler_version(bad, FIXTURE_DATASET)
                self.assertEqual(result["status"], "unparseable_version")
                self.assertEqual(result["matches"], [])

    def test_malformed_dataset_entry_is_skipped_never_guessed(self):
        broken = {"bugs": [{"uid": "X", "introducedVersion": "not-a-version", "fixedVersion": "0.9.0", "severity": "low", "summary": "s", "verified": True}]}
        result = cb.check_compiler_version("0.5.0", broken)
        self.assertEqual(result["status"], "not_affected")

    def test_matched_entry_echoes_verified_flag(self):
        unverified = {"bugs": [{"uid": "X", "name": "n", "introducedVersion": "0.5.0", "fixedVersion": "0.6.0", "severity": "low", "summary": "s", "verified": False}]}
        result = cb.check_compiler_version("0.5.5", unverified)
        self.assertFalse(result["matches"][0]["verified"])

    def test_never_mutates_dataset(self):
        before = json.loads(json.dumps(FIXTURE_DATASET))
        cb.check_compiler_version("0.5.5", FIXTURE_DATASET)
        self.assertEqual(FIXTURE_DATASET, before)


class ComputeCompilerBugReportTests(unittest.TestCase):
    def test_provenance_and_dataset_version_echoed(self):
        result = cb.compute_compiler_bug_report({"compilerVersion": "0.5.5"}, FIXTURE_DATASET)
        self.assertEqual(result["datasetVersion"], "test-fixture-1")
        self.assertEqual(result["datasetSourceUrl"], "https://example.invalid/bugs")

    def test_real_bundled_dataset_loads_without_error(self):
        # Integration sanity check against the actual shipped file.
        dataset = cb.load_known_bugs_dataset()
        self.assertIsInstance(dataset.get("bugs"), list)
        result = cb.compute_compiler_bug_report({"compilerVersion": "0.8.20"}, dataset)
        self.assertIn(result["status"], ("affected", "not_affected"))
        self.assertTrue(dataset.get("datasetVersion"))

    def test_malformed_missing_compiler_version_raises(self):
        with self.assertRaises(cb.CompilerBugsError):
            cb.compute_compiler_bug_report({}, FIXTURE_DATASET)

    def test_malformed_dataset_missing_bugs_raises(self):
        with self.assertRaises(cb.CompilerBugsError):
            cb.compute_compiler_bug_report({"compilerVersion": "0.5.5"}, {"datasetVersion": "x"})


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cb.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end_with_custom_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset_path = Path(tmp) / "dataset.json"
            dataset_path.write_text(json.dumps(FIXTURE_DATASET), encoding="utf-8")
            input_path = Path(tmp) / "input.json"
            input_path.write_text(json.dumps({"compilerVersion": "0.5.5"}), encoding="utf-8")
            exit_code, out = self._run_cli([str(input_path), "--dataset", str(dataset_path)])
        self.assertEqual(exit_code, cb.EXIT_OK)
        self.assertEqual(json.loads(out)["status"], "affected")

    def test_cli_default_dataset_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"compilerVersion": "0.7.0"}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, cb.EXIT_OK)
        payload = json.loads(out)
        self.assertIn(payload["status"], ("affected", "not_affected"))

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, cb.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_compiler_bugs_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["compiler-bugs"], "compiler_bugs")


if __name__ == "__main__":
    unittest.main()
