"""Tests for scripts/evidence_locality.py (V3 Block 2, R3, docs/decisiones.md
D-069): deterministic evidence-locality check over already-drafted findings.

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

import evidence_locality as el  # noqa: E402

SOURCE = (
    "// SPDX-License-Identifier: MIT\n"      # 1
    "pragma solidity 0.8.20;\n"               # 2
    "contract A {\n"                          # 3
    "    uint256 public balance;\n"           # 4
    "    function withdraw() external {\n"    # 5
    "        uint256 amount = balance;\n"     # 6
    "        balance = 0;\n"                  # 7
    "        payable(msg.sender).transfer(amount);\n"  # 8
    "    }\n"                                 # 9
    "}\n"                                     # 10
)


def make_finding(evidence, file="A.sol", line_start=6, line_end=6, signature="f"):
    return {
        "signature": signature,
        "evidence": evidence,
        "locations": [{"file": file, "contract": "A", "function": "withdraw", "lineStart": line_start, "lineEnd": line_end}],
    }


def make_multi_location_finding(evidence, locations, signature="f"):
    return {"signature": signature, "evidence": evidence, "locations": locations}


class VerifyFindingEvidenceTests(unittest.TestCase):
    """Positive/negative/adversarial coverage for the per-finding check."""

    def test_positive_evidence_at_claimed_location_verifies(self):
        result = el.verify_finding_evidence(make_finding(["uint256 amount = balance;"]), {"A.sol": SOURCE})
        self.assertEqual(result["status"], "verified")
        self.assertIsNone(result["reason"])

    def test_positive_multiple_evidence_lines_all_verify(self):
        result = el.verify_finding_evidence(
            make_finding(["uint256 amount = balance;", "balance = 0;"], line_start=6, line_end=7), {"A.sol": SOURCE}
        )
        self.assertEqual(result["status"], "verified")

    def test_positive_whitespace_run_differences_still_verify(self):
        # Collapsed indentation/extra spacing must never cause a false
        # mismatch - but this is NOT a fuzzy/semantic match: only
        # whitespace RUNS are collapsed, tokens themselves (e.g. spacing
        # around an operator) must still be genuinely present.
        result = el.verify_finding_evidence(make_finding(["uint256    amount   =   balance;"]), {"A.sol": SOURCE})
        self.assertEqual(result["status"], "verified")

    def test_negative_removing_meaningful_whitespace_is_not_treated_as_equal(self):
        # "amount=balance" (no spaces around =) is a different literal
        # string than the source's "amount = balance" - normalization only
        # collapses whitespace RUNS, it never inserts/removes whitespace
        # that changes token boundaries, so this must NOT verify.
        result = el.verify_finding_evidence(make_finding(["uint256 amount=balance;"]), {"A.sol": SOURCE})
        self.assertNotEqual(result["status"], "verified")

    def test_positive_tolerance_window_absorbs_a_small_line_offset(self):
        # Claimed line is off by 2 (real line is 6) - within the default
        # +/-3 tolerance, so this still counts as "near" the claimed spot.
        result = el.verify_finding_evidence(
            make_finding(["uint256 amount = balance;"], line_start=8, line_end=8), {"A.sol": SOURCE}
        )
        self.assertEqual(result["status"], "verified")

    def test_negative_fabricated_evidence_not_in_file_at_all(self):
        result = el.verify_finding_evidence(make_finding(["this string is not in the file"]), {"A.sol": SOURCE})
        self.assertEqual(result["status"], "fabricated")
        self.assertIn("do not appear anywhere", result["reason"])

    def test_negative_location_mismatch_evidence_real_but_far_from_claimed_line(self):
        # "pragma solidity 0.8.20;" is real (line 2) but the finding claims
        # line 6, far outside the +/-3 tolerance window.
        result = el.verify_finding_evidence(
            make_finding(["pragma solidity 0.8.20;"], line_start=6, line_end=6), {"A.sol": SOURCE}
        )
        self.assertEqual(result["status"], "location_mismatch")

    def test_adversarial_one_real_one_fabricated_evidence_line_is_fabricated_not_verified(self):
        # A finding must never be treated as verified just because SOME of
        # its evidence is real - one invented line is enough to flag it.
        result = el.verify_finding_evidence(
            make_finding(["uint256 amount = balance;", "totally invented line"]), {"A.sol": SOURCE}
        )
        self.assertEqual(result["status"], "fabricated")

    def test_adversarial_fabricated_outranks_location_mismatch(self):
        # One evidence line real-but-misplaced, another fully invented -
        # the stronger signal (fabricated) must win, never be masked.
        result = el.verify_finding_evidence(
            make_finding(["pragma solidity 0.8.20;", "totally invented line"], line_start=6, line_end=6),
            {"A.sol": SOURCE},
        )
        self.assertEqual(result["status"], "fabricated")

    def test_unverifiable_missing_source_file(self):
        result = el.verify_finding_evidence(make_finding(["x"], file="Missing.sol"), {"A.sol": SOURCE})
        self.assertEqual(result["status"], "unverifiable")

    def test_unverifiable_no_evidence(self):
        finding = make_finding([])
        result = el.verify_finding_evidence(finding, {"A.sol": SOURCE})
        self.assertEqual(result["status"], "unverifiable")

    def test_unverifiable_no_locations(self):
        finding = make_finding(["uint256 amount = balance;"])
        finding["locations"] = []
        result = el.verify_finding_evidence(finding, {"A.sol": SOURCE})
        self.assertEqual(result["status"], "unverifiable")

    def test_never_raises_on_malformed_finding_shape(self):
        # Adversarial: malformed input is a RESULT, never an exception -
        # one bad finding must never abort a whole-report check.
        for bad in [{}, {"evidence": "not-a-list"}, {"evidence": [1, 2], "locations": [{"file": "A.sol"}]}]:
            with self.subTest(bad=bad):
                result = el.verify_finding_evidence(bad, {"A.sol": SOURCE})
                self.assertIn(result["status"], ("unverifiable", "fabricated", "verified", "location_mismatch"))

    def test_never_mutates_the_finding_or_source(self):
        finding = make_finding(["uint256 amount = balance;"])
        original = json.loads(json.dumps(finding))
        sources = {"A.sol": SOURCE}
        el.verify_finding_evidence(finding, sources)
        self.assertEqual(finding, original)
        self.assertEqual(sources["A.sol"], SOURCE)

    def test_single_location_finding_still_verifies_exactly_as_before(self):
        # Explicit regression coverage for the multi-location generalization:
        # a finding with exactly one location (the common case) must behave
        # identically to the original locations[0]-only implementation.
        result = el.verify_finding_evidence(
            make_finding(["uint256 amount = balance;", "balance = 0;"], line_start=6, line_end=7), {"A.sol": SOURCE}
        )
        self.assertEqual(result["status"], "verified")

    def test_valid_match_in_locations_index_one_verifies(self):
        # Evidence doesn't fit location[0]'s window at all, but does fit
        # location[1]'s - a finding must never be penalized just because
        # its correct location isn't listed first.
        finding = make_multi_location_finding(
            ["uint256 amount = balance;"],
            [
                {"file": "A.sol", "lineStart": 2, "lineEnd": 2},  # window ~1-5, does not reach line 6
                {"file": "A.sol", "lineStart": 6, "lineEnd": 6},  # window ~3-9, reaches line 6
            ],
        )
        result = el.verify_finding_evidence(finding, {"A.sol": SOURCE})
        self.assertEqual(result["status"], "verified")

    def test_all_locations_mismatch_yields_location_mismatch_not_verified(self):
        # Evidence is real (line 6) but neither declared location's window
        # reaches it - every location individually mismatches, so the
        # overall result must be location_mismatch, never a false verified.
        finding = make_multi_location_finding(
            ["uint256 amount = balance;"],
            [
                {"file": "A.sol", "lineStart": 1, "lineEnd": 1},
                {"file": "A.sol", "lineStart": 2, "lineEnd": 2},
            ],
        )
        result = el.verify_finding_evidence(finding, {"A.sol": SOURCE})
        self.assertEqual(result["status"], "location_mismatch")

    def test_fabricated_evidence_outranks_a_verifiable_second_location(self):
        # One evidence line would verify against location[0]; the other is
        # entirely invented. Fabricated must still win overall - checking
        # more locations must never let a fabricated line slip through.
        finding = make_multi_location_finding(
            ["uint256 amount = balance;", "totally invented line"],
            [
                {"file": "A.sol", "lineStart": 6, "lineEnd": 6},
                {"file": "A.sol", "lineStart": 7, "lineEnd": 7},
            ],
        )
        result = el.verify_finding_evidence(finding, {"A.sol": SOURCE})
        self.assertEqual(result["status"], "fabricated")


class VerifyReportEvidenceTests(unittest.TestCase):
    def test_one_result_per_finding_same_order(self):
        findings = [make_finding(["uint256 amount = balance;"], signature="a"), make_finding(["fabricated"], signature="b")]
        results = el.verify_report_evidence(findings, {"A.sol": SOURCE})
        self.assertEqual([r["signature"] for r in results], ["a", "b"])
        self.assertEqual([r["status"] for r in results], ["verified", "fabricated"])

    def test_non_dict_finding_entry_yields_unverifiable_never_crashes(self):
        results = el.verify_report_evidence([None, "not-a-dict"], {"A.sol": SOURCE})
        self.assertEqual([r["status"] for r in results], ["unverifiable", "unverifiable"])

    def test_findings_not_a_list_raises(self):
        with self.assertRaises(el.EvidenceLocalityError):
            el.verify_report_evidence("not-a-list", {"A.sol": SOURCE})

    def test_source_files_not_a_dict_raises(self):
        with self.assertRaises(el.EvidenceLocalityError):
            el.verify_report_evidence([], ["not-a-dict"])

    def test_source_files_with_non_string_value_raises(self):
        with self.assertRaises(el.EvidenceLocalityError):
            el.verify_report_evidence([], {"A.sol": 123})

    def test_empty_findings_yields_empty_results(self):
        self.assertEqual(el.verify_report_evidence([], {}), [])


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = el.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({
                "findings": [make_finding(["uint256 amount = balance;"]), make_finding(["fabricated line"])],
                "sourceFiles": {"A.sol": SOURCE},
            }), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, el.EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["verifiedCount"], 1)
        self.assertEqual(payload["flaggedCount"], 1)
        self.assertEqual(len(payload["results"]), 2)

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps({"findings": [], "sourceFiles": {}}))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, el.EXIT_OK)
        self.assertEqual(json.loads(out)["results"], [])

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, el.EXIT_FAILED)
        envelope = json.loads(out)
        self.assertFalse(envelope["ok"])

    def test_cli_tolerance_lines_flag_is_honored(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            # Real line is 6; claimed line 2 is 4 lines off - outside a
            # tightened tolerance of 1, so it must now mismatch.
            p.write_text(json.dumps({
                "findings": [make_finding(["uint256 amount = balance;"], line_start=2, line_end=2)],
                "sourceFiles": {"A.sol": SOURCE},
            }), encoding="utf-8")
            exit_code, out = self._run_cli([str(p), "--tolerance-lines", "1"])
        self.assertEqual(json.loads(out)["results"][0]["status"], "location_mismatch")


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_verify_evidence_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["verify-evidence"], "evidence_locality")


if __name__ == "__main__":
    unittest.main()
