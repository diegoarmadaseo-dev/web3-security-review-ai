"""Tests for scripts/render_report.py (Subfase 1.2 - Report).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import score  # noqa: E402
import render_report  # noqa: E402

SC_CATEGORIES = ["SC%02d" % n for n in range(1, 11)]

KNOWN_TEMPLATE_TAGS = {
    "!doctype", "html", "head", "meta", "title", "style", "body",
    "h1", "h2", "h3", "p", "ul", "li", "table", "tr", "th", "td",
    "pre", "div", "strong", "code",
}


def _finding(**overrides):
    base = {
        "category": "SC01",
        "signature": "unprotected-admin-function",
        "severity": "HIGH",
        "confidence": "high",
        "status": "suspected",
        "locations": [{"file": "A.sol", "lineStart": 10, "lineEnd": 12, "contract": "A", "function": "setFee"}],
        "evidence": ["function setFee(uint f) public { fee = f; }"],
        "description": "La funcion no tiene control de acceso.",
        "recommendation": "Anadir un modifier onlyOwner.",
        "patch": None,
    }
    base.update(overrides)
    return base


def make_report(mode: str = "standard", findings=None) -> dict:
    coverage = [{"category": c, "status": "NOT_DETECTED"} for c in SC_CATEGORIES]
    findings = findings if findings is not None else [_finding()]
    for f in findings:
        if f.get("status") != "informational" and f.get("category") in SC_CATEGORIES:
            index = SC_CATEGORIES.index(f["category"])
            coverage[index]["status"] = "DETECTED"
    draft = {
        "generatedBy": "ai",
        "skillVersion": "1.0.0",
        "analysisEngineVersion": "1.0.0",
        "checklistVersion": "2026.1",
        "scoreVersion": "2026.1",
        "mode": mode,
        "language": "es",
        "compilerVersion": "0.8.20",
        "scriptsAvailable": True,
        "inputHash": "sha256:" + "a" * 64,
        "scope": {"completeness": "complete", "reasons": []},
        "categoryCoverage": coverage,
        "findings": findings,
        "limitations": ["Off-chain infrastructure was not assessed."],
        "riskIndicator": {"scoreStatus": "not_computed", "score": None, "band": None},
        "scoreStatus": "not_computed",
    }
    return score.score_report(draft)


class MarkdownRenderTests(unittest.TestCase):
    def test_mandatory_notice_is_present_verbatim(self):
        text = render_report.render_markdown(make_report())
        self.assertIn(render_report.MANDATORY_NOTICE_TITLE, text)
        self.assertIn("It is NOT:", text)
        self.assertIn("a formal security audit", text)
        self.assertIn("The absence of a reported finding does NOT mean that no vulnerability exists.", text)

    def test_finding_content_is_rendered(self):
        text = render_report.render_markdown(make_report())
        self.assertIn("La funcion no tiene control de acceso.", text)
        self.assertIn("Anadir un modifier onlyOwner.", text)
        self.assertIn("function setFee(uint f) public { fee = f; }", text)

    def test_clean_report_shows_not_detected_sentence(self):
        text = render_report.render_markdown(make_report(findings=[]))
        self.assertIn(render_report.NOT_DETECTED_NOTE, text)
        self.assertNotIn("No vulnerabilities found", text)

    def test_computed_score_shows_band_and_scope_note(self):
        text = render_report.render_markdown(make_report())
        self.assertIn("according to the analyzed scope", text)
        self.assertIn("Band: LOW", text)

    def test_low_band_carries_deployment_caveat(self):
        text = render_report.render_markdown(make_report(findings=[]))
        self.assertIn("does not mean that deployment is safe", text)

    def test_not_computed_score_shows_fixed_message_not_a_number(self):
        report = make_report(findings=[])
        report["riskIndicator"] = {"scoreStatus": "not_computed", "score": None, "band": None, "message": render_report.SCORE_UNAVAILABLE_FALLBACK}
        report["scoreStatus"] = "not_computed"
        text = render_report.render_markdown(report)
        self.assertIn(render_report.SCORE_UNAVAILABLE_FALLBACK, text)
        self.assertNotIn("Score:", text)

    def test_patch_always_carries_fixed_disclaimer_regardless_of_ai_text(self):
        finding = _finding(patch={"format": "unified-diff", "diff": "--- a/A.sol\n+++ b/A.sol\n"})
        report = make_report(mode="standard", findings=[finding])
        text = render_report.render_markdown(report)
        self.assertIn(render_report.PATCH_DISCLAIMER, text)

    def test_category_coverage_table_lists_all_ten(self):
        text = render_report.render_markdown(make_report())
        for category in SC_CATEGORIES:
            self.assertIn(category, text)

    def test_informational_finding_is_separated_from_real_findings(self):
        info = _finding(category="EXTRA-prompt-injection", signature="injection-attempt", severity="INFORMATIONAL", status="informational", description="Prompt injection attempt detected.")
        real = _finding()
        text = render_report.render_markdown(make_report(findings=[real, info]))
        self.assertIn("## Informational Notices", text)
        self.assertIn("Prompt injection attempt detected.", text)

    def test_rendering_is_deterministic(self):
        report = make_report()
        first = render_report.render_markdown(copy.deepcopy(report))
        second = render_report.render_markdown(copy.deepcopy(report))
        self.assertEqual(first, second)

    def test_executive_summary_is_rendered_when_present(self):
        report = make_report(mode="pro")
        report["executiveSummary"] = "Overall risk is low within the analyzed scope."
        text = render_report.render_markdown(report)
        self.assertIn("## Executive Summary", text)
        self.assertIn("Overall risk is low within the analyzed scope.", text)

    def test_executive_summary_section_absent_when_not_present(self):
        text = render_report.render_markdown(make_report())
        self.assertNotIn("## Executive Summary", text)

    def test_architecture_notes_are_rendered_when_present(self):
        report = make_report(mode="pro")
        report["architectureNotes"] = [{"title": "Upgrade surface", "description": "The proxy admin is a single EOA."}]
        text = render_report.render_markdown(report)
        self.assertIn("## Architecture Notes", text)
        self.assertIn("### Upgrade surface", text)
        self.assertIn("The proxy admin is a single EOA.", text)

    def test_architecture_notes_section_absent_when_not_present(self):
        text = render_report.render_markdown(make_report())
        self.assertNotIn("## Architecture Notes", text)


class HTMLRenderTests(unittest.TestCase):
    def test_html_refused_outside_pro_mode(self):
        for mode in ("quick", "standard"):
            with self.subTest(mode=mode):
                report = make_report(mode=mode)
                with self.assertRaises(render_report.ReportRenderError):
                    render_report.render_html(report)

    def test_html_renders_for_pro_mode(self):
        html_text = render_report.render_html(make_report(mode="pro"))
        self.assertIn("<html", html_text)
        self.assertIn(render_report.MANDATORY_NOTICE_TITLE, html_text)

    def test_html_is_self_contained_no_external_resources(self):
        html_text = render_report.render_html(make_report(mode="pro"))
        self.assertNotRegex(html_text, r"https?://")
        self.assertNotIn("<script src", html_text)
        self.assertNotIn("<link ", html_text)

    def test_html_escapes_adversarial_content_from_analyzed_code(self):
        malicious = _finding(
            evidence=["<script>alert(1)</script>"],
            description="Payload: <img src=x onerror=alert(2)>",
            patch={"format": "unified-diff", "diff": "<script>alert(3)</script>"},
        )
        html_text = render_report.render_html(make_report(mode="pro", findings=[malicious]))
        self.assertNotIn("<script>alert", html_text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)
        live_tags = set(re.findall(r"<\s*/?\s*([a-zA-Z0-9!-]+)", html_text))
        self.assertEqual(live_tags - KNOWN_TEMPLATE_TAGS, set())

    def test_html_lang_attribute_reflects_report_language(self):
        report = make_report(mode="pro")
        report["language"] = "it"
        html_text = render_report.render_html(report)
        self.assertIn('lang="it"', html_text)

    def test_html_defaults_lang_to_en_when_missing(self):
        report = make_report(mode="pro")
        del report["language"]
        html_text = render_report.render_html(report)
        self.assertIn('lang="en"', html_text)

    def test_executive_summary_is_rendered_in_html(self):
        report = make_report(mode="pro")
        report["executiveSummary"] = "Overall risk is low within the analyzed scope."
        html_text = render_report.render_html(report)
        self.assertIn("Executive Summary", html_text)
        self.assertIn("Overall risk is low within the analyzed scope.", html_text)

    def test_architecture_notes_are_rendered_in_html(self):
        report = make_report(mode="pro")
        report["architectureNotes"] = [{"title": "Upgrade surface", "description": "The proxy admin is a single EOA."}]
        html_text = render_report.render_html(report)
        self.assertIn("Architecture Notes", html_text)
        self.assertIn("Upgrade surface", html_text)

    def test_architecture_notes_escape_adversarial_content(self):
        report = make_report(mode="pro")
        report["architectureNotes"] = [{"title": "<script>alert(4)</script>", "description": "Payload: <img src=x onerror=alert(5)>"}]
        html_text = render_report.render_html(report)
        self.assertNotIn("<script>alert", html_text)
        self.assertIn("&lt;script&gt;alert(4)&lt;/script&gt;", html_text)
        live_tags = set(re.findall(r"<\s*/?\s*([a-zA-Z0-9!-]+)", html_text))
        self.assertEqual(live_tags - KNOWN_TEMPLATE_TAGS, set())


class ModesConfigFailsLoudlyTests(unittest.TestCase):
    """A broken config/modes.json must stop HTML rendering, not guess a default."""

    def test_broken_modes_config_propagates_from_render_html(self):
        report = make_report(mode="pro")
        with mock.patch.object(render_report, "load_modes_config", side_effect=render_report.ModesConfigError("boom")):
            with self.assertRaises(render_report.ModesConfigError):
                render_report.render_html(report)

    def test_cli_reports_broken_modes_config_as_a_clean_error_envelope(self):
        old = sys.stdin
        sys.stdin = io.StringIO(json.dumps(make_report(mode="pro")))
        buf = io.StringIO()
        try:
            with mock.patch.object(render_report, "load_modes_config", side_effect=render_report.ModesConfigError("boom")):
                with contextlib.redirect_stdout(buf):
                    exit_code = render_report.main(["--format", "html"])
        finally:
            sys.stdin = old
        self.assertEqual(exit_code, render_report.EXIT_FAILED)
        self.assertFalse(json.loads(buf.getvalue())["ok"])


class CLITests(unittest.TestCase):
    def _run(self, stdin_text, argv):
        import io as _io
        old = sys.stdin
        sys.stdin = _io.StringIO(stdin_text)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exit_code = render_report.main(argv)
        finally:
            sys.stdin = old
        return exit_code, buf.getvalue()

    def test_invalid_json_returns_error_envelope(self):
        exit_code, out = self._run("not json", [])
        self.assertEqual(exit_code, render_report.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])

    def test_markdown_via_stdin_default_format(self):
        exit_code, out = self._run(json.dumps(make_report()), [])
        self.assertEqual(exit_code, render_report.EXIT_OK)
        self.assertIn("# Automated AI-Assisted Smart Contract Security Review", out)

    def test_html_format_refused_for_non_pro_via_cli(self):
        exit_code, out = self._run(json.dumps(make_report(mode="standard")), ["--format", "html"])
        self.assertEqual(exit_code, render_report.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])

    def test_html_format_succeeds_for_pro_via_cli(self):
        exit_code, out = self._run(json.dumps(make_report(mode="pro")), ["--format", "html"])
        self.assertEqual(exit_code, render_report.EXIT_OK)
        self.assertIn("<!doctype html>", out)


class OnchainLocationPrefixTests(unittest.TestCase):
    """V2.8 Block 2 (C-06): an onchain-sourced location must surface its
    chain identity prominently, so a reader scanning a report never
    mistakes two different chains' findings for the same contract."""

    ADDR = "0xabcdef0123456789012345678901234567890123"

    def test_onchain_location_gets_a_chain_prefix(self):
        loc = {"file": "onchain:/1/%s/Vault.sol" % self.ADDR, "contract": "Vault", "function": "withdraw", "lineStart": 12}
        text = render_report._location_text(loc)
        self.assertTrue(text.startswith("[chain ethereum (1)"))
        # Full original text is still present - purely additive, nothing removed.
        self.assertIn("onchain:/1/%s/Vault.sol#Vault#withdraw (line 12)" % self.ADDR, text)

    def test_local_location_gets_no_prefix(self):
        # Negative control: a non-onchain finding's rendering must be
        # byte-for-byte unaffected by this change.
        loc = {"file": "Vault.sol", "contract": "Vault", "function": "withdraw", "lineStart": 12}
        text = render_report._location_text(loc)
        self.assertFalse(text.startswith("[chain"))
        self.assertEqual(text, "Vault.sol#Vault#withdraw (line 12)")

    def test_unknown_chain_falls_back_to_numeric_id(self):
        loc = {"file": "onchain:/999999999/%s/Vault.sol" % self.ADDR, "contract": "Vault"}
        text = render_report._location_text(loc)
        self.assertTrue(text.startswith("[chain 999999999"))

    def test_two_different_chains_render_visibly_differently(self):
        # The core risk this fixes: same file#contract#function suffix,
        # different chains - must not look identical at a glance.
        loc1 = {"file": "onchain:/1/%s/Vault.sol" % self.ADDR, "contract": "Vault"}
        loc2 = {"file": "onchain:/137/%s/Vault.sol" % self.ADDR, "contract": "Vault"}
        text1, text2 = render_report._location_text(loc1), render_report._location_text(loc2)
        self.assertNotEqual(text1.split("]")[0], text2.split("]")[0])

    def test_broken_chain_lookup_never_crashes_rendering(self):
        # Adversarial: this is a display-only helper - any lookup failure
        # must degrade to the bare chainId, never raise.
        import chains
        with mock.patch.object(chains, "get_chain_capabilities", side_effect=RuntimeError("boom")):
            loc = {"file": "onchain:/1/%s/Vault.sol" % self.ADDR, "contract": "Vault"}
            text = render_report._location_text(loc)
        self.assertTrue(text.startswith("[chain 1"))

    def test_malformed_onchain_path_returns_none_prefix_not_a_crash(self):
        self.assertIsNone(render_report._onchain_location_prefix("onchain:/not-a-number/0xabc/Vault.sol"))
        self.assertIsNone(render_report._onchain_location_prefix("onchain:/"))


if __name__ == "__main__":
    unittest.main()
