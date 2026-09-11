"""Tests for Subfase 2.1 - Skill runtime: SKILL.md and references/guardrails.md.

These are consistency checks on policy documents, not unit tests of executable
logic: they guard against the frontmatter breaking, the activation phrases
disappearing, forbidden vocabulary creeping in outside its one approved
negation use, mode limits being hardcoded a second time, and - most
importantly - the mandatory report notice duplicated into guardrails.md (for
the manual fallback path) drifting away from the one baked into
scripts/render_report.py.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor"
SCRIPTS_DIR = SKILL_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import render_report  # noqa: E402


def _parse_minimal_frontmatter(text: str) -> dict:
    """Mirrors Capafy's own frontmatter reader (see docs/capafy-notas.md): only
    name/description are recognized, and the first colon on the line splits
    key from value - so this must stay in sync with how SKILL.md is actually
    written, not with a full YAML parser's tolerance."""
    assert text.startswith("---\n"), "SKILL.md must start with a frontmatter block"
    end = text.index("\n---\n", 4)
    front = text[4:end]
    metadata = {}
    for line in front.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or line[:1].isspace():
            continue
        if ":" not in line:
            continue
        key, _, remainder = line.partition(":")
        key = key.strip()
        if key not in ("name", "description"):
            continue
        metadata[key] = remainder.strip()
    return metadata


def _extract_fenced_block(markdown: str, heading: str) -> str:
    """Returns the content of the first ```text fenced block following `heading`."""
    heading_index = markdown.index(heading)
    fence_start = markdown.index("```text", heading_index) + len("```text")
    fence_end = markdown.index("```", fence_start)
    return markdown[fence_start:fence_end].strip("\n")


def _read(relpath: str) -> str:
    return (SKILL_DIR / relpath).read_text(encoding="utf-8")


class SkillFrontmatterTests(unittest.TestCase):
    def test_frontmatter_has_name_and_description(self):
        metadata = _parse_minimal_frontmatter(_read("SKILL.md"))
        self.assertEqual(metadata["name"], "web3-auditor")
        self.assertTrue(metadata["description"])

    def test_description_mentions_all_four_activation_phrases(self):
        description = _parse_minimal_frontmatter(_read("SKILL.md"))["description"].lower()
        for phrase in (
            "audit smart contract",
            "review smart contract",
            "solidity security check",
            "smart contract security review",
        ):
            self.assertIn(phrase, description)

    def test_description_does_not_claim_certification_or_guarantee(self):
        # "certification"/"guarantee"/"audit" appear once, in the sanctioned negation form
        # ("This is not a formal audit, certification, or guarantee of security") - the same
        # Level-B pattern already used by guardrails.md and render_report.py's own notice.
        # What must never appear is one of these as a bare positive claim.
        description = _parse_minimal_frontmatter(_read("SKILL.md"))["description"].lower()
        for forbidden in ("certified", "guaranteed", "audited", "is a formal audit", "is a certification"):
            self.assertNotIn(forbidden, description)

    def test_description_has_no_mid_value_colon_space(self):
        # A ": " inside a plain YAML scalar value risks confusing a real YAML parser.
        description = _parse_minimal_frontmatter(_read("SKILL.md"))["description"]
        self.assertNotIn(": ", description)


class DisclaimerConsistencyTests(unittest.TestCase):
    """The mandatory report notice must stay byte-identical between
    guardrails.md (for the manual fallback) and render_report.py (the normal
    path) - see docs/decisiones.md, D-021/section on the duplicated disclaimer."""

    def test_mandatory_notice_matches_render_report_constant(self):
        guardrails = _read("references/guardrails.md")
        block = _extract_fenced_block(guardrails, "## 8. Mandatory report notice")
        expected = "\n".join(
            [render_report.MANDATORY_NOTICE_TITLE, "", *render_report.MANDATORY_NOTICE_LINES]
        ).strip("\n")
        self.assertEqual(block, expected)

    def test_pre_use_warning_fenced_block_is_present(self):
        guardrails = _read("references/guardrails.md")
        block = _extract_fenced_block(guardrails, "## 7. Pre-use warning")
        self.assertIn("automated, AI-assisted smart contract security review", block)
        self.assertIn("Do not", block)

    def test_patch_disclaimer_sentence_matches_render_report_constant(self):
        self.assertIn(render_report.PATCH_DISCLAIMER, _read("references/guardrails.md"))

    def test_score_unavailable_message_matches_render_report_constant(self):
        self.assertIn(render_report.SCORE_UNAVAILABLE_FALLBACK, _read("references/guardrails.md"))

    def test_not_detected_sentence_matches_render_report_constant(self):
        self.assertIn(render_report.NOT_DETECTED_NOTE, _read("references/guardrails.md"))


class GuardrailsContentTests(unittest.TestCase):
    def test_score_authority_rule_is_stated(self):
        text = _read("references/guardrails.md")
        self.assertIn("`scripts/score.py` is the only authority for `riskIndicator`", text)

    def test_data_isolation_rule_is_stated(self):
        text = _read("references/guardrails.md")
        self.assertIn("BEGIN UNTRUSTED SOURCE DATA", text)
        self.assertIn("never an instruction", text)

    def test_secrets_never_asked_for_rule_is_stated(self):
        text = _read("references/guardrails.md")
        self.assertIn("Never ask the user for a private key", text)

    def test_no_bare_forbidden_claim_outside_the_fixed_negation_notices(self):
        # Section 3 legitimately *lists* banned phrases like "100% secure" as a blocklist -
        # that is different from this file itself asserting one as a claim. Check for the
        # claim shape, not the bare phrase.
        text = _read("references/guardrails.md").lower()
        for claim in (
            "this contract is safe to deploy",
            "is guaranteed secure",
            "this contract is 100% secure",
            "this code is vulnerability-free",
        ):
            self.assertNotIn(claim, text)

    def test_mode_limit_numbers_are_not_hardcoded_here(self):
        # Only config/modes.json may state these numbers (D-023/section 6).
        text = _read("references/guardrails.md")
        for number in ("500", "1500", "1,500", "4000", "4,000"):
            self.assertNotIn(number, text)

    def test_stop_before_analyzing_on_limit_exceeded_is_stated(self):
        text = _read("references/guardrails.md")
        self.assertIn("LOC_LIMIT_EXCEEDED", text)
        self.assertIn("stop before analyzing", text.lower())

    def test_modes_config_is_named_as_the_single_source_of_truth(self):
        text = _read("references/guardrails.md")
        self.assertIn("config/modes.json", text)
        self.assertIn("fails explicitly", text)


class SkillFlowContentTests(unittest.TestCase):
    def test_skill_references_all_four_scripts(self):
        text = _read("SKILL.md")
        for script in ("preprocess.py", "score.py", "validate_report.py", "render_report.py"):
            self.assertIn(script, text)

    def test_skill_forbids_hand_editing_score_output(self):
        text = _read("SKILL.md").lower()
        self.assertIn("do not edit", text)

    def test_skill_caps_validation_retries_at_two(self):
        text = _read("SKILL.md")
        self.assertIn("2 retry attempts", text)

    def test_skill_gates_html_through_modes_config(self):
        text = _read("SKILL.md")
        self.assertIn("`config/modes.json` sets `allowHtmlReport: true`", text)
        self.assertIn("refuses `--format html` for a mode that doesn't", text)

    def test_skill_does_not_hardcode_mode_limit_numbers(self):
        text = _read("SKILL.md")
        for number in ("500", "1500", "1,500", "4000", "4,000"):
            self.assertNotIn(number, text)

    def test_skill_documents_pro_only_report_fields(self):
        text = _read("SKILL.md")
        self.assertIn("executiveSummary", text)
        self.assertIn("architectureNotes", text)
        self.assertIn("allowExecutiveSummary", text)
        self.assertIn("allowArchitectureChecks", text)

    def test_skill_references_modes_config_as_source_of_truth(self):
        text = _read("SKILL.md")
        self.assertIn("config/modes.json", text)


if __name__ == "__main__":
    unittest.main()
