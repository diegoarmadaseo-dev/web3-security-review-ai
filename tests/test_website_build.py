"""Tests for website/build_site.py (V2.12 - Static marketing/pricing/docs
site + CLI reference, docs/decisiones.md D-067, capabilities W-01/W-02/W-04).

Covers: pricing/config drift and public-facing (commercial-claims) security,
per the explicit V2.12 IMPLEMENT ONLY requirement.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = REPO_ROOT / "website"
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_site as bs  # noqa: E402
from preprocess import load_modes_config  # noqa: E402
import cli  # noqa: E402

# Same Level-A prohibited-term list docs/commercial-claims.md's own commit
# procedure greps for - reused verbatim, never re-derived, so this test can
# never silently drift from the actual compliance policy.
LEVEL_A_TERMS = [
    "certified", "certificacion", "certificación", "audited", "audit completed",
    "complete audit", "professional audit", "official", "safe to deploy",
    "guaranteed", "100% secure", "fully secure", "vulnerability-free",
    "no vulnerabilities", "no security issues", "production-ready",
    "zero retention", "no logs", "never stored", "private by default",
    "deploy with confidence", "secure your contract",
    "eliminate vulnerabilities", "audit your contract",
]


class TierComparisonDriftTests(unittest.TestCase):
    """Pricing/config drift (explicit requirement): the tier table must be a
    live function of config/modes.json, never a hardcoded second copy."""

    def test_reflects_the_real_current_modes_json(self):
        modes_config = load_modes_config()
        tiers = bs.build_tier_comparison(modes_config)
        self.assertEqual({t["mode"] for t in tiers}, set(modes_config["modes"].keys()))
        for tier in tiers:
            real_rules = modes_config["modes"][tier["mode"]]
            for key, _label in bs._FEATURE_LABELS:
                self.assertEqual(tier["features"][key], real_rules.get(key), "%s.%s drifted" % (tier["mode"], key))

    def test_reflects_an_edited_copy_not_a_cached_snapshot(self):
        # Proves the function is a live transform, not a value baked in at
        # import time - mutate a COPY of the config and confirm it shows up.
        modes_config = load_modes_config()
        edited = json.loads(json.dumps(modes_config))
        edited["modes"]["standard"]["allowHtmlReport"] = True
        edited["modes"]["standard"]["maxEffectiveLoc"] = 999999
        tiers = bs.build_tier_comparison(edited)
        standard = next(t for t in tiers if t["mode"] == "standard")
        self.assertTrue(standard["features"]["allowHtmlReport"])
        self.assertEqual(standard["features"]["maxEffectiveLoc"], 999999)

    def test_preferred_order_with_a_hypothetical_extra_mode_never_drops_it(self):
        modes_config = load_modes_config()
        edited = json.loads(json.dumps(modes_config))
        edited["modes"]["enterprise-preview"] = dict(edited["modes"]["pro"])
        tiers = bs.build_tier_comparison(edited)
        self.assertIn("enterprise-preview", [t["mode"] for t in tiers])
        self.assertEqual([t["mode"] for t in tiers[:3]], ["quick", "standard", "pro"])

    def test_malformed_modes_config_raises_never_guesses(self):
        with self.assertRaises(bs.BuildSiteError):
            bs.build_tier_comparison({"modes": "not-a-dict"})

    def test_no_price_field_exists_anywhere_in_tier_data(self):
        modes_config = load_modes_config()
        tiers = bs.build_tier_comparison(modes_config)
        serialized = json.dumps(tiers).lower()
        self.assertNotIn("price", serialized)
        self.assertNotIn("$", serialized)
        self.assertNotIn("cycle", serialized)


class CliReferenceDriftTests(unittest.TestCase):
    def test_every_cli_command_is_represented(self):
        entries = bs.collect_cli_reference()
        self.assertEqual({e["command"] for e in entries}, set(cli.COMMANDS.keys()))

    def test_help_text_matches_the_real_parser_output_live(self):
        # Adversarial: prove this isn't hand-typed prose by cross-checking
        # against a freshly-built parser for one representative command.
        import pr_gate
        entries = bs.collect_cli_reference()
        pr_gate_entry = next(e for e in entries if e["command"] == "pr-gate")
        self.assertEqual(pr_gate_entry["help"], pr_gate.build_arg_parser().format_help())

    def test_preprocess_and_analyze_pipeline_help_render_without_error(self):
        # These two need modes_config injected into build_arg_parser(); a
        # regression here would silently produce an empty/broken doc page.
        entries = bs.collect_cli_reference()
        for command in ("preprocess", "analyze-pipeline"):
            entry = next(e for e in entries if e["command"] == command)
            self.assertIn("usage:", entry["help"])


class HtmlDocumentStructureTests(unittest.TestCase):
    """V2.12 FIX W-01 ONLY: every generated page must be a complete,
    navigable HTML document, never a bare content fragment."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = bs.build_site(self._tmp.name, capafy_listing_url="https://example-placeholder.invalid/x")
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items()}

    def test_every_page_starts_with_doctype_html(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertTrue(html.lower().startswith("<!doctype html>"), html[:50])

    def test_every_page_declares_english_lang(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('<html lang="en">', html)

    def test_every_page_has_head_with_charset_and_viewport(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn("<head>", html)
                self.assertIn('<meta charset="utf-8">', html)
                self.assertIn('name="viewport"', html)

    def test_every_page_has_a_title_and_meta_description(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertRegex(html, r"<title>[^<]+</title>")
                self.assertIn('name="description"', html)

    def test_titles_are_unique_across_pages(self):
        titles = [re.search(r"<title>([^<]+)</title>", html).group(1) for html in self.pages.values()]
        self.assertEqual(len(titles), len(set(titles)), titles)

    def test_meta_descriptions_are_unique_across_pages(self):
        descriptions = [re.search(r'name="description" content="([^"]+)"', html).group(1) for html in self.pages.values()]
        self.assertEqual(len(descriptions), len(set(descriptions)), descriptions)

    def test_every_page_links_to_the_other_two_home_pricing_docs(self):
        all_names = set(self.pages.keys())
        for name, html in self.pages.items():
            with self.subTest(page=name):
                for other in all_names - {name}:
                    self.assertIn('href="%s"' % other, html, "%s is missing a link to %s" % (name, other))

    def test_docs_page_has_a_cta_back_toward_pricing(self):
        self.assertIn('href="pricing.html"', self.pages["docs.html"])

    def test_wrapping_preserves_existing_body_content_byte_for_byte(self):
        # The fix must be purely additive around content - claims/pricing/
        # CLI text themselves are unchanged.
        self.assertIn(bs.POSITIONING_HEADLINE, self.pages["index.html"])
        self.assertIn(bs.NOT_AN_AUDIT_NOTE, self.pages["index.html"])
        self.assertIn("tier-comparison", self.pages["pricing.html"])
        self.assertIn("cli-command", self.pages["docs.html"])

    def test_page_still_parses_as_one_html_document_not_concatenated_fragments(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertEqual(html.lower().count("<html"), 1)
                self.assertEqual(html.lower().count("</html>"), 1)
                self.assertEqual(html.lower().count("<body>"), 1)


class BuildSiteOutputTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_writes_exactly_three_pages(self):
        written = bs.build_site(self._tmp.name, capafy_listing_url="https://example-placeholder.invalid/x")
        self.assertEqual(set(written.keys()), {"index.html", "pricing.html", "docs.html"})
        for path in written.values():
            self.assertTrue(Path(path).is_file())

    def test_unconfigured_capafy_url_is_an_obvious_placeholder_not_a_fake_link(self):
        written = bs.build_site(self._tmp.name, capafy_listing_url=None)
        index_html = Path(written["index.html"]).read_text(encoding="utf-8")
        self.assertIn(bs._UNCONFIGURED_CAPAFY_URL, index_html)
        self.assertNotIn("http://", index_html)
        self.assertNotIn("https://", index_html)

    def test_configured_capafy_url_is_used_verbatim(self):
        url = "https://example-placeholder.invalid/some-listing"
        written = bs.build_site(self._tmp.name, capafy_listing_url=url)
        index_html = Path(written["index.html"]).read_text(encoding="utf-8")
        pricing_html = Path(written["pricing.html"]).read_text(encoding="utf-8")
        self.assertIn(url, index_html)
        self.assertIn(url, pricing_html)

    def test_pricing_page_never_shows_a_dollar_amount(self):
        written = bs.build_site(self._tmp.name, capafy_listing_url="https://example-placeholder.invalid/x")
        pricing_html = Path(written["pricing.html"]).read_text(encoding="utf-8")
        self.assertNotIn("$", pricing_html)
        self.assertFalse(re.search(r"\b\d+\s*(usd|dollars)\b", pricing_html, re.IGNORECASE))

    def test_index_uses_approved_positioning_verbatim(self):
        written = bs.build_site(self._tmp.name, capafy_listing_url="https://example-placeholder.invalid/x")
        index_html = Path(written["index.html"]).read_text(encoding="utf-8")
        self.assertIn(bs.POSITIONING_HEADLINE, index_html)
        self.assertIn(bs.POSITIONING_TAGLINE, index_html)
        self.assertIn(bs.LLM_PROCESSING_NOTE, index_html)
        self.assertIn(bs.RETENTION_NOTE, index_html)

    def test_docs_page_is_explicit_that_website_never_executes_or_sees_source(self):
        written = bs.build_site(self._tmp.name, capafy_listing_url="https://example-placeholder.invalid/x")
        docs_html = Path(written["docs.html"]).read_text(encoding="utf-8")
        self.assertIn("never executes them for you", docs_html)
        self.assertIn("never sees your source code", docs_html)

    def test_user_supplied_html_in_report_content_is_escaped(self):
        # This generator itself never renders user report content (that's
        # W-03's job), but html.escape must still be in the render path for
        # any future field that could carry it - verified on the one field
        # already interpolated with escape(): the CTA URL.
        malicious_url = "https://x.invalid/\"><script>alert(1)</script>"
        written = bs.build_site(self._tmp.name, capafy_listing_url=malicious_url)
        index_html = Path(written["index.html"]).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", index_html)


class CommercialClaimsSweepTests(unittest.TestCase):
    """Extends docs/commercial-claims.md's own commit-time grep procedure
    (previously scoped to .claude/skills and capafy/) to website/'s
    generated output - explicitly required by the doc's own stated scope
    ("cualquier material de marketing")."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = bs.build_site(self._tmp.name, capafy_listing_url="https://example-placeholder.invalid/x")
        self.all_text = "".join(Path(p).read_text(encoding="utf-8") for p in self.written.values()).lower()

    def test_zero_level_a_prohibited_terms(self):
        hits = [term for term in LEVEL_A_TERMS if term in self.all_text]
        self.assertEqual(hits, [], "prohibited term(s) found in generated site: %r" % hits)

    def test_never_exposes_capafy_verify_markers(self):
        self.assertNotIn("capafy-verify", self.all_text)

    def test_never_exposes_a_dollar_price_anywhere_on_the_site(self):
        self.assertNotIn("$", self.all_text)

    def test_never_names_a_specific_llm_provider_or_model(self):
        # docs/commercial-claims.md: provider/model stay [CAPAFY-VERIFY]
        # until documentary confirmation - the site must use the generic
        # approved phrase only.
        for banned in ("anthropic", "claude", "gpt", "openai", "gemini"):
            self.assertNotIn(banned, self.all_text)

    def test_never_claims_a_v3_capability_as_live(self):
        # No hosted history/monitoring dashboard, accounts, or project
        # management exists yet - the site must never claim otherwise.
        for banned in ("dashboard", "your projects", "sign up", "log in", "create an account"):
            self.assertNotIn(banned, self.all_text)


if __name__ == "__main__":
    unittest.main()
