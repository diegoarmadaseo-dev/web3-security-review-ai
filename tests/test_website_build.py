"""Tests for website/build_site.py + website/content.py + website/seo.py
(Vericexa rebrand, 10-page expansion of V2.12's site).

Covers: pricing/config drift, commercial-claims security (extended to the
brand rebrand and the AVAILABLE/PARTIAL feature-status honesty rules), SEO/
GEO metadata validity, link integrity across the full page mesh, and basic
accessibility structure.

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
import content  # noqa: E402
import seo  # noqa: E402
from preprocess import load_modes_config  # noqa: E402
import cli  # noqa: E402

TEST_BASE_URL = "https://example-vericexa.invalid"

ALL_PAGE_NAMES = [name for name, _label in content.ALL_PAGES]

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

# D-007's secret-pattern discipline, applied to website/ source and output.
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[a-zA-Z0-9-]+"),
    re.compile(r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"][a-zA-Z0-9]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bmnemonic\b\s*[:=]"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id shape
]
LOCAL_PATH_PATTERN = re.compile(r"[A-Za-z]:\\Users\\|/home/[a-zA-Z0-9_-]+/|/Users/[a-zA-Z0-9_-]+/")


def _build(tmp_dir: str, **kwargs):
    kwargs.setdefault("base_url", TEST_BASE_URL)
    return bs.build_site(tmp_dir, **kwargs)


class TierComparisonDriftTests(unittest.TestCase):
    """Pricing/config drift: the tier table must be a live function of
    config/modes.json, never a hardcoded second copy."""

    def test_reflects_the_real_current_modes_json(self):
        modes_config = load_modes_config()
        tiers = bs.build_tier_comparison(modes_config)
        self.assertEqual({t["mode"] for t in tiers}, set(modes_config["modes"].keys()))
        for tier in tiers:
            real_rules = modes_config["modes"][tier["mode"]]
            for key, _label in bs._FEATURE_LABELS:
                self.assertEqual(tier["features"][key], real_rules.get(key), "%s.%s drifted" % (tier["mode"], key))

    def test_reflects_an_edited_copy_not_a_cached_snapshot(self):
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
        import pr_gate
        entries = bs.collect_cli_reference()
        pr_gate_entry = next(e for e in entries if e["command"] == "pr-gate")
        self.assertEqual(pr_gate_entry["help"], pr_gate.build_arg_parser().format_help())

    def test_preprocess_and_analyze_pipeline_help_render_without_error(self):
        entries = bs.collect_cli_reference()
        for command in ("preprocess", "analyze-pipeline"):
            entry = next(e for e in entries if e["command"] == command)
            self.assertIn("usage:", entry["help"])


class ContentCentralizationTests(unittest.TestCase):
    """content.py is the single source of truth for pages/titles/
    descriptions - never a second hand-typed list in build_site.py."""

    def test_page_titles_and_descriptions_cover_every_page_exactly(self):
        self.assertEqual(set(content.PAGE_TITLES.keys()), set(ALL_PAGE_NAMES))
        self.assertEqual(set(content.PAGE_DESCRIPTIONS.keys()), set(ALL_PAGE_NAMES))

    def test_no_duplicate_titles_or_descriptions(self):
        self.assertEqual(len(content.PAGE_TITLES.values()), len(set(content.PAGE_TITLES.values())))
        self.assertEqual(len(content.PAGE_DESCRIPTIONS.values()), len(set(content.PAGE_DESCRIPTIONS.values())))

    def test_pricing_is_unpublished_and_has_no_amounts(self):
        self.assertFalse(content.PRICING_PUBLISHED)
        for tier in content.PRICING_TIERS:
            self.assertIsNone(tier["price"])
            self.assertIsNone(tier["billing_period"])

    def test_feature_lists_are_grounded_with_evidence(self):
        for f in content.FEATURES_AVAILABLE + content.FEATURES_PARTIAL:
            self.assertTrue(f.get("evidence"), "%s has no evidence pointer" % f["name"])

    def test_v3_advisory_scripts_are_all_represented_in_features_available(self):
        # Every advisory script shipped since V3 Block 3 must be named in at
        # least one FEATURES_AVAILABLE entry's own evidence trail, so the
        # website can never silently drift stale again the way the old
        # "Upgrade Review" partial entry did before this test existed.
        evidence_text = " ".join(f.get("evidence", "") for f in content.FEATURES_AVAILABLE)
        v3_advisory_scripts = [
            "storage_layout.py", "privilege_path.py", "bytecode_advisory.py", "change_impact.py",
            "proxy_fingerprint.py", "compiler_bugs.py", "upgrade_gap.py", "initializer_safety.py",
            "bytecode_size.py", "bytecode_compiler_bugs.py", "delegatecall_cycle.py",
            "constructor_zero_address.py", "render_advisory_summary.py", "upgrade_authority_guard.py",
            "bytecode_metamorphic_signal.py", "implementation_constructor_signal.py",
            "finding_context_bundle.py", "advisory_gate.py",
        ]
        for script in v3_advisory_scripts:
            self.assertIn(script, evidence_text, "%s is not referenced by any FEATURES_AVAILABLE entry" % script)

    def test_faq_items_are_unique_questions(self):
        questions = [q for q, _a in content.FAQ_ITEMS]
        self.assertEqual(len(questions), len(set(questions)))


class BuildSiteOutputTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_writes_exactly_ten_pages_plus_seo_and_static_files(self):
        written = _build(self._tmp.name)
        expected = set(ALL_PAGE_NAMES) | {"sitemap.xml", "robots.txt", "styles.css", "favicon.svg"}
        self.assertEqual(set(written.keys()), expected)
        for path in written.values():
            self.assertTrue(Path(path).is_file())

    def test_no_external_checkout_or_marketplace_link_anywhere(self):
        # SEO-fixes requirement: every CTA is an internal Vericexa page: no
        # external href (no "http://"/"https://" anchor) exists anywhere in
        # the generated site, and build_site() takes no URL parameter that
        # could reintroduce one.
        import inspect
        self.assertNotIn("capafy_listing_url", inspect.signature(bs.build_site).parameters)
        written = _build(self._tmp.name)
        for name, path in written.items():
            if not name.endswith(".html"):
                continue
            html = Path(path).read_text(encoding="utf-8")
            # Only real clickable <a> links - <link rel="canonical"> and
            # og:url legitimately carry an absolute https:// URL and are not
            # a checkout CTA.
            for href in re.findall(r'<a\b[^>]*\bhref="(https?://[^"]+)"', html):
                with self.subTest(page=name, href=href):
                    self.fail("external anchor link found: %s" % href)

    def test_pricing_page_never_shows_a_dollar_amount(self):
        written = _build(self._tmp.name)
        pricing_html = Path(written["pricing.html"]).read_text(encoding="utf-8")
        self.assertNotIn("$", pricing_html)
        self.assertFalse(re.search(r"\b\d+\s*(usd|dollars)\b", pricing_html, re.IGNORECASE))

    def test_home_uses_approved_positioning_verbatim(self):
        written = _build(self._tmp.name)
        index_html = Path(written["index.html"]).read_text(encoding="utf-8")
        self.assertIn(content.HOME_HEADLINE, index_html)
        self.assertIn(content.POSITIONING_TAGLINE, index_html)
        self.assertIn(content.NOT_AN_AUDIT_NOTE, index_html)
        self.assertIn(content.LLM_PROCESSING_NOTE, index_html)
        self.assertIn(content.RETENTION_NOTE, index_html)

    def test_developers_page_is_explicit_that_website_never_executes_or_sees_source(self):
        written = _build(self._tmp.name)
        html = Path(written["developers.html"]).read_text(encoding="utf-8")
        self.assertIn("never executes them for you", html)
        self.assertIn("never sees your source code", html)

    def test_base_url_is_escaped_against_injection(self):
        malicious_base = "https://x.invalid/\"><script>alert(1)</script>"
        written = _build(self._tmp.name, base_url=malicious_base)
        index_html = Path(written["index.html"]).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", index_html)

    def test_base_url_env_var_is_honored_when_no_explicit_base_url(self, ):
        import os
        old = os.environ.get(content.BASE_URL_ENV)
        os.environ[content.BASE_URL_ENV] = "https://env-example.invalid"
        try:
            written = bs.build_site(self._tmp.name)
        finally:
            if old is None:
                os.environ.pop(content.BASE_URL_ENV, None)
            else:
                os.environ[content.BASE_URL_ENV] = old
        html = Path(written["index.html"]).read_text(encoding="utf-8")
        self.assertIn("https://env-example.invalid", html)


class HtmlDocumentStructureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

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

    def test_page_still_parses_as_one_html_document_not_concatenated_fragments(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertEqual(html.lower().count("<html"), 1)
                self.assertEqual(html.lower().count("</html>"), 1)
                self.assertEqual(html.lower().count("<body>"), 1)

    def test_pricing_and_developers_pages_keep_their_live_data_markers(self):
        self.assertIn("tier-comparison", self.pages["pricing.html"])
        self.assertIn("cli-command", self.pages["developers.html"])


class LinkIntegrityTests(unittest.TestCase):
    """Every page must be reachable from every other page (footer mesh) and
    every internal href must resolve to a file this build actually wrote."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

    def test_every_page_links_to_every_other_page(self):
        all_names = set(self.pages.keys())
        for name, html in self.pages.items():
            with self.subTest(page=name):
                for other in all_names - {name}:
                    self.assertIn('href="%s"' % other, html, "%s is missing a link to %s" % (name, other))

    def test_developers_page_has_a_cta_back_toward_pricing(self):
        self.assertIn('href="pricing.html"', self.pages["developers.html"])

    def test_no_internal_href_points_to_a_file_the_build_did_not_write(self):
        written_names = set(self.written.keys())
        href_re = re.compile(r'href="([a-zA-Z0-9_.-]+\.(?:html|xml|txt))"')
        for name, html in self.pages.items():
            for href in href_re.findall(html):
                with self.subTest(page=name, href=href):
                    self.assertIn(href, written_names)


class SeoMetadataTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

    def test_every_page_has_canonical_og_and_twitter_tags(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('rel="canonical"', html)
                self.assertIn('property="og:title"', html)
                self.assertIn('property="og:description"', html)
                self.assertIn('property="og:url"', html)
                self.assertIn('name="twitter:card"', html)

    def test_canonical_url_uses_the_configured_base_url(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn(TEST_BASE_URL, html)

    def test_every_page_has_valid_organization_website_and_softwareapplication_jsonld(self):
        for name, html in self.pages.items():
            blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
            types = []
            for block in blocks:
                data = json.loads(block)  # raises if malformed - the assertion itself
                types.append(data["@type"])
            with self.subTest(page=name):
                self.assertIn("Organization", types)
                self.assertIn("WebSite", types)
                self.assertIn("SoftwareApplication", types)
                self.assertIn("BreadcrumbList", types)

    def test_faqpage_jsonld_only_on_faq_page(self):
        for name, html in self.pages.items():
            has_faq = '"@type": "FAQPage"' in html
            with self.subTest(page=name):
                self.assertEqual(has_faq, name == "faq.html")

    def test_software_application_jsonld_never_asserts_a_price(self):
        html = self.pages["index.html"]
        block = re.search(r'"@type": "SoftwareApplication".*?\}', html, re.S).group(0)
        self.assertNotIn("offers", block)
        self.assertNotIn("price", block)

    def test_sitemap_lists_every_page_exactly_once(self):
        sitemap = Path(self.written["sitemap.xml"]).read_text(encoding="utf-8")
        locs = re.findall(r"<loc>(.*?)</loc>", sitemap)
        self.assertEqual(len(locs), len(ALL_PAGE_NAMES))
        self.assertEqual(len(locs), len(set(locs)))
        for loc in locs:
            self.assertTrue(loc.startswith(TEST_BASE_URL))

    def test_robots_txt_points_at_the_sitemap_and_allows_crawling(self):
        robots = Path(self.written["robots.txt"]).read_text(encoding="utf-8")
        self.assertIn("Allow: /", robots)
        self.assertIn("Sitemap: %s/sitemap.xml" % TEST_BASE_URL, robots)

    def test_favicon_and_stylesheet_are_linked_and_written(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('rel="icon"', html)
                self.assertIn('rel="stylesheet" href="styles.css"', html)
        self.assertTrue(Path(self.written["styles.css"]).is_file())
        self.assertTrue(Path(self.written["favicon.svg"]).is_file())


class AccessibilityBasicsTests(unittest.TestCase):
    """Structural a11y checks feasible with stdlib-only tooling (no
    headless-browser contrast/focus engine available in this pipeline):
    landmark presence, single h1, alt attributes, table header scope."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

    def test_every_page_has_exactly_one_h1(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertEqual(len(re.findall(r"<h1[ >]", html)), 1)

    def test_every_page_has_a_skip_link_and_main_landmark(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('class="skip-link" href="#main"', html)
                self.assertIn('id="main"', html)

    def test_every_page_has_a_labeled_nav_landmark(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn("<nav", html)
                self.assertIn('aria-label="Primary"', html)

    def test_every_img_has_an_alt_attribute(self):
        img_re = re.compile(r"<img\b[^>]*>")
        for name, html in self.pages.items():
            for img in img_re.findall(html):
                with self.subTest(page=name, img=img):
                    self.assertIn("alt=", img)

    def test_every_table_header_declares_scope(self):
        for name, html in self.pages.items():
            for th in re.findall(r"<th\b[^>]*>", html):
                with self.subTest(page=name, th=th):
                    self.assertIn("scope=", th)

    def test_current_nav_item_is_marked_aria_current(self):
        for name, html in self.pages.items():
            if name in ALL_PAGE_NAMES[: content.PRIMARY_NAV_COUNT]:
                with self.subTest(page=name):
                    self.assertIn('aria-current="page"', html)


class FeatureStatusHonestyTests(unittest.TestCase):
    """The AVAILABLE/PARTIAL distinction must never blur into an overclaim -
    explicit requirement: partial features never read as fully live, and no
    hosted monitoring/alerts/accounts capability is implied."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.features_html = Path(self.written["features.html"]).read_text(encoding="utf-8")
        self.all_text = "".join(
            Path(p).read_text(encoding="utf-8") for name, p in self.written.items() if name.endswith(".html")
        ).lower()

    def test_every_available_feature_name_appears_under_an_available_pill(self):
        for f in content.FEATURES_AVAILABLE:
            marker = '<span class="status-pill available">Available</span>\n<h3>%s</h3>' % f["name"]
            self.assertIn(marker, self.features_html)

    def test_every_partial_feature_name_appears_under_a_partial_pill(self):
        for f in content.FEATURES_PARTIAL:
            marker = '<span class="status-pill partial">Partial</span>\n<h3>%s</h3>' % f["name"]
            self.assertIn(marker, self.features_html)

    def test_no_hosted_monitoring_or_alerting_is_ever_claimed(self):
        # Substrings chosen to match an AFFIRMATIVE claim ("automated alerts",
        # a plural noun) without also matching this site's own correct
        # negation ("no automated alerting", a gerund) - see FEATURES_PARTIAL.
        for banned in ("real-time alert", "24/7 monitoring", "automated alerts", "email notification", "push notification"):
            self.assertNotIn(banned, self.all_text)

    def test_monitoring_feature_states_it_is_self_run_cli_only(self):
        monitoring = next(f for f in content.FEATURES_PARTIAL if f["name"] == "Monitoring")
        self.assertIn("no hosted monitoring service", monitoring["detail"].lower())
        self.assertIn("no hosted monitoring service", self.all_text)

    def test_no_benchmark_or_accuracy_claim_is_published(self):
        # evals/results/summary.md is internal QA only (docs/decisiones.md
        # D-024) and must never surface as a product accuracy claim. Bare
        # "benchmark" is not banned outright: content.DEMO_SOURCE_NOTE uses
        # it correctly, in the same negated form ("not ... a benchmark
        # result") docs/commercial-claims.md already relies on for "audit"/
        # "certified"/"guaranteed" elsewhere - only an affirmative claim
        # shape is actually dangerous.
        for banned in ("a benchmark result showing", "detection rate", "false positive rate", "accuracy of"):
            self.assertNotIn(banned, self.all_text)


class CommercialClaimsSweepTests(unittest.TestCase):
    """Extends docs/commercial-claims.md's own commit-time grep procedure to
    website/'s generated output, across all 10 pages."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.all_text = "".join(
            Path(p).read_text(encoding="utf-8") for name, p in self.written.items() if name.endswith(".html")
        ).lower()

    def test_zero_level_a_prohibited_terms(self):
        hits = [term for term in LEVEL_A_TERMS if term in self.all_text]
        self.assertEqual(hits, [], "prohibited term(s) found in generated site: %r" % hits)

    def test_never_exposes_capafy_verify_markers(self):
        self.assertNotIn("capafy-verify", self.all_text)

    def test_never_exposes_a_dollar_price_anywhere_on_the_site(self):
        self.assertNotIn("$", self.all_text)

    def test_never_names_a_specific_llm_provider_or_model(self):
        for banned in ("anthropic", "claude", "gpt", "openai", "gemini"):
            self.assertNotIn(banned, self.all_text)

    def test_never_claims_an_unbuilt_capability_as_live(self):
        for banned in ("dashboard", "your projects", "sign up", "log in", "create an account"):
            self.assertNotIn(banned, self.all_text)

    def test_old_brand_name_is_fully_retired(self):
        self.assertNotIn("security review analyzer", self.all_text)

    def test_new_brand_and_positioning_appear(self):
        self.assertIn(content.BRAND_NAME.lower(), self.all_text)
        self.assertIn(content.POSITIONING.lower(), self.all_text)

    def test_third_party_marketplace_brand_name_never_appears(self):
        # SEO-fixes requirement: the site discloses that a third-party
        # processes LLM calls / governs purchase terms (legal.html,
        # privacy.html) but never names or links to it as a brand.
        self.assertNotIn("capafy", self.all_text)


class HeadingHierarchyTests(unittest.TestCase):
    """SEO-fixes requirement: fix the H1->H3 skip specifically flagged on
    developers.html (CLI command headings) and faq.html (question headings).
    Scoped to exactly these two pages, matching the audited fix - not a new
    sitewide rule (pricing.html's own thin h1-only structure was noted in
    the audit but was not one of the fixes requested this pass)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

    def test_developers_page_has_an_h2_before_its_h3_cli_commands(self):
        html = self.pages["developers.html"]
        h2_pos = html.index("<h2>CLI reference</h2>")
        first_h3_pos = re.search(r"<h3[ >]", html).start()
        self.assertLess(h2_pos, first_h3_pos)

    def test_faq_questions_are_h2_not_h3(self):
        html = self.pages["faq.html"]
        self.assertGreaterEqual(len(re.findall(r"<h2[ >]", html)), len(content.FAQ_ITEMS))
        # No h3 at all on this page now that questions were promoted to h2 -
        # the only deeper heading on the site is the shared footer's h4.
        self.assertNotIn("<h3", html)


class InternalCtaTests(unittest.TestCase):
    """CTA flow is entirely internal (Analyze a Contract / View Demo / See
    How It Works) - no external checkout, per the SEO-fixes requirement."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

    def test_home_hero_has_analyze_and_demo_ctas(self):
        html = self.pages["index.html"]
        self.assertIn('href="%s"' % content.CTA_ANALYZE[1], html)
        self.assertIn(content.CTA_ANALYZE[0], html)
        self.assertIn('href="%s"' % content.CTA_DEMO[1], html)
        self.assertIn(content.CTA_DEMO[0], html)

    def test_content_pages_each_have_a_next_step_cta(self):
        for name in ("features.html", "demo.html", "methodology.html", "pricing.html", "faq.html"):
            with self.subTest(page=name):
                self.assertIn('class="cta"', self.pages[name])

    def test_every_cta_class_link_points_to_a_real_internal_page(self):
        written_names = set(self.written.keys())
        cta_href_re = re.compile(r'<p class="cta">.*?href="([^"]+)"', re.S)
        for name, html in self.pages.items():
            for href in cta_href_re.findall(html):
                with self.subTest(page=name, href=href):
                    self.assertFalse(href.startswith("http"))
                    self.assertIn(href, written_names)


class KeywordPlacementTests(unittest.TestCase):
    """Priority keywords added by the SEO-fixes pass appear naturally
    on-page (not just in seo/keyword-map.md)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.all_text = "".join(
            Path(p).read_text(encoding="utf-8") for name, p in self.written.items() if name.endswith(".html")
        ).lower()

    def test_new_priority_keywords_appear(self):
        for phrase in ("smart contract monitoring", "blockchain security platform", "smart contract security diff"):
            self.assertIn(phrase, self.all_text)


class SecretAndInternalLeakScanTests(unittest.TestCase):
    """D-007-style secret sweep plus a check against leaking local absolute
    paths or internal-only files (evals/results/summary.md's QA-only
    metrics, [CAPAFY-VERIFY] markers) into published output."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)

    def test_no_secret_pattern_in_generated_output(self):
        for name, path in self.written.items():
            text = Path(path).read_text(encoding="utf-8")
            for pattern in SECRET_PATTERNS:
                with self.subTest(page=name, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(text))

    def test_no_local_absolute_path_in_generated_output(self):
        for name, path in self.written.items():
            text = Path(path).read_text(encoding="utf-8")
            with self.subTest(page=name):
                self.assertIsNone(LOCAL_PATH_PATTERN.search(text))

    def test_no_secret_pattern_in_website_source(self):
        for py_file in WEBSITE_DIR.glob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for pattern in SECRET_PATTERNS:
                with self.subTest(file=py_file.name, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(text))


if __name__ == "__main__":
    unittest.main()
