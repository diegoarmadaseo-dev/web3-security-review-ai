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
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

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
    """Isolated from the real process environment for BOTH url env vars
    (VERICEXA_BASE_URL neutralized by always supplying an explicit
    base_url; VERICEXA_APP_URL - Phase 6C - by explicitly popping it for
    the duration) so this suite's result never depends on ambient
    environment state, e.g. a real VERICEXA_APP_URL exported for an actual
    staging build running on the same machine/CI."""
    kwargs.setdefault("base_url", TEST_BASE_URL)
    kwargs.setdefault("app_url", None)
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop(content.APP_BASE_URL_ENV, None)
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

    def test_pricing_is_published_with_the_confirmed_d086_amounts(self):
        self.assertTrue(content.PRICING_PUBLISHED)
        expected = {
            "quick": ("$19/month", "$190/year"),
            "standard": ("$39/month", "$390/year"),
            "pro": ("$79/month", "$790/year"),
        }
        for tier in content.PRICING_TIERS:
            monthly, annual = expected[tier["mode"]]
            self.assertEqual(tier["price_monthly"], monthly)
            self.assertEqual(tier["price_annual"], annual)

    def test_black_friday_first_year_prices_match_the_confirmed_d086_amounts(self):
        self.assertEqual(
            content.BLACK_FRIDAY_FIRST_YEAR_PRICES,
            {"quick": "$133", "standard": "$273", "pro": "$553"},
        )

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

    def test_pricing_page_shows_only_the_confirmed_d086_dollar_amounts(self):
        # D-086: pricing is now published - this guards against a DIFFERENT
        # or invented amount ever appearing, not against dollar amounts
        # existing at all (see tests.test_website_build.ContentCentralization
        # Tests.test_pricing_is_published_with_the_confirmed_d086_amounts).
        # D-087: the Black Friday first-year prices are now ALWAYS present
        # in the raw HTML too (hidden by default, revealed at runtime) -
        # see tests.test_website_build.BlackFridayWebsiteTests.
        written = _build(self._tmp.name)
        pricing_html = Path(written["pricing.html"]).read_text(encoding="utf-8")
        found = set(re.findall(r"\$\d[\d,]*(?:/\w+)?", pricing_html))
        allowed = {"$19/month", "$190/year", "$39/month", "$390/year", "$79/month", "$790/year", "$133", "$273", "$553"}
        self.assertTrue(found, "expected at least one confirmed price on the pricing page")
        self.assertTrue(found <= allowed, "unexpected/invented price(s) found: %r" % (found - allowed))

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

    def test_only_the_confirmed_d086_dollar_amounts_appear_anywhere_on_the_site(self):
        # D-086: pricing is now published - this guards against a
        # DIFFERENT/invented amount appearing anywhere on the site
        # (pricing.html and faq.html both legitimately mention real
        # prices today), never against "$" existing at all.
        found = set(re.findall(r"\$\d[\d,]*(?:/\w+)?", self.all_text))
        allowed = {"$19/month", "$190/year", "$39/month", "$390/year", "$79/month", "$790/year", "$133", "$273", "$553"}
        self.assertTrue(found <= allowed, "unexpected/invented price(s) found: %r" % (found - allowed))

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


class AppCtaTests(unittest.TestCase):
    """Phase 6C (docs/decisiones.md D-084): the one conditional, config-gated
    external CTA to the standalone backend's own /auth/login. Off by
    default (byte-identical to pre-Phase-6C output); explicit opt-in only."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _pages(self, **kwargs):
        written = _build(self._tmp.name, **kwargs)
        return {name: Path(path).read_text(encoding="utf-8") for name, path in written.items() if name.endswith(".html")}

    def test_unconfigured_dev_build_renders_no_app_cta_anywhere(self):
        pages = self._pages()
        for name, html in pages.items():
            with self.subTest(page=name):
                self.assertNotIn(content.APP_LOGIN_PATH, html)
                self.assertNotIn(content.APP_CTA_LOGIN_LABEL, html)
                self.assertNotIn(content.APP_CTA_GET_STARTED_LABEL, html)

    def test_configured_app_url_renders_exact_login_href_on_home_and_pricing(self):
        app_url = "https://app.example-vericexa.invalid"
        pages = self._pages(app_url=app_url)
        expected_href = 'href="%s%s"' % (app_url, content.APP_LOGIN_PATH)
        self.assertIn(expected_href, pages["index.html"])
        self.assertIn(content.APP_CTA_LOGIN_LABEL, pages["index.html"])
        self.assertIn(expected_href, pages["pricing.html"])
        self.assertIn(content.APP_CTA_GET_STARTED_LABEL, pages["pricing.html"])

    def test_app_url_trailing_slash_never_produces_a_double_slash(self):
        pages = self._pages(app_url="https://app.example-vericexa.invalid/")
        self.assertIn('href="https://app.example-vericexa.invalid/auth/login"', pages["index.html"])
        self.assertNotIn("//auth/login", pages["index.html"])

    def test_app_url_env_var_is_honored_when_no_explicit_arg_given(self):
        written_paths = {}
        with mock.patch.dict(os.environ, {content.APP_BASE_URL_ENV: "https://env.example-vericexa.invalid"}):
            written = bs.build_site(self._tmp.name, base_url=TEST_BASE_URL)
            written_paths = {name: Path(path).read_text(encoding="utf-8") for name, path in written.items() if name.endswith(".html")}
        self.assertIn('href="https://env.example-vericexa.invalid/auth/login"', written_paths["index.html"])

    def test_staging_env_without_app_url_fails_clearly(self):
        with self.assertRaises(bs.BuildSiteError):
            _build(self._tmp.name, env="staging")

    def test_production_env_without_app_url_fails_clearly(self):
        with self.assertRaises(bs.BuildSiteError):
            _build(self._tmp.name, env="production")

    def test_staging_env_with_app_url_succeeds(self):
        pages = self._pages(env="staging", app_url="https://staging.example-vericexa.invalid")
        self.assertIn("auth/login", pages["index.html"])

    def test_unrecognized_env_value_fails_clearly_never_silently_ignored(self):
        with self.assertRaises(bs.BuildSiteError):
            _build(self._tmp.name, env="not-a-real-env")

    def test_no_stray_external_href_beyond_the_one_configured_app_login_link(self):
        app_url = "https://app.example-vericexa.invalid"
        pages = self._pages(app_url=app_url)
        expected = "%s%s" % (app_url, content.APP_LOGIN_PATH)
        for name, html in pages.items():
            hrefs = re.findall(r'<a\b[^>]*\bhref="(https?://[^"]+)"', html)
            with self.subTest(page=name):
                for href in hrefs:
                    self.assertEqual(href, expected)


class LegalPlaceholderPagesTests(unittest.TestCase):
    """Phase 6C (D-084): cookies.html/refund.html are new structural
    placeholders ONLY - clearly marked, no invented policy text.
    privacy.html's own pre-existing substantive claims are untouched.
    legal.html's own account-related claim was DELIBERATELY corrected in
    Phase 7 (D-085, see build_site.py's own docstring note) - the tests
    below assert the NEW accurate text and that the old contradictory
    phrase is gone, never that legal.html itself is unmodified."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.pages = {name: Path(path).read_text(encoding="utf-8") for name, path in self.written.items() if name.endswith(".html")}

    def test_cookies_and_refund_pages_are_written_and_linked(self):
        self.assertIn("cookies.html", self.written)
        self.assertIn("refund.html", self.written)
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIn('href="cookies.html"', html)
                self.assertIn('href="refund.html"', html)

    def test_cookies_and_refund_pages_carry_the_placeholder_marker(self):
        self.assertIn(content.PLACEHOLDER_MARKER, self.pages["cookies.html"])
        self.assertIn(content.PLACEHOLDER_MARKER, self.pages["refund.html"])

    def test_privacy_page_keeps_its_pre_existing_claims_unmodified(self):
        self.assertIn(
            "The pages on this site are static: they set no cookies",
            self.pages["privacy.html"],
        )


class LegalAccountClaimCorrectionTests(unittest.TestCase):
    """Phase 7 (D-085): the "does not... create accounts" contradiction
    Phase 5/6C flagged (build_site.py's own docstring) is fixed. Asserts
    the OLD phrase is gone AND the new text is accurate/neutral - not
    just that something changed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.legal_html = Path(self.written["legal.html"]).read_text(encoding="utf-8")

    def test_old_contradictory_account_claim_is_gone(self):
        self.assertNotIn("does not process payments, create accounts", self.legal_html)
        self.assertNotIn("create accounts, or run the analysis engine itself", self.legal_html)

    def test_new_text_describes_the_separate_application_by_fact(self):
        self.assertIn("A separate application, linked from this site", self.legal_html)
        self.assertIn("creates or signs in to an account", self.legal_html)
        self.assertIn("stores workspace and account data", self.legal_html)
        self.assertIn("pending final legal review", self.legal_html)

    def test_payments_and_analysis_engine_claims_about_this_site_are_kept(self):
        # Only the accounts clause was in scope for this phase - the site
        # itself still does not process payments or run the analyzer.
        self.assertIn("It does not process payments", self.legal_html)
        self.assertIn("run the analysis engine itself", self.legal_html)

    def test_no_invented_company_identity_vat_or_legal_claim(self):
        lowered = self.legal_html.lower()
        for forbidden in ("nif", "cif", "vat", "gdpr", "dpa", "s.l.", "s.a.", "inc.", "llc"):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, lowered)

    def test_no_retention_period_or_refund_policy_invented(self):
        lowered = self.legal_html.lower()
        for forbidden in ("30 days", "90 days", "days of retention", "refund within", "money-back"):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, lowered)


class IsBlackFridayWindowTests(unittest.TestCase):
    """Pure-function tests for build_site.is_black_friday_window() (D-086)
    - no build, no I/O. PRESENTATION ONLY, see that function's own
    docstring; backend/black_friday.py has the equivalent real-enforcement
    tests."""

    def setUp(self):
        self.now = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
        self.start = "2026-11-23T00:00:00+00:00"
        self.end = "2026-11-30T23:59:59+00:00"

    def test_inside_window_and_enabled_is_true(self):
        self.assertTrue(bs.is_black_friday_window(self.now, True, self.start, self.end))

    def test_disabled_is_false_even_inside_the_window(self):
        self.assertFalse(bs.is_black_friday_window(self.now, False, self.start, self.end))

    def test_before_window_is_false(self):
        self.assertFalse(bs.is_black_friday_window(datetime(2026, 11, 22, tzinfo=timezone.utc), True, self.start, self.end))

    def test_after_window_is_false(self):
        self.assertFalse(bs.is_black_friday_window(datetime(2026, 12, 1, tzinfo=timezone.utc), True, self.start, self.end))

    def test_missing_start_or_end_is_false_never_a_crash(self):
        self.assertFalse(bs.is_black_friday_window(self.now, True, None, self.end))
        self.assertFalse(bs.is_black_friday_window(self.now, True, self.start, None))

    def test_malformed_date_string_is_false_never_a_crash(self):
        self.assertFalse(bs.is_black_friday_window(self.now, True, "not-a-date", self.end))

    def test_naive_start_or_end_is_false_never_a_silent_misfire(self):
        self.assertFalse(bs.is_black_friday_window(self.now, True, "2026-11-23T00:00:00", self.end))


class BlackFridayWebsiteTests(unittest.TestCase):
    """D-087 (supersedes D-086's build-time-only design, which had a real
    staleness bug - see build_site.py's own module docstring). BUILD-TIME
    STRUCTURAL VALIDATION ONLY: the campaign markup/script must always be
    present, safe-by-default (hidden), and correctly wired - actual
    show/hide is a RUNTIME concern now, covered by tests/
    test_website_black_friday_runtime.py's real Node execution of the
    exact shipped JS, never re-tested here with a fake build clock."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        written = bs.build_site(self._tmp.name, base_url=TEST_BASE_URL)
        self.pricing_html = Path(written["pricing.html"]).read_text(encoding="utf-8")

    def test_black_friday_markup_is_always_present_regardless_of_build_time(self):
        # The exact bug this phase fixes: a build must NEVER omit this
        # markup just because "now" (at build time) was outside the
        # window - omitting it would leave the runtime script with
        # nothing to reveal later.
        self.assertIn("Black Friday", self.pricing_html)
        self.assertIn("$133", self.pricing_html)
        self.assertIn("$273", self.pricing_html)
        self.assertIn("$553", self.pricing_html)
        self.assertIn(content.BLACK_FRIDAY_RENEWAL_NOTE, self.pricing_html)

    def test_every_black_friday_presentation_element_starts_hidden(self):
        # Fail-hidden default: if the script never runs (JS blocked/
        # fails), a visitor sees the ordinary pricing page, never a
        # stale/incorrect Black Friday claim.
        for match in re.finditer(r'<[^>]*data-bf-presentation[^>]*>', self.pricing_html):
            with self.subTest(tag=match.group(0)):
                self.assertIn("hidden", match.group(0))

    def test_normal_annual_price_element_has_no_hidden_attribute_by_default(self):
        # The normal price (data-bf-normal) is what a visitor sees unless
        # the runtime script confirms the campaign and hides it.
        normal_price_tags = re.findall(r'<span data-bf-normal>[^<]*</span>', self.pricing_html)
        self.assertEqual(len(normal_price_tags), 3)  # quick/standard/pro.
        for tag in normal_price_tags:
            self.assertNotIn("hidden", tag)

    def test_monthly_price_cells_have_neither_bf_attribute_structurally_incapable_of_a_discount(self):
        monthly_row = re.search(r'<tr><th scope="row">Price \(monthly\)</th>(.*?)</tr>', self.pricing_html, re.S).group(1)
        self.assertNotIn("data-bf-presentation", monthly_row)
        self.assertNotIn("data-bf-normal", monthly_row)
        self.assertNotIn("$133", monthly_row)
        self.assertNotIn("$273", monthly_row)
        self.assertNotIn("$553", monthly_row)

    def test_script_is_present_exactly_once_with_the_confirmed_boundaries(self):
        self.assertEqual(self.pricing_html.count("<script>"), 1)
        self.assertIn(json.dumps(content.BLACK_FRIDAY_START_UTC), self.pricing_html)
        self.assertIn(json.dumps(content.BLACK_FRIDAY_END_UTC), self.pricing_html)

    def test_cta_area_carries_an_optional_black_friday_badge_also_hidden_by_default(self):
        cta_section = re.search(r'<p class="cta">(.*?)</p>', self.pricing_html, re.S).group(1)
        self.assertIn("data-bf-presentation", cta_section)
        self.assertIn("hidden", cta_section)

    def test_black_friday_cta_badge_text_renders_a_single_percent_sign(self):
        # Regression guard for a real formatting defect the final audit
        # found: bf_cta_badge is a plain conditional string, never passed
        # through Python's own `%` operator - a `%%` escape (correct
        # inside black_friday_notice, which IS `%`-formatted) is wrong
        # here and renders as a literal double percent sign instead of
        # collapsing to one.
        cta_section = re.search(r'<p class="cta">(.*?)</p>', self.pricing_html, re.S).group(1)
        self.assertIn("30% off annual", cta_section)
        self.assertNotIn("%%", cta_section)


class NoTrialMessagingTests(unittest.TestCase):
    """Section 8's own explicit requirement: no trial claim anywhere, and
    an explicit no-trial statement is present (D-086)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.written = _build(self._tmp.name)
        self.all_text = "".join(
            Path(p).read_text(encoding="utf-8") for name, p in self.written.items() if name.endswith(".html")
        ).lower()

    def test_no_trial_note_appears_on_the_pricing_page(self):
        pricing_html = Path(self.written["pricing.html"]).read_text(encoding="utf-8")
        self.assertIn("no free trial", pricing_html.lower())

    def test_no_page_ever_claims_a_trial_is_offered(self):
        for phrase in ("start your free trial", "try free", "free trial available", "14-day trial", "30-day trial"):
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, self.all_text)

    def test_demo_page_is_never_described_as_a_trial(self):
        demo_html = Path(self.written["demo.html"]).read_text(encoding="utf-8").lower()
        self.assertNotIn("trial", demo_html)


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
