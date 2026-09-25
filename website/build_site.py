#!/usr/bin/env python3
"""Build-time static site generator for the Vericexa website (V2.13 rebrand
and 10-page expansion of the V2.12 site, docs/decisiones.md D-067 base;
capabilities W-01, W-02, W-04 kept, extended with SEO/GEO output).

Architecture is unchanged from V2.12 and is NOT rebuilt by this generator
itself: this file still renders no accounts, no payment UI, no storage, no
hosted-analyzer-execution UI of its own - it remains a thin, PUBLIC, static
layer. Per the SEO-fixes pass, the public site names or links no external
distribution mechanism anywhere: every CTA is an internal Vericexa page
(content.CTA_ANALYZE/CTA_DEMO/CTA_HOW_IT_WORKS) except the one conditional
app-login CTA described in the Phase 6C note below (never a third-party
marketplace), and the only remaining dynamic surface it links to is the
stateless W-03 endpoint (server.py).

Phase 5 note (docs/decisiones.md D-077 follow-up): a THIRD-PARTY marketplace
(docs/capafy-notas.md, capafy/pricing.md) is no longer the only mechanism
that can own auth/billing/tiers/execution - an independent standalone-SaaS
backend now exists (backend/http_app.py, backend/billing.py, backend/
worker_supervisor.py, Phases 1-4).

Phase 6C note (docs/decisiones.md D-084): this generator now HAS a
config-gated capability to link the standalone backend's own GET
/auth/login entry point (content.APP_BASE_URL_ENV / --app-url below), but
it remains OFF by default - build_site() with no app URL configured
renders byte-identical output to before this phase, no dead/placeholder
link anywhere. --env staging/production fails the build loudly if the
app URL is missing, so that choice can never happen by accident either way.

Phase 7 note (docs/decisiones.md D-085): legal.html/privacy.html's own
claims were the one precondition Phase 6C left unmet before a live CTA -
that text is now updated (content.py's LEGAL_SECTIONS) to describe the
separate application by fact, without inventing company identity, a
retention period, or any other legal claim. Actually setting
APP_BASE_URL_ENV/VERICEXA_APP_URL for a real deploy is still a separate
decision Diego has not made - this phase removes the CONTRADICTION, it
does not enable the CTA. Whichever mechanism is confirmed, it is still
disclosed BY FACT in legal.html/privacy.html, generically worded per
content.py's LEGAL_SECTIONS/PRIVACY_SECTIONS - never removed, never named
as a brand on the public site.

All brand/copy/feature-status/pricing facts live in website/content.py (one
place to edit, never restated here - same single-source-of-truth discipline
D-058 established for config/modes.json). All SEO/structured-data encoding
lives in website/seo.py. This file is the orchestrator: it turns content.py
data plus two LIVE sources - preprocess.load_modes_config() (config/
modes.json) and each script's own --help text (V2.11 cli.py) - into static
HTML, sitemap.xml and robots.txt. Neither live source is duplicated as a
second hand-copied value anywhere in this file.

Pricing (D-086, docs/decisiones.md): content.PRICING_PUBLISHED is True -
Diego confirmed real monthly/annual amounts, rendered from content.
PRICING_TIERS (see content.py's own module docstring on why publishing a
price is a content decision, independent of whether Checkout is live).
The pricing page shows tier NAMES, FEATURE differences AND real prices.

BLACK FRIDAY IS A RUNTIME, NOT BUILD-TIME, PRESENTATION CONCERN (D-087 -
this replaced an earlier build-time-only design, D-086, that had a real
staleness bug: a site built before 2026-11-23 would never show the
campaign at all without a rebuild exactly at the boundary). This
generator now emits ONE small, inline, vanilla-JS snippet - the site's
first and only JavaScript - see render_black_friday_script()'s own
docstring for the full design (fail-hidden default, UTC-safe by
construction, no discount logic of any kind, structurally incapable of
discounting a monthly price). is_black_friday_window() below remains a
correct, independently tested pure function but is no longer used to
gate anything rendered here - kept as a small reusable utility, not
dead code removed for its own sake.

Standard library only (Python side - no new pip dependency). No network
access, no accounts, no payment logic, no discount mechanism of any
kind. Python 3.8+.
"""
from __future__ import annotations

import argparse
import datetime
import importlib
import json
import os
import shutil
import sys
from html import escape
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SCRIPTS_DIR = os.path.join(REPO_ROOT, ".claude", "skills", "web3-auditor", "scripts")
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from preprocess import load_modes_config, ModesConfigError  # noqa: E402
import cli  # noqa: E402 - V2.11 unified dispatcher; source of truth for the CLI/CI reference page
import content as c  # noqa: E402
import seo  # noqa: E402

BUILD_VERSION = "2026.2"

EXIT_OK = 0
EXIT_FAILED = 1

_PREFERRED_MODE_ORDER = ["quick", "standard", "pro"]

_FEATURE_LABELS = [
    ("maxEffectiveLoc", "Max lines of code analyzed"),
    ("maxSourceFiles", "Max source files"),
    ("allowPatch", "Suggested remediation patches"),
    ("allowGasSuggestions", "Gas suggestions"),
    ("allowHtmlReport", "HTML report"),
    ("allowArchitectureChecks", "Architecture notes"),
    ("allowExecutiveSummary", "Executive summary"),
    ("allowSystemGraph", "Multi-contract system graph"),
]


class BuildSiteError(Exception):
    """Raised when config/modes.json or a script's own CLI parser cannot be
    loaded - this generator never falls back to a guessed/hardcoded limit or
    an empty CLI reference page."""


# ---------------------------------------------------------------------------
# Live data sources (W-04 tier table, W-02 CLI reference) - unchanged logic
# from V2.12, still pure functions of config/modes.json and cli.py.
# ---------------------------------------------------------------------------

def build_tier_comparison(modes_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """W-04. Returns one entry per mode in config/modes.json, in the
    preferred display order (quick/standard/pro) followed by any other mode
    not in that list (forward-compatible with a future mode name, never
    silently dropped). No price/billing field exists anywhere in this shape
    - deliberately, see module docstring."""
    modes = modes_config.get("modes")
    if not isinstance(modes, dict):
        raise BuildSiteError("modes_config['modes'] must be an object")
    ordered_names = [name for name in _PREFERRED_MODE_ORDER if name in modes]
    ordered_names += [name for name in modes if name not in _PREFERRED_MODE_ORDER]
    tiers = []
    for name in ordered_names:
        rules = modes[name]
        tiers.append({
            "mode": name,
            "features": {key: rules.get(key) for key, _label in _FEATURE_LABELS},
        })
    return tiers


def collect_cli_reference() -> List[Dict[str, str]]:
    """W-02. Captures each script's OWN --help text via cli.COMMANDS +
    build_arg_parser() (V2.11) - never a hand-typed copy of its arguments
    that could drift from the real CLI."""
    entries = []
    for command in sorted(cli.COMMANDS):
        module_name = cli.COMMANDS[command]
        module = importlib.import_module(module_name)
        builder = getattr(module, "build_arg_parser")
        try:
            parser = builder()
        except TypeError:
            # preprocess.py / analyze_pipeline.py's build_arg_parser(modes_config)
            # requires the modes config; every other script's takes none.
            parser = builder(load_modes_config())
        entries.append({
            "command": command,
            "module": module_name,
            "help": parser.format_help(),
        })
    return entries


# ---------------------------------------------------------------------------
# Shared page shell: nav, footer, <head> (SEO/GEO), JSON-LD
# ---------------------------------------------------------------------------

def render_nav_html(current_page: str) -> str:
    items = []
    for href, label in c.ALL_PAGES[: c.PRIMARY_NAV_COUNT]:
        current = ' aria-current="page"' if href == current_page else ""
        items.append('<li><a href="%s"%s>%s</a></li>' % (escape(href), current, escape(label)))
    return (
        '<nav class="primary-nav" aria-label="Primary">\n<ul>\n%s\n</ul>\n</nav>\n' % "\n".join(items)
    )


def render_footer_html() -> str:
    def _links(pages):
        return "\n".join('<li><a href="%s">%s</a></li>' % (escape(h), escape(l)) for h, l in pages)

    product = [p for p in c.ALL_PAGES if p[0] in ("features.html", "demo.html", "methodology.html", "pricing.html")]
    developer = [p for p in c.ALL_PAGES if p[0] in ("developers.html", "faq.html")]
    legal = [p for p in c.ALL_PAGES if p[0] in ("legal.html", "privacy.html", "disclaimer.html", "cookies.html", "refund.html")]
    return (
        '<footer class="site-footer">\n<div class="wrap">\n'
        '<div class="footer-grid">\n'
        '<div><h4>Product</h4><ul>%s</ul></div>\n'
        '<div><h4>Developers</h4><ul>%s</ul></div>\n'
        '<div><h4>Legal</h4><ul>%s</ul></div>\n'
        '<div><h4>%s</h4><ul><li><a href="index.html">Home</a></li></ul></div>\n'
        '</div>\n'
        '<p class="footer-legal-note">%s</p>\n'
        '</div>\n</footer>\n'
    ) % (
        _links(product), _links(developer), _links(legal),
        escape(c.BRAND_NAME), escape(c.NOT_AN_AUDIT_NOTE),
    )


def render_page(page_name: str, body_html: str, base_url: str, extra_jsonld: str = "") -> str:
    head_meta = seo.render_head_meta(page_name, base_url)
    jsonld = (
        seo.organization_jsonld(base_url)
        + seo.website_jsonld(base_url)
        + seo.software_application_jsonld(base_url)
        + seo.breadcrumb_jsonld(base_url, page_name)
        + extra_jsonld
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "%s"
        '<link rel="icon" type="image/svg+xml" href="favicon.svg">\n'
        '<link rel="stylesheet" href="styles.css">\n'
        "%s"
        "</head>\n"
        "<body>\n"
        '<a class="skip-link" href="#main">Skip to content</a>\n'
        '<header class="site-header"><div class="wrap">\n'
        '<a class="brand" href="index.html"><img src="favicon.svg" alt="" width="28" height="28">%s</a>\n'
        "%s"
        "</div></header>\n"
        '<main id="main">\n%s</main>\n'
        "%s"
        "</body>\n"
        "</html>\n"
    ) % (
        head_meta, jsonld, escape(c.BRAND_NAME), render_nav_html(page_name), body_html,
        render_footer_html(),
    )


# ---------------------------------------------------------------------------
# Illustrations - visual layer only. Restrained HTML/CSS/inline-SVG built
# from concepts and data ALREADY approved in content.py (DEMO_FINDING,
# category labels, feature copy fragments) - never a new product claim, a
# new metric, or invented output. Every illustration is captioned as
# illustrative and aria-hidden where it only repeats what the adjacent,
# unchanged prose already says. No images, no JS, no third-party assets.
# ---------------------------------------------------------------------------

def _illo(inner: str, caption: str, css_class: str) -> str:
    return (
        '<div class="illo %s" aria-hidden="true">\n%s\n'
        '<p class="illo-caption">%s</p>\n</div>\n'
    ) % (css_class, inner, escape(caption))


def _illo_titlebar(label: str) -> str:
    return (
        '<div class="illo-titlebar"><span class="dot"></span><span class="dot"></span>'
        '<span class="dot"></span><span class="label">%s</span></div>\n'
    ) % escape(label)


def illo_hero_flow() -> str:
    finding = c.DEMO_FINDING
    inner = (
        '<div class="illo-flow">\n'
        '<div class="step"><strong>Submit source</strong>Solidity / Vyper, pasted or from a repo</div>\n'
        '<div class="chevron">&rarr;</div>\n'
        '<div class="step"><strong>Analyze</strong>Deterministic detectors + AI-assisted review</div>\n'
        '<div class="chevron">&rarr;</div>\n'
        '<div class="step"><strong>%s &middot; %s</strong>Categorized finding with evidence</div>\n'
        "</div>\n"
    ) % (escape(finding["category"]), escape(finding["severity"]))
    return _illo(inner, "Illustrative flow - not a specific run's output.", "illo-flow-wrap")


def illo_code_panel() -> str:
    lines = c.DEMO_FINDING["evidence"]
    rendered = []
    for i, line in enumerate(lines):
        cls = "hl" if i == len(lines) - 1 else None
        text = escape(line)
        rendered.append('<span class="hl">%s</span>' % text if cls else text)
    inner = (
        _illo_titlebar("contract_c.sol")
        + '<div class="illo-code"><pre>%s</pre></div>\n' % "\n".join(rendered)
    )
    return _illo(inner, c.DEMO_SOURCE_NOTE, "")


def illo_diff_panel() -> str:
    inner = (
        _illo_titlebar("security diff")
        + '<div class="diff-body">\n'
        '<span class="diff-line removed">- finding resolved</span>\n'
        '<span class="diff-line added">+ finding new</span>\n'
        '<span class="diff-line neutral">~ finding regressed</span>\n'
        "</div>\n"
    )
    return _illo(inner, "Illustrative diff categories - no specific run shown.", "illo-diff")


def illo_verify_panel() -> str:
    inner = (
        '<div class="illo-compare">'
        '<span class="chip">verified on-chain record</span>'
        '<span class="arrow">&rarr;</span>'
        '<span class="chip">normalized source</span>'
        "</div>\n"
    )
    return _illo(inner, "Bytecode-only, unverified contracts are out of scope by design.", "")


def illo_compare_panel() -> str:
    inner = (
        '<div class="illo-compare">'
        '<span class="chip">source bytecode</span>'
        '<span class="arrow">&rarr;</span>'
        '<span class="chip">deployed runtime bytecode</span>'
        '<span class="arrow">&rarr;</span>'
        '<span class="result">MATCH</span>'
        "</div>\n"
    )
    return _illo(
        inner,
        "One of four real verdicts (MATCH / MISMATCH / UNRESOLVED / UNAVAILABLE), shown for illustration only.",
        "",
    )


def illo_chain_panel() -> str:
    inner = (
        '<div class="illo-compare">'
        '<span class="chip">Chain A &middot; 0x9f…3e</span>'
        '<span class="arrow">&ne;</span>'
        '<span class="chip">Chain B &middot; 0x9f…3e</span>'
        "</div>\n"
    )
    return _illo(inner, "Same address, different chain - never treated as the same target.", "")


def illo_cli_panel() -> str:
    inner = (
        _illo_titlebar("your CI pipeline")
        + '<div class="term-body"><span class="cmd">cli.py pr-gate --report report.json</span>'
        '<span class="cursor"></span>'
        '<div class="out">applies explicit pass/fail rules, exits non-zero on failure</div></div>\n'
    )
    return _illo(inner, "Runs in your own pipeline - this site never executes it for you.", "illo-terminal")


def illo_graph_panel() -> str:
    svg = (
        '<svg viewBox="0 0 260 100" role="presentation">'
        '<line class="edge" x1="60" y1="50" x2="130" y2="25"/>'
        '<line class="edge" x1="60" y1="50" x2="130" y2="75"/>'
        '<line class="edge" x1="130" y1="25" x2="200" y2="50"/>'
        '<line class="edge" x1="130" y1="75" x2="200" y2="50"/>'
        '<circle class="node" cx="60" cy="50" r="16"/>'
        '<circle class="node" cx="130" cy="25" r="14"/>'
        '<circle class="node proxy" cx="130" cy="75" r="14"/>'
        '<circle class="pulse" cx="200" cy="50" r="16"/>'
        '<circle class="node" cx="200" cy="50" r="16"/>'
        '<text x="60" y="53" text-anchor="middle">A</text>'
        '<text x="130" y="28" text-anchor="middle">B</text>'
        '<text x="130" y="78" text-anchor="middle">proxy</text>'
        '<text x="200" y="53" text-anchor="middle">C</text>'
        "</svg>\n"
    )
    return _illo('<div class="illo-graph">%s</div>' % svg, "Contracts, calls and proxies - Pro tier.", "")


def illo_timeline_panel() -> str:
    inner = (
        '<div class="track"><span class="point" style="left:15%"></span>'
        '<span class="point" style="left:80%"></span></div>\n'
        '<div class="labels"><span>Snapshot A</span><span>Snapshot B</span></div>\n'
    )
    return _illo('<div class="illo-timeline">%s</div>' % inner, "Run from your own CI or cron - no hosted service.", "")


# name -> illustration renderer, keyed to content.FEATURES_AVAILABLE/PARTIAL
# entries by their exact "name" so a future rename fails loudly (KeyError)
# instead of silently losing its illustration.
_FEATURE_ILLUSTRATIONS = {
    "Pre-Deployment Review": illo_code_panel,
    "Security Diff": illo_diff_panel,
    "Deployed-Source Verification": illo_verify_panel,
    "Source vs Deployed": illo_compare_panel,
    "Multi-Chain EVM": illo_chain_panel,
    "CI Security Gate": illo_cli_panel,
    "Multi-Contract Review": illo_graph_panel,
    "Upgrade Review": illo_compare_panel,
    "Monitoring": illo_timeline_panel,
}


# ---------------------------------------------------------------------------
# Page bodies - each pulls only from content.py (+ the two live sources for
# pricing.html/developers.html). No product fact is typed twice.
# ---------------------------------------------------------------------------

def _cta_link(cta: "tuple[str, str]", css_class: str = "button secondary") -> str:
    """Renders one of content.py's internal-only CTAs (label, href). Never
    takes an external URL - there is no external checkout link on this site."""
    label, href = cta
    return '<a class="%s" href="%s">%s</a>' % (css_class, escape(href), escape(label))


def is_black_friday_window(now: "datetime.datetime", enabled: bool, start: Optional[str], end: Optional[str]) -> bool:
    """D-086: PRESENTATION ONLY - whether THIS BUILD should show the Black
    Friday notice, decided once at build time (a static site has no
    per-request clock - see module docstring). start/end are raw
    BLACK_FRIDAY_START/END env var strings (ISO-8601, matching backend/
    main.py's own _utc_datetime_env() format) - malformed/missing values
    resolve to "not shown" rather than failing the whole site build, since
    getting this wrong has no security consequence (backend/black_friday.py
    is the real, independently-re-checked enforcement point)."""
    if not enabled or not start or not end:
        return False
    try:
        start_dt = datetime.datetime.fromisoformat(start)
        end_dt = datetime.datetime.fromisoformat(end)
    except ValueError:
        return False
    if start_dt.tzinfo is None or end_dt.tzinfo is None:
        return False
    return start_dt <= now <= end_dt


def render_app_cta(app_base_url: Optional[str], label: str, css_class: str = "button") -> str:
    """The ONE conditional external link this site ever renders - see
    module docstring's Phase 6C note and content.py's own comment above
    APP_BASE_URL_ENV. Returns "" (nothing at all - never a dead/placeholder
    href) when app_base_url is falsy, so an unconfigured build's output is
    byte-identical to before this function existed."""
    if not app_base_url:
        return ""
    href = app_base_url.rstrip("/") + c.APP_LOGIN_PATH
    return '<a class="%s" href="%s">%s</a>' % (css_class, escape(href), escape(label))


def render_home_html(app_base_url: Optional[str] = None) -> str:
    diffs = "\n".join("<li>%s</li>" % escape(d) for d in c.DIFFERENTIATORS)
    app_cta = render_app_cta(app_base_url, c.APP_CTA_LOGIN_LABEL, "button")
    return (
        '<section class="hero wrap">\n'
        "<h1>%s</h1>\n"
        '<p class="tagline">%s</p>\n'
        '<div class="notice">%s</div>\n'
        '<div class="cta">%s %s %s</div>\n'
        "%s"
        "</section>\n"

        '<section class="section wrap">\n'
        "<h2>What %s reviews</h2>\n"
        '<p class="section-intro">Solidity (0.8.x primary; limited support for older Solidity and for '
        "Vyper) smart contract source - before deployment, or against what is already on-chain.</p>\n"
        "</section>\n"

        '<section class="section wrap">\n'
        "<h2>Who it's for</h2>\n"
        '<p class="section-intro">%s</p>\n'
        "</section>\n"

        '<section class="section wrap">\n'
        "<h2>How it differs from a basic Solidity scanner</h2>\n"
        "<ul>%s</ul>\n"
        "</section>\n"

        '<section class="section wrap">\n'
        '<p class="notice quiet">%s</p>\n'
        '<p class="notice quiet">%s</p>\n'
        "</section>\n"
    ) % (
        escape(c.HOME_HEADLINE), escape(c.POSITIONING_TAGLINE), escape(c.NOT_AN_AUDIT_NOTE),
        _cta_link(c.CTA_ANALYZE, "button"), _cta_link(c.CTA_DEMO), app_cta, illo_hero_flow(),
        escape(c.BRAND_NAME), escape(c.WHO_ITS_FOR), diffs,
        escape(c.LLM_PROCESSING_NOTE), escape(c.RETENTION_NOTE),
    )


def _feature_card(f: Dict[str, str], status: str) -> str:
    illustration = _FEATURE_ILLUSTRATIONS.get(f["name"])
    return (
        '<article class="card">\n'
        '<span class="status-pill %s">%s</span>\n'
        "<h3>%s</h3>\n"
        "<p>%s</p>\n"
        '<p class="detail">%s</p>\n'
        "%s"
        "</article>\n"
    ) % (
        status, status.capitalize(), escape(f["name"]), escape(f["summary"]), escape(f["detail"]),
        illustration() if illustration else "",
    )


def render_features_html() -> str:
    available = "\n".join(_feature_card(f, "available") for f in c.FEATURES_AVAILABLE)
    partial = "\n".join(_feature_card(f, "partial") for f in c.FEATURES_PARTIAL)
    return (
        '<section class="section wrap">\n'
        "<h1>Features</h1>\n"
        '<p class="section-intro">"Available" ships today, end to end. "Partial" is real and working, '
        "but narrower than the name might suggest on its own - each card says exactly what is and isn't "
        "covered.</p>\n"
        "</section>\n"
        '<section class="section wrap">\n<h2>Available</h2>\n<div class="card-grid">%s</div>\n</section>\n'
        '<section class="section wrap">\n<h2>Partial</h2>\n<div class="card-grid">%s</div>\n</section>\n'
        '<section class="section wrap"><p class="cta">%s</p></section>\n'
    ) % (available, partial, _cta_link(c.CTA_HOW_IT_WORKS, "button"))


def render_demo_html() -> str:
    finding = c.DEMO_FINDING
    evidence = "\n".join("<li><code>%s</code></li>" % escape(line) for line in finding["evidence"])
    sev = finding["severity"].lower()
    ri = c.DEMO_RISK_INDICATOR
    return (
        '<section class="section wrap">\n'
        "<h1>Example output</h1>\n"
        '<p class="section-intro">%s</p>\n'
        "</section>\n"
        '<section class="section wrap">\n'
        '<div class="finding-card">\n'
        '<span class="severity-badge %s">%s</span>\n'
        '<p class="meta">%s &middot; %s.%s &middot; confidence: %s &middot; confirmed</p>\n'
        "<p>%s</p>\n"
        "<h3>Evidence</h3>\n<ul>%s</ul>\n"
        "<h3>Suggested remediation</h3>\n<p>%s</p>\n"
        '<p class="notice quiet">%s</p>\n'
        "</div>\n"
        "</section>\n"
        '<section class="section wrap">\n'
        "<h2>Automated Risk Indicator</h2>\n"
        '<p>Band: <strong>%s</strong> (score %s/100)</p>\n'
        '<p class="section-intro">%s %s</p>\n'
        '<p class="cta">%s</p>\n'
        "</section>\n"
    ) % (
        escape(c.DEMO_SOURCE_NOTE),
        sev, escape(finding["severity"]),
        escape(finding["category"]), escape(finding["contract"]), escape(finding["function"]),
        escape(finding["confidence"]),
        escape(finding["description"]),
        evidence,
        escape(finding["recommendation"]),
        escape(c.PATCH_NOTE),
        escape(ri["band"]), escape(ri["score"]),
        escape(ri["explanation"]), escape(c.RISK_INDICATOR_LOW_NOTE),
        _cta_link(c.CTA_ANALYZE, "button"),
    )


def render_methodology_html() -> str:
    steps = "\n".join(
        "<li><h3>%s</h3><p>%s</p></li>" % (escape(name), escape(desc)) for name, desc in c.PIPELINE_STEPS
    )
    confidence = "\n".join(
        "<tr><th scope=\"row\">%s</th><td>%s</td></tr>" % (escape(name), escape(desc))
        for name, desc in c.CONFIDENCE_LEVELS
    )
    categories = "\n".join(
        "<tr><th scope=\"row\">%s</th><td>%s</td><td>%s</td></tr>"
        % (escape(cat["id"]), escape(cat["name"]), escape(cat["description"]))
        for cat in c.CATEGORIES
    )
    return (
        '<section class="section wrap">\n'
        "<h1>Methodology</h1>\n"
        '<p class="section-intro">How a review goes from submitted source to a report.</p>\n'
        '<ol class="pipeline">%s</ol>\n'
        "</section>\n"
        '<section class="section wrap">\n'
        "<h2>Confidence levels</h2>\n"
        '<div class="table-scroll"><table><tbody>%s</tbody></table></div>\n'
        "</section>\n"
        '<section class="section wrap">\n'
        "<h2>Categories (SC01-SC10)</h2>\n"
        '<p class="section-intro">Ten categories used to classify findings.</p>\n'
        '<div class="table-scroll"><table>\n'
        '<thead><tr><th scope="col">ID</th><th scope="col">Category</th><th scope="col">What it covers</th></tr></thead>\n'
        "<tbody>%s</tbody></table></div>\n"
        "</section>\n"
        '<section class="section wrap">\n'
        "<h2>Scope and limitations</h2>\n"
        "<p>%s</p>\n<p>%s</p>\n"
        '<p class="cta">%s</p>\n'
        "</section>\n"
    ) % (
        steps, confidence, categories, escape(c.FALSE_NEGATIVE_NOTE), escape(c.NOT_AN_AUDIT_NOTE),
        _cta_link(c.CTA_ANALYZE, "button"),
    )


def render_developers_html(cli_entries: List[Dict[str, str]]) -> str:
    sections = []
    for entry in cli_entries:
        sections.append(
            '<section class="cli-command">\n<h3><code>cli.py %s</code></h3>\n'
            "<pre>%s</pre>\n</section>\n" % (escape(entry["command"]), escape(entry["help"]))
        )
    intro = (
        '<section class="section wrap">\n<h1>Developers</h1>\n'
        '<p class="section-intro">Standard/Pro buyers can wire this analyzer\'s deterministic layer '
        "into their own CI pipeline. These commands run in YOUR OWN environment and your own runtime - "
        "this website never executes them for you and never sees your source code.</p>\n</section>\n"
    )
    outro = '<section class="section wrap"><p class="cta"><a class="button secondary" href="pricing.html">See pricing and tiers</a></p></section>\n'
    return (
        intro
        + '<section class="section wrap">\n<h2>CLI reference</h2>\n'
        + "\n".join(sections) + "</section>\n" + outro
    )


# D-087: the pure boundary check, shipped verbatim inside the inline
# <script> render_pricing_html() emits below AND executed as-is (via
# Node, no browser needed) by tests/test_website_black_friday_runtime.py
# - the tested code IS the shipped code, never a hand-copied second
# version that could drift. Deliberately takes nowMs as a parameter
# (never reads Date.now() itself) so it stays a pure, trivially testable
# function; the tiny caller below it is the only place that touches the
# real clock or the DOM.
BLACK_FRIDAY_BOUNDARY_CHECK_JS = (
    "function isBlackFridayActive(nowMs, startMs, endMs) { return nowMs >= startMs && nowMs <= endMs; }"
)


def render_black_friday_script() -> str:
    """D-087: RUNTIME (not build-time) Black Friday presentation - fixes
    the staleness bug a build-time-only check had (see content.py's own
    comment above BLACK_FRIDAY_START_UTC and build_site.py's module
    docstring). Every element that should only be visible during the
    campaign carries data-bf-presentation and starts `hidden` (the safe,
    fail-hidden default if JS never runs - "before/after campaign: no
    banner" is what a visitor sees either way); every element that should
    be hidden ONCE the campaign is confirmed active (the normal annual
    price, replaced by the first-year price) carries data-bf-normal.
    Monthly price cells carry NEITHER attribute anywhere in this file -
    structurally incapable of ever presenting a discount, not merely
    prevented by this check. Date.now()/Date.parse() are both inherently
    UTC (epoch milliseconds) regardless of the visitor's own browser
    timezone - no separate UTC handling is needed or done here. This
    script only ever changes what is SHOWN - it has no reference to
    Stripe, a Price ID, a coupon, or any discount MECHANISM; the actual
    discount is decided exclusively by backend/black_friday.py on the
    server, re-checked on every real Checkout request - see that
    module's own docstring."""
    return (
        "<script>\n(function() {\n"
        '  var BF_START = Date.parse(%s);\n'
        '  var BF_END = Date.parse(%s);\n'
        "  %s\n"
        "  if (!isBlackFridayActive(Date.now(), BF_START, BF_END)) { return; }\n"
        '  var show = document.querySelectorAll("[data-bf-presentation]");\n'
        "  for (var i = 0; i < show.length; i++) { show[i].hidden = false; }\n"
        '  var hide = document.querySelectorAll("[data-bf-normal]");\n'
        "  for (var j = 0; j < hide.length; j++) { hide[j].hidden = true; }\n"
        "})();\n</script>\n"
    ) % (json.dumps(c.BLACK_FRIDAY_START_UTC), json.dumps(c.BLACK_FRIDAY_END_UTC), BLACK_FRIDAY_BOUNDARY_CHECK_JS)


def render_pricing_html(tiers: List[Dict[str, Any]], app_base_url: Optional[str] = None) -> str:
    rows = []
    for key, label in _FEATURE_LABELS:
        cells = []
        for tier in tiers:
            value = tier["features"].get(key)
            if isinstance(value, bool):
                text = "Yes" if value else "-"
            elif value is None:
                text = "Unlimited" if key == "maxSourceFiles" else "-"
            else:
                text = str(value)
            cells.append("<td>%s</td>" % escape(text))
        rows.append('<tr><th scope="row">%s</th>%s</tr>' % (escape(label), "".join(cells)))
    header_cells = "".join('<th scope="col">%s</th>' % escape(t["mode"].capitalize()) for t in tiers)
    price_rows = ""
    black_friday_notice = ""
    black_friday_script = ""
    if c.PRICING_PUBLISHED:
        monthly_cells, annual_cells = [], []
        for tier in tiers:
            cfg = next((p for p in c.PRICING_TIERS if p["mode"] == tier["mode"]), None)
            monthly_price = escape(cfg["price_monthly"] if cfg else "Contact")
            monthly_cells.append("<td>%s</td>" % monthly_price)
            annual_price = escape(cfg["price_annual"] if cfg else "Contact")
            if cfg and tier["mode"] in c.BLACK_FRIDAY_FIRST_YEAR_PRICES:
                bf_price = escape(c.BLACK_FRIDAY_FIRST_YEAR_PRICES[tier["mode"]])
                annual_cells.append(
                    '<td><span data-bf-normal>%s</span>'
                    '<span data-bf-presentation hidden>%s first year (%s)</span></td>'
                    % (annual_price, bf_price, escape(c.BLACK_FRIDAY_RENEWAL_NOTE))
                )
            else:
                annual_cells.append("<td>%s</td>" % annual_price)
        price_rows = (
            '<tr><th scope="row">Price (monthly)</th>%s</tr>\n'
            '<tr><th scope="row">Price (annual)</th>%s</tr>\n'
        ) % ("".join(monthly_cells), "".join(annual_cells))
        # D-087: ALWAYS rendered (never gated on this build's own clock -
        # see render_black_friday_script()'s own docstring) - `hidden` by
        # default, revealed only by that script, only inside a visitor's
        # own browser, only during the real campaign window.
        black_friday_notice = (
            '<div class="notice" data-bf-presentation hidden>\n<h2>Black Friday - 30%% off the first year</h2>\n'
            "<p>Annual plans only. %s</p>\n</div>\n"
        ) % escape(c.BLACK_FRIDAY_RENEWAL_NOTE)
        black_friday_script = render_black_friday_script()
    app_cta = render_app_cta(app_base_url, c.APP_CTA_GET_STARTED_LABEL, "button")
    bf_cta_badge = (
        '<span class="notice" data-bf-presentation hidden>Black Friday: 30% off annual</span>' if c.PRICING_PUBLISHED else ""
    )
    return (
        '<section class="section wrap">\n<h1>Pricing</h1>\n'
        '<p class="section-intro">%s</p>\n'
        '<div class="notice">%s</div>\n'
        "%s"
        "</section>\n"
        '<section class="section wrap">\n'
        '<div class="table-scroll"><table class="tier-comparison">\n'
        '<thead><tr><th scope="col">Feature</th>%s</tr></thead>\n'
        "<tbody>\n%s%s\n</tbody>\n"
        "</table></div>\n"
        '<p class="cta">%s %s %s</p>\n'
        "%s"
        "</section>\n"
    ) % (
        escape(c.PRICING_NOTE), escape(c.NO_TRIAL_NOTE), black_friday_notice,
        header_cells, price_rows, "\n".join(rows), _cta_link(c.CTA_ANALYZE, "button"), app_cta, bf_cta_badge,
        black_friday_script,
    )


def render_faq_html() -> str:
    items = "\n".join(
        '<div class="faq-item"><h2>%s</h2><p>%s</p></div>' % (escape(q), escape(a)) for q, a in c.FAQ_ITEMS
    )
    return (
        '<section class="section wrap">\n<h1>Frequently asked questions</h1>\n%s\n'
        '<p class="cta">%s</p>\n</section>\n'
    ) % (items, _cta_link(c.CTA_ANALYZE, "button"))


def _sections_page(title: str, sections: List[Any]) -> str:
    body = "\n".join("<h2>%s</h2>\n<p>%s</p>" % (escape(h), escape(p)) for h, p in sections)
    return '<section class="section wrap">\n<h1>%s</h1>\n%s\n</section>\n' % (escape(title), body)


def render_legal_html() -> str:
    return _sections_page("Legal", c.LEGAL_SECTIONS)


def render_privacy_html() -> str:
    return _sections_page("Privacy", c.PRIVACY_SECTIONS)


def render_disclaimer_html() -> str:
    return _sections_page("Disclaimer", c.DISCLAIMER_SECTIONS)


def render_cookies_html() -> str:
    return _sections_page("Cookies", c.COOKIES_SECTIONS)


def render_refund_html() -> str:
    return _sections_page("Refund & Cancellation", c.REFUND_SECTIONS)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

_BUILD_ENVS = ("dev", "staging", "production")


def build_site(
    out_dir: str, base_url: Optional[str] = None, app_url: Optional[str] = None, env: str = "dev",
) -> Dict[str, str]:
    """Generates the static site into out_dir. Returns {relative_path: absolute_path}
    for every file written (pages + sitemap.xml + robots.txt + static assets).
    Pure function of content.py + config/modes.json + each script's own
    --help output (plus SITE_LAST_UPDATED, a manually-bumped constant, never
    datetime.now()) - no network, no account/session state. No external
    checkout/marketplace URL is accepted or rendered anywhere except the one
    conditional app-login CTA (content.APP_BASE_URL_ENV / app_url below,
    Phase 6C) - every other CTA is one of content.py's internal-only CTA_*
    constants.

    app_url (or the VERICEXA_APP_URL env var) is OPTIONAL for env="dev" (the
    default): omitting it simply renders no app CTA anywhere, byte-identical
    to this function's pre-Phase-6C output - never a dead/placeholder link.
    For env="staging"/"production" it is REQUIRED and this function raises
    BuildSiteError immediately if missing - a staging/production build must
    never silently ship without knowing where its own login CTA points, and
    must never silently fall back to a guessed/hardcoded domain either (see
    content.py's own comment above APP_BASE_URL_ENV).

    D-087: this function is NOT parameterized by "now" for Black Friday
    presentation - that would reintroduce the exact staleness bug D-087
    fixes (a build's own clock, frozen at build time, going stale the
    moment real time crosses the campaign boundary). Black Friday
    presentation is entirely a RUNTIME concern now - see
    render_pricing_html()/render_black_friday_script()."""
    if env not in _BUILD_ENVS:
        raise BuildSiteError("env must be one of %r, got %r" % (_BUILD_ENVS, env))
    site_base_url = (base_url or os.environ.get(c.BASE_URL_ENV) or c.DEFAULT_BASE_URL).rstrip("/")
    app_base_url = (app_url or os.environ.get(c.APP_BASE_URL_ENV) or "").rstrip("/") or None
    if env != "dev" and not app_base_url:
        raise BuildSiteError(
            "env=%r requires an app base URL (--app-url or the %s env var) - "
            "refusing to build a staging/production site with no configured "
            "app login destination." % (env, c.APP_BASE_URL_ENV)
        )
    try:
        modes_config = load_modes_config()
    except ModesConfigError as exc:
        raise BuildSiteError("could not load config/modes.json: %s" % exc) from exc

    tiers = build_tier_comparison(modes_config)
    cli_entries = collect_cli_reference()

    bodies = {
        "index.html": render_home_html(app_base_url),
        "features.html": render_features_html(),
        "demo.html": render_demo_html(),
        "methodology.html": render_methodology_html(),
        "developers.html": render_developers_html(cli_entries),
        "pricing.html": render_pricing_html(tiers, app_base_url),
        "faq.html": render_faq_html(),
        "legal.html": render_legal_html(),
        "privacy.html": render_privacy_html(),
        "disclaimer.html": render_disclaimer_html(),
        "cookies.html": render_cookies_html(),
        "refund.html": render_refund_html(),
    }
    extra_jsonld = {"faq.html": seo.faq_jsonld(c.FAQ_ITEMS)}
    pages = {
        name: render_page(name, body, site_base_url, extra_jsonld.get(name, ""))
        for name, body in bodies.items()
    }

    os.makedirs(out_dir, exist_ok=True)
    written: Dict[str, str] = {}
    for relative_path, body in pages.items():
        full_path = os.path.join(out_dir, relative_path)
        with open(full_path, "w", encoding="utf-8") as handle:
            handle.write(body)
        written[relative_path] = full_path

    sitemap_path = os.path.join(out_dir, "sitemap.xml")
    with open(sitemap_path, "w", encoding="utf-8") as handle:
        handle.write(seo.render_sitemap_xml(site_base_url, list(bodies.keys())))
    written["sitemap.xml"] = sitemap_path

    robots_path = os.path.join(out_dir, "robots.txt")
    with open(robots_path, "w", encoding="utf-8") as handle:
        handle.write(seo.render_robots_txt(site_base_url))
    written["robots.txt"] = robots_path

    for static_name in ("styles.css", "favicon.svg"):
        src = os.path.join(STATIC_DIR, static_name)
        dst = os.path.join(out_dir, static_name)
        shutil.copyfile(src, dst)
        written[static_name] = dst

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_site.py",
        description="Build the static Vericexa marketing/pricing/docs site from content.py, config/modes.json and each script's own --help output.",
    )
    parser.add_argument("--out", default=os.path.join(SCRIPT_DIR, "dist"), help="Output directory (default: website/dist).")
    parser.add_argument("--base-url", default=None, help="Canonical site base URL for SEO tags/sitemap (default: %s env var, then %s)." % (c.BASE_URL_ENV, c.DEFAULT_BASE_URL))
    parser.add_argument("--app-url", default=None, help="Standalone backend's public base URL for the app login CTA (default: %s env var; no other default - see build_site()'s own docstring)." % c.APP_BASE_URL_ENV)
    parser.add_argument("--env", default="dev", choices=_BUILD_ENVS, help="Build environment (default: dev). staging/production require --app-url or %s to be set, and fail the build otherwise." % c.APP_BASE_URL_ENV)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        written = build_site(args.out, base_url=args.base_url, app_url=args.app_url, env=args.env)
    except BuildSiteError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    print(json.dumps({"ok": True, "buildVersion": BUILD_VERSION, "files": written}, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
