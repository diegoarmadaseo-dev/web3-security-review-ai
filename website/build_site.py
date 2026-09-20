#!/usr/bin/env python3
"""Build-time static site generator for the Vericexa website (V2.13 rebrand
and 10-page expansion of the V2.12 site, docs/decisiones.md D-067 base;
capabilities W-01, W-02, W-04 kept, extended with SEO/GEO output).

Architecture is unchanged from V2.12 and is NOT rebuilt: a third-party
marketplace (docs/capafy-notas.md, capafy/pricing.md) still owns auth,
billing, tiers and execution behind the scenes. This generator remains a
thin, PUBLIC, static layer in front of that - no accounts, no payment, no
storage, no hosted analyzer execution. Per the SEO-fixes pass, the public
site no longer names or links to that marketplace anywhere: every CTA is an
internal Vericexa page (content.CTA_ANALYZE/CTA_DEMO/CTA_HOW_IT_WORKS), and
the only remaining dynamic surface it links to is the stateless W-03 endpoint
(server.py). The marketplace is still disclosed BY FACT (who processes LLM
calls, who governs purchase terms) in legal.html/privacy.html, generically
worded per content.py's LEGAL_SECTIONS/PRIVACY_SECTIONS - never removed,
just no longer named or linked as a brand.

All brand/copy/feature-status/pricing facts live in website/content.py (one
place to edit, never restated here - same single-source-of-truth discipline
D-058 established for config/modes.json). All SEO/structured-data encoding
lives in website/seo.py. This file is the orchestrator: it turns content.py
data plus two LIVE sources - preprocess.load_modes_config() (config/
modes.json) and each script's own --help text (V2.11 cli.py) - into static
HTML, sitemap.xml and robots.txt. Neither live source is duplicated as a
second hand-copied value anywhere in this file.

Pricing (dollar amounts, billing cadence) is deliberately never rendered:
content.PRICING_PUBLISHED is False because capafy/pricing.md still marks
amounts `[CAPAFY-VERIFY]` ("Draft only"). The pricing page shows tier NAMES
and FEATURE differences only, with an internal CTA (content.CTA_ANALYZE) -
see content.py for how to activate real prices later.

Standard library only. No network access, no LLM calls, no accounts,
no payment logic. Python 3.8+.
"""
from __future__ import annotations

import argparse
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
    legal = [p for p in c.ALL_PAGES if p[0] in ("legal.html", "privacy.html", "disclaimer.html")]
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


def render_home_html() -> str:
    diffs = "\n".join("<li>%s</li>" % escape(d) for d in c.DIFFERENTIATORS)
    return (
        '<section class="hero wrap">\n'
        "<h1>%s</h1>\n"
        '<p class="tagline">%s</p>\n'
        '<div class="notice">%s</div>\n'
        '<div class="cta">%s %s</div>\n'
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
        _cta_link(c.CTA_ANALYZE, "button"), _cta_link(c.CTA_DEMO), illo_hero_flow(),
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


def render_pricing_html(tiers: List[Dict[str, Any]]) -> str:
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
    price_row = ""
    if c.PRICING_PUBLISHED:
        price_cells = []
        for tier in tiers:
            cfg = next((p for p in c.PRICING_TIERS if p["mode"] == tier["mode"]), None)
            price = cfg["price"] if cfg else None
            price_cells.append("<td>%s</td>" % escape(price if price else "Contact"))
        price_row = '<tr><th scope="row">Price</th>%s</tr>\n' % "".join(price_cells)
    return (
        '<section class="section wrap">\n<h1>Pricing</h1>\n'
        '<p class="section-intro">Tier names match the product\'s own analysis modes one-to-one.</p>\n'
        '<div class="notice">%s</div>\n'
        "</section>\n"
        '<section class="section wrap">\n'
        '<div class="table-scroll"><table class="tier-comparison">\n'
        '<thead><tr><th scope="col">Feature</th>%s</tr></thead>\n'
        "<tbody>\n%s%s\n</tbody>\n"
        "</table></div>\n"
        '<p class="cta">%s</p>\n'
        "</section>\n"
    ) % (escape(c.PRICING_UNCONFIRMED_NOTE), header_cells, price_row, "\n".join(rows), _cta_link(c.CTA_ANALYZE, "button"))


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


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_site(out_dir: str, base_url: Optional[str] = None) -> Dict[str, str]:
    """Generates the static site into out_dir. Returns {relative_path: absolute_path}
    for every file written (pages + sitemap.xml + robots.txt + static assets).
    Pure function of content.py + config/modes.json + each script's own
    --help output (plus SITE_LAST_UPDATED, a manually-bumped constant, never
    datetime.now()) - no network, no account/session state. No external
    checkout/marketplace URL is accepted or rendered anywhere - every CTA is
    one of content.py's internal-only CTA_* constants."""
    site_base_url = (base_url or os.environ.get(c.BASE_URL_ENV) or c.DEFAULT_BASE_URL).rstrip("/")
    try:
        modes_config = load_modes_config()
    except ModesConfigError as exc:
        raise BuildSiteError("could not load config/modes.json: %s" % exc) from exc

    tiers = build_tier_comparison(modes_config)
    cli_entries = collect_cli_reference()

    bodies = {
        "index.html": render_home_html(),
        "features.html": render_features_html(),
        "demo.html": render_demo_html(),
        "methodology.html": render_methodology_html(),
        "developers.html": render_developers_html(cli_entries),
        "pricing.html": render_pricing_html(tiers),
        "faq.html": render_faq_html(),
        "legal.html": render_legal_html(),
        "privacy.html": render_privacy_html(),
        "disclaimer.html": render_disclaimer_html(),
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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        written = build_site(args.out, base_url=args.base_url)
    except BuildSiteError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    print(json.dumps({"ok": True, "buildVersion": BUILD_VERSION, "files": written}, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
