#!/usr/bin/env python3
"""Build-time static site generator: English marketing/pricing/docs (V2.12,
docs/decisiones.md D-067, capabilities W-01, W-02, W-04).

Capafy owns auth, billing, tiers and execution (docs/capafy-notas.md,
capafy/pricing.md). This site is a thin, PUBLIC, static layer in front of
that - it implements NO competing accounts, payment, storage or hosted
analyzer execution. Every dynamic page it links to is either an external
Capafy URL (checkout/login) or the stateless W-03 endpoint (server.py),
never something this generator runs itself.

W-04 (tier/limits table): sourced LIVE from config/modes.json via the
Skill's own preprocess.load_modes_config() - the exact same single-source-
of-truth discipline D-058 established for chains.json. This generator holds
no second, hand-copied list of limits that could silently drift.

Pricing (dollar amounts, billing cadence): deliberately NEVER rendered here.
capafy/pricing.md marks the amounts and billing mechanism `[CAPAFY-VERIFY]`
("Draft only - nothing here is configured in Capafy yet"); a website
showing them as if confirmed would violate V2.12's own explicit rule
("Never expose [CAPAFY-VERIFY] or internal billing details"). The pricing
page shows tier NAMES and FEATURE differences only, with a CTA out to the
Capafy listing for the actual current price.

W-02 (CLI/CI integration docs): the reference page is built by literally
capturing each script's own --help text via cli.COMMANDS + build_arg_parser()
(V2.11) - never hand-typed prose that could drift from the real CLI.

Commercial-claims compliance (docs/commercial-claims.md): every string
literal written into generated HTML on this page comes from the file's own
"Permitted" vocabulary and "Formulas obligatorias" - never invented sales
copy. tests/test_website_build.py sweeps all generated output against the
same Level-A prohibited-term list docs/commercial-claims.md's own commit
procedure already greps for.

Standard library only. No network access, no LLM calls, no accounts,
no payment logic. Python 3.8+.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from html import escape
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SCRIPTS_DIR = os.path.join(REPO_ROOT, ".claude", "skills", "web3-auditor", "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from preprocess import load_modes_config, ModesConfigError  # noqa: E402
import cli  # noqa: E402 - V2.11 unified dispatcher; source of truth for the CLI/CI reference page

BUILD_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

# No Capafy listing URL exists anywhere in this repo, and this generator
# never guesses/fabricates one - the CTA target is a build-time input the
# deployer must supply (env var), defaulting to an intentionally-broken
# placeholder anchor so an unconfigured build can never ship a fake link
# silently as if it were real.
CAPAFY_LISTING_URL_ENV = "CAPAFY_LISTING_URL"
_UNCONFIGURED_CAPAFY_URL = "#capafy-listing-url-not-configured"

# Approved marketing copy, verbatim from docs/commercial-claims.md
# ("Posicionamiento oficial" / "Permitted"). Never invented here.
POSITIONING_HEADLINE = "Automated AI-assisted smart contract security review."
POSITIONING_TAGLINE = "Review your smart contract code for common security risks with AI-assisted analysis."
LLM_PROCESSING_NOTE = "LLM processing via Capafy infrastructure."
RETENTION_NOTE = (
    "The Skill deletes its local temporary working copy at the end of execution. "
    "This does not control platform, runtime, provider, billing, security or "
    "execution-log retention outside the Skill."
)
NOT_AN_AUDIT_NOTE = (
    "This is an automated, AI-assisted preliminary security review. It is NOT a "
    "formal security audit, certification, or guarantee of security."
)

# Unique per page - vocabulary drawn only from docs/commercial-claims.md's
# own "Permitted" list, never invented sales copy (V2.12 FIX W-01 ONLY:
# content/claims stay unchanged, only document structure/navigation is new).
PAGE_TITLES = {
    "index.html": "Security Review Analyzer - Automated AI-Assisted Smart Contract Security Review",
    "pricing.html": "Pricing and Tiers - Security Review Analyzer",
    "docs.html": "CLI and CI Integration Docs - Security Review Analyzer",
}
PAGE_DESCRIPTIONS = {
    "index.html": "Automated, AI-assisted preliminary security review for Solidity and Vyper smart contracts, with findings, an Automated Risk Indicator and suggested remediation.",
    "pricing.html": "Compare Quick, Standard and Pro tier features - lines of code analyzed, source files, suggested remediation patches, gas suggestions and report formats.",
    "docs.html": "Reference for wiring this analyzer's CLI and CI security gate into your own pipeline, including PR ingestion, baseline diffing and continuous monitoring.",
}

_NAV_LINKS = [("index.html", "Home"), ("pricing.html", "Pricing"), ("docs.html", "Docs")]

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


def render_pricing_html(tiers: List[Dict[str, Any]], capafy_listing_url: str) -> str:
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
        rows.append("<tr><th scope=\"row\">%s</th>%s</tr>" % (escape(label), "".join(cells)))
    header_cells = "".join("<th scope=\"col\">%s</th>" % escape(t["mode"].capitalize()) for t in tiers)
    return (
        "<table class=\"tier-comparison\">\n"
        "<thead><tr><th scope=\"col\">Feature</th>%s</tr></thead>\n"
        "<tbody>\n%s\n</tbody>\n"
        "</table>\n"
        "<p class=\"pricing-cta\">Current pricing and checkout: "
        "<a href=\"%s\">view this listing on Capafy</a>.</p>\n"
    ) % (header_cells, "\n".join(rows), escape(capafy_listing_url))


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


def render_cli_docs_html(entries: List[Dict[str, str]]) -> str:
    sections = []
    for entry in entries:
        sections.append(
            "<section class=\"cli-command\">\n<h3><code>cli.py %s</code></h3>\n"
            "<pre>%s</pre>\n</section>\n" % (escape(entry["command"]), escape(entry["help"]))
        )
    intro = (
        "<p>Standard/Pro buyers can wire this analyzer's deterministic layer "
        "into their own CI pipeline. These commands run in YOUR OWN "
        "environment and your own runtime - this website never executes "
        "them for you and never sees your source code.</p>\n"
    )
    outro = "<p class=\"cta\"><a href=\"pricing.html\">See pricing and tiers</a></p>\n"
    return intro + "\n".join(sections) + outro


def render_nav_html(current_page: str) -> str:
    """Home <-> Pricing <-> Docs on every page - every page links to both
    others, so no pairwise navigation path is ever missing."""
    items = []
    for href, label in _NAV_LINKS:
        if href == current_page:
            items.append("<a href=\"%s\" aria-current=\"page\">%s</a>" % (escape(href), escape(label)))
        else:
            items.append("<a href=\"%s\">%s</a>" % (escape(href), escape(label)))
    return "<nav>%s</nav>\n" % " | ".join(items)


def render_page(page_name: str, body_html: str) -> str:
    """Wraps a page's body content into a complete HTML document (V2.12 FIX
    W-01 ONLY) - doctype/html lang/head/charset/viewport/unique title/unique
    meta description/nav, added around content that is otherwise byte-for-
    byte the same as before this fix. Never touches W-02/W-03/W-04 logic."""
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>%s</title>\n"
        "<meta name=\"description\" content=\"%s\">\n"
        "</head>\n"
        "<body>\n"
        "%s"
        "%s"
        "</body>\n"
        "</html>\n"
    ) % (escape(PAGE_TITLES[page_name]), escape(PAGE_DESCRIPTIONS[page_name]), render_nav_html(page_name), body_html)


def render_home_html(capafy_listing_url: str) -> str:
    return (
        "<h1>%s</h1>\n<p class=\"tagline\">%s</p>\n"
        "<p class=\"disclaimer\">%s</p>\n"
        "<p class=\"llm-note\">%s</p>\n"
        "<p class=\"retention-note\">%s</p>\n"
        "<p class=\"cta\"><a href=\"%s\">Get started on Capafy</a></p>\n"
    ) % (
        escape(POSITIONING_HEADLINE), escape(POSITIONING_TAGLINE),
        escape(NOT_AN_AUDIT_NOTE), escape(LLM_PROCESSING_NOTE), escape(RETENTION_NOTE),
        escape(capafy_listing_url),
    )


def build_site(out_dir: str, capafy_listing_url: Optional[str] = None) -> Dict[str, str]:
    """Generates the static site into out_dir. Returns {relative_path: absolute_path}
    for every file written. Pure function of config/modes.json + each script's
    own --help output - no network, no account/session state."""
    url = capafy_listing_url or os.environ.get(CAPAFY_LISTING_URL_ENV) or _UNCONFIGURED_CAPAFY_URL
    try:
        modes_config = load_modes_config()
    except ModesConfigError as exc:
        raise BuildSiteError("could not load config/modes.json: %s" % exc) from exc

    tiers = build_tier_comparison(modes_config)
    cli_entries = collect_cli_reference()

    bodies = {
        "index.html": render_home_html(url),
        "pricing.html": render_pricing_html(tiers, url),
        "docs.html": render_cli_docs_html(cli_entries),
    }
    pages = {name: render_page(name, body) for name, body in bodies.items()}

    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for relative_path, body in pages.items():
        full_path = os.path.join(out_dir, relative_path)
        with open(full_path, "w", encoding="utf-8") as handle:
            handle.write(body)
        written[relative_path] = full_path
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
        description="Build the static English marketing/pricing/docs site from config/modes.json and each script's own --help output.",
    )
    parser.add_argument("--out", default=os.path.join(SCRIPT_DIR, "dist"), help="Output directory (default: website/dist).")
    parser.add_argument("--capafy-url", default=None, help="Capafy listing URL for CTAs (default: %s env var)." % CAPAFY_LISTING_URL_ENV)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        written = build_site(args.out, capafy_listing_url=args.capafy_url)
    except BuildSiteError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    print(json.dumps({"ok": True, "buildVersion": BUILD_VERSION, "files": written}, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
