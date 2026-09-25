#!/usr/bin/env python3
"""Centralized brand, copy, feature-status, pricing and legal content for the
Vericexa website (V2.13, docs/decisiones.md D-067 follow-up: Vericexa rebrand
and 10-page expansion of the V2.12 site).

Single source of truth: every product fact/claim rendered anywhere in
website/build_site.py is read from here, never re-typed in a page function.
This mirrors the discipline config/modes.json already established for tier
limits (D-058) - one place to edit, no second hand-copied string that could
drift from it.

Every AVAILABLE/PARTIAL feature claim below is grounded in a specific,
already-committed script or config in .claude/skills/web3-auditor/ - see the
inline "Evidence" note on each entry. Nothing here describes a capability
that does not exist yet (no hosted accounts, no dashboard, no automated
alerts/monitoring service - see FEATURES_PARTIAL["monitoring"]).

Pricing is centralized but UNPUBLISHED (PRICING_PUBLISHED = False): no real
dollar amounts have been confirmed for either potential distribution path -
capafy/pricing.md still marks its own amounts [CAPAFY-VERIFY] ("Draft only"),
and the independent standalone-SaaS backend (backend/billing.py, Phase 3-4,
docs/decisiones.md D-077) has its own Stripe Price ID configuration that is
equally unconfirmed/unset today. This module holds tier names/features only,
ready for later activation once Diego confirms real numbers for whichever
path is actually live - flip PRICING_PUBLISHED and fill in each tier's
"price"/"billing_period" when that happens. No other code path needs to
change.

Standard library only. No network access, no LLM calls, no accounts.
Python 3.8+.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Brand
# ---------------------------------------------------------------------------

BRAND_NAME = "Vericexa"
DOMAIN = "vericexa.com"
DEFAULT_BASE_URL = "https://vericexa.com"
BASE_URL_ENV = "VERICEXA_BASE_URL"

# The standalone backend's own public base URL (Phase 6C, docs/decisiones.md
# D-084) - e.g. "https://app.vericexa.com". Deliberately has NO default
# (unlike DEFAULT_BASE_URL above): this is a real deployment's own address,
# never guessed. Unset by default, so build_site.py's build_site() renders
# no app CTA at all (never a dead/placeholder link) unless a caller
# explicitly supplies one - see that function's own docstring on the
# staging/production fail-fast gate.
APP_BASE_URL_ENV = "VERICEXA_APP_URL"
APP_LOGIN_PATH = "/auth/login"  # backend/http_app.py's real GET /auth/login entry point (Phase 5).

# Global positioning line (meta description fallback, footer, Organization/
# WebApplication JSON-LD). Distinct from HOME_HEADLINE, which is the shorter
# on-page H1 - both strings were specified verbatim and are kept verbatim.
POSITIONING = "Automated Smart Contract Security Review Platform for Web3 Developers"
HOME_HEADLINE = "Automated Smart Contract Security Review for Web3 Developers"

# Approved marketing copy, verbatim from docs/commercial-claims.md
# ("Posicionamiento oficial" / "Permitted" / "Formulas obligatorias"). Never
# invented here - see docs/commercial-claims.md for the source list.
POSITIONING_TAGLINE = "Review your smart contract code for common security risks with AI-assisted analysis."
WHO_ITS_FOR = (
    "Web3 developers and teams who want an automated, AI-assisted pass before deploying a contract, or "
    "wired into CI as a recurring gate - alongside, not instead of, a full audit from security "
    "professionals for anything holding real value."
)
LLM_PROCESSING_NOTE = "LLM processing via third-party infrastructure."
RETENTION_NOTE = (
    "The Skill deletes its local temporary working copy at the end of execution. "
    "This does not control platform, runtime, provider, billing, security or "
    "execution-log retention outside the Skill."
)
NOT_AN_AUDIT_NOTE = (
    "This is an automated, AI-assisted preliminary security review. It is NOT a "
    "formal security audit, certification, or guarantee of security."
)
PRE_USE_WARNING = (
    "This is an automated, AI-assisted smart contract security review. It is not a "
    "formal security audit, certification, or guarantee of security. Findings may be "
    "incomplete or incorrect. Do not rely on this review as the sole basis for "
    "deployment or other security-critical decisions."
)
RISK_INDICATOR_NOTE = (
    "This indicator reflects findings detected within the analyzed scope. It is not "
    "a measure of overall protocol security."
)
RISK_INDICATOR_LOW_NOTE = "A LOW automated risk indicator does not mean that deployment is safe."
PATCH_NOTE = "Suggested remediation only. Review, compile, test and validate independently before use."
NO_FINDINGS_NOTE = "No findings matching the configured detection criteria were identified within the analyzed scope."
FALSE_NEGATIVE_NOTE = "The absence of a reported finding does NOT mean that no vulnerability exists."
SCORE_UNAVAILABLE_NOTE = "Automated deterministic scoring was unavailable in this runtime."

# ---------------------------------------------------------------------------
# Calls to action - internal Vericexa pages only, plus (Phase 6C) ONE
# conditional link to the standalone backend's own /auth/login entry point,
# rendered ONLY when APP_BASE_URL_ENV is actually configured (see
# build_site.render_app_cta()). Never a third-party marketplace link - the
# real distribution/billing/LLM-processing mechanism (docs/capafy-notas.md)
# is disclosed as a fact, not a brand name or link, in legal.html/
# privacy.html only (see LEGAL_SECTIONS / PRIVACY_SECTIONS).
#
# IMPORTANT, CARRIED FORWARD FROM Phase 5 (build_site.py's own prior
# docstring): legal.html currently states this website "does not process
# payments, create accounts, or run the analysis engine itself". Actually
# CONFIGURING APP_BASE_URL_ENV for a real deploy makes that claim false the
# moment the CTA below goes live - that revision is a business/legal
# decision for Diego to make deliberately, not a side effect of setting an
# env var. This phase only builds the config-gated CAPABILITY (off unless
# explicitly configured); it does not decide to use it and does not touch
# legal.html/privacy.html's own text.
# ---------------------------------------------------------------------------

CTA_ANALYZE: Tuple[str, str] = ("Analyze a Contract", "developers.html")
CTA_DEMO: Tuple[str, str] = ("View Demo", "demo.html")
CTA_HOW_IT_WORKS: Tuple[str, str] = ("See How It Works", "methodology.html")
APP_CTA_LOGIN_LABEL = "Sign In"
APP_CTA_GET_STARTED_LABEL = "Get Started"

# ---------------------------------------------------------------------------
# Navigation / pages
# ---------------------------------------------------------------------------

# (filename, nav label) - single source of truth for every nav/footer/
# sitemap/breadcrumb render. Order here is header nav order for the first
# PRIMARY_NAV_COUNT entries; every entry (including the rest) is linked from
# the footer on every page, so the site is always a fully connected mesh.
ALL_PAGES: List[Tuple[str, str]] = [
    ("index.html", "Home"),
    ("features.html", "Features"),
    ("demo.html", "Demo"),
    ("methodology.html", "Methodology"),
    ("developers.html", "Developers"),
    ("pricing.html", "Pricing"),
    ("faq.html", "FAQ"),
    ("legal.html", "Legal"),
    ("privacy.html", "Privacy"),
    ("disclaimer.html", "Disclaimer"),
    ("cookies.html", "Cookies"),
    ("refund.html", "Refund & Cancellation"),
]
PRIMARY_NAV_COUNT = 7  # Home..FAQ in the header; Legal/Privacy/Disclaimer/Cookies/Refund live in the footer only.

PAGE_TITLES: Dict[str, str] = {
    "index.html": "Vericexa - Automated Smart Contract Security Review Platform",
    "features.html": "Features - Vericexa Smart Contract Security Review",
    "demo.html": "Example Output - Vericexa Smart Contract Security Review",
    "methodology.html": "Methodology - How Vericexa Reviews Smart Contracts",
    "developers.html": "Developers - CLI and CI Integration - Vericexa",
    "pricing.html": "Pricing and Tiers - Vericexa",
    "faq.html": "FAQ - Vericexa Smart Contract Security Review",
    "legal.html": "Legal - Vericexa",
    "privacy.html": "Privacy - Vericexa",
    "disclaimer.html": "Disclaimer - Vericexa",
    "cookies.html": "Cookie Policy - Vericexa",
    "refund.html": "Refund & Cancellation Policy - Vericexa",
}
PAGE_DESCRIPTIONS: Dict[str, str] = {
    "index.html": "Vericexa is an automated, AI-assisted blockchain security platform for Web3 developers, reviewing smart contracts with findings, an Automated Risk Indicator and suggested remediation for Solidity and Vyper.",
    "features.html": "What Vericexa reviews today: pre-deployment review, security diffing, deployed-source verification, source-vs-deployed bytecode comparison, multi-chain EVM support, a CI security gate, and a deterministic advisory layer covering upgrade/proxy safety, bytecode-only checks, cross-contract reachability and constructor sanity.",
    "demo.html": "A real example finding from Vericexa's internal test fixtures, showing the report format: severity, confidence, evidence, recommendation and Automated Risk Indicator.",
    "methodology.html": "How Vericexa's review pipeline works: deterministic detectors across ten vulnerability categories, AI-assisted analysis, confidence levels and the Automated Risk Indicator.",
    "developers.html": "Reference for wiring Vericexa's CLI and CI security gate into your own pipeline, including PR ingestion, baseline diffing and snapshot drift tracking.",
    "pricing.html": "Compare Quick, Standard and Pro tier features - lines of code analyzed, source files, suggested remediation patches, gas suggestions and report formats.",
    "faq.html": "Answers to common questions about what Vericexa is, what it reviews, how the Automated Risk Indicator works, data retention and current pricing status.",
    "legal.html": "Terms governing use of the Vericexa website: content ownership, informational scope, and how the underlying security review product is distributed and governed.",
    "privacy.html": "What data the Vericexa website and its stateless API endpoint do - and do not - process or store.",
    "disclaimer.html": "The full security review disclaimer: scope, limitations, and what an automated, AI-assisted review is not.",
    "cookies.html": "Cookie policy for the Vericexa website - what this static site does and does not set today, and where the finalized policy will be published.",
    "refund.html": "Refund and cancellation policy for Vericexa subscriptions - where the finalized policy will be published once confirmed.",
}

# ---------------------------------------------------------------------------
# Product features - repository-evidenced only. Each entry names the exact
# script/config it is grounded in so a future editor can re-verify the claim
# instead of trusting the prose.
# ---------------------------------------------------------------------------

FEATURES_AVAILABLE: List[Dict[str, str]] = [
    {
        "name": "Pre-Deployment Review",
        "summary": "Automated, AI-assisted review of Solidity (0.8.x primary; limited support for older Solidity and for Vyper) source before you deploy.",
        "detail": "Runs a deterministic detector layer across ten vulnerability categories plus AI-assisted analysis, returning categorized findings with severity, confidence and an Automated Risk Indicator.",
        "evidence": "scripts/preprocess.py, scripts/detectors/, scripts/score.py, scripts/render_report.py",
    },
    {
        "name": "Security Diff",
        "summary": "A smart contract security diff: compare two analysis runs to see what changed, plus a structural risk classification of that change.",
        "detail": "Diffs two reports, or two preprocessed inputs, to highlight new, resolved and regressed findings - so a re-review after a fix focuses on what actually moved. A separate structural check classifies each diff as no-change, safe, or worth a closer look, based on what changed (visibility, modifiers, inheritance), independent of whether any detector already flagged it.",
        "evidence": "scripts/diff_reports.py, scripts/change_impact.py",
    },
    {
        "name": "Deployed-Source Verification",
        "summary": "Turn an already-fetched, verified on-chain contract record into review-ready source.",
        "detail": "Normalizes a verified (address, network) record you already retrieved into the same multi-file input the review pipeline uses. Bytecode-only, unverified contracts are explicitly out of scope and reported as such, never guessed. This step makes no network call itself.",
        "evidence": "scripts/ingest_onchain.py",
    },
    {
        "name": "Source vs Deployed",
        "summary": "Deterministic, byte-level comparison between compiled source and live on-chain bytecode.",
        "detail": "Checks source-vs-runtime and constructor-vs-runtime bytecode, proxy-implementation bytecode, opcode-capability support per chain, and compiler-version consistency - with explicit MATCH/MISMATCH/UNRESOLVED/UNAVAILABLE verdicts rather than a guess when data is missing.",
        "evidence": "scripts/compare_bytecode.py",
    },
    {
        "name": "Multi-Chain EVM",
        "summary": "Chain-aware analysis across multiple EVM-compatible networks.",
        "detail": "Chain identity (chain ID and address together) is validated explicitly, so two different chains sharing an address are never silently treated as the same target. Cross-chain implementation-drift and provenance checks build on that same identity discipline.",
        "evidence": "scripts/chains.py, scripts/compare_bytecode.py, scripts/monitor_diff.py",
    },
    {
        "name": "CI Security Gate",
        "summary": "A provider-agnostic pass/fail gate for pull requests and CI pipelines.",
        "detail": "Reads a report from a file or stdin and applies explicit gating rules inside your own pipeline. No hosted runner and no third-party account are required to use it.",
        "evidence": "scripts/pr_gate.py",
    },
    {
        "name": "Upgrade and Proxy Safety Checks",
        "summary": "A set of deterministic advisory checks for upgradeable and proxy-based contracts.",
        "detail": "Covers unprotected upgrade-authority functions, missing or removed initializer/reinitializer guards, storage-layout collisions and shrinking storage-gap reservations between two versions, delegatecall-cycle detection across a resolved proxy graph, recognized proxy patterns (EIP-1167 minimal proxies and the EIP-1967 storage-slot convention), and a structural signal when a proxy's own implementation contract has a constructor that accepts parameters. Each check is advisory-only with its own stated scope - none assigns a severity or a definitive verdict, and governance/timelock review is not covered.",
        "evidence": "scripts/upgrade_authority_guard.py, scripts/initializer_safety.py, scripts/storage_layout.py, scripts/upgrade_gap.py, scripts/delegatecall_cycle.py, scripts/proxy_fingerprint.py, scripts/implementation_constructor_signal.py",
    },
    {
        "name": "Bytecode-Only and Compiler-Version Advisory Checks",
        "summary": "Advisory checks that work even when only compiled bytecode is available, with no source.",
        "detail": "Flags the presence of specific opcodes (DELEGATECALL, CALLCODE, SELFDESTRUCT) and their combination with CREATE2 in bytecode alone, checks deployed bytecode size against the EIP-170 limit, and cross-references a contract's compiler version - extracted from bytecode metadata when source is unavailable, or supplied directly when it is - against a dataset of known compiler bugs. Each result states its own confidence; offered because a large share of deployed contracts have no verified source available for a deeper check.",
        "evidence": "scripts/bytecode_advisory.py, scripts/bytecode_size.py, scripts/bytecode_metamorphic_signal.py, scripts/bytecode_compiler_bugs.py, scripts/compiler_bugs.py",
    },
    {
        "name": "Cross-Contract and Constructor Sanity Checks",
        "summary": "Checks that look beyond a single function: cross-contract reachability and constructor-argument sanity.",
        "detail": "Traces whether an unguarded, externally reachable function in one contract can call an equally unguarded function in another contract within the same bundle, and checks planned constructor arguments for the literal zero address on parameters already identified as address-typed. Both are advisory signals, not confirmed findings - reachability and intent still need to be assessed by the caller.",
        "evidence": "scripts/privilege_path.py, scripts/constructor_zero_address.py",
    },
    {
        "name": "Advisory Workflow and Reporting",
        "summary": "Tools for consuming the advisory checks above as part of a review or a CI pipeline, not just as one-off JSON output.",
        "detail": "Renders a bundle of advisory-check results as one human-readable summary, assembles the already-known context (function, contract, related call/delegatecall edges) around one specific location to speed up reviewing a finding, and reduces a bundle of advisory results to a single pass/fail signal for a pipeline gate - each strictly relaying what the underlying checks already computed, never adding a new judgment of its own.",
        "evidence": "scripts/render_advisory_summary.py, scripts/finding_context_bundle.py, scripts/advisory_gate.py",
    },
]

FEATURES_PARTIAL: List[Dict[str, str]] = [
    {
        "name": "Multi-Contract Review",
        "summary": "A cross-contract system graph (contracts, calls, proxies) is computed in Pro-tier analysis.",
        "detail": "That graph powers proxy resolution and cross-contract checks today. A standalone multi-contract review narrative is not yet a separate deliverable, and system-graph computation is limited to the Pro tier.",
        "evidence": "scripts/preprocess.py (compute_system_graph, gated by modes.json allowSystemGraph)",
    },
    {
        "name": "Monitoring",
        "summary": "Smart contract monitoring via a CLI tool that tracks on-chain snapshot drift and finding lifecycle across repeated scans.",
        "detail": "You run it yourself, for example from your own CI or cron, against snapshots you provide. There is no hosted monitoring service, no database and no automated alerting - scheduling and notification stay on your own infrastructure.",
        "evidence": "scripts/monitor_diff.py",
    },
]

# ---------------------------------------------------------------------------
# Differentiation (Home page "how it differs from a basic Solidity scanner")
# - each line grounded in a FEATURES_AVAILABLE entry above, never a new claim.
# ---------------------------------------------------------------------------

DIFFERENTIATORS: List[str] = [
    "Deterministic detectors across ten vulnerability categories, combined with AI-assisted analysis - not pattern-matching alone.",
    "Verifies deployed bytecode against your source, including proxy implementations and cross-chain drift - a basic source-only scanner cannot see what is actually on-chain.",
    "Chain-identity-aware: the same address on two different chains is never silently treated as the same contract.",
    "Ships a provider-agnostic CI security gate and a security-diff mode, so review fits into a pipeline instead of a one-off report.",
    "Layers deterministic advisory checks for upgrade/proxy safety, bytecode-only coverage and cross-contract reachability on top of the core review - each one advisory-only, with its own stated scope, and never silently altering the score.",
]

# ---------------------------------------------------------------------------
# SC01-SC10 taxonomy (labels reused verbatim from scripts/preprocess.py;
# one-line descriptions written independently, per D-011 - never copied from
# any third-party taxonomy text).
# ---------------------------------------------------------------------------

CATEGORIES: List[Dict[str, str]] = [
    {"id": "SC01", "name": "Access Control", "description": "A function or state change is reachable by an account that should not be able to reach it."},
    {"id": "SC02", "name": "Business Logic", "description": "The contract's own accounting or workflow rules can be violated or bypassed, independent of any single unsafe operation."},
    {"id": "SC03", "name": "Price Oracle Manipulation", "description": "A price or rate feed the contract relies on can be manipulated or is read unsafely."},
    {"id": "SC04", "name": "Flash Loan-Facilitated Attacks", "description": "Borrow-and-repay-in-one-transaction patterns that can be combined with other weaknesses to extract value."},
    {"id": "SC05", "name": "Lack of Input Validation", "description": "A parameter (address, amount, array) is used without the checks its context requires."},
    {"id": "SC06", "name": "Unchecked External Calls", "description": "The result of a call to another contract is not checked, or its failure is not handled safely."},
    {"id": "SC07", "name": "Arithmetic Errors (rounding and precision)", "description": "Order of operations or fixed-point handling loses precision or rounds in the wrong direction."},
    {"id": "SC08", "name": "Reentrancy", "description": "External control can re-enter the contract before a state update completes."},
    {"id": "SC09", "name": "Integer Overflow/Underflow", "description": "Arithmetic can wrap unexpectedly, typically in unchecked blocks or older compiler versions."},
    {"id": "SC10", "name": "Proxy and Upgradeability", "description": "Upgrade functions, initializers or delegatecall targets are not as tightly controlled as the rest of the contract."},
]

CONFIDENCE_LEVELS: List[Tuple[str, str]] = [
    ("High", "Strong, direct evidence in the analyzed code supports the finding."),
    ("Medium", "The pattern is present but depends on context or assumptions that could not be fully verified from the analyzed scope."),
    ("Low", "A heuristic signal worth reviewing, without strong direct evidence either way."),
]

PIPELINE_STEPS: List[Tuple[str, str]] = [
    ("Preprocess", "Parse and normalize the submitted source into a structured form - contracts, functions, state variables, call graph and (Pro tier) a cross-contract system graph."),
    ("Deterministic detectors", "Run rule-based checks across the SC01-SC10 categories against the normalized structure."),
    ("AI-assisted analysis", "A model reviews the code and detector signals in context and drafts findings with severity, confidence and evidence."),
    ("Automated Risk Indicator", "A deterministic script scores confirmed findings by severity and confidence - never the model itself - producing a band with a fixed, scope-limited explanation."),
    ("Report render", "Assemble findings, the risk indicator, scope/limitations and the mandatory disclaimer into a Markdown or (Pro tier) HTML report."),
]

# ---------------------------------------------------------------------------
# Pricing - centralized, UNPUBLISHED. See module docstring.
# ---------------------------------------------------------------------------

PRICING_PUBLISHED = False  # Flip only once real prices are confirmed for whichever distribution path (Capafy or the independent standalone backend, backend/billing.py) is actually live - see module docstring.

PRICING_TIERS: List[Dict[str, Optional[str]]] = [
    {"mode": "quick", "display_name": "Quick", "price": None, "billing_period": None},
    {"mode": "standard", "display_name": "Standard", "price": None, "billing_period": None},
    {"mode": "pro", "display_name": "Pro", "price": None, "billing_period": None},
]

PRICING_UNCONFIRMED_NOTE = (
    "Pricing is not yet finalized. Tier names above match the product's own analysis "
    "modes one-to-one; pricing and checkout details will be published here once confirmed."
)

# ---------------------------------------------------------------------------
# FAQ - real, repository-grounded questions only (used for on-page copy and
# for the FAQPage JSON-LD on faq.html).
# ---------------------------------------------------------------------------

FAQ_ITEMS: List[Tuple[str, str]] = [
    (
        "What is Vericexa?",
        "Vericexa is an automated, AI-assisted smart contract security review platform for Web3 developers. "
        + POSITIONING_TAGLINE,
    ),
    (
        "Is this a substitute for a professional security audit?",
        NOT_AN_AUDIT_NOTE + " Findings may be incomplete or incorrect; do not rely on this review as the sole basis "
        "for deployment or other security-critical decisions.",
    ),
    (
        "What languages and versions does Vericexa review?",
        "Solidity is the primary target, at 0.8.x; older Solidity and Vyper are supported with limitations.",
    ),
    (
        "What is the Automated Risk Indicator?",
        RISK_INDICATOR_NOTE + " " + RISK_INDICATOR_LOW_NOTE,
    ),
    (
        "How is Vericexa different from a basic Solidity scanner?",
        " ".join(DIFFERENTIATORS),
    ),
    (
        "Does Vericexa store my source code?",
        RETENTION_NOTE,
    ),
    (
        "Can I run Vericexa's checks in CI?",
        "Yes - the CI Security Gate reads a report from a file or stdin and applies explicit pass/fail rules inside your own pipeline. It is provider-agnostic and requires no hosted account.",
    ),
    (
        "Does Vericexa continuously monitor my contracts after deployment?",
        "There is a CLI tool for tracking on-chain snapshot drift and finding lifecycle across repeated scans, which you run yourself (for example from your own CI or cron). There is no hosted monitoring service and no automated alerting today.",
    ),
    (
        "What does Vericexa cost?",
        PRICING_UNCONFIRMED_NOTE,
    ),
    (
        "Who is Vericexa for?",
        WHO_ITS_FOR,
    ),
]

# ---------------------------------------------------------------------------
# Legal / Privacy / Disclaimer - built only from already-approved formulas
# (docs/commercial-claims.md) and neutral, uncontroversial website-operation
# facts. Deliberately NOT sourced from docs/legal-risk-register.md, whose
# draft commercial-terms language is explicitly marked
# "LEGAL REVIEW REQUIRED" / "Nada de este documento se publica" (D-012).
# ---------------------------------------------------------------------------

LEGAL_SECTIONS: List[Tuple[str, str]] = [
    (
        "About this website",
        "This website (%s) is an informational and marketing site for Vericexa. It does not process payments, "
        "create accounts, or run the analysis engine itself." % DOMAIN,
    ),
    (
        "The product itself",
        "The underlying analysis Skill is distributed and transacted through a third-party marketplace. Any "
        "purchase, subscription or usage terms for the analysis service are governed by that marketplace's own "
        "terms at the time of purchase, not by this page.",
    ),
    (
        "No warranty on website content",
        "This website and its content are provided as-is, without warranty of any kind, to the extent permitted "
        "by law.",
    ),
    (
        "Trademarks",
        "\"%s\" and the %s name refer to this product. Any other names that may be referenced on this site "
        "belong to their respective owners." % (BRAND_NAME, BRAND_NAME),
    ),
]

PRIVACY_SECTIONS: List[Tuple[str, str]] = [
    (
        "This website",
        "The pages on this site are static: they set no cookies and require no account or sign-in to read.",
    ),
    (
        "The stateless API endpoint",
        "This site links to a stateless render/validate/diff HTTP endpoint. Each request is processed in memory "
        "and the response is returned directly - no request body, report content or result is written to a "
        "database or persisted after the response is sent. The endpoint keeps only a short-lived, in-memory "
        "per-IP request counter to enforce a rate limit against abuse; that counter is never persisted to disk "
        "and resets when the process restarts.",
    ),
    (
        "The analysis Skill",
        RETENTION_NOTE + " " + LLM_PROCESSING_NOTE + " Provider- or platform-level retention outside the Skill's "
        "own temporary working copy is controlled by that third-party infrastructure, not by this website.",
    ),
]

DISCLAIMER_SECTIONS: List[Tuple[str, str]] = [
    ("Not an audit", PRE_USE_WARNING),
    ("False negatives", FALSE_NEGATIVE_NOTE + " Absence of a finding reflects the analyzed scope, not a guarantee."),
    ("Automated Risk Indicator", RISK_INDICATOR_NOTE + " " + RISK_INDICATOR_LOW_NOTE),
    ("Suggested remediation", PATCH_NOTE),
    ("Data retention", RETENTION_NOTE),
    ("LLM processing", LLM_PROCESSING_NOTE),
    (
        "No warranty",
        "No statement on this website or in any report creates a warranty, certification, guarantee, or "
        "an audit performed by a professional.",
    ),
]

# ---------------------------------------------------------------------------
# Cookies / Refund - Phase 6C structural placeholders ONLY (docs/decisiones.md
# D-084). Neither page existed before this phase; legal.html/privacy.html
# already cover Terms/Privacy in full, so no separate terms.html was added.
# Every sentence below restates an ALREADY-PUBLISHED fact from PRIVACY_SECTIONS
# above (this site sets no cookies) or is an explicit, visible placeholder
# marker - never a new legal/business claim, never an invented policy. Diego
# must replace PLACEHOLDER_* below with real, reviewed text before either
# page is considered final - see docs/decisiones.md D-084 and
# docs/legal-risk-register.md.
# ---------------------------------------------------------------------------

PLACEHOLDER_MARKER = (
    "PLACEHOLDER - this section is not yet final. It will be replaced with "
    "reviewed policy text once confirmed; nothing below should be treated as "
    "a final legal statement."
)

COOKIES_SECTIONS: List[Tuple[str, str]] = [
    (
        "Current state",
        "This static website sets no cookies and requires no account or sign-in to read - the same fact "
        "already stated in Privacy. If a future login/checkout flow on the standalone application "
        "(separate from this marketing site) sets any cookie, that will be disclosed here before it ships.",
    ),
    ("Policy text", PLACEHOLDER_MARKER),
]

REFUND_SECTIONS: List[Tuple[str, str]] = [
    (
        "Status",
        "No subscription is sold through this website today (see Pricing) - there is nothing to refund or "
        "cancel yet. A real refund/cancellation policy will be published here before any paid plan goes live.",
    ),
    ("Policy text", PLACEHOLDER_MARKER),
]

# ---------------------------------------------------------------------------
# Demo page - a single real finding from evals/results/actual/sc01_unprotected_withdraw.json
# (an internal test fixture, not a customer contract), trimmed for length.
# evals/results/summary.md is explicit that eval pass/fail metrics are
# internal QA only and may never be presented as a product accuracy claim
# (docs/decisiones.md D-024) - this page shows report FORMAT, never a score.
# ---------------------------------------------------------------------------

DEMO_SOURCE_NOTE = (
    "This is a real finding produced against an internal test fixture "
    "(evals/cases/sc01_unprotected_withdraw.sol), shown to illustrate the report format. "
    "It is not a customer contract, a benchmark result, or a claim about detection accuracy."
)

DEMO_FINDING: Dict[str, Any] = {
    "category": "SC01",
    "severity": "CRITICAL",
    "confidence": "high",
    "contract": "TreasuryVault",
    "function": "withdrawAll",
    "description": (
        "withdrawAll is external with no access-control modifier and no in-body authorization check of any "
        "kind. It reads the contract's entire ether balance and forwards all of it to an arbitrary "
        "caller-supplied address. Any external account can call withdrawAll(attackerAddress) in a single "
        "transaction and immediately drain every deposit."
    ),
    "evidence": [
        "mapping(address => uint256) public deposits;",
        "function withdrawAll(address payable to) external {",
        "uint256 balance = address(this).balance;",
        "to.transfer(balance);",
    ],
    "recommendation": (
        "Gate this function behind proper access control (for example onlyOwner), or replace it with a "
        "user-scoped withdraw(uint256 amount) that checks and decrements the caller's own recorded deposit "
        "before sending funds."
    ),
}

DEMO_RISK_INDICATOR: Dict[str, str] = {
    "band": "HIGH",
    "score": "40",
    "explanation": RISK_INDICATOR_NOTE,
}
