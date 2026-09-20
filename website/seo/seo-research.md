# SEO/GEO research - Vericexa website

Research date: 2026-09-19. Grounds `keyword-map.md` and the on-page copy in
`website/content.py`. No competitor text is copied anywhere on the site -
findings below are summarized in our own words, with sources linked for
verification. This document is internal; it is not published as part of
`website/dist/`.

## Competitive landscape (from current search results)

Three distinct categories currently rank for our target terms. Vericexa's
honest position (per `content.py`'s FEATURES_AVAILABLE/PARTIAL) sits between
the first two:

1. **Free/open-source static analyzers** - Slither (Trail of Bits, Python,
   Solidity + Vyper, source-only static analysis), Mythril (symbolic
   execution over EVM bytecode), Echidna (property-based fuzzing), Solhint
   (lint-level style/security rules). These are source-only, no AI-authored
   narrative findings, no deployed-bytecode verification, no multi-chain
   identity handling.
   [Slither on GitHub](https://github.com/crytic/slither),
   [Hacken's 2026 audit tools review](https://hacken.io/discover/audit-tools-review/).

2. **Full-service audit firms** - CertiK, OpenZeppelin, Trail of Bits,
   Cyfrin, Sherlock, Spearbit, Hacken, Quantstamp, QuillAudits. Manual
   line-by-line review combined with automated tooling; higher cost, longer
   turnaround, and the only category that can issue a genuine professional
   audit. Vericexa is explicitly **not** in this category and says so on
   every page (`content.NOT_AN_AUDIT_NOTE`).
   [Sherlock's 2026 top-10 list](https://sherlock.xyz/post/top-10-best-smart-contract-auditing-companies-in-2026).

3. **AI-assisted automated review platforms** - e.g. Veritas Protocol
   (AI model over source code, positioned as faster/cheaper than manual
   audits). This is Vericexa's closest category.
   [Veritas Protocol 2026 post](https://www.veritasprotocol.com/blog/best-automated-smart-contract-audit-platform-2026).

4. **Hosted monitoring/alerting platforms** - Tenderly Monitor, OpenZeppelin
   Monitor, AuditBase, LeewayHertz: real-time alerts to Slack/PagerDuty/
   webhooks, automatic re-scan on proxy upgrade. This is a real, mature
   category and Vericexa's current Monitoring capability (`monitor_diff.py`)
   does **not** compete with it - no hosted service, no alerting, CLI-only,
   run by the user. `content.py`'s FEATURES_PARTIAL entry for Monitoring and
   the FAQ answer both say this explicitly, so search intent for "smart
   contract monitoring" is met honestly rather than overclaimed.
   [Tenderly Monitor](https://tenderly.co/products/monitor).

5. **CI/CD integration pattern** - the dominant pattern is a static-analysis
   step (commonly the official Slither GitHub Action) that fails the build
   above a configured severity threshold, run in parallel with other
   security jobs on every PR. Vericexa's CI Security Gate
   (`scripts/pr_gate.py`) follows the same fail-on-severity, PR-triggered
   pattern, which is what `developers.html` and the "CI Security Gate"
   feature copy describe.
   [Smart Contract CI/CD with Foundry, Slither and audit gates](https://dev.to/pharos_production/smart-contract-cicd-foundry-slither-and-audit-gates-4ael).

## Positioning implication

Vericexa's defensible, evidence-backed pitch is not "better than Slither" or
"replaces an audit" - it is: deterministic multi-category detection *plus*
AI-assisted analysis *plus* deployed-bytecode verification *plus* a CI gate,
in one pipeline, without requiring a hosted account. That is exactly what
`content.DIFFERENTIATORS` says, and nothing stronger.

## On-page SEO/GEO implementation notes

- Every page ships a unique `<title>`/meta description, canonical URL, Open
  Graph and Twitter Card tags, and `Organization`/`WebSite`/
  `SoftwareApplication` JSON-LD (`website/seo.py`).
- `SoftwareApplication` JSON-LD deliberately omits an `offers`/price field -
  pricing is unconfirmed (`content.PRICING_PUBLISHED = False`); structured
  data must never assert a number the page itself won't show.
- `FAQPage` JSON-LD is emitted only on `faq.html`, from the same real
  question/answer content rendered on the page (no separate, longer list
  invented for search engines).
- No competitor name is used as a comparison keyword anywhere in on-page
  copy (avoids a trademark/claims risk); differentiation is described by
  capability, not by naming who lacks it.
- No og:image/twitter:image is set - the build pipeline is stdlib-only with
  no image-generation step, and a broken/placeholder social image would be
  worse than none. Revisit if a real brand image asset is produced later.
