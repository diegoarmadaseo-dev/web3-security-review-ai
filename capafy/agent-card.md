# Agent Card — Draft

Capafy is the distribution channel for `Security Review Analyzer` V1, reopened for that purpose only
(`docs/decisiones.md`, D-030) — the core stays fully independent of Capafy (D-026), unchanged by this
file. Draft values for the Capafy listing form (see `docs/capafy-notas.md` for the verified field list:
`title`, `shortDescription`, `detailedDescription`, `versionUpdateInfo`, `welcomeMessage`, `logoUrl`,
`tags`, `categoryId`/`categoryName`, `purpose` per skill, `lang`). Nothing here is published by itself;
Diego copies these values into the Capafy web form. Wording follows `references/guardrails.md` and
`docs/commercial-claims.md` — do not paraphrase the fixed phrases below.

## title

```
Security Review Analyzer
```

Public commercial name (supersedes the working name "Web3 Security Review AI" — see
`docs/decisiones.md`, D-004/D-025). Technical Skill identifier stays `web3-auditor` (unrelated to the
listing title; changing it would break the Skill's own discovery path).

## purpose (per-skill, shown in the listing)

```
Automated, AI-assisted security review for Solidity smart contracts.
```

## shortDescription

```
Automated, AI-assisted security review for Solidity smart contracts. Produces categorized findings
with severity and confidence, a deterministic Automated Risk Indicator, and a Markdown or HTML report.
This is not a formal audit, certification, or guarantee of security.
```

## detailedDescription

```
Review your smart contract code for common security risks with AI-assisted analysis.

Security Review Analyzer reads Solidity source (0.8.x primary; limited support for older Solidity and
for Vyper) and produces a structured report: categorized findings with severity and confidence, an
Automated Risk Indicator, gas notes and suggested remediation patches (Standard/Pro), and — in Pro
mode — architecture-level notes and an executive summary. Findings are scoped to the code you submit;
the report states plainly what was and was not assessed.

Three modes are available, differing in size limits and included features (exact limits and features
are configured in the Skill itself, not restated here to avoid drift): Quick, Standard, and Pro.

This is an automated, AI-assisted preliminary review — not a formal security audit, certification, or
guarantee of security, and not a substitute for independent professional review before deploying code
that holds or manages value. Findings may be incomplete or incorrect. The absence of a reported finding
does not mean no vulnerability exists.

LLM processing via Capafy infrastructure.
```

## welcomeMessage (verbatim — `references/guardrails.md`, section 7)

```
This is an automated, AI-assisted smart contract security review. It is not a formal security
audit, certification, or guarantee of security. Findings may be incomplete or incorrect. Do not
rely on this review as the sole basis for deployment or other security-critical decisions.
```

## tags (≤5 — limit itself is `[CAPAFY-VERIFY]`, see Q-004)

```
solidity, smart-contracts, security-review, web3, ai-assisted
```

## categoryName

```
Developer Tools / Security
```

`[CAPAFY-VERIFY]` — whether this exact category exists in the live console is not confirmed (Q-004).
Never `Crypto`, `Finance`, or anything implying a financial/professional-auditor service (RISK-009).

## lang

```
en
```

Initial listing language. Does not restrict the product: the Skill reads code and produces report
prose in whatever language the user writes in (see `references/guardrails.md`, section 10).

## versionUpdateInfo

```
1.0.0 — initial release.
```

## logoUrl

`[CAPAFY-VERIFY]` / pending creative asset — no logo has been produced yet. Not a copy decision.

## Vocabulary check

Every string above is a direct reuse or close paraphrase of already-reviewed content in `SKILL.md`,
`references/guardrails.md`, and `docs/commercial-claims.md`'s permitted-vocabulary list, including the
broadened absolute-claims rule from D-029 (see that document for the actual list — not reproduced
here). Re-run the project's forbidden-terms grep over this file before publishing (see
`capafy/publish-checklist.md`).
