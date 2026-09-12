# Publish Checklist — Draft

Capafy is the distribution channel for `Security Review Analyzer` V1, reopened for that purpose only
(`docs/decisiones.md`, D-030) — the core stays fully independent of Capafy (D-026), unchanged by this
file. Run through this before Diego clicks Submit in Capafy's own review flow. This repo never runs
`capafy-publisher` and never publishes anything itself — every step below ends with Diego taking the
actual action in Capafy's web UI.

## Core independence (re-verify at publish time, not just once)

- [ ] `grep -rniE "capafy" .claude/skills/web3-auditor/` returns zero matches.
- [ ] `grep -rniE "requests\.|urllib|http\.client|socket\." .claude/skills/web3-auditor/scripts/*.py`
      returns zero matches.
- [ ] Nothing in `SKILL.md`/`config/modes.json`/`scripts/` changed to accommodate Capafy-specific
      billing tiers or any other platform requirement — any tier/mode-gating mechanism lives entirely
      on Capafy's side.

## Content and vocabulary

- [ ] Forbidden-terms grep (level A, `docs/commercial-claims.md` — includes the D-029 broadened
      absolute-claims rule) run over `.claude/skills/` **and** `capafy/` — zero matches outside the
      already-documented exceptions (`references/guardrails.md`, `scripts/preprocess.py`'s detector,
      `scripts/render_report.py`'s mandatory notice — see `docs/decisiones.md` D-020/D-021/D-022).
- [ ] Level B terms (`audit`, `certification`, `guarantee`, `secure`, `private`, `confidential`)
      manually reviewed wherever they appear in `capafy/*.md` — each use is a negation/limitation, not
      an affirmative claim.
- [ ] `capafy/agent-card.md`'s final copy (title, descriptions, welcome message, tags, category) matches
      what is actually pasted into the Capafy form — no drift between this draft and the live listing.
- [ ] Category and tag count fit whatever the live console actually allows (`[CAPAFY-VERIFY]`, Q-004) —
      re-check against the console, not just this draft's assumed 5-tag limit.
- [ ] `detailedDescription`/`shortDescription` length fits the console's real limit (`[CAPAFY-VERIFY]`,
      Q-008 — only "suspicious" thresholds, not hard limits, are confirmed in the public repo).

## Data, retention, and legal

- [ ] `capafy/data-declaration.md` has no remaining `[DIEGO]` placeholder used as if it were confirmed.
- [ ] LLM provider/model and its retention policy either confirmed (Q-005) or left generic
      ("LLM processing via Capafy infrastructure") — never a specific, unverified provider claim.
- [ ] 90-day log retention (Q-003) not stated anywhere buyer-facing unless a real source is found.
- [ ] Anexo A's proposed commercial-terms language (`docs/legal-risk-register.md`) is **not** included
      anywhere published — it is explicitly gated on Q-007 and `LEGAL REVIEW REQUIRED`, neither resolved.
- [ ] RISK-001 through RISK-014 in `docs/legal-risk-register.md` re-skimmed for anything newly relevant
      to the specific pricing/tiering shipped (e.g. RISK-009 misleading-claims, given the tier names).

## Pricing

- [ ] `capafy/pricing.md`'s tiers (Quick $19 / Standard $39 / Pro $79, names matching product modes)
      configured exactly as drafted — no separate, differently-named tier structure introduced without
      updating this file first.
- [ ] Billing mechanism confirmed (`[CAPAFY-VERIFY]`): whether Capafy supports the intended
      one-time/flat charge, or whether it must be configured as a recurring `subscription` cycle
      (`cycleType: "week"` is the current working assumption in `capafy/pricing.md`).
- [ ] `cycleMaxMessageCount` per tier and how multiple billing lines render to a buyer, both confirmed
      in the console — none configured until confirmed.

## Packaging invariants (already enforced by this repo's own pre-commit checks, re-verify at publish time)

- [ ] `.claude/skills/web3-auditor/` contains no `tests/`, `evals/`, `capafy/`, `docs/`, secrets, local
      absolute paths, emails, or leftover `.gitkeep`/`__pycache__` artifacts.
- [ ] Root-level `CLAUDE.md`, `README.md`, and any other root `.md`/`.txt` are **not** marked for
      inclusion as "workspace documents" (`docs/decisiones.md`, D-013) — Download packages never include
      them regardless; Run Online only if explicitly marked, which this project never does.
- [ ] `python3`/`python` availability in Run Online (`[CAPAFY-VERIFY]`, Q-001) — if unavailable,
      confirm the listing copy doesn't imply the score is always computed (it already correctly allows
      for `scoreStatus: "not_computed"`, but double-check the demo/screenshot doesn't accidentally show
      only the happy path).

## Demo

- [ ] `capafy/demo-case.md` followed: the shown report was produced by a real run, not copied from
      `evals/results/actual/`.

## Final step

- [ ] Diego reviews the `review_url` Capafy generates (expires in 1 hour per `docs/capafy-notas.md`) and
      clicks Submit himself. No automated tooling in this repo performs this step.
