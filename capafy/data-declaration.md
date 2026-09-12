# Data Declaration — Draft

Capafy is the distribution channel for `Security Review Analyzer` V1, reopened for that purpose only
(`docs/decisiones.md`, D-030) — the core stays fully independent of Capafy (D-026), unchanged by this
file. Draft for whatever data-handling disclosure Capafy's listing flow requires. Follows RISK-006
(`docs/legal-risk-register.md`) and the retention wording fixed in `docs/commercial-claims.md`. Every
`[CAPAFY-VERIFY]` item below is unconfirmed against the live console/ToS - reopening Capafy does not
resolve any of them by itself, since none were ever actually checked against the live product (they
were only marked moot while Capafy was off the roadmap, per D-030); every `[DIEGO]` item needs a
decision or a source only Diego can supply. Do not fill either placeholder with an invented value.

## What this Skill does with submitted code

- Source code, comments, and any submitted documentation are treated as data for this run only,
  never persisted by the Skill beyond producing the report (`references/guardrails.md`, section 1).
- The Skill's own temporary working files (the preprocessing artifact, the draft/scored report JSON)
  are deleted at the end of a run — see `SKILL.md`, Step 10.
- The Skill never writes submitted source code into any persistent log it controls.

## What this Skill does not control

Fixed wording (`docs/commercial-claims.md` — reuse verbatim, do not shorten or rephrase):

```
The Skill deletes its local temporary working copy at the end of execution. This does not control
platform, runtime, provider, billing, security or execution-log retention outside the Skill.
```

Never go beyond what that sentence already covers — no stronger retention or confidentiality promise
is within this Skill's control to make.

## LLM processing

```
LLM processing via Capafy infrastructure.
```

- Effective LLM provider and model at runtime: `[CAPAFY-VERIFY]` (Q-005). Do not name a specific
  provider/model until confirmed; do not claim confidential or no-third-party processing.
- Provider's own data-retention policy for that processing: `[CAPAFY-VERIFY]` (Q-005).

## Instance / chat history retention

- Capafy's own public documentation confirms chat history persists in the instance and is readable
  by anyone with access to that instance (`docs/capafy-notas.md`).
- A 90-day retention period for execution logs is asserted by Diego but not found in the public repo
  (only a 90-day window on usage *statistics* queries is confirmed) — `[CAPAFY-VERIFY]` (Q-003).
  `[DIEGO]`: source or confirmation needed before this number appears anywhere buyer-facing.

## Python availability (affects the deterministic score)

- Whether `python3` is available in the Run Online runtime is `[CAPAFY-VERIFY]` (Q-001). If it is not,
  `scoreStatus` becomes `"not_computed"` per the Skill's own designed fallback — this is expected
  behavior, not a defect, and should not be described as a limitation of this declaration.

## What must never appear in this declaration

Any claim from `docs/commercial-claims.md`'s prohibited-vocabulary list (level A) - including the
broadened rule from D-029 covering any unscoped absolute safety/security claim, not just the terms
listed by name - or any equivalent promise this Skill or Capafy has not actually made and verified.
That list is not reproduced here — see the source document, and re-run this repo's forbidden-terms
grep over this file before publishing.
