# Demo / Test Case — Draft

Capafy is the distribution channel for `Security Review Analyzer` V1, reopened for that purpose only
(`docs/decisiones.md`, D-030) — the core stays fully independent of Capafy (D-026), unchanged by this
file. Proposal for the example shown in the Capafy listing (screenshot, sample output, or a "try it"
prompt).

## Do not reuse the Subfase 3.1 eval outputs as the demo

`evals/results/actual/*.json` were hand-authored for QA purposes (see `docs/decisiones.md`, D-024, and
the "Internal QA only" notice now in `evals/results/summary.md`) — not produced by an independent
invocation of this Skill's runtime. Presenting one of those reports as "here's what the product found"
would misrepresent a hand-written example as genuine product output, exactly the kind of overclaiming
`docs/commercial-claims.md` exists to prevent. The eval *contracts* are fine to reuse as input (they are
original, minimal, and each demonstrates one clear issue); the *report shown in the listing* must come
from a fresh, real run.

## Proposed contract

`evals/cases/sc08_reentrant_withdraw.sol` — a short (17-line), classic reentrancy example: an external
call before the state write, no guard. It is easy for a non-expert buyer to follow (the bug is visible
in a few lines) and does not require explaining oracle/flash-loan mechanics to land the point. `quick`
mode is enough to demonstrate it (no gas notes or patch needed for the demo to be legible).

Do not use `evals/cases/injection_fake_audit_claim.sol` or the mode-limit/patch-safety/incomplete-context
cases as the public demo — they are deliberately edge-case-y and would need extra explanation that
distracts from a first impression of the product.

## Before publishing

1. Run the Skill for real (Claude Code with the `web3-auditor` Skill active, or Capafy's own Run Online
   runtime once available) against `sc08_reentrant_withdraw.sol` in `quick` mode.
2. Use that genuine output — report text and Automated Risk Indicator as actually computed — as the
   demo. Do not edit the AI-authored prose by hand afterward; if the wording needs to change, re-run
   rather than hand-edit (hand-editing would reintroduce the same authenticity problem this note exists
   to avoid).
3. Confirm the rendered demo still passes the forbidden-terms grep (`capafy/publish-checklist.md`)
   before it goes into the listing, the same way any other AI-authored report text would.
