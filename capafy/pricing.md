# Pricing Draft — Capafy Marketplace

Draft only — nothing here is configured in Capafy yet. Supersedes the earlier Basic/Pro/Premium
$3.99/$8.99/$19.99 proposal (`docs/decisiones.md`, D-025): Diego now uses the product's own reference
prices directly as the Capafy prices too, with tiers named after the product's own modes so a tier's
name and the mode it unlocks always match. Every value below that depends on how Capafy's console
actually behaves is marked `[CAPAFY-VERIFY]` — none of it is invented.

## One price list, tier names match mode names

| Capafy tier | Price | Unlocks (product mode access) |
|---|---|---|
| Quick | $19 | `quick` only |
| Standard | $39 | `quick` + `standard` |
| Pro | $79 | `quick` + `standard` + `pro` |

Naming the tiers Quick/Standard/Pro — the same names as the product's own analysis modes, with the
same cumulative access — is a deliberate fix for the collision the previous draft left open: a buyer on
the Capafy "Pro" tier now genuinely gets the product's `pro` analysis mode, nothing more to reconcile.
No tier is named "Enterprise" (per Diego's earlier instruction): none of these three offers has
anything resembling enterprise features (SSO, team seats, SLAs, etc.).

`[CAPAFY-VERIFY]` — billing mechanism: the confirmed Capafy billing modes are `subscription`
(`cycleType` `week`/`month`) and `hourly` (`docs/capafy-notas.md`); a flat, one-time, non-recurring
charge at exactly $19/$39/$79 is not confirmed as a distinct billing mode in the public repo. Until
checked in the live console, the working assumption for this draft is `billingMode: "subscription"`,
`cycleType: "week"`, `cyclePrice` set to the amounts above — i.e. $19/$39/$79 **per week**, not a
one-time fee. If Diego intends these as one-time prices instead, that requires confirming Capafy
actually supports a non-recurring charge before configuring anything.

## What is verified vs. `[CAPAFY-VERIFY]`

Verified in `docs/capafy-notas.md` (from the cloned public repo, not the live console):
- `subscription` billing (`cycleType` `week`/`month`, `cyclePrice`, `cycleMaxMessageCount`) exists as a
  documented billing mode.
- "Several billing lines per Agent" exist as a capability — this is what makes 3 tiers under one
  listing ("Security Review Analyzer") plausible, instead of 3 separate listings.
- A daily subscription cycle is *not* shown in the public repo (only week/month) — consistent with the
  weekly cycle proposed here.

Not verified — mark `[CAPAFY-VERIFY]` and confirm in the live console before configuring anything:
- Whether a one-time, non-recurring price is supported at all (see above), or whether every line must
  be a recurring cycle.
- The actual range/default for `cycleMaxMessageCount` per line, and whether it can be set to a
  different value on each of the 3 lines.
- How the storefront displays multiple billing lines to a buyer — as clearly labeled tiers, as a
  dropdown, or as a single "starting at $X" price with tiers hidden until checkout. This directly
  affects how the listing copy should describe the three offers.
- Whether mode-gating (Quick tier = quick mode only, etc.) is something Capafy's billing lines can
  enforce themselves, or something this Skill's own runtime would have to check against the buyer's
  tier — per Diego's explicit instruction, **the core is never modified for this**
  (`SKILL.md`/`config/modes.json`/`scripts/` stay exactly as they are); any such gating lives entirely
  on Capafy's side, never in this repo.

## Do not publish until

1. The billing-mechanism question above (one-time vs. recurring) is confirmed in the console.
2. `cycleMaxMessageCount` per tier and the storefront's multi-line display are confirmed in the console.
3. Mode-gating mechanism (Capafy-side vs. none) is confirmed, given the core cannot change for it.
