# Pricing Draft — Capafy Marketplace

Draft only — nothing here is configured in Capafy yet. Reflects Diego's decisions for Subfase 3.2:
Capafy uses its own low, marketplace-appropriate prices, separate from the product's own reference
prices; billing mode is `subscription` (weekly), not `download` (keeps the Skill Package/source closed
during Run Online) and not the `hourly` mode explored earlier. Every value below that depends on how
Capafy's console actually behaves is marked `[CAPAFY-VERIFY]` — none of it is invented.

## Two different price lists — do not conflate them

- **Product reference prices** (not Capafy-specific, used elsewhere): Quick $19 / Standard $39 / Pro $79.
- **Capafy marketplace prices** (this file): Basic $3.99/week / Pro $8.99/week / Premium $19.99/week.

These numbers are intentionally unrelated. Nothing in the Skill, its code, or its report content
references either price list — pricing lives entirely in Capafy's own billing configuration.

## Proposed tiers (`billingMode: "subscription"`, `cycleType: "week"`)

| Capafy tier | `cyclePrice` | Proposed mode access | `cycleMaxMessageCount` |
|---|---|---|---|
| Basic | $3.99 | `quick` only | `[CAPAFY-VERIFY]` |
| Pro | $8.99 | `quick` + `standard` | `[CAPAFY-VERIFY]` |
| Premium | $19.99 | `quick` + `standard` + `pro` | `[CAPAFY-VERIFY]` |

**Naming collision to resolve with Diego before publishing:** the middle Capafy tier is named "Pro,"
but the product's own most advanced *analysis mode* is also called `pro` (HTML report, executive
summary, architecture notes). As proposed above, the Capafy "Pro" tier does **not** unlock the
product's `pro` mode — only "Premium" does. This is confusing on its face and needs either a tier
rename or an explicit callout in the listing copy; do not assume either fix without Diego's sign-off.

Per Diego's instruction: no tier is named "Enterprise" — none of these three offers has anything
resembling enterprise features (SSO, team seats, SLAs, etc.). If that ever changes, name the tier for
what it actually includes, not to sound more premium.

## What is verified vs. `[CAPAFY-VERIFY]`

Verified in `docs/capafy-notas.md` (from the cloned public repo, not the live console):
- `subscription` billing (`cycleType` `week`/`month`, `cyclePrice`, `cycleMaxMessageCount`) exists as
  a documented billing mode.
- "Several billing lines per Agent" exist as a capability — this is what makes 3 tiers under one
  listing ("Security Review Analyzer") plausible, instead of 3 separate listings.
- A daily subscription cycle is *not* shown in the public repo (only week/month) — matches Q-002,
  consistent with the weekly cycle proposed here.

Not verified — mark `[CAPAFY-VERIFY]` and confirm in the live console before configuring anything:
- The actual range/default for `cycleMaxMessageCount` per line, and whether it can be set to a
  different value on each of the 3 lines (required for the tiers to feel meaningfully different, not
  just "same access, different price").
- How the storefront displays multiple billing lines to a buyer — as clearly labeled tiers, as a
  dropdown, or as a single "starting at $X" price with tiers hidden until checkout. This directly
  affects how the listing copy should describe the three offers.
- Whether mode-gating (Basic = quick only, etc.) is something Capafy's billing lines can enforce
  themselves, or something this Skill's own runtime would have to check against the buyer's tier —
  and if the latter, note per Diego's instruction that **the core must not be modified for this**
  (`SKILL.md`/`config/modes.json` stay as they are); any such gating would have to live entirely on
  Capafy's side, not in this repo.
- Whether Capafy's `hourly` mode (`hourlyPrice`, `minPurchaseHours`, `hourlyMaxMessageCount`) remains
  worth revisiting as a fallback if subscription tiers can't achieve per-tier mode-gating.
  `docs/capafy-notas.md` already confirms `minPurchaseHours` as low as 1 hour is representable
  ("1–24 h por pedido"); `hourlyMaxMessageCount`'s exact configurability is equally unverified there.

## Do not publish until

1. The naming collision above is resolved with Diego.
2. `cycleMaxMessageCount` per tier and the storefront's multi-line display are confirmed in the console.
3. Mode-gating mechanism (Capafy-side vs. none) is confirmed, given the core cannot change for it.
