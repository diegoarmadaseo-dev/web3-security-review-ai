#!/usr/bin/env python3
"""Black Friday 2026 campaign eligibility (Phase 7, docs/decisiones.md
D-086) - a small, pure, provider-agnostic module deliberately kept
separate from backend/billing.py (which only knows how to CALL Stripe,
never WHEN a discount should apply - same separation of concerns as
backend/retention.py's purge functions vs. the scheduler that decides
when to call them).

BACKEND IS AUTHORITATIVE, NOT THE WEBSITE: resolve_promotion_code() below
is the ONE function backend/http_app.py's checkout handler calls on
EVERY /billing/checkout request - never cached, never trusted from a
client-supplied flag, never inferred from whether the website's own CTA
happened to be visible when the request was made (see website/
build_site.py's own docstring on why a static site cannot enforce
anything - it can only decide what to SHOW). A request arriving after
the campaign window closes is re-evaluated fresh, every time, and gets
None regardless of how it was constructed or when the client's page was
built/cached/bookmarked.

ELIGIBILITY IS INTERVAL-ONLY AT THIS LAYER: annual interval + campaign
enabled + now within [start, end] (inclusive both ends, matching the
confirmed campaign window "00:00:00 UTC through 23:59:59 UTC") is
the complete rule - all three plans (quick/standard/pro) qualify equally
per the confirmed commercial rules (docs/decisiones.md D-086), so plan is
not a parameter here. "First-time customer" is deliberately NOT
re-implemented in Python: the promotion_code_id this module returns is
expected to already carry Stripe's own native
PromotionCode.restrictions.first_time_transaction=True (a real,
Stripe-enforced restriction, confirmed against the installed SDK - see
D-086's own audit trail) - Stripe itself rejects redemption for a
returning customer when that restriction is set, so this module never
needs to know a customer's own purchase history to be correct.

FAILS CLOSED: any missing/malformed piece of config (not enabled, no
promotion_code_id configured, no start/end configured) resolves to None
(no discount) rather than guessing - see backend/main.py's own
_load_black_friday_config() for where these values are validated at
process startup, never here.

Standard library only. No network access, no Stripe SDK import - this
module has no idea what a PromotionCode even IS beyond a string id.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

_ELIGIBLE_INTERVAL = "annual"


def resolve_promotion_code(
    interval: str,
    now: datetime,
    enabled: bool,
    start: Optional[datetime],
    end: Optional[datetime],
    promotion_code_id: Optional[str],
) -> Optional[str]:
    """Returns promotion_code_id if this checkout should receive the
    Black Friday discount, else None. See module docstring for the full
    rule. now/start/end must all be timezone-aware (backend/main.py's own
    config loader is the one place that parses/validates this - see that
    function's docstring); a naive datetime comparison would silently
    misbehave across a UTC offset, so this function trusts its caller to
    have already normalized that rather than guessing a timezone here."""
    if not enabled or not promotion_code_id or start is None or end is None:
        return None
    if interval != _ELIGIBLE_INTERVAL:
        return None
    if not (start <= now <= end):
        return None
    return promotion_code_id
