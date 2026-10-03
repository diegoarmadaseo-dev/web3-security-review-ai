#!/usr/bin/env python3
"""Launch commercial catalog (docs/decisiones.md D-107) - the ONE place
the backend defines what each plan sells. Pure data plus a few pure
helpers; no database, no Stripe SDK, no environment reads. Standard
library only.

THREE PLANS, FIVE PRICES (never five plans): a plan carries the product
capabilities (per-scan LOC ceiling, usage allowance, members, projects);
a price mode is one way to pay for a plan:

    vericexa_quick_onetime     quick     one-time payment, exactly 1 scan
    vericexa_standard_monthly  standard  subscription, 1 month of service
    vericexa_standard_annual   standard  subscription, 12 months of service
    vericexa_pro_monthly       pro       subscription, 1 month of service
    vericexa_pro_annual        pro       subscription, 12 months of service

ANNUAL = 12 SERVICE MONTHS, NOT 12 QUOTAS UP FRONT: Standard/Pro usage is
always metered per SERVICE MONTH (20K / 60K effective LOC each month),
whichever price mode paid for it. An annual price pays once for twelve
service months; it never makes 240K/720K available at once, and unused
LOC never rolls over into the next service month (see service_month()).

QUICK IS A SCAN CREDIT, NOT A SUBSCRIPTION: one paid Quick checkout grants
exactly one scan of at most 3,000 effective LOC. There is no period, no
reset and no recurring billing; a second scan needs a second purchase.

Stripe Price IDs are deployment configuration, never constants here: the
test-mode and live-mode IDs differ, so backend/main.py reads them from
STRIPE_PRICE_* environment variables (PRICE_ENV_VARS) and backend/
billing.py resolves them. All five Price IDs are required.

"Effective LOC" is exactly the engine's own measure (scripts/preprocess.py
line_metrics(): non-blank lines with code once comments are masked) -
see backend/loc_count.py.
"""
from __future__ import annotations

import calendar
from datetime import datetime
from typing import Dict, Optional, Tuple

PLAN_QUICK = "quick"
PLAN_STANDARD = "standard"
PLAN_PRO = "pro"
PLANS_ORDER = (PLAN_QUICK, PLAN_STANDARD, PLAN_PRO)

BILLING_ONE_TIME = "one_time"
BILLING_SUBSCRIPTION = "subscription"

USAGE_SCAN_CREDIT = "scan_credit"      # quick: 1 scan per purchase, never resets
USAGE_SERVICE_MONTH = "service_month"  # standard/pro: LOC allowance per service month, no rollover

# None means "no limit defined by the catalog" (unlimited).
PLANS: Dict[str, Dict[str, object]] = {
    PLAN_QUICK: {
        "display_name": "Quick",
        "stripe_product_name": "Vericexa Quick",
        "billing_type": BILLING_ONE_TIME,
        "usage_model": USAGE_SCAN_CREDIT,
        "max_loc_per_scan": 3000,
        "scans_per_purchase": 1,
        "monthly_loc_quota": None,
        "max_projects": None,
        "max_members": None,        # not defined by the Launch catalog
        "queue_priority": "normal",
        "priority_support": False,
    },
    PLAN_STANDARD: {
        "display_name": "Standard",
        "stripe_product_name": "Vericexa Standard",
        "billing_type": BILLING_SUBSCRIPTION,
        "usage_model": USAGE_SERVICE_MONTH,
        "max_loc_per_scan": 10000,
        "scans_per_purchase": None,
        "monthly_loc_quota": 20000,
        "max_projects": None,
        "max_members": 2,
        "queue_priority": "normal",
        "priority_support": False,
    },
    PLAN_PRO: {
        "display_name": "Pro",
        "stripe_product_name": "Vericexa Pro",
        "billing_type": BILLING_SUBSCRIPTION,
        "usage_model": USAGE_SERVICE_MONTH,
        "max_loc_per_scan": 20000,
        "scans_per_purchase": None,
        "monthly_loc_quota": 60000,
        "max_projects": None,
        "max_members": 5,
        "queue_priority": "priority",   # read at admission: Pro jobs get analysis_jobs.priority = 1 (D-108, repository.claim_next_job())
        "priority_support": True,
    },
}

INTERVAL_ONE_TIME = "one_time"
INTERVAL_MONTHLY = "monthly"
INTERVAL_ANNUAL = "annual"

# amount_cents is the catalog price in USD cents - informational/contract
# only; what Stripe charges is whatever the configured Price ID says.
PRICE_MODES: Dict[str, Dict[str, object]] = {
    "vericexa_quick_onetime": {"plan": PLAN_QUICK, "interval": INTERVAL_ONE_TIME, "checkout_mode": "payment",
                               "amount_cents": 2999, "currency": "usd", "service_months": None},
    "vericexa_standard_monthly": {"plan": PLAN_STANDARD, "interval": INTERVAL_MONTHLY, "checkout_mode": "subscription",
                                  "amount_cents": 19999, "currency": "usd", "service_months": 1},
    "vericexa_standard_annual": {"plan": PLAN_STANDARD, "interval": INTERVAL_ANNUAL, "checkout_mode": "subscription",
                                 "amount_cents": 199990, "currency": "usd", "service_months": 12},
    "vericexa_pro_monthly": {"plan": PLAN_PRO, "interval": INTERVAL_MONTHLY, "checkout_mode": "subscription",
                             "amount_cents": 28999, "currency": "usd", "service_months": 1},
    "vericexa_pro_annual": {"plan": PLAN_PRO, "interval": INTERVAL_ANNUAL, "checkout_mode": "subscription",
                            "amount_cents": 289990, "currency": "usd", "service_months": 12},
}

# price mode key -> environment variable holding its Stripe Price ID.
PRICE_ENV_VARS: Dict[str, str] = {
    "vericexa_quick_onetime": "STRIPE_PRICE_QUICK_ONETIME",
    "vericexa_standard_monthly": "STRIPE_PRICE_STANDARD_MONTHLY",
    "vericexa_standard_annual": "STRIPE_PRICE_STANDARD_ANNUAL",
    "vericexa_pro_monthly": "STRIPE_PRICE_PRO_MONTHLY",
    "vericexa_pro_annual": "STRIPE_PRICE_PRO_ANNUAL",
}
# D-086 combinations that no longer exist. Setting their variables is a
# configuration error (backend/main.py), never silently ignored.
LEGACY_PRICE_ENV_VARS = ("STRIPE_PRICE_QUICK_MONTHLY", "STRIPE_PRICE_QUICK_ANNUAL")

# Plan -> analysis modes it may request (D-086's P0 authorization rule,
# unchanged: cumulative).
PLAN_ALLOWED_MODES = {
    PLAN_QUICK: frozenset({"quick"}),
    PLAN_STANDARD: frozenset({"quick", "standard"}),
    PLAN_PRO: frozenset({"quick", "standard", "pro"}),
}


def price_mode_key(plan: str, interval: str) -> Optional[str]:
    """The price mode selling `plan` at `interval`, or None when that
    combination is not sold (e.g. quick+monthly, pro+one_time)."""
    for key, mode in PRICE_MODES.items():
        if mode["plan"] == plan and mode["interval"] == interval:
            return key
    return None


def plan(plan_name: str) -> Dict[str, object]:
    return PLANS[plan_name]


# ---------------------------------------------------------------------------
# Usage states
# ---------------------------------------------------------------------------

STATE_NORMAL = "normal"
STATE_WARNING = "warning"
STATE_DANGER = "danger"
STATE_BLOCKED = "blocked"
STATE_UNLIMITED = "unlimited"


def usage_state(used: int, limit: Optional[int]) -> str:
    """<80% normal, 80-89% warning, 90-99% danger, >=100% blocked; no
    limit -> unlimited. Integer arithmetic only (no float rounding at the
    boundaries). A blocked state only means the NEXT operation that needs
    more allowance is refused - the account itself stays usable."""
    if limit is None:
        return STATE_UNLIMITED
    if limit <= 0 or used >= limit:
        return STATE_BLOCKED
    if used * 10 >= limit * 9:
        return STATE_DANGER
    if used * 10 >= limit * 8:
        return STATE_WARNING
    return STATE_NORMAL


# ---------------------------------------------------------------------------
# Service months (Standard/Pro usage periods)
# ---------------------------------------------------------------------------

def add_months(anchor: datetime, months: int) -> datetime:
    """anchor + months calendar months, clamping the day to the target
    month's length (Jan 31 + 1 -> Feb 28/29, + 2 -> Mar 31), always from
    the ORIGINAL anchor day so clamping never drifts month after month."""
    total = anchor.month - 1 + months
    year, month = anchor.year + total // 12, total % 12 + 1
    day = min(anchor.day, calendar.monthrange(year, month)[1])
    return anchor.replace(year=year, month=month, day=day)


def service_month(anchor: datetime, now: datetime) -> Tuple[datetime, datetime]:
    """The [start, end) service month containing `now`, counting whole
    months from `anchor` (the subscription's current period start). For a
    monthly subscription Stripe moves the anchor every renewal, so this is
    simply the current billing period; for an annual one the anchor stays
    put for 12 months and this yields month 1, 2, ... 12 in turn. `now`
    before the anchor (clock skew) maps to the first month."""
    if now < anchor:
        return anchor, add_months(anchor, 1)
    k = (now.year - anchor.year) * 12 + (now.month - anchor.month)
    if k > 0 and add_months(anchor, k) > now:
        k -= 1
    while add_months(anchor, k + 1) <= now:   # at most one step: guards the day-clamp edge
        k += 1
    return add_months(anchor, k), add_months(anchor, k + 1)
