#!/usr/bin/env python3
"""Stripe billing layer (Phase 3, docs/decisiones.md D-077 follow-up).
Thin wrapper around the Stripe SDK only - no HTTP, no persistence, no
tenant/session logic (see backend/http_app.py for the routes that call
this, backend/repository.py for the entitlements/webhook_events rows).

EXPLICIT CONFIG, NEVER ENVIRONMENT: StripeBilling.__init__ takes the
secret key, webhook secret and price allowlist as constructor arguments
- this module never calls os.environ itself (same discipline
backend/db.py's connect_postgres(dsn) already established: a caller
reading os.environ and passing values in explicitly, once, at the
process entrypoint, not scattered os.environ.get() calls inside library
code). This also makes every function here trivially testable with fake
config and no real network access.

PRICE SECURITY: create_checkout_session() takes an internal PLAN NAME
("quick"/"standard"/"pro") and INTERVAL ("monthly"/"annual"), never a
Stripe Price ID - resolve_price_id() is the one place a (plan, interval)
pair is looked up (via price_key()) against the server-supplied
price_allowlist, now 6 entries deep (D-086, docs/decisiones.md) - Stripe
Price ID -> plan/interval mapping is the caller's config, not this
module's. An unrecognized plan, interval, or combination raises
PriceNotAllowedError; there is no code path that accepts a client-
supplied Price ID at all, so there is nothing to tamper with.

BLACK FRIDAY DISCOUNT SECURITY (D-086): create_checkout_session()'s
black_friday_promotion_code_id parameter is likewise never client-
supplied - it is an already-resolved PromotionCode id the CALLER decided
to pass after checking eligibility (annual interval, campaign window,
enabled) itself; see that function's own docstring. This module does no
eligibility reasoning and accepts no client-shaped discount/coupon/
campaign-flag parameter of any kind - there is equally nothing to tamper
with here.

WEBHOOK SIGNATURE: verify_and_parse_webhook() calls
stripe.Webhook.construct_event(), which verifies the signature over the
RAW payload bytes and only THEN parses JSON - never the other way
around (parsing untrusted JSON before verifying its signature would
defeat the point of signing it). Returns the SDK's Event object as-is,
never converted via to_dict_recursive()/to_dict() - both are explicitly
marked "for internal stripe-python use only" and deprecated for removal
in the installed SDK (stripe==12.5.1, confirmed by the DeprecationWarning
those calls raise). This is safe to skip: every stripe.StripeObject
(Event, Session, Subscription, Invoice, and everything nested inside
them) is itself a genuine dict subclass (confirmed via
`issubclass(stripe.checkout.Session, dict)` and the same for
stripe._stripe_object.StripeObject) - .get()/[]/`in` all behave
identically to a plain dict at every nesting level, which is all this
module's callers (backend/http_app.py's webhook dispatch, this file's
own subscription_period_end()/invoice_workspace_id()) ever rely on.

Stripe's own object shapes used here, confirmed against the installed
SDK (stripe==12.5.1) rather than assumed:
  * Subscription.current_period_end is NOT a top-level field in this API
    version - it now lives per subscription item
    (items.data[N].current_period_end), since a subscription can have
    items with different billing periods. _subscription_period_end()
    reads the first item's, which is correct for this phase's
    one-price-per-subscription model and never crashes if absent.
  * Invoice metadata inheritance from its subscription differs across
    Stripe API versions (subscription_details.metadata in newer
    versions, a direct top-level metadata in older ones) -
    _invoice_workspace_id() tries both and returns None rather than
    guessing if neither is present; customer.subscription.updated (which
    Stripe always fires alongside a real payment failure/success) is the
    authoritative path for entitlement status either way, so a skipped
    invoice event never leaves entitlements stale on its own.

Stripe SDK is imported lazily/optionally, same pattern as backend/db.py's
psycopg import - an environment that never configures billing (e.g. the
existing test suite, or a deployment that hasn't enabled billing yet)
never needs it installed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import stripe
except ImportError:  # optional - see module docstring.
    stripe = None

_ALLOWED_PLANS = ("quick", "standard", "pro")
_ALLOWED_INTERVALS = ("monthly", "annual")


def price_key(plan: str, interval: str) -> str:
    """The ONE place a (plan, interval) pair becomes a price_allowlist
    key (D-086) - "quick_monthly", "quick_annual", etc. Used both here
    (resolve_price_id) and by backend/main.py when building the
    allowlist from 6 STRIPE_PRICE_* env vars, so the key FORMAT itself
    is never hand-typed twice. Does not validate plan/interval itself -
    resolve_price_id() below is the one place that raises for an
    unrecognized pair; this is a pure string-formatting helper only."""
    return "%s_%s" % (plan, interval)


class BillingError(Exception):
    """Raised only for misuse of this module itself (missing SDK, bad
    config, an unrecognized plan) - never for a Stripe API error, which
    always propagates as the SDK's own exception type, unchanged (same
    philosophy as backend/repository.RepositoryError)."""


class PriceNotAllowedError(BillingError):
    """A caller asked to check out a plan name not in the server-side
    allowlist - see module docstring on price security."""


class WebhookVerificationError(BillingError):
    """The webhook payload's signature did not verify, or the payload/
    signature header was malformed - the caller (backend/http_app.py)
    must turn this into a clean 400, never process the payload."""


def _require_stripe() -> None:
    if stripe is None:
        raise BillingError(
            'the "stripe" package is not installed - run: pip install "stripe>=11,<13" '
            "(see backend/requirements.txt). Nothing else in this codebase needs it."
        )


def stripe_timestamp_to_iso(value: Any) -> Optional[str]:
    """Converts a Stripe Unix-seconds timestamp (e.g. a Subscription
    item's current_period_end, or an Event's own `created`) to an
    ISO-8601 UTC string, matching backend/repository.py's own
    utcnow_iso() format - so a stored value and a freshly-converted one
    are always directly, correctly comparable as plain strings on SQLite
    (TEXT) and natively as TIMESTAMPTZ on Postgres. Returns None for
    anything that isn't a real number, never raises - a malformed/absent
    timestamp is something callers must treat as "no signal", never
    fabricate a value for."""
    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def subscription_period_end(subscription: Dict[str, Any]) -> Optional[str]:
    """Small, pure shape-extraction helper - deliberately public (unlike
    the rest of this module's SDK-call surface) so backend/http_app.py's
    webhook event dispatch can reuse it without duplicating Stripe
    object-shape knowledge. Reads current_period_end off the
    subscription's first item - see module docstring on why this is no
    longer a top-level field."""
    items = ((subscription.get("items") or {}).get("data")) or []
    if not items:
        return None
    return stripe_timestamp_to_iso(items[0].get("current_period_end"))


def invoice_workspace_id(invoice: Dict[str, Any]) -> Optional[str]:
    """Public for the same reason as subscription_period_end() above. See
    module docstring on invoice metadata inheritance uncertainty across
    Stripe API versions - tries both known shapes, never guesses."""
    direct = (invoice.get("metadata") or {}).get("workspace_id")
    if direct:
        return direct
    parent = invoice.get("parent") or {}
    subscription_details = parent.get("subscription_details") or invoice.get("subscription_details") or {}
    return (subscription_details.get("metadata") or {}).get("workspace_id")


class StripeBilling:
    """Constructed once per process with real (or test-mode) Stripe
    config, then reused - never re-reads config per call. Safe to hold in
    a long-lived variable and pass into backend.http_app.make_handler()
    the same way email_sender/host_allowlist already are."""

    def __init__(self, secret_key: str, webhook_secret: str, price_allowlist: Dict[str, str]) -> None:
        _require_stripe()
        if not isinstance(secret_key, str) or not secret_key:
            raise BillingError("secret_key is required")
        if not isinstance(webhook_secret, str) or not webhook_secret:
            raise BillingError("webhook_secret is required")
        if not price_allowlist:
            raise BillingError("price_allowlist must contain at least one plan_interval -> Price ID mapping")
        self._client = stripe.StripeClient(secret_key)
        self._webhook_secret = webhook_secret
        self._price_allowlist: Dict[str, str] = dict(price_allowlist)

    def resolve_price_id(self, plan: str, interval: str) -> str:
        """The ONE place a (plan, interval) pair becomes a Stripe Price
        ID - see module docstring on price security. price_key() is the
        single source of truth for how the pair becomes an allowlist
        key; this is the only function that ever looks one up."""
        if plan not in _ALLOWED_PLANS or interval not in _ALLOWED_INTERVALS:
            raise PriceNotAllowedError("plan %r / interval %r is not an allowlisted, sellable combination" % (plan, interval))
        key = price_key(plan, interval)
        if key not in self._price_allowlist:
            raise PriceNotAllowedError("plan %r / interval %r is not an allowlisted, sellable combination" % (plan, interval))
        return self._price_allowlist[key]

    def create_checkout_session(
        self,
        plan: str,
        interval: str,
        workspace_id: str,
        success_url: str,
        cancel_url: str,
        customer_id: Optional[str] = None,
        customer_email: Optional[str] = None,
        black_friday_promotion_code_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Raises PriceNotAllowedError for an unrecognized plan/interval
        pair (the caller turns this into a clean 400 - see http_app.py).
        Always stamps workspace_id, plan AND interval onto BOTH the
        Checkout Session itself (client_reference_id/metadata - read by
        the checkout.session.completed handler) and the resulting
        Subscription (subscription_data.metadata - read by the
        customer.subscription.* handlers) so every later webhook event
        can resolve its workspace/plan/interval without this module
        needing a database lookup of its own.

        BLACK FRIDAY (D-086): black_friday_promotion_code_id is an
        ALREADY-RESOLVED, already-eligibility-checked Stripe PromotionCode
        id - this function does no eligibility reasoning of its own
        (annual-only, campaign window, first-time-customer are all the
        CALLER's job, see backend/http_app.py's own docstring on why that
        logic lives there, never here). When given, it is attached via
        the native `discounts` Checkout param - never `allow_promotion_
        codes` (that renders a customer-facing code-entry field; this
        product's Black Friday offer is automatic, no code the customer
        ever sees or types - see docs/decisiones.md D-086)."""
        price_id = self.resolve_price_id(plan, interval)
        params: Dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            "client_reference_id": workspace_id,
            "metadata": {"workspace_id": workspace_id, "plan": plan, "interval": interval},
            "subscription_data": {"metadata": {"workspace_id": workspace_id, "plan": plan, "interval": interval}},
        }
        if customer_id:
            params["customer"] = customer_id
        elif customer_email:
            params["customer_email"] = customer_email
        if black_friday_promotion_code_id:
            params["discounts"] = [{"promotion_code": black_friday_promotion_code_id}]
        return self._client.checkout.sessions.create(params)

    def create_portal_session(self, customer_id: str, return_url: str) -> Dict[str, Any]:
        return self._client.billing_portal.sessions.create({"customer": customer_id, "return_url": return_url})

    def verify_and_parse_webhook(self, payload: bytes, sig_header: str) -> Dict[str, Any]:
        """Verifies `payload` (the UNTOUCHED raw request body - see
        backend/http_app.py's webhook handler) against `sig_header` (the
        Stripe-Signature header, verbatim) before any JSON parsing
        happens - see module docstring. Raises WebhookVerificationError
        for a missing/malformed/tampered/wrong-secret signature; the
        caller must turn this into a clean 400 and never touch
        `payload` any other way."""
        if not sig_header:
            raise WebhookVerificationError("missing Stripe-Signature header")
        try:
            return stripe.Webhook.construct_event(payload, sig_header, self._webhook_secret)
        except (ValueError, stripe.SignatureVerificationError) as exc:
            raise WebhookVerificationError(str(exc)) from exc
