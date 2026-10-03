"""Deterministic in-memory Stripe for the D-115 billing tests and for the
Sandbox E2E harness's --simulate mode (tests/stripe_sandbox_e2e.py).

Not a test module (no unittest cases) and never imported by backend code:
StripeSimulator is swapped into a real backend.billing.StripeBilling's
`_client` attribute after construction, standing in for stripe.StripeClient
for exactly the calls the backend and the harness make:

  checkout.sessions.create/retrieve/expire/list, checkout.sessions.line_items.list,
  subscriptions.retrieve/cancel, billing_portal.sessions.create, prices.retrieve,
  events.list

and it plays Stripe's side of the flow the way real Stripe does it (shapes
confirmed against stripe==12.5.1 and Stripe's documented behavior):

  * pay_checkout(): a Quick (payment-mode) session completes "paid" (or
    "unpaid" for an asynchronous method, settled later by
    settle_async_payment()); a subscription-mode session creates the
    Customer and the Subscription and emits customer.subscription.created
    (status incomplete), customer.subscription.updated (active),
    invoice.paid and checkout.session.completed - all in the SAME second,
    as Stripe does;
  * renew() (new period, invoice.paid / invoice.payment_failed),
    change_price() (portal upgrade/downgrade), cancel() (deleted);
  * every event carries a SNAPSHOT of its object at emission time, its own
    `created` second and livemode=False - like real Sandbox events.

events are kept in emission order (self.emitted); events.list() returns
newest first, like Stripe. sign_payload() builds a Stripe-Signature header
(HMAC-SHA256 over "<t>.<body>", the scheme stripe.Webhook verifies).
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import itertools
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import stripe
except ImportError:  # the simulator itself does not need the SDK
    stripe = None

import backend.plans as plans

CHECKOUT_URL = "https://checkout.stripe.test/fake"
PORTAL_URL = "https://billing.stripe.test/fake"
_MONTH = 30 * 86400
_YEAR = 365 * 86400


def sign_payload(payload: bytes, secret: str, timestamp: Optional[int] = None) -> str:
    """A valid Stripe-Signature header for `payload` under `secret`."""
    ts = int(time.time()) if timestamp is None else int(timestamp)
    signature = hmac.new(secret.encode("utf-8"), ("%d." % ts).encode("ascii") + payload, hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (ts, signature)


def _not_found(kind: str, object_id: str) -> Exception:
    if stripe is not None:
        return stripe.InvalidRequestError("No such %s: '%s'" % (kind, object_id), "id")
    return KeyError(object_id)


class _Namespace:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


class _LineItems:
    def __init__(self, sim: "StripeSimulator") -> None:
        self._sim = sim
        # session id -> [(price_id, quantity)] overriding what the session sold
        # (tests: "what Stripe reports as paid" differs from the ledger).
        self.store: Dict[str, List[Tuple[Optional[str], Any]]] = {}

    def list(self, session_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if session_id in self.store:
            items = self.store[session_id]
        else:
            session = self._sim.sessions.get(session_id)
            if session is None:
                raise _not_found("checkout.session", session_id)
            items = [(li.get("price"), li.get("quantity")) for li in session.get("line_items") or []]
        return {"object": "list", "data": [{"price": {"id": p}, "quantity": q} for p, q in items], "has_more": False}


class _CheckoutSessions:
    def __init__(self, sim: "StripeSimulator") -> None:
        self._sim = sim
        self.calls: List[Dict[str, Any]] = []      # every create() params, in order
        self.line_items = _LineItems(sim)

    def create(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(params)
        session_id = "cs_test_sim_%d" % next(self._sim._seq)
        session = dict(params)
        session.update({
            "id": session_id, "object": "checkout.session", "url": CHECKOUT_URL, "status": "open", "payment_status": "unpaid",
            "customer": params.get("customer"), "subscription": None, "livemode": False, "created": self._sim.now,
        })
        self._sim.sessions[session_id] = session
        return copy.deepcopy(session)

    def retrieve(self, session_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        session = self._sim.sessions.get(session_id)
        if session is None:
            raise _not_found("checkout.session", session_id)
        return copy.deepcopy(session)

    def expire(self, session_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        session = self._sim.sessions.get(session_id)
        if session is None:
            raise _not_found("checkout.session", session_id)
        if session["status"] != "open":
            if stripe is not None:
                raise stripe.InvalidRequestError("Only Checkout Sessions with a status of 'open' can be expired.", "session")
            raise ValueError("not open")
        session["status"] = "expired"
        self._sim.emit("checkout.session.expired", session)
        return copy.deepcopy(session)

    def list(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        found = [s for s in self._sim.sessions.values() if not params.get("subscription") or s.get("subscription") == params["subscription"]]
        return {"object": "list", "data": [copy.deepcopy(s) for s in found[: int(params.get("limit", 10))]], "has_more": False}


class _PortalSessions:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def create(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(params)
        return {"id": "bps_test_%d" % len(self.calls), "url": PORTAL_URL, **params}


class _Subscriptions:
    def __init__(self, sim: "StripeSimulator") -> None:
        self._sim = sim
        self.retrieve_calls = 0
        # subscription id -> object; tests may also put Stripe's "current
        # state" here directly.
        self.store: Dict[str, Dict[str, Any]] = sim.subscriptions_store

    def retrieve(self, subscription_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self.retrieve_calls += 1
        if self._sim.fail_next_retrieves > 0:
            self._sim.fail_next_retrieves -= 1
            if stripe is not None:
                raise stripe.APIConnectionError("simulated Stripe outage")
            raise ConnectionError("simulated Stripe outage")
        subscription = self.store.get(subscription_id)
        if subscription is None:
            raise _not_found("subscription", subscription_id)
        return copy.deepcopy(subscription)

    def cancel(self, subscription_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if subscription_id not in self.store:
            raise _not_found("subscription", subscription_id)
        self._sim.cancel(subscription_id)
        return copy.deepcopy(self.store[subscription_id])


class _Prices:
    def __init__(self, sim: "StripeSimulator") -> None:
        self._sim = sim

    def retrieve(self, price_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        price = self._sim.prices_store.get(price_id)
        if price is None:
            raise _not_found("price", price_id)
        return copy.deepcopy(price)


class _Events:
    def __init__(self, sim: "StripeSimulator") -> None:
        self._sim = sim

    def list(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        gte = ((params.get("created") or {}).get("gte")) if isinstance(params.get("created"), dict) else None
        types = params.get("types")
        found = [e for e in self._sim.emitted if (gte is None or e["created"] >= gte) and (not types or e["type"] in types)]
        found = list(reversed(found))[: int(params.get("limit", 100))]   # newest first, like Stripe
        return {"object": "list", "data": copy.deepcopy(found), "has_more": False}


class StripeSimulator:
    """See module docstring. price_allowlist: price mode key -> Price ID
    (the backend's own allowlist), used to build the Price objects."""

    def __init__(self, price_allowlist: Optional[Dict[str, str]] = None, start: int = 1_800_000_000) -> None:
        self._seq = itertools.count(1)
        self.now = start
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.subscriptions_store: Dict[str, Dict[str, Any]] = {}
        self.prices_store: Dict[str, Dict[str, Any]] = {}
        self.emitted: List[Dict[str, Any]] = []
        self.fail_next_retrieves = 0
        self.checkout = _Namespace(sessions=_CheckoutSessions(self))
        self.billing_portal = _Namespace(sessions=_PortalSessions())
        self.subscriptions = _Subscriptions(self)
        self.prices = _Prices(self)
        self.events = _Events(self)
        for key, price_id in (price_allowlist or {}).items():
            mode = plans.PRICE_MODES[key]
            recurring = None if mode["interval"] == plans.INTERVAL_ONE_TIME else {"interval": "month" if mode["interval"] == plans.INTERVAL_MONTHLY else "year", "interval_count": 1}
            self.prices_store[price_id] = {"id": price_id, "object": "price", "livemode": False, "active": True,
                                           "type": "one_time" if recurring is None else "recurring", "recurring": recurring,
                                           "unit_amount": mode["amount_cents"], "currency": mode["currency"], "product": "prod_sim_%s" % mode["plan"]}

    # -- events ---------------------------------------------------------------

    def emit(self, event_type: str, obj: Dict[str, Any]) -> Dict[str, Any]:
        event = {"id": "evt_sim_%d" % next(self._seq), "object": "event", "type": event_type, "created": self.now, "livemode": False,
                 "api_version": "2025-03-31.basil", "data": {"object": copy.deepcopy(obj)}}
        self.emitted.append(event)
        return event

    def events_since(self, index: int) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.emitted[index:])

    # -- Stripe's side of the flow ---------------------------------------------

    def _customer_for(self, session: Dict[str, Any]) -> str:
        if not session.get("customer"):
            session["customer"] = "cus_sim_%d" % next(self._seq)
        return session["customer"]

    def _subscription_items(self, price_id: str, start: int) -> Dict[str, Any]:
        price = self.prices_store.get(price_id) or {"id": price_id, "recurring": {"interval": "month"}}
        length = _YEAR if (price.get("recurring") or {}).get("interval") == "year" else _MONTH
        return {"object": "list", "data": [{"id": "si_sim_%d" % next(self._seq), "price": copy.deepcopy(price), "quantity": 1,
                                            "current_period_start": start, "current_period_end": start + length}]}

    def pay_checkout(self, session_id: str, async_payment: bool = False, subscription_status: str = "active") -> List[Dict[str, Any]]:
        """The customer completes the hosted Checkout page. Returns the events
        Stripe emits, in emission order."""
        session = self.sessions[session_id]
        assert session["status"] == "open", "only an open session can be paid"
        first = len(self.emitted)
        customer = self._customer_for(session)
        session["status"] = "complete"
        if session["mode"] == "payment":
            session["payment_status"] = "unpaid" if async_payment else "paid"
            self.emit("checkout.session.completed", session)
            return self.events_since(first)
        sub_id = "sub_sim_%d" % next(self._seq)
        subscription = {"id": sub_id, "object": "subscription", "customer": customer, "status": "incomplete", "livemode": False,
                        "cancel_at_period_end": False, "metadata": dict((session.get("subscription_data") or {}).get("metadata") or {}),
                        "items": self._subscription_items(session["line_items"][0]["price"], self.now)}
        self.subscriptions_store[sub_id] = subscription
        session["subscription"] = sub_id
        session["payment_status"] = "paid"
        self.emit("customer.subscription.created", subscription)
        subscription["status"] = subscription_status
        self.emit("customer.subscription.updated", subscription)
        self.emit("invoice.paid", self._invoice(subscription, paid=True))
        self.emit("checkout.session.completed", session)
        return self.events_since(first)

    def settle_async_payment(self, session_id: str, succeeded: bool = True) -> List[Dict[str, Any]]:
        session = self.sessions[session_id]
        first = len(self.emitted)
        session["payment_status"] = "paid" if succeeded else "unpaid"
        self.emit("checkout.session.async_payment_succeeded" if succeeded else "checkout.session.async_payment_failed", session)
        return self.events_since(first)

    def _invoice(self, subscription: Dict[str, Any], paid: bool) -> Dict[str, Any]:
        return {"id": "in_sim_%d" % next(self._seq), "object": "invoice", "customer": subscription["customer"], "status": "paid" if paid else "open",
                "parent": {"type": "subscription_details", "subscription_details": {"subscription": subscription["id"],
                                                                                     "metadata": dict(subscription.get("metadata") or {})}}}

    def renew(self, subscription_id: str, paid: bool = True) -> List[Dict[str, Any]]:
        """The next billing period starts (monthly renewal; for an annual
        price, the next year). A failed payment leaves the subscription
        past_due."""
        subscription = self.subscriptions_store[subscription_id]
        first = len(self.emitted)
        item = subscription["items"]["data"][0]
        length = item["current_period_end"] - item["current_period_start"]
        self.now = item["current_period_end"]
        item["current_period_start"], item["current_period_end"] = self.now, self.now + length
        subscription["status"] = "active" if paid else "past_due"
        self.emit("invoice.paid" if paid else "invoice.payment_failed", self._invoice(subscription, paid))
        self.emit("customer.subscription.updated", subscription)
        return self.events_since(first)

    def change_price(self, subscription_id: str, price_id: str) -> List[Dict[str, Any]]:
        subscription = self.subscriptions_store[subscription_id]
        first = len(self.emitted)
        subscription["items"]["data"][0]["price"] = copy.deepcopy(self.prices_store.get(price_id) or {"id": price_id})
        self.emit("customer.subscription.updated", subscription)
        return self.events_since(first)

    def cancel(self, subscription_id: str) -> List[Dict[str, Any]]:
        subscription = self.subscriptions_store[subscription_id]
        first = len(self.emitted)
        subscription["status"] = "canceled"
        self.emit("customer.subscription.deleted", subscription)
        return self.events_since(first)

    def advance(self, seconds: int) -> None:
        self.now += int(seconds)
