"""D-115 Stripe billing, end to end and deterministic (no network, no real
Stripe): POST /billing/checkout -> what Stripe does when the customer pays
(tests/stripe_simulator.py) -> SIGNED webhooks over real HTTP -> entitlement
-> scan admission -> usage/quota. Uses the five Sandbox Price IDs of
docs/staging-config.md (D-107) so the catalog under test is the real one.

What each class proves:
  * StripeModeTests - a Sandbox deployment never accepts a live key, a live
    event, a malformed webhook secret (and the reverse for live mode);
  * CheckoutTests - the 5 price modes, the server-chosen Price, the
    checkout ledger binding (workspace + user), one payable checkout per
    workspace, refusals (wrong user/role, still-billing subscription);
  * QuickTests - one-time payment, async success/failure, exactly one
    credit under replays/concurrency, line-item verification, consumption
    and the 3,000 LOC limit;
  * SubscriptionTests - the 4 subscription modes, Stripe's same-second burst
    in EVERY order, renewal = new service month, annual = 12 monthly
    allowances without rollover, payment failure, cancellation, portal plan
    change, Stripe outage -> 500 -> retry;
  * BindingSecurityTests - wrong workspace / customer / subscription,
    unbound subscriptions, duplicate live subscriptions, late events of an
    old subscription, unknown workspaces, mode mismatch, operator alerts.

Run from the repository root: python -m unittest tests.test_backend_stripe_billing
"""
from __future__ import annotations

import itertools
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from typing import Any, Dict, List

import backend.billing as billing
import backend.http_app as http_app
import backend.object_storage as object_storage
import backend.plans as plans
import backend.repository as repo
import tests.test_backend_billing as billing_tests
from tests.stripe_simulator import StripeSimulator, sign_payload
from tests.test_backend_http_app import HOST, _CapturingEmailSender

# docs/staging-config.md / D-107 - the real Sandbox Price IDs (public
# identifiers, not secrets).
SANDBOX_PRICE_IDS = {
    "vericexa_quick_onetime": "price_1UMFnY1jc8PYYLrPXxSbSEUF",
    "vericexa_standard_monthly": "price_1UMFvU1jc8PYYLrPsrZuTqJl",
    "vericexa_standard_annual": "price_1UMFvU1jc8PYYLrPg7Kia6bO",
    "vericexa_pro_monthly": "price_1UMFwj1jc8PYYLrP2rA1xonm",
    "vericexa_pro_annual": "price_1UMFy51jc8PYYLrPLyQHT8Fh",
}
WEBHOOK_SECRET = "whsec_d115_test_only_not_a_real_secret"
SUBSCRIPTION_MODES = (("standard", "monthly"), ("standard", "annual"), ("pro", "monthly"), ("pro", "annual"))


def _sol(effective_lines: int) -> str:
    body = ["pragma solidity ^0.8.20;", "contract C {"] + ["    uint256 public v%d;" % i for i in range(max(0, effective_lines - 3))] + ["}"]
    return "\n".join(body) + "\n"


class _Alerts:
    def __init__(self):
        self.events = []

    def emit(self, event_type, severity, detail):
        self.events.append((event_type, severity, detail))


class StripeModeTests(unittest.TestCase):
    def test_sandbox_accepts_only_test_keys_and_whsec_secrets(self):
        ok = billing.StripeBilling("rk_test_restricted", WEBHOOK_SECRET, dict(SANDBOX_PRICE_IDS))
        self.assertEqual(ok.mode, "test")
        live_key = "sk_live_" + "s" * 30
        for key, secret, mode in ((live_key, WEBHOOK_SECRET, "test"), ("rk_live_" + "r" * 30, WEBHOOK_SECRET, "test"),
                                  ("sk_test_x", WEBHOOK_SECRET, "live"), ("pk_test_publishable", WEBHOOK_SECRET, "test"),
                                  ("sk_test_x", "not_whsec", "test"), ("sk_test_x", "whsec_", "test"), ("sk_test_x", WEBHOOK_SECRET, "staging")):
            with self.subTest(mode=mode, key_class=key[:8]):
                with self.assertRaises(billing.BillingError) as ctx:
                    billing.StripeBilling(key, secret, dict(SANDBOX_PRICE_IDS), mode=mode)
                self.assertNotIn("s" * 30, str(ctx.exception))       # never echoes the key
                self.assertNotIn("r" * 30, str(ctx.exception))
        self.assertEqual(billing.StripeBilling(live_key, WEBHOOK_SECRET, dict(SANDBOX_PRICE_IDS), mode="live").mode, "live")

    def test_each_mode_verifies_only_its_own_events(self):
        for mode, key in (("test", "sk_test_x"), ("live", "sk_live_x")):
            instance = billing.StripeBilling(key, WEBHOOK_SECRET, dict(SANDBOX_PRICE_IDS), mode=mode)
            for livemode in (False, True):
                body = json.dumps({"id": "evt_1", "type": "customer.updated", "livemode": livemode, "data": {"object": {}}}).encode()
                header = sign_payload(body, WEBHOOK_SECRET)
                if livemode == (mode == "live"):
                    self.assertEqual(instance.verify_and_parse_webhook(body, header)["id"], "evt_1")
                else:
                    with self.assertRaises(billing.WebhookModeMismatchError):
                        instance.verify_and_parse_webhook(body, header)

    def test_the_sandbox_catalog_is_the_documented_one(self):
        instance = billing.StripeBilling("sk_test_x", WEBHOOK_SECRET, dict(SANDBOX_PRICE_IDS))
        for (plan, interval), key in zip((("quick", "one_time"),) + SUBSCRIPTION_MODES, plans.PRICE_MODES):
            self.assertEqual(instance.resolve_price_id(plan, interval), SANDBOX_PRICE_IDS[key])
            self.assertEqual(instance.plan_for_price_id(SANDBOX_PRICE_IDS[key])["plan"], plan)
        self.assertIsNone(instance.plan_for_price_id("price_unknown"))


class _StripeE2ETestCase(billing_tests._BillingHttpTestCase):
    """A real server with SQLite, local object storage, a StripeBilling in
    Sandbox mode whose client is the Stripe simulator, and an alert sink."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed = repo.connect(self.db_path)
        repo.init_schema(seed)
        seed.close()
        self.storage_dir = tempfile.mkdtemp(prefix="stripe-e2e-tests-")
        self.email_sender = _CapturingEmailSender()
        self.alerts = _Alerts()
        self.billing = billing.StripeBilling("sk_test_fake", WEBHOOK_SECRET, dict(SANDBOX_PRICE_IDS))
        self.stripe = StripeSimulator(dict(SANDBOX_PRICE_IDS), start=int(time.time()) - 3600)
        self.billing._client = self.stripe
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path), email_sender=self.email_sender, host_allowlist=[HOST], host=HOST, port=0,
            secure_cookies=False, billing=self.billing, alert_sender=self.alerts,
            storage=object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="test-only-secret"),
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.addCleanup(lambda: shutil.rmtree(self.storage_dir, ignore_errors=True))
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)
        self._emails = itertools.count(1)

    # -- helpers -------------------------------------------------------------

    def db(self):
        conn = repo.connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def owner(self, role="owner"):
        cookie, ws, user_id = self._login_and_own_workspace("owner-%d@example.com" % next(self._emails), role=role)
        return cookie, ws, user_id

    def checkout(self, cookie, ws, plan, interval=None, expect=200, extra=None):
        payload = {"workspace_id": ws, "plan": plan}
        if interval is not None:
            payload["interval"] = interval
        payload.update(extra or {})
        status, _, body = self.post_json("/billing/checkout", payload, headers={"Cookie": cookie})
        self.assertEqual(status, expect, body)
        return list(self.stripe.sessions)[-1] if status == 200 else json.loads(body)

    def deliver(self, events: List[Dict[str, Any]], expect_status=200) -> List[str]:
        outcomes = []
        for event in events:
            status, _, body = self.post_webhook(event, secret=WEBHOOK_SECRET)
            self.assertEqual(status, expect_status, body)
            data = json.loads(body)
            outcomes.append("ignored:duplicate" if data.get("duplicate") else data.get("outcome", data.get("error")))
        return outcomes

    def entitlement(self, ws):
        return repo.get_entitlement_by_workspace(self.db(), ws)

    def usage(self, ws, now=None):
        conn = self.db()
        return repo.usage_summary(conn, ws, repo.get_entitlement_by_workspace(conn, ws), now=now)

    def submit(self, cookie, ws, loc, mode="quick"):
        status, _, body = self.post_json("/workspaces/%s/jobs" % ws, {"mode": mode, "source": _sol(loc)}, headers={"Cookie": cookie})
        return status, json.loads(body)

    def subscribe(self, plan="standard", interval="monthly"):
        cookie, ws, user = self.owner()
        session_id = self.checkout(cookie, ws, plan, interval)
        self.deliver(self.stripe.pay_checkout(session_id))
        return cookie, ws, self.entitlement(ws)["stripe_subscription_id"]


class CheckoutTests(_StripeE2ETestCase):
    def test_each_of_the_five_price_modes_creates_a_bound_checkout_session(self):
        cookie, ws, user = self.owner()
        for i, (plan, interval) in enumerate((("quick", "one_time"),) + SUBSCRIPTION_MODES):
            session_id = self.checkout(cookie, ws, plan, interval)
            params = self.stripe.checkout.sessions.calls[-1]
            price = SANDBOX_PRICE_IDS[plans.price_mode_key(plan, interval)]
            mode = "payment" if plan == "quick" else "subscription"
            self.assertEqual((params["mode"], params["line_items"]), (mode, [{"price": price, "quantity": 1}]))
            self.assertEqual((params["client_reference_id"], params["metadata"]), (ws, {"workspace_id": ws, "plan": plan, "interval": interval}))
            if mode == "subscription":
                self.assertEqual(params["subscription_data"]["metadata"], {"workspace_id": ws, "plan": plan, "interval": interval})
            else:
                self.assertEqual(params["customer_creation"], "always")
            row = repo.get_checkout_session(self.db(), session_id)
            self.assertEqual((row["workspace_id"], row["user_id"], row["plan"], row["billing_interval"], row["price_id"], row["checkout_mode"], row["status"]),
                             (ws, user, plan, interval, price, mode, "open"))
        # each new checkout expired the previous one, in Stripe and locally
        statuses = [repo.get_checkout_session(self.db(), s)["status"] for s in self.stripe.sessions]
        self.assertEqual(statuses, ["expired"] * 4 + ["open"])
        self.assertEqual([s["status"] for s in self.stripe.sessions.values()], ["expired"] * 4 + ["open"])

    def test_the_client_never_chooses_the_price_and_quick_defaults_to_one_time(self):
        cookie, ws, _ = self.owner()
        self.checkout(cookie, ws, "quick", extra={"price": "price_evil", "line_items": [{"price": "price_evil"}], "mode": "subscription"})
        params = self.stripe.checkout.sessions.calls[-1]
        self.assertEqual((params["mode"], params["line_items"][0]["price"]), ("payment", SANDBOX_PRICE_IDS["vericexa_quick_onetime"]))
        for plan, interval in (("quick", "monthly"), ("standard", "one_time"), ("pro", None), ("trial", "one_time"), ("enterprise", "annual")):
            self.checkout(cookie, ws, plan, interval, expect=400)

    def test_wrong_user_role_or_origin_cannot_check_out(self):
        _, ws, _ = self.owner()
        stranger, _, _ = self.owner()
        self.checkout(stranger, ws, "standard", "monthly", expect=403)                 # another user's workspace
        member, member_ws, _ = self.owner(role="member")
        self.checkout(member, member_ws, "standard", "monthly", expect=403)            # members cannot buy
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": "quick"})
        self.assertEqual(status, 401)
        cookie, own_ws, _ = self.owner()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": own_ws, "plan": "quick"}, headers={"Cookie": cookie, "Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM billing_checkout_sessions").fetchone()[0], 0)

    def test_a_paid_or_settling_previous_checkout_refuses_a_new_one(self):
        cookie, ws, _ = self.owner()
        first = self.checkout(cookie, ws, "standard", "monthly")
        events = self.stripe.pay_checkout(first)              # paid, webhooks not delivered yet
        self.assertEqual(self.checkout(cookie, ws, "pro", "monthly", expect=409)["error"], "checkout_already_completed")
        self.assertEqual(repo.get_checkout_session(self.db(), first)["status"], "completed")
        self.assertEqual(self.checkout(cookie, ws, "pro", "monthly", expect=409)["error"], "checkout_already_completed")   # still unapplied
        self.deliver(events)                                  # the webhooks arrive: the subscription is applied
        self.assertEqual(self.checkout(cookie, ws, "pro", "monthly", expect=409)["error"], "this workspace already has an active subscription")
        cookie2, ws2, _ = self.owner()
        quick = self.checkout(cookie2, ws2, "quick")
        self.assertEqual(self.deliver(self.stripe.pay_checkout(quick, async_payment=True)), ["applied:awaiting_payment"])
        self.assertEqual(self.checkout(cookie2, ws2, "quick", expect=409)["error"], "checkout_payment_pending")

    def test_a_subscription_that_still_bills_refuses_a_second_one(self):
        cookie, ws, user = self.owner()
        conn = self.db()
        repo.create_entitlement(conn, ws, "standard", "active", stripe_customer_id="cus_x", stripe_subscription_id="sub_x", billing_interval="monthly")
        for status, expected in (("active", 409), ("trialing", 409), ("past_due", 409), ("unpaid", 409), ("canceled", 200), ("incomplete_expired", 200)):
            repo.update_entitlement_status(conn, ws, status)
            self.checkout(cookie, ws, "pro", "annual", expect=expected)

    def test_a_stripe_failure_records_no_checkout_session(self):
        cookie, ws, _ = self.owner()

        def boom(params):
            raise billing.stripe.APIConnectionError("simulated outage")

        original = self.stripe.checkout.sessions.create
        self.stripe.checkout.sessions.create = boom
        try:
            status, _, body = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": "quick"}, headers={"Cookie": cookie})
        finally:
            self.stripe.checkout.sessions.create = original
        self.assertEqual((status, json.loads(body)["error"]), (500, "internal error"))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM billing_checkout_sessions").fetchone()[0], 0)


class QuickTests(_StripeE2ETestCase):
    def test_quick_purchase_grants_one_credit_that_one_scan_consumes(self):
        cookie, ws, _ = self.owner()
        session_id = self.checkout(cookie, ws, "quick")
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(self.deliver(self.stripe.pay_checkout(session_id)), ["applied:quick_credit_granted"])
        ent = self.entitlement(ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"], ent["stripe_customer_id"]),
                         ("quick", "active", None, self.stripe.sessions[session_id]["customer"]))
        self.assertEqual(self.usage(ws)["scans_available"], 1)
        self.assertEqual(repo.get_checkout_session(self.db(), session_id)["status"], "completed")
        self.assertEqual(self.submit(cookie, ws, 3001)[1]["error"], "loc_per_scan_limit_exceeded")   # Quick limit, credit kept
        self.assertEqual(self.submit(cookie, ws, 3000)[0], 200)
        usage = self.usage(ws)
        self.assertEqual((usage["scans_available"], usage["scans_reserved"]), (0, 1))
        status, body = self.submit(cookie, ws, 10)
        self.assertEqual((status, body["error"]), (402, "no_scan_credit"))

    def test_asynchronous_payment_success_and_failure(self):
        cookie, ws, _ = self.owner()
        failed = self.checkout(cookie, ws, "quick")
        self.assertEqual(self.deliver(self.stripe.pay_checkout(failed, async_payment=True)), ["applied:awaiting_payment"])
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(self.deliver(self.stripe.settle_async_payment(failed, succeeded=False)), ["applied:payment_failed"])
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(repo.get_checkout_session(self.db(), failed)["status"], "payment_failed")
        retry = self.checkout(cookie, ws, "quick")                                   # a failed payment never blocks buying again
        self.deliver(self.stripe.pay_checkout(retry, async_payment=True))
        self.assertEqual(self.deliver(self.stripe.settle_async_payment(retry)), ["applied:quick_credit_granted"])
        self.assertEqual(self.usage(ws)["scans_available"], 1)
        late_failure = self.stripe.emit("checkout.session.async_payment_failed", self.stripe.sessions[retry])
        self.assertEqual(self.deliver([late_failure]), ["ignored:checkout_already_completed"])   # status only moves forward
        self.assertEqual(self.usage(ws)["scans_available"], 1)

    def test_only_exactly_one_unit_of_the_quick_price_grants_a_credit(self):
        cookie, ws, _ = self.owner()
        for paid in ([(SANDBOX_PRICE_IDS["vericexa_standard_monthly"], 1)], [(SANDBOX_PRICE_IDS["vericexa_quick_onetime"], 2)],
                     [(SANDBOX_PRICE_IDS["vericexa_quick_onetime"], 1), ("price_other", 1)], [], [("price_foreign_product", 1)]):
            cookie, ws, _ = self.owner()
            session_id = self.checkout(cookie, ws, "quick")
            self.stripe.checkout.sessions.line_items.store[session_id] = paid
            self.assertEqual(self.deliver(self.stripe.pay_checkout(session_id)), ["rejected:line_items_mismatch"])
            self.assertEqual(repo.get_checkout_session(self.db(), session_id)["status"], "completed")
            self.assertIsNone(self.entitlement(ws))
        # ...but only after the grace period: right after it, a new checkout is refused
        self.assertEqual(self.checkout(cookie, ws, "quick", expect=409)["error"], "checkout_already_completed")
        conn = self.db()
        conn.execute("UPDATE billing_checkout_sessions SET updated_at = ?", ("2000-01-01T00:00:00+00:00",))
        conn.commit()
        self.checkout(cookie, ws, "quick")
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)
        self.assertTrue(all(e[2]["error_type"] == "rejected:line_items_mismatch" for e in self.alerts.events))

    def test_redeliveries_and_concurrent_deliveries_grant_exactly_one_credit(self):
        cookie, ws, _ = self.owner()
        session_id = self.checkout(cookie, ws, "quick")
        event = self.stripe.pay_checkout(session_id)[0]
        copies = [dict(event, id="evt_copy_%d" % i, type="checkout.session.completed" if i % 2 else "checkout.session.async_payment_succeeded")
                  for i in range(6)]
        results, barrier = [], threading.Barrier(len(copies) + 1)

        def go(e):
            barrier.wait(10)
            results.append(self.post_webhook(e, secret=WEBHOOK_SECRET)[0])

        threads = [threading.Thread(target=go, args=(e,)) for e in copies + [event]]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertEqual(results, [200] * 7)
        self.assertEqual(self.deliver([event]), ["ignored:duplicate"])
        credits = self.db().execute("SELECT id FROM scan_credits WHERE workspace_id = ?", (ws,)).fetchall()
        self.assertEqual([c[0] for c in credits], [session_id])

    def test_an_expired_checkout_grants_nothing(self):
        cookie, ws, _ = self.owner()
        session_id = self.checkout(cookie, ws, "quick")
        self.stripe.sessions[session_id]["status"] = "open"
        self.stripe.checkout.sessions.expire(session_id)
        self.assertEqual(self.deliver(self.stripe.events_since(len(self.stripe.emitted) - 1)), ["applied:checkout_expired"])
        self.assertEqual(repo.get_checkout_session(self.db(), session_id)["status"], "expired")
        self.assertIsNone(self.entitlement(ws))


class SubscriptionTests(_StripeE2ETestCase):
    def test_each_subscription_mode_activates_with_its_plan_interval_and_quota(self):
        for plan, interval in SUBSCRIPTION_MODES:
            with self.subTest(plan=plan, interval=interval):
                cookie, ws, _ = self.owner()
                session_id = self.checkout(cookie, ws, plan, interval)
                outcomes = self.deliver(self.stripe.pay_checkout(session_id))
                self.assertIn("applied:subscription_active", outcomes)
                sub_id = self.stripe.sessions[session_id]["subscription"]
                ent = self.entitlement(ws)
                item = self.stripe.subscriptions_store[sub_id]["items"]["data"][0]
                self.assertEqual((ent["plan"], ent["billing_interval"], ent["status"], ent["stripe_subscription_id"], ent["stripe_customer_id"]),
                                 (plan, interval, "active", sub_id, self.stripe.sessions[session_id]["customer"]))
                self.assertEqual((ent["current_period_start"], ent["current_period_end"]),
                                 (billing.stripe_timestamp_to_iso(item["current_period_start"]), billing.stripe_timestamp_to_iso(item["current_period_end"])))
                usage = self.usage(ws)
                self.assertEqual((usage["loc_limit"], usage["max_loc_per_scan"], usage["loc_used"]),
                                 (plans.PLANS[plan]["monthly_loc_quota"], plans.PLANS[plan]["max_loc_per_scan"], 0))
                row = repo.get_checkout_session(self.db(), session_id)
                self.assertEqual((row["status"], row["stripe_subscription_id"]), ("completed", sub_id))
                self.assertEqual(self.submit(cookie, ws, 100, mode=plan)[0], 200)
                self.assertEqual(self.usage(ws)["loc_used"], 100)

    def test_the_same_second_burst_ends_active_in_every_delivery_order(self):
        # Stripe emits created(incomplete) / updated(active) / invoice.paid /
        # checkout.session.completed within one second; any delivery order
        # must end active (Phase 3's created-ordering could stick at incomplete).
        _, _, user = self.owner()
        conn = self.db()
        orders = 0
        for permutation in itertools.permutations(range(4)):
            ws = repo.create_workspace(conn, "Burst WS", user)
            session = self.billing.create_checkout_session("pro", "annual", ws, "https://a/ok", "https://a/no")
            repo.record_checkout_session(conn, session["id"], ws, user, "pro", "annual", SANDBOX_PRICE_IDS["vericexa_pro_annual"], "subscription", None)
            conn.commit()
            events = self.stripe.pay_checkout(session["id"])
            self.assertEqual(len({e["created"] for e in events}), 1)
            for i in permutation:
                http_app._apply_webhook_event(conn, self.billing, events[i]["type"], events[i]["data"]["object"])
            ent = repo.get_entitlement_by_workspace(conn, ws)
            self.assertEqual((ent["plan"], ent["billing_interval"], ent["status"]), ("pro", "annual", "active"), permutation)
            orders += 1
        self.assertEqual(orders, 24)

    def test_renewal_starts_a_new_service_month_and_resets_usage(self):
        cookie, ws, sub_id = self.subscribe("standard", "monthly")
        self.assertEqual(self.submit(cookie, ws, 5000, mode="standard")[0], 200)
        before = self.usage(ws)
        self.assertEqual(before["loc_used"], 5000)
        self.deliver(self.stripe.renew(sub_id))
        after = self.usage(ws)
        self.assertGreater(after["period_start"], before["period_start"])
        self.assertEqual((after["loc_used"], after["loc_limit"]), (0, 20000))
        self.assertEqual(self.entitlement(ws)["status"], "active")

    def test_an_annual_subscription_gets_twelve_monthly_allowances_without_rollover(self):
        cookie, ws, sub_id = self.subscribe("pro", "annual")
        self.assertEqual(self.submit(cookie, ws, 1000, mode="pro")[0], 200)
        ent = self.entitlement(ws)
        anchor = repo._parse_iso(ent["current_period_start"])
        month1 = self.usage(ws, now=anchor + timedelta(days=1))
        month2 = self.usage(ws, now=anchor + timedelta(days=40))
        month12 = self.usage(ws, now=anchor + timedelta(days=340))
        self.assertEqual((month1["loc_used"], month1["loc_limit"]), (1000, 60000))
        self.assertEqual((month2["loc_used"], month2["loc_limit"]), (0, 60000))            # unused allowance does not roll over
        self.assertEqual(len({month1["period_start"], month2["period_start"], month12["period_start"]}), 3)
        self.assertEqual(ent["current_period_end"], billing.stripe_timestamp_to_iso(self.stripe.subscriptions_store[sub_id]["items"]["data"][0]["current_period_end"]))

    def test_payment_failure_blocks_scans_until_the_payment_succeeds(self):
        cookie, ws, sub_id = self.subscribe("standard", "monthly")
        self.assertEqual(self.deliver(self.stripe.renew(sub_id, paid=False)), ["applied:subscription_past_due"] * 2)
        self.assertEqual(self.entitlement(ws)["status"], "past_due")
        self.assertEqual(self.submit(cookie, ws, 100, mode="standard")[0], 402)
        self.assertEqual(self.checkout(cookie, ws, "pro", "monthly", expect=409)["error"], "this workspace already has an active subscription")
        self.deliver(self.stripe.renew(sub_id, paid=True))
        self.assertEqual(self.entitlement(ws)["status"], "active")
        self.assertEqual(self.submit(cookie, ws, 100, mode="standard")[0], 200)

    def test_cancellation_revokes_access_and_a_new_subscription_can_follow(self):
        cookie, ws, sub_id = self.subscribe("standard", "annual")
        self.assertEqual(self.deliver(self.stripe.cancel(sub_id)), ["applied:subscription_canceled"])
        self.assertEqual(self.entitlement(ws)["status"], "canceled")
        self.assertEqual(self.submit(cookie, ws, 100, mode="standard")[0], 402)
        session_id = self.checkout(cookie, ws, "pro", "monthly")
        self.deliver(self.stripe.pay_checkout(session_id))
        ent = self.entitlement(ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"]), ("pro", "active", self.stripe.sessions[session_id]["subscription"]))
        self.assertEqual(self.deliver(self.stripe.events_since(0)[:4]), ["ignored:duplicate"] * 4)   # replays of the first purchase

    def test_a_portal_plan_change_updates_plan_interval_and_quota(self):
        cookie, ws, sub_id = self.subscribe("standard", "monthly")
        self.deliver(self.stripe.change_price(sub_id, SANDBOX_PRICE_IDS["vericexa_pro_annual"]))
        ent = self.entitlement(ws)
        self.assertEqual((ent["plan"], ent["billing_interval"], self.usage(ws)["loc_limit"]), ("pro", "annual", 60000))
        self.assertEqual(self.deliver(self.stripe.change_price(sub_id, "price_not_in_catalog")), ["rejected:unknown_price"])
        self.assertEqual(self.entitlement(ws)["plan"], "pro")

    def test_a_stripe_outage_answers_500_and_the_redelivery_applies(self):
        cookie, ws, _ = self.owner()
        session_id = self.checkout(cookie, ws, "standard", "monthly")
        events = self.stripe.pay_checkout(session_id)
        self.stripe.fail_next_retrieves = 1
        status, _, _ = self.post_webhook(events[1], secret=WEBHOOK_SECRET)
        self.assertEqual(status, 500)
        row = billing_tests._fetch_webhook_event(self.db(), events[1]["id"])
        self.assertEqual((row["processed_at"], row["processing_error"]), (None, "APIConnectionError"))
        self.assertEqual(self.deliver([events[1]]), ["applied:subscription_active"])        # Stripe's retry of the same event id
        self.assertEqual(self.entitlement(ws)["status"], "active")
        self.assertEqual(self.alerts.events[0][1:], ("error", {"event_type": "customer.subscription.updated", "error_type": "APIConnectionError"}))


class BindingSecurityTests(_StripeE2ETestCase):
    def test_a_subscription_not_created_by_this_backend_is_rejected(self):
        _, ws, _ = self.owner()
        foreign = {"id": "sub_foreign", "object": "subscription", "customer": "cus_foreign", "status": "active", "metadata": {"workspace_id": ws},
                   "items": self.stripe._subscription_items(SANDBOX_PRICE_IDS["vericexa_pro_annual"], self.stripe.now)}
        self.stripe.subscriptions_store["sub_foreign"] = foreign
        self.assertEqual(self.deliver([self.stripe.emit("customer.subscription.created", foreign)]), ["rejected:unbound_subscription"])
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(self.alerts.events[-1][1:], ("warning", {"event_type": "customer.subscription.created", "error_type": "rejected:unbound_subscription"}))

    def test_events_naming_another_workspace_are_rejected(self):
        cookie, ws, _ = self.owner()
        _, other_ws, _ = self.owner()
        session_id = self.checkout(cookie, ws, "standard", "monthly")
        events = self.stripe.pay_checkout(session_id)
        tampered = json.loads(json.dumps(events[3]))                                      # checkout.session.completed
        tampered["id"] = "evt_tampered_1"
        tampered["data"]["object"]["client_reference_id"] = other_ws
        self.assertEqual(self.deliver([tampered]), ["rejected:workspace_mismatch"])
        sub_id = self.stripe.sessions[session_id]["subscription"]
        self.stripe.subscriptions_store[sub_id]["metadata"]["workspace_id"] = other_ws    # subscription now claims the other workspace
        self.assertEqual(set(self.deliver(events[:3])), {"rejected:workspace_mismatch"})
        self.assertIsNone(self.entitlement(ws))
        self.assertIsNone(self.entitlement(other_ws))

    def test_a_customer_mismatch_is_rejected(self):
        cookie, ws, _ = self.owner()
        quick = self.checkout(cookie, ws, "quick")
        self.deliver(self.stripe.pay_checkout(quick))
        customer = self.entitlement(ws)["stripe_customer_id"]
        self.assertEqual(self.submit(cookie, ws, 10)[0], 200)                             # use the Quick scan
        session_id = self.checkout(cookie, ws, "standard", "monthly")
        self.assertEqual(self.stripe.checkout.sessions.calls[-1]["customer"], customer)   # the workspace's customer is reused
        events = self.stripe.pay_checkout(session_id)
        self.stripe.subscriptions_store[self.stripe.sessions[session_id]["subscription"]]["customer"] = "cus_somebody_else"
        self.assertEqual(set(self.deliver(events[:3])), {"rejected:customer_mismatch"})
        self.assertEqual(self.entitlement(ws)["plan"], "quick")

    def test_a_subscription_mismatch_is_rejected(self):
        cookie, ws, sub_id = self.subscribe("standard", "monthly")
        session_id = [s for s in self.stripe.sessions][-1]
        completed = json.loads(json.dumps(self.stripe.emitted[3]))
        completed["id"] = "evt_other_sub"
        completed["data"]["object"]["subscription"] = "sub_some_other"
        self.assertEqual(self.deliver([completed]), ["rejected:subscription_mismatch"])
        self.assertEqual(repo.get_checkout_session(self.db(), session_id)["stripe_subscription_id"], sub_id)

    def test_a_second_live_subscription_is_refused_until_the_first_is_really_gone(self):
        cookie, ws, first_sub = self.subscribe("standard", "monthly")
        conn = self.db()
        # Two Checkouts paid in parallel (HTTP checkout refuses the 2nd one; the
        # ledger row is made directly to model a race).
        customer = self.entitlement(ws)["stripe_customer_id"]
        second = self.billing.create_checkout_session("pro", "monthly", ws, "https://a/ok", "https://a/no", customer_id=customer)
        repo.record_checkout_session(conn, second["id"], ws, repo.get_workspace(conn, ws)["owner_user_id"], "pro", "monthly",
                                     SANDBOX_PRICE_IDS["vericexa_pro_monthly"], "subscription", customer)
        conn.commit()
        events = self.stripe.pay_checkout(second["id"])
        self.assertIn("rejected:duplicate_subscription", self.deliver(events))
        self.assertEqual(self.entitlement(ws)["stripe_subscription_id"], first_sub)
        # once Stripe really cancels the first one (refund), the second takes over
        self.stripe.subscriptions_store[first_sub]["status"] = "canceled"
        retry = self.stripe.emit("customer.subscription.updated", self.stripe.subscriptions_store[self.stripe.sessions[second["id"]]["subscription"]])
        self.assertEqual(self.deliver([retry]), ["applied:subscription_active"])
        self.assertEqual(self.entitlement(ws)["plan"], "pro")

    def test_late_events_of_an_old_subscription_never_override_the_current_state(self):
        cookie, ws, sub_id = self.subscribe("standard", "monthly")
        deleted = self.stripe.cancel(sub_id)
        self.deliver(deleted)
        quick = self.checkout(cookie, ws, "quick")
        self.deliver(self.stripe.pay_checkout(quick))
        late = [dict(e, id=e["id"] + "_late") for e in self.stripe.emitted[:4] + deleted]   # old burst + deletion redelivered later
        outcomes = self.deliver(late)
        self.assertTrue(all(o.startswith("ignored:") for o in outcomes), outcomes)
        ent = self.entitlement(ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"]), ("quick", "active", None))
        self.assertEqual(self.usage(ws)["scans_available"], 1)

    def test_unknown_or_malformed_workspaces_are_rejected_without_a_500(self):
        for i, claimed in enumerate(("00000000-0000-0000-0000-000000000000", "not-a-uuid", "")):
            sub = {"id": "sub_ghost_%d" % i, "customer": "cus_g", "status": "active", "metadata": {"workspace_id": claimed},
                   "items": self.stripe._subscription_items(SANDBOX_PRICE_IDS["vericexa_standard_monthly"], self.stripe.now)}
            self.stripe.subscriptions_store[sub["id"]] = sub
            expected = "ignored:subscription_without_workspace" if not claimed else "rejected:unknown_workspace"
            self.assertEqual(self.deliver([self.stripe.emit("customer.subscription.updated", sub)]), [expected])
        invoice = self.stripe.emit("invoice.paid", {"id": "in_one_off", "customer": "cus_g"})
        self.assertEqual(self.deliver([invoice]), ["ignored:not_a_subscription_invoice"])

    def test_a_mode_mismatch_between_event_and_checkout_is_rejected(self):
        cookie, ws, _ = self.owner()
        session_id = self.checkout(cookie, ws, "standard", "monthly")
        events = self.stripe.pay_checkout(session_id)
        forged = json.loads(json.dumps(events[3]))
        forged["id"] = "evt_mode"
        forged["data"]["object"]["mode"] = "payment"
        forged["data"]["object"]["payment_status"] = "paid"
        self.assertEqual(self.deliver([forged]), ["rejected:mode_mismatch"])
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
