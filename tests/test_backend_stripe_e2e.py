"""Stripe billing end-to-end, automated (docs/decisiones.md D-115).

The whole chain through the REAL HTTP server (SQLite): checkout (real
handler, the Sandbox Price IDs of docs/staging-config.md) -> what Stripe
would do (a small simulator over the tests' fake Stripe client: the
Checkout Session's line items, the subscription it creates, renewals,
failed payments, cancellations) -> SIGNED webhooks (real signature
verification) -> entitlement -> scan admission -> quota/credit consumption.

What this cannot prove - and docs/stripe-sandbox-e2e.md runs against real
Stripe Sandbox - is Stripe's own behaviour: the hosted Checkout page, real
event payload shapes and timing, Stripe-generated signatures.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.billing as billing  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.repository as repo  # noqa: E402
import tests.test_backend_billing as billing_tests  # noqa: E402
from tests.test_backend_commercial import SANDBOX_PRICE_IDS, _sol  # noqa: E402
from tests.test_backend_http_app import HOST, _CapturingEmailSender, _HttpAppTestCase  # noqa: E402

DAY = 86400


class StripeSimulator:
    """What Stripe Sandbox does after a Checkout, over the fake client:
    Stripe's current state lives in the fake's stores, events are
    built like Stripe's (same object shapes the handler reads)."""

    def __init__(self, client):
        self.client = client
        self.counter = 0

    def complete_checkout(self, params, session_id, status="active", period_start=None, quantity=1, paid_price=None):
        """Pays checkout `params` (as sent to Stripe by the backend).
        Returns (session object, subscription object or None)."""
        self.counter += 1
        price = paid_price or params["line_items"][0]["price"]
        self.client.checkout.sessions.line_items.store[session_id] = [(price, quantity)]
        session = {"id": session_id, "object": "checkout.session", "mode": params["mode"], "payment_status": "paid", "status": "complete",
                   "client_reference_id": params["client_reference_id"], "customer": "cus_sim_%d" % self.counter, "metadata": dict(params["metadata"])}
        if params["mode"] != "subscription":
            return session, None
        start = period_start if period_start is not None else int(time.time())
        interval = params["metadata"]["interval"]
        subscription = {"id": "sub_sim_%d" % self.counter, "object": "subscription", "customer": session["customer"], "status": status,
                        "cancel_at_period_end": False, "metadata": dict(params["subscription_data"]["metadata"]),
                        "items": {"data": [{"price": {"id": price}, "current_period_start": start,
                                            "current_period_end": start + (365 if interval == "annual" else 30) * DAY}]}}
        self.client.subscriptions.store[subscription["id"]] = subscription
        session["subscription"] = subscription["id"]
        return session, subscription

    def update(self, subscription, **changes):
        subscription = json.loads(json.dumps(subscription))
        for key, value in changes.items():
            if key == "period_start":
                item = subscription["items"]["data"][0]
                item["current_period_end"] = value + (item["current_period_end"] - item["current_period_start"])
                item["current_period_start"] = value
            else:
                subscription[key] = value
        self.client.subscriptions.store[subscription["id"]] = subscription
        return subscription

    @staticmethod
    def invoice(subscription):
        return {"object": "invoice", "customer": subscription["customer"],
                "parent": {"subscription_details": {"subscription": subscription["id"], "metadata": dict(subscription["metadata"])}}}


class _StripeE2ECase(_HttpAppTestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed = repo.connect(self.db_path)
        repo.init_schema(seed)
        seed.close()
        self.storage_dir = tempfile.mkdtemp(prefix="stripe-e2e-")
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="test-only-secret")
        self.email_sender = _CapturingEmailSender()
        self.billing = billing_tests._make_billing(dict(SANDBOX_PRICE_IDS))
        self.stripe = StripeSimulator(self.billing._client)
        self.httpd = http_app.run_server(connect_fn=lambda: repo.connect(self.db_path), email_sender=self.email_sender, host_allowlist=[HOST],
                                         host=HOST, port=0, secure_cookies=False, storage=self.storage, billing=self.billing,
                                         max_pending_jobs_per_workspace=20, submit_rate_limit_per_window=200)
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.05)
        self.addCleanup(lambda: shutil.rmtree(self.storage_dir, ignore_errors=True))
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)
        self.events = 0

    # -- helpers -----------------------------------------------------------
    def owner(self, email):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        ws = repo.create_workspace(conn, "Billing WS", repo.get_user_by_email(conn, email)["id"])
        conn.close()
        return cookie, ws

    def checkout(self, cookie, ws, plan, interval):
        status, _, body = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": plan, "interval": interval, "success_path": "/app#/billing"},
                                         headers={"Cookie": cookie})
        return status, json.loads(body)

    def last_checkout(self):
        sessions = self.billing._client.checkout.sessions
        return sessions.calls[-1], "cs_test_%d" % len(sessions.calls)

    def event(self, event_type, obj, created=None, event_id=None):
        self.events += 1
        return {"id": event_id or "evt_e2e_%d" % self.events, "type": event_type, "created": created or int(time.time()), "data": {"object": obj}}

    def deliver(self, event, secret=None, raw=None, signature=None):
        body = raw if raw is not None else json.dumps(event).encode()
        header = signature if signature is not None else billing_tests._stripe_signature_header(body, secret or billing_tests.WEBHOOK_SECRET)
        conn = self._conn()
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body)), "Host": self.host_header}
        if header:
            headers["Stripe-Signature"] = header
        conn.request("POST", "/billing/webhook", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else None

    def subscribe(self, cookie, ws, plan, interval, period_start=None, shuffle_seed=0):
        """Checkout + the event burst Stripe really sends for a paid
        subscription checkout - all in the SAME second, in a shuffled
        delivery order. Returns the subscription."""
        status, body = self.checkout(cookie, ws, plan, interval)
        self.assertEqual(status, 200, body)
        params, session_id = self.last_checkout()
        session, sub = self.stripe.complete_checkout(params, session_id, period_start=period_start)
        incomplete = dict(sub, status="incomplete")
        second = int(time.time())
        burst = [self.event("customer.subscription.created", incomplete, second), self.event("invoice.paid", self.stripe.invoice(sub), second),
                 self.event("customer.subscription.updated", sub, second), self.event("checkout.session.completed", session, second)]
        random.Random(shuffle_seed).shuffle(burst)
        for event in burst:
            self.assertEqual(self.deliver(event)[0], 200)
        return sub

    def entitlement(self, ws):
        conn = repo.connect(self.db_path)
        try:
            return repo.get_entitlement_by_workspace(conn, ws)
        finally:
            conn.close()

    def submit(self, cookie, ws, loc, mode="quick"):
        status, _, body = self.post_json("/workspaces/%s/jobs" % ws, {"mode": mode, "source": _sol(loc)}, headers={"Cookie": cookie})
        return status, json.loads(body)

    def usage(self, cookie, ws):
        return json.loads(self.get("/workspaces/%s" % ws, headers={"Cookie": cookie})[2])["usage"]

    def credits(self, ws):
        conn = repo.connect(self.db_path)
        try:
            return conn.execute("SELECT COUNT(*) FROM scan_credits WHERE workspace_id = ?", (ws,)).fetchone()[0]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Quick: one-time payment -> exactly one scan
# ---------------------------------------------------------------------------

class QuickE2ETests(_StripeE2ECase):
    def test_checkout_payment_credit_scan_and_second_scan_refused(self):
        cookie, ws = self.owner("q-e2e@example.com")
        status, body = self.checkout(cookie, ws, "quick", "one_time")
        self.assertEqual((status, body["checkout_url"]), (200, "https://checkout.stripe.test/fake"))
        params, session_id = self.last_checkout()
        self.assertEqual((params["mode"], params["line_items"], params["client_reference_id"]),
                         ("payment", [{"price": SANDBOX_PRICE_IDS["vericexa_quick_onetime"], "quantity": 1}], ws))
        self.assertNotIn("subscription_data", params)
        # Returning to success_url grants nothing: only the webhook does.
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(self.submit(cookie, ws, 10)[0], 402)
        session, _ = self.stripe.complete_checkout(params, session_id)
        self.assertEqual(self.deliver(self.event("checkout.session.completed", session))[0], 200)
        ent = self.entitlement(ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"]), ("quick", "active", None))
        self.assertEqual(self.usage(cookie, ws)["scans_available"], 1)
        self.assertEqual(self.submit(cookie, ws, 3001)[1]["error"], "loc_per_scan_limit_exceeded")    # 3K per scan
        status, body = self.submit(cookie, ws, 3000)
        self.assertEqual(status, 200, body)
        status, body = self.submit(cookie, ws, 10)
        self.assertEqual((status, body["error"]), (402, "no_scan_credit"))
        self.assertEqual(self.credits(ws), 1)

    def test_credit_granted_exactly_once_whatever_is_redelivered(self):
        cookie, ws = self.owner("q-once@example.com")
        self.checkout(cookie, ws, "quick", "one_time")
        params, session_id = self.last_checkout()
        session, _ = self.stripe.complete_checkout(params, session_id)
        first = self.event("checkout.session.completed", session)
        results, barrier = [], threading.Barrier(8)

        def deliver(event):
            barrier.wait()
            results.append(self.deliver(event)[0])

        events = [first] * 4 + [self.event("checkout.session.async_payment_succeeded", session) for _ in range(4)]   # same event.id x4, same session x4
        threads = [threading.Thread(target=deliver, args=(e,)) for e in events]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertTrue(all(code == 200 for code in results), results)
        self.assertEqual(self.credits(ws), 1)
        self.assertEqual(self.usage(cookie, ws)["scans_available"], 1)

    def test_unpaid_or_wrong_price_quick_session_grants_nothing(self):
        cookie, ws = self.owner("q-wrong@example.com")
        self.checkout(cookie, ws, "quick", "one_time")
        params, session_id = self.last_checkout()
        session, _ = self.stripe.complete_checkout(params, session_id)
        self.deliver(self.event("checkout.session.completed", dict(session, payment_status="unpaid")))
        session_std, _ = self.stripe.complete_checkout(params, "cs_wrong_price", paid_price=SANDBOX_PRICE_IDS["vericexa_standard_monthly"])
        self.deliver(self.event("checkout.session.completed", session_std))
        session_two, _ = self.stripe.complete_checkout(params, "cs_two_units", quantity=2)
        self.deliver(self.event("checkout.session.completed", session_two))
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(self.credits(ws), 0)


# ---------------------------------------------------------------------------
# Standard / Pro: subscription -> entitlement -> per-scan limit -> quota
# ---------------------------------------------------------------------------

class SubscriptionE2ETests(_StripeE2ECase):
    CASES = (("standard", "monthly", 10000, 20000), ("standard", "annual", 10000, 20000), ("pro", "monthly", 20000, 60000), ("pro", "annual", 20000, 60000))

    def test_activation_for_every_plan_and_interval(self):
        for seed, (plan, interval, per_scan, quota) in enumerate(self.CASES):
            with self.subTest(plan=plan, interval=interval):
                cookie, ws = self.owner("%s-%s@example.com" % (plan, interval))
                sub = self.subscribe(cookie, ws, plan, interval, shuffle_seed=seed)
                params, _ = self.last_checkout()
                self.assertEqual((params["mode"], params["line_items"][0]["price"], params["subscription_data"]["metadata"]["workspace_id"]),
                                 ("subscription", SANDBOX_PRICE_IDS["vericexa_%s_%s" % (plan, interval)], ws))
                ent = self.entitlement(ws)
                self.assertEqual((ent["plan"], ent["billing_interval"], ent["status"], ent["stripe_subscription_id"]), (plan, interval, "active", sub["id"]))
                status, body = self.submit(cookie, ws, per_scan + 1, mode=plan)
                self.assertEqual((status, body["error"]), (413, "loc_per_scan_limit_exceeded"))
                status, body = self.submit(cookie, ws, per_scan, mode=plan)
                self.assertEqual(status, 200, body)
                usage = self.usage(cookie, ws)
                self.assertEqual((usage["loc_used"], usage["loc_limit"], usage["billing_interval"]), (per_scan, quota, interval))
                # Exhaust the service month: no overage.
                while usage["loc_remaining"] >= per_scan:
                    self.assertEqual(self.submit(cookie, ws, per_scan, mode=plan)[0], 200)
                    usage = self.usage(cookie, ws)
                status, body = self.submit(cookie, ws, usage["loc_remaining"] + 1, mode=plan)
                self.assertEqual((status, body["error"]), (402, "loc_quota_exceeded"))
                # A second subscription cannot be bought on top.
                self.assertEqual(self.checkout(cookie, ws, plan, interval)[0], 409)

    def test_monthly_renewal_resets_the_quota_without_rollover(self):
        cookie, ws = self.owner("renew-monthly@example.com")
        start = datetime(2026, 1, 15, tzinfo=timezone.utc)
        sub = self.subscribe(cookie, ws, "standard", "monthly", period_start=int(start.timestamp()))
        conn = repo.connect(self.db_path)
        ent = repo.get_entitlement_by_workspace(conn, ws)
        contract = repo.create_contract(conn, ws, "s3://x", "h", "n")
        repo.enqueue_job_with_usage(conn, ws, contract, repo.get_user_by_email(conn, "renew-monthly@example.com")["id"], "standard", None, ent, 5000,
                                    now=start + timedelta(days=3))
        self.assertEqual(repo.usage_summary(conn, ws, ent, now=start + timedelta(days=3))["loc_remaining"], 15000)
        conn.close()
        # Renewal: Stripe moves the period, pays the invoice, sends both.
        renewed = self.stripe.update(sub, period_start=int(datetime(2026, 2, 15, tzinfo=timezone.utc).timestamp()))
        self.assertEqual(self.deliver(self.event("invoice.paid", self.stripe.invoice(renewed)))[0], 200)
        self.assertEqual(self.deliver(self.event("customer.subscription.updated", renewed))[0], 200)
        conn = repo.connect(self.db_path)
        ent = repo.get_entitlement_by_workspace(conn, ws)
        self.assertTrue(ent["current_period_start"].startswith("2026-02-15"))
        new_month = repo.usage_summary(conn, ws, ent, now=datetime(2026, 2, 16, tzinfo=timezone.utc))
        self.assertEqual((new_month["loc_used"], new_month["loc_remaining"], new_month["loc_limit"]), (0, 20000, 20000))   # reset, never 35000
        conn.close()

    def test_annual_keeps_a_monthly_quota_without_rollover(self):
        cookie, ws = self.owner("annual-quota@example.com")
        start = datetime(2026, 1, 31, tzinfo=timezone.utc)
        self.subscribe(cookie, ws, "pro", "annual", period_start=int(start.timestamp()))
        conn = repo.connect(self.db_path)
        ent = repo.get_entitlement_by_workspace(conn, ws)
        user = repo.get_user_by_email(conn, "annual-quota@example.com")["id"]
        contract = repo.create_contract(conn, ws, "s3://x", "h", "n")
        repo.enqueue_job_with_usage(conn, ws, contract, user, "pro", None, ent, 20000, now=start + timedelta(days=1))
        month1 = repo.usage_summary(conn, ws, ent, now=start + timedelta(days=1))
        self.assertEqual((month1["loc_used"], month1["loc_limit"]), (20000, 60000))
        month2 = repo.usage_summary(conn, ws, ent, now=datetime(2026, 3, 1, tzinfo=timezone.utc))     # 28-Feb boundary (day clamp)
        self.assertEqual((month2["loc_used"], month2["loc_remaining"], month2["period_start"][:10]), (0, 60000, "2026-02-28"))
        month12 = repo.usage_summary(conn, ws, ent, now=datetime(2026, 12, 31, 12, tzinfo=timezone.utc))
        self.assertEqual((month12["loc_used"], month12["loc_limit"]), (0, 60000))                    # never 720K up front
        conn.close()


# ---------------------------------------------------------------------------
# Failed payment, cancellation, duplicates, replay, isolation, signatures
# ---------------------------------------------------------------------------

class LifecycleE2ETests(_StripeE2ECase):
    def test_payment_failed_blocks_scans_and_paying_restores(self):
        cookie, ws = self.owner("failed@example.com")
        sub = self.subscribe(cookie, ws, "standard", "monthly")
        past_due = self.stripe.update(sub, status="past_due")
        self.assertEqual(self.deliver(self.event("invoice.payment_failed", self.stripe.invoice(past_due)))[0], 200)
        self.assertEqual(self.entitlement(ws)["status"], "past_due")
        status, body = self.submit(cookie, ws, 10, mode="standard")
        self.assertEqual((status, body["error"]), (402, "this workspace has no active subscription"))
        self.assertEqual(self.checkout(cookie, ws, "pro", "monthly")[0], 409)            # fix the payment in the portal, no 2nd subscription
        self.assertEqual(self.post_json("/billing/portal", {"workspace_id": ws}, headers={"Cookie": cookie})[0], 200)
        active = self.stripe.update(past_due, status="active")
        self.deliver(self.event("invoice.paid", self.stripe.invoice(active)))
        self.assertEqual(self.submit(cookie, ws, 10, mode="standard")[0], 200)

    def test_cancellation_at_period_end_then_deleted(self):
        cookie, ws = self.owner("cancel@example.com")
        sub = self.subscribe(cookie, ws, "pro", "annual")
        ending = self.stripe.update(sub, cancel_at_period_end=True)                     # canceled in the portal: access until period end
        self.deliver(self.event("customer.subscription.updated", ending))
        self.assertEqual(self.entitlement(ws)["status"], "active")
        self.assertEqual(self.submit(cookie, ws, 10, mode="pro")[0], 200)
        canceled = self.stripe.update(ending, status="canceled")
        self.assertEqual(self.deliver(self.event("customer.subscription.deleted", canceled))[0], 200)
        self.assertEqual(self.entitlement(ws)["status"], "canceled")
        self.assertEqual(self.submit(cookie, ws, 10, mode="pro")[0], 402)
        self.assertEqual(self.checkout(cookie, ws, "standard", "monthly")[0], 200)      # may subscribe again

    def test_duplicate_and_replayed_webhooks_change_nothing(self):
        cookie, ws = self.owner("replay@example.com")
        sub = self.subscribe(cookie, ws, "standard", "monthly")
        activation = self.event("customer.subscription.updated", sub, event_id="evt_activation")
        self.assertEqual(self.deliver(activation)[1].get("duplicate"), None)
        self.assertEqual(self.deliver(activation)[1].get("duplicate"), True)              # same event.id: never reprocessed
        canceled = self.stripe.update(sub, status="canceled")
        self.deliver(self.event("customer.subscription.deleted", canceled))
        self.assertEqual(self.deliver(activation)[1].get("duplicate"), True)
        old = self.event("customer.subscription.updated", sub)                           # a NEW id carrying the old payload (stale delivery)
        self.assertEqual(self.deliver(old)[0], 200)
        self.assertEqual(self.entitlement(ws)["status"], "canceled")                     # Stripe's current state wins

    def test_concurrent_subscription_events_are_idempotent(self):
        cookie, ws = self.owner("concurrent@example.com")
        status, _ = self.checkout(cookie, ws, "pro", "monthly")
        params, session_id = self.last_checkout()
        session, sub = self.stripe.complete_checkout(params, session_id)
        events = ([self.event("customer.subscription.created", dict(sub, status="incomplete"), 1_900_000_000) for _ in range(3)]
                  + [self.event("customer.subscription.updated", sub, 1_900_000_000) for _ in range(3)]
                  + [self.event("checkout.session.completed", session, 1_900_000_000) for _ in range(3)]
                  + [self.event("invoice.paid", self.stripe.invoice(sub), 1_900_000_000) for _ in range(3)])
        results, barrier = [], threading.Barrier(len(events))

        def deliver(event):
            barrier.wait()
            results.append(self.deliver(event)[0])

        threads = [threading.Thread(target=deliver, args=(e,)) for e in events]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        self.assertEqual(results, [200] * len(events))
        ent = self.entitlement(ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"]), ("pro", "active", sub["id"]))
        conn = repo.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entitlements").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)
        conn.close()

    def test_wrong_price_or_plan_never_grants(self):
        cookie, ws = self.owner("wrong-price@example.com")
        self.checkout(cookie, ws, "standard", "monthly")
        params, session_id = self.last_checkout()
        for i, price in enumerate((SANDBOX_PRICE_IDS["vericexa_quick_onetime"], "price_1OLD_d086_standard_monthly", "price_other_product")):
            session, sub = self.stripe.complete_checkout(params, "%s_%d" % (session_id, i), paid_price=price)
            self.deliver(self.event("customer.subscription.created", sub))
            self.deliver(self.event("checkout.session.completed", session))
        self.assertIsNone(self.entitlement(ws))
        self.assertEqual(self.submit(cookie, ws, 10, mode="standard")[0], 402)
        self.assertEqual(self.checkout(cookie, ws, "enterprise", "monthly")[0], 400)

    def test_cross_workspace_isolation(self):
        cookie_a, ws_a = self.owner("iso-a@example.com")
        cookie_b, ws_b = self.owner("iso-b@example.com")
        self.assertEqual(self.checkout(cookie_a, ws_b, "pro", "monthly")[0], 403)          # cannot buy for someone else's workspace
        sub_b = self.subscribe(cookie_b, ws_b, "pro", "monthly")
        self.assertIsNone(self.entitlement(ws_a))
        self.checkout(cookie_a, ws_a, "standard", "monthly")
        params, session_id = self.last_checkout()
        session, _ = self.stripe.complete_checkout(params, session_id)
        forged = dict(session, subscription=sub_b["id"])                                    # A's session pointing at B's subscription
        self.deliver(self.event("checkout.session.completed", forged))
        self.assertEqual(self.entitlement(ws_b)["stripe_subscription_id"], sub_b["id"])
        self.assertIsNone(self.entitlement(ws_a))
        self.assertEqual(self.submit(cookie_a, ws_a, 10, mode="standard")[0], 402)

    def test_signature_failures_change_nothing(self):
        cookie, ws = self.owner("sig@example.com")
        self.checkout(cookie, ws, "quick", "one_time")
        params, session_id = self.last_checkout()
        session, _ = self.stripe.complete_checkout(params, session_id)
        event = self.event("checkout.session.completed", session, event_id="evt_sig")
        body = json.dumps(event).encode()
        good = billing_tests._stripe_signature_header(body, billing_tests.WEBHOOK_SECRET)
        self.assertEqual(self.deliver(event, secret="whsec_wrong")[0], 400)
        self.assertEqual(self.deliver(event, raw=body.replace(ws.encode(), b"00000000-0000-0000-0000-000000000000"), signature=good)[0], 400)
        self.assertEqual(self.deliver(event, signature="")[0], 400)
        self.assertEqual(self.deliver(event, signature="t=1,v1=deadbeef")[0], 400)
        old = billing_tests._stripe_signature_header(body, billing_tests.WEBHOOK_SECRET, timestamp=int(time.time()) - 3600)
        self.assertEqual(self.deliver(event, signature=old)[0], 400)                     # outside Stripe's tolerance: replayed capture
        conn = repo.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM webhook_events").fetchone()[0], 0)
        conn.close()
        self.assertEqual(self.credits(ws), 0)
        self.assertEqual(self.deliver(event)[0], 200)
        self.assertEqual(self.credits(ws), 1)

    def test_client_cannot_grant_capacity(self):
        cookie, ws = self.owner("client@example.com")
        status, _ = self.checkout(cookie, ws, "quick", "one_time")
        self.assertEqual(status, 200)
        payload = {"workspace_id": ws, "plan": "standard", "interval": "monthly", "price": SANDBOX_PRICE_IDS["vericexa_pro_annual"],
                   "status": "active", "customer": "cus_attacker", "success_path": "https://evil.example/steal"}
        self.post_json("/billing/checkout", payload, headers={"Cookie": cookie})
        params, _ = self.last_checkout()
        self.assertEqual(params["line_items"][0]["price"], SANDBOX_PRICE_IDS["vericexa_standard_monthly"])
        self.assertNotIn("customer", params)
        self.assertTrue(params["success_url"].startswith("http://%s/" % self.host_header))
        self.assertIsNone(self.entitlement(ws))                                             # starting a checkout grants nothing


if __name__ == "__main__":
    unittest.main()
