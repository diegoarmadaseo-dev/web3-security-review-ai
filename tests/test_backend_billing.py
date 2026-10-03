"""Tests for backend/billing.py (Phase 3 Stripe billing layer,
docs/decisiones.md D-077 follow-up) and the three /billing/* routes it
wires into backend/http_app.py.

No live Stripe credentials or network access anywhere in this file:
  * backend.billing.StripeBilling.create_checkout_session()/
    create_portal_session() are tested against a local
    _FakeStripeClient double (tests/stripe_simulator.py) (swapped in for the real
    stripe.StripeClient AFTER construction - construction itself never
    makes a network call) rather than mocking the SDK's internals.
  * Webhook signature verification is tested against REAL HMAC-SHA256
    signatures computed locally by _stripe_signature_header() (the same
    algorithm stripe.Webhook.construct_event() itself uses, confirmed by
    reading stripe._webhook.WebhookSignature.verify_header()'s source -
    this needs no network either, since HMAC verification is pure local
    computation).

Two layers of tests:
  * pure backend.billing unit tests (no HTTP) - price resolution,
    checkout/portal param construction, signature verification edge
    cases, the "stripe not installed" degradation path;
  * end-to-end HTTP tests via a real running server (same http.client
    convention tests/test_backend_http_app.py already established),
    reusing that file's _HttpAppTestCase for every request helper and
    only overriding setUp() to also wire in a configured StripeBilling.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import backend.billing as billing
import backend.db as db
import backend.http_app as http_app
import backend.plans as plans
import backend.repository as repo
import backend.tenant_scope as tenant_scope
from tests.stripe_simulator import StripeSimulator
from tests.test_backend_http_app import HOST, _CapturingEmailSender, _HttpAppTestCase

WEBHOOK_SECRET = "whsec_test_fake_secret_for_billing_tests"
# D-107: the Launch catalog's 5 price modes (backend/plans.py).
PRICE_ALLOWLIST = {
    key: "price_%s_%s_test" % (mode["plan"], mode["interval"])
    for key, mode in plans.PRICE_MODES.items()
}
BF_PROMOTION_CODE_ID = "promo_bf_test"


def _stripe_signature_header(payload: bytes, secret: str, timestamp: Optional[int] = None) -> str:
    """The same algorithm stripe.Webhook.construct_event() verifies
    against (confirmed by reading stripe._webhook.WebhookSignature.
    verify_header()'s source): HMAC-SHA256 over "{timestamp}.{body}",
    formatted as "t=<timestamp>,v1=<hex signature>". Pure local
    computation - no network, no real Stripe credentials."""
    ts = int(time.time()) if timestamp is None else timestamp
    signed_payload = ("%d." % ts).encode("ascii") + payload
    signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (ts, signature)


def _FakeStripeClient(price_allowlist: Optional[Dict[str, str]] = None) -> StripeSimulator:
    """Stands in for stripe.StripeClient - a stateful tests/stripe_simulator.
    StripeSimulator swapped into a real StripeBilling instance's `_client`
    attribute after construction (see module docstring). Records every
    checkout/portal create() call (`.calls`) and plays Stripe's side of
    the flow (D-115)."""
    return StripeSimulator(dict(price_allowlist or PRICE_ALLOWLIST))


def _make_billing(price_allowlist: Optional[Dict[str, str]] = None) -> billing.StripeBilling:
    instance = billing.StripeBilling("sk_test_fake", WEBHOOK_SECRET, dict(price_allowlist or PRICE_ALLOWLIST))
    instance._client = _FakeStripeClient()  # no network - see module docstring.
    return instance


def _event(event_type: str, event_id: str, obj: Dict[str, Any], created: Optional[int] = None) -> Dict[str, Any]:
    event: Dict[str, Any] = {"id": event_id, "type": event_type, "livemode": False, "data": {"object": obj}}
    if created is not None:
        event["created"] = created
    return event


def _checkout_session_completed_obj(
    workspace_id: str, plan: str, interval: str = "monthly", customer="cus_test_1", subscription="sub_test_1"
) -> Dict[str, Any]:
    return {
        "client_reference_id": workspace_id,
        "customer": customer,
        "subscription": subscription,
        "metadata": {"workspace_id": workspace_id, "plan": plan, "interval": interval},
    }






def _fetch_webhook_event(conn: Any, event_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT * FROM webhook_events WHERE id = ?", (event_id,))
    return db.normalize_row(cur.fetchone())


# ---------------------------------------------------------------------------
# Pure backend.billing unit tests - no HTTP, no network.
# ---------------------------------------------------------------------------

class PriceResolutionTests(unittest.TestCase):
    def test_allowlisted_plan_interval_resolves_to_its_configured_price_id(self):
        instance = _make_billing()
        self.assertEqual(instance.resolve_price_id("standard", "monthly"), "price_standard_monthly_test")
        self.assertEqual(instance.resolve_price_id("standard", "annual"), "price_standard_annual_test")

    def test_unknown_plan_raises_price_not_allowed(self):
        instance = _make_billing()
        with self.assertRaises(billing.PriceNotAllowedError):
            instance.resolve_price_id("enterprise-unlisted", "monthly")

    def test_unknown_interval_raises_price_not_allowed(self):
        instance = _make_billing()
        with self.assertRaises(billing.PriceNotAllowedError):
            instance.resolve_price_id("quick", "weekly")

    def test_unsold_combinations_raise_price_not_allowed(self):
        # D-107: quick is one-time only; standard/pro have no one-time price.
        instance = _make_billing()
        for plan, interval in (("quick", "monthly"), ("quick", "annual"), ("standard", "one_time"), ("pro", "one_time")):
            with self.assertRaises(billing.PriceNotAllowedError):
                instance.resolve_price_id(plan, interval)

    def test_price_key_maps_to_the_catalog_price_modes(self):
        self.assertEqual(billing.price_key("quick", "one_time"), "vericexa_quick_onetime")
        self.assertEqual(billing.price_key("standard", "monthly"), "vericexa_standard_monthly")
        self.assertEqual(billing.price_key("pro", "annual"), "vericexa_pro_annual")
        self.assertIsNone(billing.price_key("quick", "monthly"))


class MissingStripeSdkTests(unittest.TestCase):
    """Mirrors backend/db.py's missing-psycopg degradation path."""

    def setUp(self):
        self._real_stripe = billing.stripe
        billing.stripe = None
        self.addCleanup(self._restore)

    def _restore(self):
        billing.stripe = self._real_stripe

    def test_constructing_without_stripe_installed_raises_billing_error(self):
        with self.assertRaises(billing.BillingError):
            billing.StripeBilling("sk_test_fake", WEBHOOK_SECRET, dict(PRICE_ALLOWLIST))


class CheckoutSessionCreationTests(unittest.TestCase):
    def test_resolves_plan_and_interval_to_the_allowlisted_price_id_never_a_client_supplied_one(self):
        instance = _make_billing()
        instance.create_checkout_session("standard", "monthly", "ws-1", "https://app.test/success", "https://app.test/cancel")
        params = instance._client.checkout.sessions.calls[0]
        self.assertEqual(params["line_items"], [{"price": "price_standard_monthly_test", "quantity": 1}])

    def test_annual_interval_resolves_to_the_distinct_annual_price_id(self):
        instance = _make_billing()
        instance.create_checkout_session("standard", "annual", "ws-1", "https://app.test/success", "https://app.test/cancel")
        params = instance._client.checkout.sessions.calls[0]
        self.assertEqual(params["line_items"], [{"price": "price_standard_annual_test", "quantity": 1}])

    def test_stamps_workspace_id_plan_and_interval_onto_both_checkout_session_and_subscription_metadata(self):
        instance = _make_billing()
        instance.create_checkout_session("pro", "annual", "ws-42", "https://app.test/success", "https://app.test/cancel")
        params = instance._client.checkout.sessions.calls[0]
        self.assertEqual(params["client_reference_id"], "ws-42")
        self.assertEqual(params["metadata"]["workspace_id"], "ws-42")
        self.assertEqual(params["metadata"]["interval"], "annual")
        self.assertEqual(params["subscription_data"]["metadata"]["workspace_id"], "ws-42")
        self.assertEqual(params["subscription_data"]["metadata"]["plan"], "pro")
        self.assertEqual(params["subscription_data"]["metadata"]["interval"], "annual")

    def test_unknown_plan_raises_before_any_client_call(self):
        instance = _make_billing()
        with self.assertRaises(billing.PriceNotAllowedError):
            instance.create_checkout_session("not-a-real-plan", "monthly", "ws-1", "https://app.test/s", "https://app.test/c")
        self.assertEqual(instance._client.checkout.sessions.calls, [])

    def test_unknown_interval_raises_before_any_client_call(self):
        instance = _make_billing()
        with self.assertRaises(billing.PriceNotAllowedError):
            instance.create_checkout_session("standard", "weekly", "ws-1", "https://app.test/s", "https://app.test/c")
        self.assertEqual(instance._client.checkout.sessions.calls, [])

    def test_existing_customer_id_is_passed_through_never_a_new_customer_email_too(self):
        instance = _make_billing()
        instance.create_checkout_session("standard", "monthly", "ws-1", "https://app.test/s", "https://app.test/c", customer_id="cus_existing")
        params = instance._client.checkout.sessions.calls[0]
        self.assertEqual(params["customer"], "cus_existing")
        self.assertNotIn("customer_email", params)

    def test_returns_a_plain_dict_not_an_sdk_object(self):
        instance = _make_billing()
        result = instance.create_checkout_session("standard", "monthly", "ws-1", "https://app.test/s", "https://app.test/c")
        self.assertIsInstance(result, dict)
        self.assertIn("url", result)

    def test_no_black_friday_promotion_code_means_no_discounts_param_at_all(self):
        instance = _make_billing()
        instance.create_checkout_session("standard", "annual", "ws-1", "https://app.test/s", "https://app.test/c")
        params = instance._client.checkout.sessions.calls[0]
        self.assertNotIn("discounts", params)
        self.assertNotIn("allow_promotion_codes", params)

    def test_black_friday_promotion_code_is_attached_via_discounts_never_allow_promotion_codes(self):
        instance = _make_billing()
        instance.create_checkout_session(
            "standard", "annual", "ws-1", "https://app.test/s", "https://app.test/c",
            black_friday_promotion_code_id=BF_PROMOTION_CODE_ID,
        )
        params = instance._client.checkout.sessions.calls[0]
        self.assertEqual(params["discounts"], [{"promotion_code": BF_PROMOTION_CODE_ID}])
        self.assertNotIn("allow_promotion_codes", params)


class PortalSessionCreationTests(unittest.TestCase):
    def test_sends_the_given_customer_id_and_return_url(self):
        instance = _make_billing()
        instance.create_portal_session("cus_abc", "https://app.test/account")
        params = instance._client.billing_portal.sessions.calls[0]
        self.assertEqual(params["customer"], "cus_abc")
        self.assertEqual(params["return_url"], "https://app.test/account")


class WebhookSignatureVerificationTests(unittest.TestCase):
    def setUp(self):
        self.instance = _make_billing()
        self.payload = json.dumps(_event("checkout.session.completed", "evt_1", _checkout_session_completed_obj("ws-1", "standard"))).encode("utf-8")

    def test_valid_signature_parses_and_returns_the_event_as_a_plain_dict(self):
        header = _stripe_signature_header(self.payload, WEBHOOK_SECRET)
        event = self.instance.verify_and_parse_webhook(self.payload, header)
        self.assertEqual(event["id"], "evt_1")
        self.assertEqual(event["type"], "checkout.session.completed")
        self.assertIsInstance(event, dict)

    def test_missing_signature_header_is_rejected(self):
        with self.assertRaises(billing.WebhookVerificationError):
            self.instance.verify_and_parse_webhook(self.payload, "")

    def test_tampered_payload_after_signing_is_rejected(self):
        header = _stripe_signature_header(self.payload, WEBHOOK_SECRET)
        tampered = self.payload.replace(b"ws-1", b"ws-EVIL")
        with self.assertRaises(billing.WebhookVerificationError):
            self.instance.verify_and_parse_webhook(tampered, header)

    def test_signature_computed_with_the_wrong_secret_is_rejected(self):
        header = _stripe_signature_header(self.payload, "whsec_totally_different_secret")
        with self.assertRaises(billing.WebhookVerificationError):
            self.instance.verify_and_parse_webhook(self.payload, header)

    def test_malformed_signature_header_is_rejected(self):
        with self.assertRaises(billing.WebhookVerificationError):
            self.instance.verify_and_parse_webhook(self.payload, "not-a-valid-header-at-all")

    def test_validly_signed_but_non_json_payload_is_rejected_not_crashed(self):
        garbage = b"this is not json"
        header = _stripe_signature_header(garbage, WEBHOOK_SECRET)
        with self.assertRaises(billing.WebhookVerificationError):
            self.instance.verify_and_parse_webhook(garbage, header)


# ---------------------------------------------------------------------------
# End-to-end HTTP tests - real server, real requests, fake Stripe client.
# ---------------------------------------------------------------------------

class _BillingHttpTestCase(_HttpAppTestCase):
    """Same bootstrap as _HttpAppTestCase (see that class), but also
    wires a StripeBilling (backed by _FakeStripeClient - no network) into
    the server so the three /billing/* routes are reachable."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed_conn = repo.connect(self.db_path)
        repo.init_schema(seed_conn)
        seed_conn.close()

        self.email_sender = _CapturingEmailSender()
        self.billing = _make_billing()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path),
            email_sender=self.email_sender,
            host_allowlist=[HOST],
            host=HOST,
            port=0,
            secure_cookies=False,
            billing=self.billing,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)

    def _create_workspace(self, name="Webhook Test Workspace"):
        """For webhook-only tests that never log in - entitlements.
        workspace_id is a real foreign key (REFERENCES workspaces(id),
        FK enforcement is on for every connection this module opens - see
        backend/repository.py's connect()), so a webhook event naming a
        workspace that doesn't really exist would correctly fail, exactly
        as it would in production. A real Stripe integration only ever
        gets a real workspace's UUID into client_reference_id/metadata in
        the first place (that value is stamped on by THIS backend's own
        create_checkout_session() call), so this mirrors reality rather
        than working around it."""
        conn = repo.connect(self.db_path)
        owner = repo.create_user(conn, "%s-%s@example.com" % (name.lower().replace(" ", "-"), repo.new_id()))
        workspace_id = repo.create_workspace(conn, name, owner)
        conn.close()
        return workspace_id

    def _login_and_own_workspace(self, email="owner@example.com", role="owner"):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        user = repo.get_user_by_email(conn, email)
        workspace_id = repo.create_workspace(conn, "Test Workspace", user["id"])
        if role != "owner":
            repo.update_workspace_member_role(conn, workspace_id, user["id"], role)
        conn.close()
        return cookie, workspace_id, user["id"]

    def post_webhook(self, event_dict=None, raw_body=None, secret=None, signature_header=None):
        body = raw_body if raw_body is not None else json.dumps(event_dict).encode("utf-8")
        if signature_header is None:
            signature_header = _stripe_signature_header(body, secret if secret is not None else WEBHOOK_SECRET)
        conn = self._conn()
        hdrs = {"Content-Type": "application/json", "Content-Length": str(len(body)), "Host": self.host_header}
        if signature_header:  # falsy (empty string / None) omits the header entirely.
            hdrs["Stripe-Signature"] = signature_header
        conn.request("POST", "/billing/webhook", body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result

    def entitlement(self, workspace_id):
        conn = repo.connect(self.db_path)
        try:
            return repo.get_entitlement_by_workspace(conn, workspace_id)
        finally:
            conn.close()

    def _restart_with_black_friday(self, enabled=True, start=None, end=None, promotion_code_id=BF_PROMOTION_CODE_ID):
        """Same shutdown-then-run_server(...) pattern already established
        elsewhere in this suite (e.g. tests/test_backend_http_app.py's
        RateLimitAlertTests) for reconfiguring a running test server."""
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path),
            email_sender=self.email_sender,
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False,
            billing=self.billing,
            black_friday_enabled=enabled, black_friday_start=start, black_friday_end=end,
            black_friday_promotion_code_id=promotion_code_id,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)


class CheckoutEndpointTests(_BillingHttpTestCase):
    def test_owner_can_start_checkout_for_their_own_workspace(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, body = self.post_json(
            "/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 200)
        self.assertIn("checkout_url", json.loads(body))
        self.assertEqual(self.billing._client.checkout.sessions.calls[0]["line_items"][0]["price"], "price_standard_monthly_test")

    def test_annual_interval_resolves_to_the_annual_price(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json(
            "/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "annual"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.billing._client.checkout.sessions.calls[0]["line_items"][0]["price"], "price_standard_annual_test")

    def test_missing_interval_returns_clean_400(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard"}, headers={"Cookie": cookie})
        self.assertEqual(status, 400)

    def test_unrecognized_interval_returns_clean_400(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json(
            "/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "weekly"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 400)

    def test_member_role_is_forbidden(self):
        cookie, workspace_id, _ = self._login_and_own_workspace(role="member")
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 403)

    def test_admin_role_is_allowed(self):
        cookie, workspace_id, _ = self._login_and_own_workspace(role="admin")
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)

    def test_unauthenticated_request_is_rejected(self):
        _, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"})
        self.assertEqual(status, 401)

    def test_tampered_workspace_id_the_caller_does_not_belong_to_is_forbidden_not_billed(self):
        cookie, _, _ = self._login_and_own_workspace(email="attacker@example.com")
        conn = repo.connect(self.db_path)
        victim = repo.create_user(conn, "victim@example.com")
        victim_workspace = repo.create_workspace(conn, "Victim Workspace", victim)
        conn.close()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": victim_workspace, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 403)
        self.assertEqual(self.billing._client.checkout.sessions.calls, [])

    def test_unknown_plan_returns_clean_400(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "unlisted-plan", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 400)

    def test_extra_client_supplied_price_or_customer_fields_are_silently_ignored(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json(
            "/billing/checkout",
            {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly", "price_id": "price_evil_free_plan", "customer_id": "cus_evil"},
            headers={"Cookie": cookie},
        )
        self.assertEqual(status, 200)
        params = self.billing._client.checkout.sessions.calls[0]
        self.assertEqual(params["line_items"], [{"price": "price_standard_monthly_test", "quantity": 1}])
        self.assertNotIn("cus_evil", json.dumps(params))

    def test_client_supplied_discount_coupon_or_campaign_flag_is_silently_ignored(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json(
            "/billing/checkout",
            {
                "workspace_id": workspace_id, "plan": "standard", "interval": "annual",
                "discount": "100", "coupon": "cpn_evil", "promotion_code": "promo_evil", "black_friday": True,
            },
            headers={"Cookie": cookie},
        )
        self.assertEqual(status, 200)
        params = self.billing._client.checkout.sessions.calls[0]
        self.assertNotIn("discounts", params)  # no BF campaign configured on this server - see BlackFridayCheckoutTests.
        self.assertNotIn("cpn_evil", json.dumps(params))
        self.assertNotIn("promo_evil", json.dumps(params))

    def test_duplicate_checkout_is_blocked_when_entitlement_already_active(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        conn = repo.connect(self.db_path)
        repo.create_entitlement(conn, workspace_id, "standard", "active", stripe_customer_id="cus_existing")
        conn.close()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 409)

    def test_incomplete_entitlement_does_not_block_a_new_checkout_attempt(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        conn = repo.connect(self.db_path)
        repo.create_entitlement(conn, workspace_id, "standard", "incomplete")
        conn.close()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)

    def test_cross_origin_checkout_request_is_rejected(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json(
            "/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie, "Origin": "http://evil.example"}
        )
        self.assertEqual(status, 403)

    def test_malformed_json_body_returns_400(self):
        cookie, _, _ = self._login_and_own_workspace()
        conn = self._conn()
        body = b"{not json"
        conn.request(
            "POST", "/billing/checkout", body=body,
            headers={"Content-Length": str(len(body)), "Host": self.host_header, "Origin": self.same_origin, "Cookie": cookie},
        )
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 400)


class BlackFridayCheckoutTests(_BillingHttpTestCase):
    """D-086: the backend, not the website, is authoritative for the
    campaign - every test here proves the discount is attached (or not)
    based ONLY on server-side interval/clock/config, re-evaluated fresh
    per request, never on any client-supplied field."""

    def _window(self, now=None):
        now = now or datetime.now(timezone.utc)
        return now - timedelta(days=1), now + timedelta(days=1)

    def test_annual_inside_campaign_window_gets_the_discount(self):
        start, end = self._window()
        self._restart_with_black_friday(enabled=True, start=start, end=end)
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "annual"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        params = self.billing._client.checkout.sessions.calls[0]
        self.assertEqual(params["discounts"], [{"promotion_code": BF_PROMOTION_CODE_ID}])

    def test_monthly_inside_campaign_window_never_gets_the_discount(self):
        start, end = self._window()
        self._restart_with_black_friday(enabled=True, start=start, end=end)
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn("discounts", self.billing._client.checkout.sessions.calls[0])

    def test_annual_before_campaign_window_gets_no_discount(self):
        now = datetime.now(timezone.utc)
        self._restart_with_black_friday(enabled=True, start=now + timedelta(days=1), end=now + timedelta(days=8))
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "annual"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn("discounts", self.billing._client.checkout.sessions.calls[0])

    def test_annual_after_campaign_window_gets_no_discount_stale_request_cannot_bypass(self):
        now = datetime.now(timezone.utc)
        self._restart_with_black_friday(enabled=True, start=now - timedelta(days=8), end=now - timedelta(days=1))
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "annual"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn("discounts", self.billing._client.checkout.sessions.calls[0])

    def test_campaign_disabled_gets_no_discount_even_during_what_would_be_the_window(self):
        start, end = self._window()
        self._restart_with_black_friday(enabled=False, start=start, end=end)
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "standard", "interval": "annual"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn("discounts", self.billing._client.checkout.sessions.calls[0])

    def test_client_cannot_force_the_discount_via_any_payload_field_even_with_a_live_campaign(self):
        start, end = self._window()
        self._restart_with_black_friday(enabled=True, start=start, end=end)
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json(
            "/billing/checkout",
            {
                "workspace_id": workspace_id, "plan": "standard", "interval": "monthly",  # monthly - must NOT get the discount.
                "black_friday": True, "promotion_code": "promo_evil", "discount_percent": 30,
            },
            headers={"Cookie": cookie},
        )
        self.assertEqual(status, 200)
        params = self.billing._client.checkout.sessions.calls[0]
        self.assertNotIn("discounts", params)
        self.assertNotIn("promo_evil", json.dumps(params))

    def test_stamps_interval_onto_metadata_so_the_webhook_can_persist_it(self):
        start, end = self._window()
        self._restart_with_black_friday(enabled=True, start=start, end=end)
        cookie, workspace_id, _ = self._login_and_own_workspace()
        self.post_json("/billing/checkout", {"workspace_id": workspace_id, "plan": "pro", "interval": "annual"}, headers={"Cookie": cookie})
        params = self.billing._client.checkout.sessions.calls[0]
        self.assertEqual(params["metadata"]["interval"], "annual")


class PortalEndpointTests(_BillingHttpTestCase):
    def test_owner_with_existing_customer_gets_a_portal_url(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        conn = repo.connect(self.db_path)
        repo.create_entitlement(conn, workspace_id, "standard", "active", stripe_customer_id="cus_existing", stripe_subscription_id="sub_existing")
        conn.close()
        status, _, body = self.post_json("/billing/portal", {"workspace_id": workspace_id}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("portal_url", json.loads(body))
        self.assertEqual(self.billing._client.billing_portal.sessions.calls[0]["customer"], "cus_existing")

    def test_workspace_with_no_billing_account_yet_returns_400(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        status, _, _ = self.post_json("/billing/portal", {"workspace_id": workspace_id}, headers={"Cookie": cookie})
        self.assertEqual(status, 400)

    def test_client_supplied_customer_id_is_ignored_the_stored_one_is_used(self):
        cookie, workspace_id, _ = self._login_and_own_workspace()
        conn = repo.connect(self.db_path)
        repo.create_entitlement(conn, workspace_id, "standard", "active", stripe_customer_id="cus_real", stripe_subscription_id="sub_real")
        conn.close()
        status, _, _ = self.post_json(
            "/billing/portal", {"workspace_id": workspace_id, "customer_id": "cus_evil"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.billing._client.billing_portal.sessions.calls[0]["customer"], "cus_real")

    def test_member_role_is_forbidden(self):
        cookie, workspace_id, _ = self._login_and_own_workspace(role="member")
        status, _, _ = self.post_json("/billing/portal", {"workspace_id": workspace_id}, headers={"Cookie": cookie})
        self.assertEqual(status, 403)


class MissingBillingConfigurationTests(_HttpAppTestCase):
    """Uses the PLAIN _HttpAppTestCase (billing=None, its own default) -
    every /billing/* route must degrade cleanly, never crash."""

    def test_checkout_returns_503_when_billing_is_not_configured(self):
        cookie = self.request_and_confirm_login("solo@example.com")
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": "ws-1", "plan": "standard"}, headers={"Cookie": cookie})
        self.assertEqual(status, 503)

    def test_portal_returns_503_when_billing_is_not_configured(self):
        cookie = self.request_and_confirm_login("solo2@example.com")
        status, _, _ = self.post_json("/billing/portal", {"workspace_id": "ws-1"}, headers={"Cookie": cookie})
        self.assertEqual(status, 503)

    def test_webhook_returns_503_when_billing_is_not_configured(self):
        conn = self._conn()
        body = b'{"id": "evt_1", "type": "checkout.session.completed"}'
        conn.request("POST", "/billing/webhook", body=body, headers={"Content-Length": str(len(body)), "Host": self.host_header})
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 503)


class WebhookEndpointTests(_BillingHttpTestCase):
    """Transport-level webhook behavior: signature, mode, shape,
    deduplication, outcome recording. The billing lifecycle itself (Quick,
    the 4 subscription modes, renewal, failure, cancellation, binding) is
    covered end to end in tests/test_backend_stripe_billing.py (D-115)."""

    def setUp(self):
        super().setUp()
        # entitlements.workspace_id is a real foreign key - see
        # _create_workspace()'s docstring.
        self.workspace_id = self._create_workspace()

    def _row(self, event_id):
        conn = repo.connect(self.db_path)
        try:
            return _fetch_webhook_event(conn, event_id)
        finally:
            conn.close()

    def test_unhandled_event_type_is_recorded_with_an_ignored_outcome(self):
        status, _, body = self.post_webhook(_event("customer.updated", "evt_1", {"id": "cus_1"}))
        self.assertEqual((status, json.loads(body)["outcome"]), (200, "ignored:unhandled_event_type"))
        row = self._row("evt_1")
        self.assertIsNotNone(row["processed_at"])
        self.assertIsNone(row["processing_error"])
        self.assertEqual(row["outcome"], "ignored:unhandled_event_type")

    def test_checkout_session_not_created_by_this_backend_grants_nothing(self):
        # A session from elsewhere in the Stripe account (dashboard, payment
        # link, another product) - even with this workspace in its metadata.
        status, _, body = self.post_webhook(_event("checkout.session.completed", "evt_1", _checkout_session_completed_obj(self.workspace_id, "standard")))
        self.assertEqual((status, json.loads(body)["outcome"]), (200, "ignored:unknown_checkout_session"))
        self.assertIsNone(self.entitlement(self.workspace_id))

    def test_replayed_event_id_is_a_no_op_second_time(self):
        event = _event("customer.updated", "evt_1", {"id": "cus_1"})
        self.post_webhook(event)
        status, _, body = self.post_webhook(event)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body).get("duplicate"))

    def test_tampered_payload_is_rejected_and_nothing_is_recorded(self):
        body = json.dumps(_event("checkout.session.completed", "evt_1", _checkout_session_completed_obj(self.workspace_id, "standard"))).encode("utf-8")
        header = _stripe_signature_header(body, WEBHOOK_SECRET)
        status, _, _ = self.post_webhook(raw_body=body.replace(b'"plan": "standard"', b'"plan": "pro"'), signature_header=header)
        self.assertEqual(status, 400)
        self.assertIsNone(self._row("evt_1"))

    def test_wrong_secret_is_rejected(self):
        status, _, _ = self.post_webhook(
            _event("checkout.session.completed", "evt_1", _checkout_session_completed_obj(self.workspace_id, "standard")), secret="whsec_wrong"
        )
        self.assertEqual(status, 400)
        self.assertIsNone(self._row("evt_1"))

    def test_missing_signature_header_is_rejected(self):
        status, _, _ = self.post_webhook(
            _event("checkout.session.completed", "evt_1", _checkout_session_completed_obj(self.workspace_id, "standard")), signature_header=""
        )
        self.assertEqual(status, 400)

    def test_expired_signature_timestamp_is_rejected(self):
        body = json.dumps(_event("customer.updated", "evt_old", {"id": "cus_1"})).encode("utf-8")
        status, _, _ = self.post_webhook(raw_body=body, signature_header=_stripe_signature_header(body, WEBHOOK_SECRET, timestamp=int(time.time()) - 3600))
        self.assertEqual(status, 400)
        self.assertIsNone(self._row("evt_old"))

    def test_live_event_reaching_a_sandbox_deployment_is_rejected_and_not_recorded(self):
        event = _event("customer.updated", "evt_live_1", {"id": "cus_1"})
        event["livemode"] = True
        status, _, body = self.post_webhook(event)
        self.assertEqual((status, json.loads(body)["error"]), (400, "livemode mismatch"))
        self.assertIsNone(self._row("evt_live_1"))
        del event["livemode"]                                   # every real event carries livemode
        self.assertEqual(self.post_webhook(event)[0], 400)

    def test_malformed_json_body_with_a_valid_signature_is_rejected_not_500(self):
        garbage = b"not json at all"
        status, _, _ = self.post_webhook(raw_body=garbage, signature_header=_stripe_signature_header(garbage, WEBHOOK_SECRET))
        self.assertEqual(status, 400)

    def test_event_missing_or_malformed_id_or_type_is_rejected(self):
        for event in ({"livemode": False, "data": {"object": {}}}, {"id": "evt_1", "livemode": False, "data": {}},
                      {"id": "not-an-event-id", "type": "customer.updated", "livemode": False, "data": {}},
                      {"id": "evt_1", "type": "x" * 101, "livemode": False, "data": {}}):
            body = json.dumps(event).encode("utf-8")
            status, _, _ = self.post_webhook(raw_body=body, signature_header=_stripe_signature_header(body, WEBHOOK_SECRET))
            self.assertEqual(status, 400, event)

    def test_handled_event_with_a_malformed_object_is_ignored_not_500(self):
        for i, obj in enumerate(("a string", None, ["list"])):
            event = {"id": "evt_bad_%d" % i, "type": "customer.subscription.updated", "livemode": False, "data": {"object": obj}}
            status, _, body = self.post_webhook(event)
            self.assertEqual((status, json.loads(body)["outcome"]), (200, "ignored:malformed_object"))

    def test_webhook_does_not_check_origin_a_normal_stripe_call_has_none(self):
        # No Origin header at all (post_webhook never sends one) - unlike
        # every other state-changing endpoint, this must still succeed.
        status, _, _ = self.post_webhook(_event("customer.updated", "evt_1", {"id": "cus_1"}))
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
