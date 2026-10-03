"""Tests for the Launch commercial catalog and usage accounting
(docs/decisiones.md D-107): backend/plans.py, backend/loc_count.py, the
usage ledger in backend/repository.py, the Stripe price mapping in
backend/billing.py, and the HTTP admission/checkout/portal/member rules in
backend/http_app.py. No real Stripe call and no LLM call: Stripe is the
in-process fake client from tests/test_backend_billing.py.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.billing as billing  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.loc_count as loc_count  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import preprocess as pp  # noqa: E402
import tests.test_backend_billing as billing_tests  # noqa: E402
from tests.test_backend_http_app import _WorkspaceStorageTestCase  # noqa: E402

# The Stripe test-mode Price IDs Diego supplied for the Launch catalog
# (docs/staging-config.md). Price IDs are not secrets.
SANDBOX_PRICE_IDS = {
    "vericexa_quick_onetime": "price_1UMFnY1jc8PYYLrPXxSbSEUF",
    "vericexa_standard_monthly": "price_1UMFvU1jc8PYYLrPsrZuTqJl",
    "vericexa_standard_annual": "price_1UMFvU1jc8PYYLrPg7Kia6bO",
    "vericexa_pro_monthly": "price_1UMFwj1jc8PYYLrP2rA1xonm",
    "vericexa_pro_annual": "price_1UMFy51jc8PYYLrPLyQHT8Fh",
}
UTC = timezone.utc


def _sol(effective_lines: int, comment_lines: int = 0, blank_lines: int = 0) -> str:
    """A Solidity source with exactly `effective_lines` effective LOC."""
    body = ["pragma solidity ^0.8.20;", "contract C {"] + ["    uint256 public v%d;" % i for i in range(max(0, effective_lines - 3))] + ["}"]
    body = body[:effective_lines] if effective_lines < 3 else body
    out = list(body)
    out[1:1] = ["// comment %d" % i for i in range(comment_lines)] + [""] * blank_lines
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

class CatalogTests(unittest.TestCase):
    def test_three_plans_five_price_modes(self):
        self.assertEqual(sorted(plans.PLANS), ["pro", "quick", "standard"])
        self.assertEqual(sorted(plans.PRICE_MODES), sorted([
            "vericexa_quick_onetime", "vericexa_standard_monthly", "vericexa_standard_annual", "vericexa_pro_monthly", "vericexa_pro_annual"]))
        self.assertEqual(sorted({m["plan"] for m in plans.PRICE_MODES.values()}), ["pro", "quick", "standard"])

    def test_exact_prices_and_intervals(self):
        expected = {
            "vericexa_quick_onetime": ("quick", "one_time", "payment", 2999, None),
            "vericexa_standard_monthly": ("standard", "monthly", "subscription", 19999, 1),
            "vericexa_standard_annual": ("standard", "annual", "subscription", 199990, 12),
            "vericexa_pro_monthly": ("pro", "monthly", "subscription", 28999, 1),
            "vericexa_pro_annual": ("pro", "annual", "subscription", 289990, 12),
        }
        for key, (plan, interval, checkout_mode, cents, months) in expected.items():
            m = plans.PRICE_MODES[key]
            self.assertEqual((m["plan"], m["interval"], m["checkout_mode"], m["amount_cents"], m["currency"], m["service_months"]),
                             (plan, interval, checkout_mode, cents, "usd", months), key)

    def test_plan_capabilities(self):
        q, s, p = plans.PLANS["quick"], plans.PLANS["standard"], plans.PLANS["pro"]
        self.assertEqual((q["billing_type"], q["usage_model"], q["max_loc_per_scan"], q["scans_per_purchase"], q["monthly_loc_quota"], q["max_projects"]),
                         ("one_time", "scan_credit", 3000, 1, None, None))
        self.assertEqual((s["billing_type"], s["usage_model"], s["max_loc_per_scan"], s["monthly_loc_quota"], s["max_projects"], s["max_members"]),
                         ("subscription", "service_month", 10000, 20000, None, 2))
        self.assertEqual((p["billing_type"], p["usage_model"], p["max_loc_per_scan"], p["monthly_loc_quota"], p["max_projects"], p["max_members"]),
                         ("subscription", "service_month", 20000, 60000, None, 5))
        self.assertEqual((s["queue_priority"], p["queue_priority"], s["priority_support"], p["priority_support"]), ("normal", "priority", False, True))

    def test_old_d086_combinations_do_not_exist(self):
        for plan, interval in (("quick", "monthly"), ("quick", "annual"), ("standard", "one_time"), ("pro", "one_time")):
            self.assertIsNone(plans.price_mode_key(plan, interval))
        for cents in (1900, 3900, 7900, 19000, 39000, 79000):
            self.assertNotIn(cents, [m["amount_cents"] for m in plans.PRICE_MODES.values()])

    def test_usage_state_boundaries(self):
        cases = [(0, "normal"), (15999, "normal"), (16000, "warning"), (17999, "warning"), (18000, "danger"), (19999, "danger"), (20000, "blocked"), (25000, "blocked")]
        for used, state in cases:
            self.assertEqual(plans.usage_state(used, 20000), state, used)
        self.assertEqual(plans.usage_state(10 ** 9, None), "unlimited")

    def test_service_month_steps_and_day_clamping(self):
        anchor = datetime(2026, 1, 31, 12, tzinfo=UTC)
        self.assertEqual(plans.service_month(anchor, datetime(2026, 2, 10, tzinfo=UTC)), (anchor, datetime(2026, 2, 28, 12, tzinfo=UTC)))
        self.assertEqual(plans.service_month(anchor, datetime(2026, 3, 1, tzinfo=UTC)), (datetime(2026, 2, 28, 12, tzinfo=UTC), datetime(2026, 3, 31, 12, tzinfo=UTC)))
        self.assertEqual(plans.service_month(anchor, datetime(2026, 3, 31, 12, tzinfo=UTC))[0], datetime(2026, 3, 31, 12, tzinfo=UTC))
        self.assertEqual(plans.service_month(anchor, datetime(2027, 1, 30, tzinfo=UTC))[0], datetime(2026, 12, 31, 12, tzinfo=UTC))
        self.assertEqual(plans.service_month(anchor, datetime(2025, 1, 1, tzinfo=UTC))[0], anchor)   # clock skew -> first month


# ---------------------------------------------------------------------------
# Stripe price mapping (billing.py)
# ---------------------------------------------------------------------------

class PriceMappingTests(unittest.TestCase):
    def _billing(self, allowlist):
        instance = billing.StripeBilling("sk_test_fake", "whsec_fake", dict(allowlist))
        instance._client = billing_tests._FakeStripeClient()
        return instance

    def test_sandbox_catalog_maps_exactly(self):
        b = self._billing(SANDBOX_PRICE_IDS)
        self.assertEqual(b.resolve_price_id("standard", "monthly"), "price_1UMFvU1jc8PYYLrPsrZuTqJl")
        self.assertEqual(b.resolve_price_id("standard", "annual"), "price_1UMFvU1jc8PYYLrPg7Kia6bO")
        self.assertEqual(b.resolve_price_id("pro", "monthly"), "price_1UMFwj1jc8PYYLrP2rA1xonm")
        self.assertEqual(b.resolve_price_id("pro", "annual"), "price_1UMFy51jc8PYYLrPLyQHT8Fh")
        self.assertEqual(b.plan_for_price_id("price_1UMFvU1jc8PYYLrPg7Kia6bO"), {"plan": "standard", "interval": "annual", "price_mode": "vericexa_standard_annual"})
        self.assertEqual(b.plan_for_price_id("price_1UMFwj1jc8PYYLrP2rA1xonm")["plan"], "pro")

    def test_quick_maps_to_its_real_one_time_price_only(self):
        b = self._billing(SANDBOX_PRICE_IDS)
        self.assertEqual(b.resolve_price_id("quick", "one_time"), "price_1UMFnY1jc8PYYLrPXxSbSEUF")
        self.assertEqual(b.plan_for_price_id("price_1UMFnY1jc8PYYLrPXxSbSEUF"), {"plan": "quick", "interval": "one_time", "price_mode": "vericexa_quick_onetime"})
        for interval in ("monthly", "annual"):                                              # Quick is never a subscription
            with self.assertRaises(billing.PriceNotAllowedError):
                b.resolve_price_id("quick", interval)
            with self.assertRaises(billing.PriceNotAllowedError):
                b.create_checkout_session("quick", interval, "ws-1", "https://a.test/s", "https://a.test/c")
        self.assertEqual(b._client.checkout.sessions.calls, [])

    def test_quick_price_is_required_and_the_defensive_guard_never_substitutes(self):
        with self.assertRaises(billing.BillingError):
            billing.validate_price_allowlist({k: v for k, v in SANDBOX_PRICE_IDS.items() if k != "vericexa_quick_onetime"})
        b = self._billing(SANDBOX_PRICE_IDS)
        del b._price_allowlist["vericexa_quick_onetime"]                                    # only reachable by bypassing validation
        with self.assertRaises(billing.BillingNotConfiguredError):
            b.create_checkout_session("quick", "one_time", "ws-1", "https://a.test/s", "https://a.test/c")
        self.assertEqual(b._client.checkout.sessions.calls, [])

    def test_old_prices_are_never_selected(self):
        b = self._billing(SANDBOX_PRICE_IDS)
        for plan, interval in (("quick", "monthly"), ("quick", "annual"), ("standard", "weekly"), ("enterprise", "monthly")):
            with self.assertRaises(billing.PriceNotAllowedError):
                b.resolve_price_id(plan, interval)
        for legacy in ("price_quick_monthly", "price_old_19", "price_1OldD086Quick", None, ""):
            self.assertIsNone(b.plan_for_price_id(legacy))

    def test_allowlist_validation(self):
        with self.assertRaises(billing.BillingError):
            billing.validate_price_allowlist({"quick_monthly": "price_x", **SANDBOX_PRICE_IDS})            # retired D-086 key
        with self.assertRaises(billing.BillingError):
            billing.validate_price_allowlist({k: v for k, v in SANDBOX_PRICE_IDS.items() if k != "vericexa_pro_annual"})
        with self.assertRaises(billing.BillingError):
            billing.validate_price_allowlist(dict(SANDBOX_PRICE_IDS, vericexa_pro_annual="prod_VMzwG1pHzS0d5t"))   # a Product ID is not a Price ID
        with self.assertRaises(billing.BillingError):
            billing.validate_price_allowlist(dict(SANDBOX_PRICE_IDS, vericexa_pro_annual=SANDBOX_PRICE_IDS["vericexa_pro_monthly"]))
        self.assertEqual(billing.validate_price_allowlist(SANDBOX_PRICE_IDS), SANDBOX_PRICE_IDS)

    def test_quick_checkout_is_a_one_time_payment(self):
        b = self._billing(SANDBOX_PRICE_IDS)
        b.create_checkout_session("quick", "one_time", "ws-q", "https://a.test/s", "https://a.test/c", black_friday_promotion_code_id="promo_x")
        params = b._client.checkout.sessions.calls[0]
        self.assertEqual(params["mode"], "payment")
        self.assertEqual(params["line_items"], [{"price": "price_1UMFnY1jc8PYYLrPXxSbSEUF", "quantity": 1}])
        self.assertNotIn("subscription_data", params)
        self.assertNotIn("discounts", params)
        self.assertEqual(params["payment_intent_data"]["metadata"], {"workspace_id": "ws-q", "plan": "quick", "interval": "one_time"})
        self.assertEqual(params["customer_creation"], "always")

    def test_subscription_checkouts_use_monthly_and_annual_prices(self):
        b = self._billing(SANDBOX_PRICE_IDS)
        for plan, interval in (("standard", "monthly"), ("standard", "annual"), ("pro", "monthly"), ("pro", "annual")):
            b.create_checkout_session(plan, interval, "ws-s", "https://a.test/s", "https://a.test/c")
            params = b._client.checkout.sessions.calls[-1]
            self.assertEqual(params["mode"], "subscription")
            self.assertEqual(params["line_items"][0]["price"], SANDBOX_PRICE_IDS[plans.price_mode_key(plan, interval)])
            self.assertEqual(params["subscription_data"]["metadata"]["plan"], plan)
            self.assertNotIn("payment_intent_data", params)


# ---------------------------------------------------------------------------
# Effective LOC (loc_count.py) == the engine's own count
# ---------------------------------------------------------------------------

class LocCountTests(unittest.TestCase):
    def _engine_total(self, source):
        d = tempfile.mkdtemp(prefix="loc-")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "contract.sol")
        with open(path, "w", encoding="utf-8", newline="") as h:
            h.write(source)
        return pp.run([path], mode="pro", max_loc=None, use_stdin=False, include_timestamp=False)["totals"]["totalEffectiveLoc"]

    def test_matches_preprocess_on_eval_fixtures(self):
        for case in sorted((REPO_ROOT / "evals" / "cases").glob("*.sol")):
            source = case.read_text(encoding="utf-8")
            self.assertEqual(loc_count.submission_effective_loc(source), self._engine_total(source), case.name)

    def test_matches_preprocess_on_bundles_comments_crlf_and_non_source(self):
        samples = [
            _sol(40, comment_lines=25, blank_lines=10),
            _sol(12).replace("\n", "\r\n"),
            "﻿" + _sol(7),
            "=== FILE: src/A.sol ===\n" + _sol(30) + "=== END FILE ===\n=== FILE: README.md ===\n# docs\nline\n=== END FILE ===\n"
            "=== FILE: src/B.sol ===\n/* block\ncomment */\n" + _sol(9) + "=== END FILE ===\n",
            "just some text without code\n",
        ]
        for source in samples:
            self.assertEqual(loc_count.submission_effective_loc(source), self._engine_total(source))
        self.assertEqual(loc_count.submission_effective_loc("// only a comment\n\n"), 0)

    def test_helper_builds_exact_effective_counts(self):
        for n in (3, 2999, 3000, 3001):
            self.assertEqual(loc_count.submission_effective_loc(_sol(n, comment_lines=5, blank_lines=5)), n)


# ---------------------------------------------------------------------------
# Usage ledger (repository.py)
# ---------------------------------------------------------------------------

class _LedgerCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        conn = repo.connect(self.db_path)
        repo.init_schema(conn)
        conn.close()
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.conn = repo.connect(self.db_path)
        self.addCleanup(self.conn.close)
        self.user = repo.create_user(self.conn, "ledger-%s@example.com" % repo.new_id())

    def workspace(self, plan, interval=None, period_start=None, created_at=None):
        ws = repo.create_workspace(self.conn, "WS", self.user)
        repo.create_entitlement(self.conn, ws, plan, "active", billing_interval=interval, current_period_start=period_start)
        if created_at:
            self.conn.execute("UPDATE entitlements SET created_at = ? WHERE workspace_id = ?", (created_at, ws))
            self.conn.commit()
        return ws

    def submit(self, ws, loc, now=None, conn=None, key=None, mode="quick", max_pending=repo.DEFAULT_MAX_PENDING_JOBS_PER_WORKSPACE):
        conn = conn or self.conn
        contract = repo.create_contract(conn, ws, "ref-%s" % repo.new_id(), "h", "contract.sol")
        ent = repo.get_entitlement_by_workspace(conn, ws)
        return repo.enqueue_job_with_usage(conn, ws, contract, self.user, mode, key, ent, loc, now=now, max_pending_jobs=max_pending)

    def finish(self, job_id, to_status="succeeded"):
        self.assertTrue(repo.transition_job_status(self.conn, job_id, "queued", "claimed"))
        if to_status == "failed_on_claim":
            return self.assertTrue(repo.transition_job_status(self.conn, job_id, "claimed", "failed"))
        self.assertTrue(repo.transition_job_status(self.conn, job_id, "claimed", "running"))
        self.assertTrue(repo.transition_job_status(self.conn, job_id, "running", to_status))

    def code(self, fn):
        with self.assertRaises(repo.UsageLimitError) as ctx:
            fn()
        return ctx.exception.code

    def summary(self, ws, now=None):
        return repo.usage_summary(self.conn, ws, repo.get_entitlement_by_workspace(self.conn, ws), now)


class QuickTests(_LedgerCase):
    def test_one_purchase_one_scan(self):
        ws = self.workspace("quick")
        self.assertEqual(self.code(lambda: self.submit(ws, 100)), "no_scan_credit")          # nothing purchased yet
        self.assertTrue(repo.grant_scan_credit(self.conn, "cs_test_1", ws))
        self.assertFalse(repo.grant_scan_credit(self.conn, "cs_test_1", ws))                 # redelivered webhook: no second credit
        self.assertEqual(self.summary(ws)["scans_available"], 1)
        job = self.submit(ws, 3000)
        self.assertEqual(self.code(lambda: self.submit(ws, 10)), "no_scan_credit")           # reserved by the first scan
        self.finish(job)
        s = self.summary(ws)
        self.assertEqual((s["scans_available"], s["scans_consumed"], s["state"], s["billing_type"], s["max_projects"]), (0, 1, "blocked", "one_time", None))
        self.assertEqual(self.code(lambda: self.submit(ws, 10)), "no_scan_credit")           # second scan denied
        repo.grant_scan_credit(self.conn, "cs_test_2", ws)                                   # a second purchase
        self.finish(self.submit(ws, 50))
        self.assertEqual(self.summary(ws)["scans_consumed"], 2)

    def test_per_scan_limit_3000(self):
        ws = self.workspace("quick")
        for i in range(3):
            repo.grant_scan_credit(self.conn, "cs_%d" % i, ws)
        self.assertEqual(self.code(lambda: self.submit(ws, 3001)), "loc_per_scan_limit_exceeded")
        self.submit(ws, 2999)
        self.submit(ws, 3000)
        self.assertEqual(self.code(lambda: self.submit(ws, 0)), "no_source_code")

    def test_failed_scan_gives_the_credit_back_and_never_resets_monthly(self):
        ws = self.workspace("quick")
        repo.grant_scan_credit(self.conn, "cs_only", ws)
        self.finish(self.submit(ws, 100), "failed")
        self.assertEqual(self.summary(ws)["scans_available"], 1)
        self.finish(self.submit(ws, 100))
        far_future = datetime.now(UTC) + timedelta(days=400)
        self.assertEqual(self.summary(ws, far_future)["scans_available"], 0)               # no period, no reset
        self.assertEqual(self.code(lambda: self.submit(ws, 10, now=far_future)), "no_scan_credit")


class ServiceMonthTests(_LedgerCase):
    def test_per_scan_limits(self):
        for plan, limit in (("standard", 10000), ("pro", 20000)):
            ws = self.workspace(plan, "monthly")
            self.assertEqual(self.code(lambda: self.submit(ws, limit + 1)), "loc_per_scan_limit_exceeded")
            self.submit(ws, limit - 1)
            if plan == "pro":
                self.submit(ws, limit)

    def test_standard_monthly_quota_exact_then_reject(self):
        ws = self.workspace("standard", "monthly")
        self.finish(self.submit(ws, 10000))
        self.submit(ws, 9500)                                                                # reserved, still counts
        self.assertEqual(self.summary(ws)["state"], "danger")
        self.assertEqual(self.code(lambda: self.submit(ws, 1000)), "loc_quota_exceeded")     # 19,500 + 1,000 > 20,000
        self.submit(ws, 500)                                                                 # exactly 20,000
        s = self.summary(ws)
        self.assertEqual((s["loc_used"], s["loc_remaining"], s["state"]), (20000, 0, "blocked"))
        self.assertEqual(self.code(lambda: self.submit(ws, 1)), "loc_quota_exceeded")        # 20,001

    def test_pro_monthly_quota_exact_then_reject(self):
        ws = self.workspace("pro", "monthly")
        for _ in range(3):
            self.finish(self.submit(ws, 20000))
        self.assertEqual(self.summary(ws)["loc_consumed"], 60000)
        self.assertEqual(self.code(lambda: self.submit(ws, 1)), "loc_quota_exceeded")

    def test_failed_and_canceled_jobs_release(self):
        ws = self.workspace("standard", "monthly")
        self.finish(self.submit(ws, 10000), "failed")
        self.finish(self.submit(ws, 10000), "failed_on_claim")
        job = self.submit(ws, 10000)
        self.assertTrue(repo.transition_job_status(self.conn, job, "queued", "canceled"))
        s = self.summary(ws)
        self.assertEqual((s["loc_reserved"], s["loc_consumed"]), (0, 0))
        self.assertEqual(repo.get_job_usage(self.conn, job)["status"], "released")

    def test_annual_is_twelve_service_months_not_an_upfront_pool(self):
        start = datetime(2026, 1, 15, 9, tzinfo=UTC)
        for plan, quota in (("standard", 20000), ("pro", 60000)):
            ws = self.workspace(plan, "annual", period_start=start.isoformat())
            per_scan = plans.PLANS[plan]["max_loc_per_scan"]
            month1 = datetime(2026, 1, 20, tzinfo=UTC)
            for _ in range(quota // per_scan):
                self.finish(self.submit(ws, per_scan, now=month1))
            self.assertEqual(self.code(lambda: self.submit(ws, 1, now=month1)), "loc_quota_exceeded")   # no 240K/720K pool
            month2 = datetime(2026, 2, 20, tzinfo=UTC)
            s = self.summary(ws, month2)
            self.assertEqual((s["period_start"], s["loc_used"], s["loc_limit"]), (datetime(2026, 2, 15, 9, tzinfo=UTC).isoformat(), 0, quota))
            self.submit(ws, per_scan, now=month2)
            month3 = datetime(2026, 3, 20, tzinfo=UTC)
            self.assertEqual(self.summary(ws, month3)["loc_remaining"], quota)               # no rollover from month 2
            month12 = datetime(2026, 12, 20, tzinfo=UTC)
            self.assertEqual(self.summary(ws, month12)["period_start"], datetime(2026, 12, 15, 9, tzinfo=UTC).isoformat())

    def test_monthly_period_follows_the_stripe_anchor(self):
        ws = self.workspace("standard", "monthly", period_start=datetime(2026, 5, 3, tzinfo=UTC).isoformat())
        s = self.summary(ws, datetime(2026, 5, 10, tzinfo=UTC))
        self.assertEqual((s["period_start"], s["period_end"]), (datetime(2026, 5, 3, tzinfo=UTC).isoformat(), datetime(2026, 6, 3, tzinfo=UTC).isoformat()))

    def test_fallback_anchor_is_the_entitlement_creation(self):
        ws = self.workspace("standard", "monthly", created_at=datetime(2026, 4, 7, tzinfo=UTC).isoformat())
        self.assertEqual(self.summary(ws, datetime(2026, 6, 1, tzinfo=UTC))["period_start"], datetime(2026, 5, 7, tzinfo=UTC).isoformat())


class IdempotencyTests(_LedgerCase):
    def test_settlement_happens_once(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 4000)
        self.finish(job)
        for action in ("consume", "release", "consume"):
            self.assertFalse(repo._settle_job_usage(self.conn, job, action))
        self.conn.commit()
        s = self.summary(ws)
        self.assertEqual((s["loc_reserved"], s["loc_consumed"]), (0, 4000))

    def test_same_idempotency_key_reserves_once(self):
        ws = self.workspace("standard", "monthly")
        self.submit(ws, 3000, key="same-key")
        with self.assertRaises(Exception):
            self.submit(ws, 3000, key="same-key")          # IntegrityError on the job row, before any reservation
        self.conn.rollback()
        self.assertEqual(self.summary(ws)["loc_reserved"], 3000)

    def test_fenced_finalize_and_reap(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 5000)
        claimed = repo.claim_next_job(self.conn, "worker-a")
        self.assertEqual(claimed["id"], job)
        repo.transition_job_status(self.conn, job, "claimed", "running")
        past = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
        self.conn.execute("UPDATE analysis_jobs SET lease_expires_at = ? WHERE id = ?", (past, job))
        self.conn.commit()
        self.assertEqual(repo.reap_expired_jobs(self.conn, max_attempts=3)["requeued"], 1)   # worker died: retry keeps the reservation
        self.assertEqual(repo.get_job_usage(self.conn, job)["status"], "reserved")
        stale = repo.finalize_job_attempt(self.conn, job, ws, claimed["attempt_count"], "worker-a", "running", "succeeded")
        self.assertFalse(stale["applied"])                                                    # the dead attempt cannot consume
        self.assertEqual(self.summary(ws)["loc_consumed"], 0)
        self.conn.execute("UPDATE analysis_jobs SET next_eligible_at = NULL WHERE id = ?", (job,))
        self.conn.commit()
        again = repo.claim_next_job(self.conn, "worker-b")
        repo.transition_job_status(self.conn, job, "claimed", "running")
        self.conn.execute("UPDATE analysis_jobs SET lease_expires_at = ? WHERE id = ?", (past, job))
        self.conn.commit()
        self.assertEqual(repo.reap_expired_jobs(self.conn, max_attempts=1)["failed"], 1)      # last attempt: released
        self.assertEqual(repo.get_job_usage(self.conn, job)["status"], "released")
        late = repo.finalize_job_attempt(self.conn, job, ws, again["attempt_count"], "worker-b", "running", "succeeded")
        self.assertFalse(late["applied"])
        s = self.summary(ws)
        self.assertEqual((s["loc_reserved"], s["loc_consumed"]), (0, 0))

    def test_concurrent_submissions_never_overshoot(self):
        ws = self.workspace("standard", "monthly")
        results, lock = [], threading.Lock()

        def worker():
            conn = repo.connect(self.db_path)
            conn.execute("PRAGMA busy_timeout = 10000")
            try:
                self.submit(ws, 3000, conn=conn, max_pending=100)   # isolates the LOC race from the pending-jobs cap
                outcome = "ok"
            except repo.UsageLimitError as exc:
                outcome = exc.code
            finally:
                conn.close()
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("ok"), 6)                                              # 6 x 3,000 = 18,000; a 7th would exceed 20,000
        self.assertEqual(results.count("loc_quota_exceeded"), 6)
        self.assertEqual(self.summary(ws)["loc_reserved"], 18000)

    def test_concurrent_quick_submissions_use_one_credit(self):
        ws = self.workspace("quick")
        repo.grant_scan_credit(self.conn, "cs_race", ws)
        results, lock = [], threading.Lock()

        def worker():
            conn = repo.connect(self.db_path)
            conn.execute("PRAGMA busy_timeout = 10000")
            try:
                self.submit(ws, 100, conn=conn)
                outcome = "ok"
            except repo.UsageLimitError as exc:
                outcome = exc.code
            finally:
                conn.close()
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("no_scan_credit"), 5)

    def test_concurrent_workers_consume_once(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 2000)
        claimed = repo.claim_next_job(self.conn, "worker-a")
        repo.transition_job_status(self.conn, job, "claimed", "running")
        outcomes = []

        def finalize():
            conn = repo.connect(self.db_path)
            conn.execute("PRAGMA busy_timeout = 10000")
            try:
                outcomes.append(repo.finalize_job_attempt(conn, job, ws, claimed["attempt_count"], "worker-a", "running", "succeeded")["applied"])
            finally:
                conn.close()

        threads = [threading.Thread(target=finalize) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(outcomes), [False, False, False, True])
        self.assertEqual(self.summary(ws)["loc_consumed"], 2000)


# ---------------------------------------------------------------------------
# Webhooks (_apply_webhook_event, no HTTP)
# ---------------------------------------------------------------------------

class WebhookEntitlementTests(_LedgerCase):
    def setUp(self):
        super().setUp()
        self.billing = billing.StripeBilling("sk_test_fake", "whsec_fake", dict(SANDBOX_PRICE_IDS))
        self.billing._client = billing_tests._FakeStripeClient()   # no network: Stripe's state is the fake's store (D-115)
        self.stripe = self.billing._client
        self.ws = repo.create_workspace(self.conn, "Hook WS", self.user)

    def apply(self, event_type, obj, created=1_800_000_000, stripe_state=True):
        """stripe_state: a subscription event's payload is also Stripe's
        current state (D-115 re-reads it) unless the test says otherwise."""
        if stripe_state and event_type.startswith("customer.subscription."):
            self.stripe.subscriptions.store[obj["id"]] = obj
        http_app._apply_webhook_event(self.conn, event_type, obj, billing.stripe_timestamp_to_iso(created), self.billing)

    def quick_session(self, session_id="cs_q1", payment_status="paid", paid=None):
        """paid: the session's line items as Stripe reports them (default:
        one unit of the Quick sandbox price)."""
        self.stripe.checkout.sessions.line_items.store[session_id] = paid if paid is not None else [(SANDBOX_PRICE_IDS["vericexa_quick_onetime"], 1)]
        return {"id": session_id, "mode": "payment", "payment_status": payment_status, "client_reference_id": self.ws, "customer": "cus_q",
                "metadata": {"workspace_id": self.ws, "plan": "quick", "interval": "one_time"}}

    def invoice(self, subscription_id="sub_1"):
        return {"customer": "cus_s", "parent": {"subscription_details": {"subscription": subscription_id, "metadata": {"workspace_id": self.ws}}}}

    def subscription(self, price_id, status="active", start=1_800_000_000, plan_meta="standard"):
        return {"id": "sub_1", "customer": "cus_s", "status": status, "metadata": {"workspace_id": self.ws, "plan": plan_meta, "interval": "monthly"},
                "items": {"data": [{"price": {"id": price_id}, "current_period_start": start, "current_period_end": start + 86400 * 365}]}}

    def test_quick_payment_grants_one_scan_idempotently(self):
        self.apply("checkout.session.completed", self.quick_session(payment_status="unpaid"))
        self.assertIsNone(repo.get_entitlement_by_workspace(self.conn, self.ws))             # not paid yet: nothing granted
        self.apply("checkout.session.async_payment_succeeded", self.quick_session())
        self.apply("checkout.session.completed", self.quick_session())                        # duplicate delivery
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"], ent["billing_interval"]), ("quick", "active", None, None))
        self.assertEqual(repo.usage_summary(self.conn, self.ws, ent)["scans_available"], 1)

    def test_subscription_plan_comes_from_the_price_id(self):
        self.apply("customer.subscription.created", self.subscription(SANDBOX_PRICE_IDS["vericexa_standard_annual"]), created=1_800_000_000)
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        self.assertEqual((ent["plan"], ent["billing_interval"], ent["status"]), ("standard", "annual", "active"))
        self.assertEqual(ent["current_period_start"], billing.stripe_timestamp_to_iso(1_800_000_000))
        self.apply("customer.subscription.updated", self.subscription(SANDBOX_PRICE_IDS["vericexa_pro_monthly"], plan_meta="standard"), created=1_800_000_100)
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        self.assertEqual((ent["plan"], ent["billing_interval"]), ("pro", "monthly"))          # portal upgrade: price wins over stale metadata
        self.stripe.subscriptions.store["sub_1"] = self.subscription(SANDBOX_PRICE_IDS["vericexa_pro_monthly"], status="past_due")   # renewal failed
        self.apply("invoice.payment_failed", self.invoice(), created=1_800_000_200)
        self.assertEqual(repo.get_entitlement_by_workspace(self.conn, self.ws)["status"], "past_due")
        self.stripe.subscriptions.store["sub_1"] = self.subscription(SANDBOX_PRICE_IDS["vericexa_pro_monthly"], status="active")     # retried, paid
        self.apply("invoice.paid", self.invoice(), created=1_800_000_300)
        self.assertEqual(repo.get_entitlement_by_workspace(self.conn, self.ws)["status"], "active")
        self.apply("customer.subscription.deleted", self.subscription(SANDBOX_PRICE_IDS["vericexa_pro_monthly"], status="canceled"), created=1_800_000_400)
        self.assertEqual(repo.get_entitlement_by_workspace(self.conn, self.ws)["status"], "canceled")

    def test_unknown_or_legacy_price_never_grants(self):
        self.apply("customer.subscription.created", self.subscription("price_old_d086_quick_monthly", plan_meta="quick"))
        self.assertIsNone(repo.get_entitlement_by_workspace(self.conn, self.ws))
        self.apply("customer.subscription.created", self.subscription(SANDBOX_PRICE_IDS["vericexa_quick_onetime"], plan_meta="quick"))   # the Quick price is not a subscription
        self.assertIsNone(repo.get_entitlement_by_workspace(self.conn, self.ws))

    def test_quick_credit_requires_the_quick_price_actually_paid(self):
        for i, paid in enumerate(([(SANDBOX_PRICE_IDS["vericexa_standard_monthly"], 1)], [(SANDBOX_PRICE_IDS["vericexa_quick_onetime"], 2)],
                                  [(SANDBOX_PRICE_IDS["vericexa_quick_onetime"], 1), ("price_other", 1)], [], [("price_foreign_product", 1)])):
            self.apply("checkout.session.completed", self.quick_session("cs_bad_%d" % i, paid=paid))
        self.assertIsNone(repo.get_entitlement_by_workspace(self.conn, self.ws))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)
        mismatched = self.quick_session("cs_mismatch")
        mismatched["metadata"]["workspace_id"] = repo.create_workspace(self.conn, "Other WS", self.user)
        self.apply("checkout.session.completed", mismatched)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)

    def test_late_cancellation_of_an_old_subscription_never_overrides_a_quick_purchase(self):
        self.apply("customer.subscription.created", self.subscription(SANDBOX_PRICE_IDS["vericexa_standard_monthly"]))
        self.apply("customer.subscription.deleted", self.subscription(SANDBOX_PRICE_IDS["vericexa_standard_monthly"], status="canceled"))
        self.apply("checkout.session.completed", self.quick_session())
        self.apply("customer.subscription.deleted", self.subscription(SANDBOX_PRICE_IDS["vericexa_standard_monthly"], status="canceled"))   # redelivered later
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        self.assertEqual((ent["plan"], ent["status"]), ("quick", "active"))
        self.assertEqual(repo.usage_summary(self.conn, self.ws, ent)["scans_available"], 1)

    def test_quick_payment_never_overrides_a_live_subscription(self):
        self.apply("customer.subscription.created", self.subscription(SANDBOX_PRICE_IDS["vericexa_standard_monthly"]))
        self.apply("checkout.session.completed", self.quick_session())
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        self.assertEqual(ent["plan"], "standard")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)


# ---------------------------------------------------------------------------
# HTTP: submit admission, checkout, portal, members, usage
# ---------------------------------------------------------------------------

class SubmitAdmissionHttpTests(_WorkspaceStorageTestCase):
    def _workspace(self, plan, email):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        user_id = repo.get_user_by_email(conn, email)["id"]
        ws = repo.create_workspace(conn, "Admission WS", user_id)
        repo.create_entitlement(conn, ws, plan, "active", billing_interval=None if plan == "quick" else "monthly")
        conn.close()
        return cookie, ws

    def _submit(self, cookie, ws, source, mode="quick"):
        status, _, body = self.post_json("/workspaces/%s/jobs" % ws, {"mode": mode, "source": source}, headers={"Cookie": cookie})
        return status, json.loads(body)

    def test_quick_http_flow(self):
        cookie, ws = self._workspace("quick", "adm-quick@example.com")
        status, body = self._submit(cookie, ws, _sol(10))
        self.assertEqual((status, body["error"]), (402, "no_scan_credit"))
        conn = repo.connect(self.db_path)
        repo.grant_scan_credit(conn, "cs_http", ws)
        conn.close()
        status, body = self._submit(cookie, ws, _sol(3001))
        self.assertEqual((status, body["error"], body["effective_loc"], body["max_loc_per_scan"]), (413, "loc_per_scan_limit_exceeded", 3001, 3000))
        status, body = self._submit(cookie, ws, "// nothing here\n")
        self.assertEqual((status, body["error"]), (422, "no_source_code"))
        status, body = self._submit(cookie, ws, _sol(3000))
        self.assertEqual(status, 200)
        status, body = self._submit(cookie, ws, _sol(5))
        self.assertEqual((status, body["error"]), (402, "no_scan_credit"))
        status, _, raw = self.get("/workspaces/%s" % ws, headers={"Cookie": cookie})
        usage = json.loads(raw)["usage"]
        self.assertEqual((usage["plan"], usage["scans_available"], usage["scans_reserved"], usage["max_loc_per_scan"]), ("quick", 0, 1, 3000))

    def test_standard_http_quota(self):
        cookie, ws = self._workspace("standard", "adm-std@example.com")
        status, body = self._submit(cookie, ws, _sol(10001))
        self.assertEqual((status, body["error"]), (413, "loc_per_scan_limit_exceeded"))
        self.assertEqual(self._submit(cookie, ws, _sol(10000))[0], 200)
        self.assertEqual(self._submit(cookie, ws, _sol(9500))[0], 200)
        status, body = self._submit(cookie, ws, _sol(1000))
        self.assertEqual((status, body["error"], body["loc_remaining"]), (402, "loc_quota_exceeded", 500))
        usage = json.loads(self.get("/workspaces/%s" % ws, headers={"Cookie": cookie})[2])["usage"]
        self.assertEqual((usage["loc_used"], usage["loc_limit"], usage["state"], usage["max_members"]), (19500, 20000, "danger", 2))


class MemberLimitHttpTests(_WorkspaceStorageTestCase):
    def test_standard_allows_two_members_pro_five(self):
        for plan, limit in (("standard", 2), ("pro", 5)):
            email = "owner-%s@example.com" % plan
            cookie = self.request_and_confirm_login(email)
            conn = repo.connect(self.db_path)
            ws = repo.create_workspace(conn, "Members WS", repo.get_user_by_email(conn, email)["id"])
            repo.create_entitlement(conn, ws, plan, "active", billing_interval="monthly")
            conn.close()
            for i in range(limit - 1):
                status, _, _ = self.post_json("/workspaces/%s/members" % ws, {"email": "m%d-%s@example.com" % (i, plan), "role": "member"}, headers={"Cookie": cookie})
                self.assertEqual(status, 200)
            status, _, body = self.post_json("/workspaces/%s/members" % ws, {"email": "extra-%s@example.com" % plan, "role": "member"}, headers={"Cookie": cookie})
            self.assertEqual((status, json.loads(body)["error"]), (409, "member_limit_reached"))


class CheckoutSandboxCatalogHttpTests(billing_tests._BillingHttpTestCase):
    def setUp(self):
        with mock.patch.object(billing_tests, "PRICE_ALLOWLIST", dict(SANDBOX_PRICE_IDS)):
            super().setUp()

    def test_all_five_price_modes_check_out_with_their_sandbox_prices(self):
        cookie, ws, _ = self._login_and_own_workspace("chk-owner@example.com")
        for payload in ({"workspace_id": ws, "plan": "quick", "interval": "one_time"}, {"workspace_id": ws, "plan": "quick"}):
            status, _, _ = self.post_json("/billing/checkout", payload, headers={"Cookie": cookie})
            self.assertEqual(status, 200)
            params = self.billing._client.checkout.sessions.calls[-1]
            self.assertEqual((params["mode"], params["line_items"][0]["price"]), ("payment", "price_1UMFnY1jc8PYYLrPXxSbSEUF"))
            self.assertNotIn("subscription_data", params)
        for plan, interval in (("quick", "monthly"), ("quick", "annual"), ("pro", "one_time")):
            status, _, body = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": plan, "interval": interval}, headers={"Cookie": cookie})
            self.assertEqual(status, 400, (plan, interval))
        for plan, interval in (("standard", "monthly"), ("standard", "annual"), ("pro", "monthly"), ("pro", "annual")):
            status, _, _ = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": plan, "interval": interval}, headers={"Cookie": cookie})
            self.assertEqual(status, 200, (plan, interval))
            self.assertEqual(self.billing._client.checkout.sessions.calls[-1]["line_items"][0]["price"], SANDBOX_PRICE_IDS[plans.price_mode_key(plan, interval)])


class QuickCheckoutAndPortalHttpTests(billing_tests._BillingHttpTestCase):
    def test_quick_rules(self):
        cookie, ws, _ = self._login_and_own_workspace("quick-owner@example.com")
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": "quick", "interval": "one_time"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(self.billing._client.checkout.sessions.calls[-1]["mode"], "payment")
        conn = repo.connect(self.db_path)
        repo.create_entitlement(conn, ws, "quick", "active", stripe_customer_id="cus_quick")
        repo.grant_scan_credit(conn, "cs_paid", ws)
        conn.close()
        status, _, body = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": "quick", "interval": "one_time"}, headers={"Cookie": cookie})
        self.assertEqual(status, 409)                                                         # unused Quick scan already available
        status, _, _ = self.post_json("/billing/checkout", {"workspace_id": ws, "plan": "standard", "interval": "monthly"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)                                                         # upgrading from Quick is allowed
        status, _, body = self.post_json("/billing/portal", {"workspace_id": ws}, headers={"Cookie": cookie})
        self.assertEqual((status, json.loads(body)["error"]), (409, "this workspace has no subscription to manage"))

    def test_signed_quick_webhook_grants_exactly_one_credit(self):
        ws = self._create_workspace("Quick Hook WS")
        self.billing._client.checkout.sessions.line_items.store["cs_test_quick_hook"] = [(billing_tests.PRICE_ALLOWLIST["vericexa_quick_onetime"], 1)]
        session = {"id": "cs_test_quick_hook", "mode": "payment", "payment_status": "paid", "client_reference_id": ws, "customer": "cus_qh",
                   "metadata": {"workspace_id": ws, "plan": "quick", "interval": "one_time"}}
        first = billing_tests._event("checkout.session.completed", "evt_quick_1", session, created=1_800_000_000)
        self.assertEqual(self.post_webhook(first)[0], 200)
        status, _, body = self.post_webhook(first)                                                     # same event.id redelivered
        self.assertEqual((status, json.loads(body).get("duplicate")), (200, True))
        retry = billing_tests._event("checkout.session.async_payment_succeeded", "evt_quick_2", session, created=1_800_000_100)
        self.assertEqual(self.post_webhook(retry)[0], 200)                                             # new event, same session
        conn = repo.connect(self.db_path)
        ent = repo.get_entitlement_by_workspace(conn, ws)
        credits = conn.execute("SELECT id, status FROM scan_credits WHERE workspace_id = ?", (ws,)).fetchall()
        conn.close()
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_subscription_id"]), ("quick", "active", None))
        self.assertEqual([tuple(c) for c in credits], [("cs_test_quick_hook", "available")])

    def test_portal_for_every_subscription_mode(self):
        for plan, interval in (("standard", "monthly"), ("standard", "annual"), ("pro", "monthly"), ("pro", "annual")):
            cookie, ws, _ = self._login_and_own_workspace("portal-%s-%s@example.com" % (plan, interval))
            conn = repo.connect(self.db_path)
            repo.create_entitlement(conn, ws, plan, "active", stripe_customer_id="cus_%s_%s" % (plan, interval),
                                    stripe_subscription_id="sub_%s_%s" % (plan, interval), billing_interval=interval)
            conn.close()
            status, _, _ = self.post_json("/billing/portal", {"workspace_id": ws}, headers={"Cookie": cookie})
            self.assertEqual(status, 200, (plan, interval))


if __name__ == "__main__":
    unittest.main()
