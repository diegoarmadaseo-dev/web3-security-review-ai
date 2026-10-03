"""Tests for the free Trial, sign-up, email verification and anti-abuse
(docs/decisiones.md D-112): backend/trial.py, backend/email_policy.py, the
Trial parts of backend/repository.py, backend/auth.py, backend/retention.py,
backend/worker_supervisor.py and the sign-up/Trial endpoints and gating in
backend/http_app.py. No network, no LLM, no Docker; Stripe is the tests'
fake client. SQLite (real-Postgres checks live in
tests/test_backend_postgres_integration.py).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.auth as auth  # noqa: E402
import backend.email_policy as email_policy  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import backend.retention as retention  # noqa: E402
import backend.targeted_review as targeted_review  # noqa: E402
import backend.trial as trial  # noqa: E402
import backend.worker_supervisor as ws_mod  # noqa: E402
from tests.test_backend_billing import PRICE_ALLOWLIST, _make_billing  # noqa: E402
from tests.test_backend_commercial import _sol  # noqa: E402
from tests.test_backend_commercial_guards import _GuardsHttpCase  # noqa: E402
from tests.test_backend_http_app import HOST, _CapturingEmailSender, _capture_stderr  # noqa: E402
from tests.test_backend_projects_multifile import A_SOL, B_SOL  # noqa: E402
from tests.test_backend_worker_supervisor_no_docker import _CollectingAlertSender  # noqa: E402

POLICY = email_policy.load_policy()


# ---------------------------------------------------------------------------
# Units: normalization, disposable denylist, catalog
# ---------------------------------------------------------------------------

class EmailPolicyTests(unittest.TestCase):
    def test_one_normalization_trim_and_lowercase_only(self):
        self.assertEqual(email_policy.normalize_email("  Alice@Example.COM "), "alice@example.com")
        self.assertEqual(email_policy.normalize_email("a.b+tag@gmail.com"), "a.b+tag@gmail.com")   # no provider-specific rewriting
        self.assertEqual(email_policy.normalize_email("X@Y.io"), auth.normalize_email("X@Y.io"))
        for bad in ("", "no-at", "a@b", None, 5, "a@" + "b" * 260 + ".com"):
            with self.subTest(email=bad):
                with self.assertRaises(auth.AuthError):
                    email_policy.normalize_email(bad)

    def test_disposable_domains_and_subdomains(self):
        for email in ("x@mailinator.com", "x@inbox.mailinator.com", "x@yopmail.com", "x@10minutemail.com", "x@guerrillamail.com"):
            self.assertTrue(POLICY.is_disposable(email), email)
        for email in ("x@gmail.com", "x@example.com", "x@notmailinator.com.example", "x@mailinator.co", "x@company.io"):
            self.assertFalse(POLICY.is_disposable(email), email)
        self.assertGreater(POLICY.size, 50)

    def test_denylist_is_data_and_can_be_extended(self):
        d = tempfile.mkdtemp(prefix="d112-deny-")
        self.addCleanup(lambda: shutil.rmtree(d, True))
        extra = os.path.join(d, "extra.txt")
        with open(extra, "w", encoding="utf-8") as h:
            h.write("# operator list\nThrowaway.Example\n\n")
        policy = email_policy.load_policy(extra)
        self.assertTrue(policy.is_disposable("a@throwaway.example"))
        self.assertTrue(policy.is_disposable("a@mailinator.com"))                     # bundled list kept
        self.assertFalse(email_policy.load_policy().is_disposable("a@throwaway.example"))
        self.assertFalse(email_policy.DisposableDomainPolicy([]).is_disposable("a@mailinator.com"))

    def test_trial_is_a_separate_free_entitlement(self):
        self.assertEqual(sorted(plans.PLANS), ["pro", "quick", "standard"])          # paid catalog unchanged
        self.assertNotIn("trial", {m["plan"] for m in plans.PRICE_MODES.values()})   # never sold through Stripe
        spec = plans.plan_spec("trial")
        self.assertEqual((spec["max_loc_per_scan"], spec["scans_per_email"], spec["max_projects"], spec["history_days"],
                          spec["report_downloads"], spec["layer2"], spec["billing_type"]), (500, 1, 1, 7, False, False, "free"))
        self.assertEqual(plans.PLAN_FEATURES["trial"], frozenset())
        self.assertFalse(plans.plan_has_feature("trial", plans.FEATURE_PRIVATE_GITHUB))
        self.assertEqual(plans.PLAN_ALLOWED_MODES["trial"], frozenset({"quick"}))
        self.assertIs(plans.plan_spec("quick"), plans.PLANS["quick"])
        self.assertIsNone(plans.plan_spec("enterprise"))
        self.assertIsNone(repo.technical_budget_limit_units("trial"))


# ---------------------------------------------------------------------------
# Entitlement (repository + trial.py)
# ---------------------------------------------------------------------------

class TrialEntitlementTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        self.conn = repo.connect(self.db_path)
        repo.init_schema(self.conn)
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self.conn.close)

    def verified_user(self, email):
        uid = repo.create_user(self.conn, email)
        repo.mark_email_verified(self.conn, uid)
        return repo.get_user(self.conn, uid)

    def test_grant_once_then_refused_for_ever(self):
        user = self.verified_user("one@example.com")
        ws = trial.grant_for_user(self.conn, user, POLICY)
        ent = repo.get_entitlement_by_workspace(self.conn, ws)
        self.assertEqual((ent["plan"], ent["status"], ent["stripe_customer_id"], ent["stripe_subscription_id"]), ("trial", "active", None, None))
        self.assertEqual(repo.get_trial_grant(self.conn, "one@example.com")["status"], "available")
        self.assertEqual(trial.status_for_user(self.conn, user, POLICY)["state"], trial.STATE_ACTIVE)
        with self.assertRaises(trial.TrialError) as ctx:
            trial.grant_for_user(self.conn, user, POLICY)
        self.assertEqual((ctx.exception.code, ctx.exception.http_status), ("trial_already_used", 409))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM entitlements WHERE plan = 'trial'").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)       # never a Quick credit

    def test_unverified_and_disposable_are_refused_without_side_effects(self):
        uid = repo.create_user(self.conn, "unverified@example.com")
        with self.assertRaises(trial.TrialError) as ctx:
            trial.grant_for_user(self.conn, repo.get_user(self.conn, uid), POLICY)
        self.assertEqual(ctx.exception.code, "email_not_verified")
        self.assertEqual(trial.status_for_user(self.conn, repo.get_user(self.conn, uid), POLICY)["state"], trial.STATE_VERIFICATION_REQUIRED)
        user = self.verified_user("x@mailinator.com")
        with self.assertRaises(trial.TrialError) as ctx:
            trial.grant_for_user(self.conn, user, POLICY)
        self.assertEqual((ctx.exception.code, ctx.exception.http_status), ("trial_not_eligible", 403))
        self.assertNotIn("mailinator", ctx.exception.detail)
        self.assertEqual(trial.status_for_user(self.conn, user, POLICY)["state"], trial.STATE_NOT_ELIGIBLE)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM trial_grants").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 0)

    def test_account_deletion_and_recreation_never_yield_a_second_trial(self):
        user = self.verified_user("again@example.com")
        ws = trial.grant_for_user(self.conn, user, POLICY)
        storage_dir = tempfile.mkdtemp(prefix="d112-del-")
        self.addCleanup(lambda: shutil.rmtree(storage_dir, True))
        retention.delete_workspace_data(self.conn, object_storage.LocalFilesystemStorage(storage_dir, sign_secret="x"), ws)
        # The account itself goes away (its address released), then the same
        # person signs up again with the same email: a brand-new users row.
        self.conn.execute("UPDATE users SET email = ?, deleted_at = ? WHERE id = ?", ("deleted-%s@invalid.example" % user["id"], repo.utcnow_iso(), user["id"]))
        self.conn.commit()
        again = self.verified_user("Again@Example.com".lower())
        self.assertNotEqual(again["id"], user["id"])
        self.assertEqual(trial.status_for_user(self.conn, again, POLICY)["state"], trial.STATE_USED)
        with self.assertRaises(trial.TrialError) as ctx:
            trial.grant_for_user(self.conn, again, POLICY)
        self.assertEqual(ctx.exception.code, "trial_already_used")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM entitlements WHERE plan = 'trial'").fetchone()[0], 1)

    def test_concurrent_trial_project_creations_yield_exactly_one(self):
        ws = trial.grant_for_user(self.conn, self.verified_user("proj-race@example.com"), POLICY)
        for round_ in range(3):                                          # repeated: the race is real, not a one-off
            self.conn.execute("DELETE FROM projects WHERE workspace_id = ?", (ws,))
            self.conn.commit()
            results, barrier = [], threading.Barrier(8)

            def attempt(i):
                conn = repo.connect(self.db_path)
                try:
                    barrier.wait()
                    repo.create_project_capped(conn, ws, "P%d-%d" % (round_, i), 1)
                    results.append("ok")
                except repo.ProjectLimitError:
                    results.append("limit")
                except Exception as exc:   # pragma: no cover - surfaced below
                    results.append(repr(exc))
                finally:
                    conn.close()

            threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
            [t.start() for t in threads]
            [t.join(30) for t in threads]
            self.assertEqual(sorted(results), ["limit"] * 7 + ["ok"])
            self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM projects WHERE workspace_id = ? AND deleted_at IS NULL", (ws,)).fetchone()[0], 1)
        with self.assertRaises(repo.ProjectNameTakenError):              # same name as the live one: name rule, nothing created
            live = self.conn.execute("SELECT name FROM projects WHERE workspace_id = ?", (ws,)).fetchone()[0]
            repo.create_project_capped(self.conn, ws, live, 2)

    def test_concurrent_grants_for_one_email_yield_exactly_one(self):
        user = self.verified_user("race@example.com")
        results, barrier = [], threading.Barrier(6)

        def attempt():
            conn = repo.connect(self.db_path)
            try:
                barrier.wait()
                results.append(("ok", repo.grant_trial(conn, "race@example.com", user["id"])))
            except repo.TrialAlreadyGrantedError:
                results.append(("refused", None))
            except Exception as exc:   # pragma: no cover - surfaced by the assertion below
                results.append(("error", repr(exc)))
            finally:
                conn.close()

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertEqual(sorted(r[0] for r in results), ["ok"] + ["refused"] * 5)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 1)   # losers left nothing behind
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM entitlements").fetchone()[0], 1)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _TrialHttpCase(_GuardsHttpCase):
    MAX_PENDING = 5
    RATE = 200
    POLICY = None

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed = repo.connect(self.db_path)
        repo.init_schema(seed)
        seed.close()
        self.storage_dir = tempfile.mkdtemp(prefix="http-trial-")
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="test-only-secret")
        self.email_sender = _CapturingEmailSender()
        self.alerts = _CollectingAlertSender()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path), email_sender=self.email_sender, host_allowlist=[HOST],
            host=HOST, port=0, secure_cookies=False, storage=self.storage, alert_sender=self.alerts, billing=_make_billing(),
            max_pending_jobs_per_workspace=self.MAX_PENDING, submit_rate_limit_per_window=self.RATE, disposable_policy=self.POLICY,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.05)
        self.addCleanup(lambda: shutil.rmtree(self.storage_dir, ignore_errors=True))
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)

    def db(self):
        conn = repo.connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def jget(self, path, cookie=None):
        status, headers, body = self.get(path, headers={"Cookie": cookie} if cookie else None)
        return status, headers, json.loads(body) if body and body[:1] in (b"{", b"[") else body

    def jpost(self, path, cookie, payload=None, **kw):
        status, headers, body = self.post_json(path, payload if payload is not None else {}, headers=dict({"Cookie": cookie}, **kw))
        return status, headers, json.loads(body) if body else None

    def signup(self, email):
        return self.post_json("/auth/signup", {"email": email})

    def verify_last(self):
        token = self.email_sender.last_token()
        self.get("/auth/verify?token=%s" % token)                            # scanner/preview: never consumes
        status, headers, _ = self.post_form("/auth/verify", {"token": token, "redirect": "/app#/dashboard"})
        return status, headers, token

    def signup_and_verify(self, email):
        status, _, body = self.signup(email)
        self.assertEqual(status, 200, body)
        status, headers, _ = self.verify_last()
        self.assertEqual(status, 303)
        return headers["Set-Cookie"].split(";")[0]

    def trial_ws(self, cookie):
        state = self.jget("/trial", cookie)[2]["trial"]
        self.assertEqual(state["state"], "active", state)
        return state["workspace_id"]

    def submit(self, cookie, ws, payload):
        return self.jpost("/workspaces/%s/jobs" % ws, cookie, dict({"mode": "quick"}, **payload))

    def finish(self, job_id, ok=True, advisory=False):
        """Plays the worker: claims and finishes the job (succeeded with a
        stored report, or failed)."""
        conn = self.db()
        claimed = repo.claim_next_job(conn, "w")
        self.assertEqual(claimed["id"], job_id)
        repo.finalize_job_attempt(conn, job_id, claimed["workspace_id"], claimed["attempt_count"], "w", "claimed", "running")
        if not ok:
            repo.finalize_job_attempt(conn, job_id, claimed["workspace_id"], claimed["attempt_count"], "w", "running", "failed", error="engine error")
            return None
        key = object_storage.workspace_key(claimed["workspace_id"], "reports", job_id)
        self.storage.put_object(key, b"# Automated security review\n", content_type="text/markdown")
        self.storage.put_object(object_storage.report_json_key(key), json.dumps({"findings": []}).encode(), content_type="application/json")
        if advisory:
            self.storage.put_object(key + targeted_review.OBJECT_SUFFIX, b'{"status": "completed"}', content_type="application/json")
        res = repo.finalize_job_attempt(conn, job_id, claimed["workspace_id"], claimed["attempt_count"], "w", "running", "succeeded",
                                        report_storage_ref=key, report_score_status="computed", report_score=90, report_risk_band="LOW")
        return res["report_id"]


class SignupAndVerificationTests(_TrialHttpCase):
    def test_signup_sends_a_link_and_only_verification_grants_the_trial(self):
        status, _, body = self.signup("  New.User@Example.com ")
        self.assertEqual((status, json.loads(body)["ok"]), (200, True))
        conn = self.db()
        self.assertEqual(conn.execute("SELECT email, purpose FROM auth_tokens").fetchall()[0][:], ("new.user@example.com", "signup"))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM trial_grants").fetchone()[0], 0)     # nothing before verification
        self.assertIsNone(repo.get_user_by_email(conn, "new.user@example.com"))                     # no account until the link is used
        self.assertIn("redirect=%2Fapp%23%2Fdashboard", self.email_sender.sent[-1][2])
        status, headers, _ = self.verify_last()
        self.assertEqual((status, headers["Location"]), (303, "/app#/dashboard"))
        cookie = headers["Set-Cookie"].split(";")[0]
        state = self.jget("/trial", cookie)[2]["trial"]
        self.assertEqual({k: state[k] for k in ("state", "email_verified", "max_loc_per_scan", "scans_remaining", "max_projects", "history_days")},
                         {"state": "active", "email_verified": True, "max_loc_per_scan": 500, "scans_remaining": 1, "max_projects": 1, "history_days": 7})
        ws = self.jget("/workspaces/%s" % state["workspace_id"], cookie)[2]
        self.assertEqual((ws["entitlement"]["plan"], ws["usage"]["usage_model"], ws["usage"]["scans_available"], ws["admission"]["features"],
                          ws["admission"]["allowed_modes"]), ("trial", "trial", 1, [], ["quick"]))
        self.assertEqual(repo.get_trial_grant(conn, "new.user@example.com")["status"], "available")

    def test_same_answer_for_new_and_existing_accounts(self):
        conn = self.db()
        repo.create_user(conn, "known@example.com")
        conn.commit()
        self.assertEqual(self.signup("known@example.com")[2], self.signup("unknown@example.com")[2])

    def test_second_signup_with_the_same_email_gets_no_second_trial(self):
        cookie = self.signup_and_verify("twice@example.com")
        first_ws = self.trial_ws(cookie)
        cookie2 = self.signup_and_verify("TWICE@example.com")
        self.assertEqual(self.trial_ws(cookie2), first_ws)
        status, _, body = self.jpost("/trial/activate", cookie2)
        self.assertEqual((status, body["error"]), (409, "trial_already_used"))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM entitlements WHERE plan = 'trial'").fetchone()[0], 1)

    def test_expired_and_reused_tokens_grant_nothing(self):
        self.signup("expired@example.com")
        conn = self.db()
        past = datetime.now(timezone.utc) - timedelta(minutes=30)
        conn.execute("UPDATE auth_tokens SET created_at = ?, expires_at = ?", (past.isoformat(), (past + timedelta(minutes=15)).isoformat()))
        conn.commit()
        status, headers, _ = self.verify_last()
        self.assertEqual(status, 200)                                             # the "link expired" page, no session
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM trial_grants").fetchone()[0], 0)
        self.signup("reuse@example.com")
        status, headers, token = self.verify_last()
        self.assertEqual(status, 303)
        status, headers, _ = self.post_form("/auth/verify", {"token": token, "redirect": "/app"})
        self.assertEqual(status, 200)                                             # replay refused
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM trial_grants").fetchone()[0], 1)

    def test_resend_and_signup_rate_limits(self):
        for _ in range(auth.RATE_LIMIT_MAX_PER_EMAIL):
            self.assertEqual(self.signup("spam@example.com")[0], 200)
        status, _, body = self.signup("spam@example.com")
        self.assertEqual((status, json.loads(body)["error"]), (429, "signup_rate_limited"))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM auth_tokens WHERE email = 'spam@example.com'").fetchone()[0], auth.RATE_LIMIT_MAX_PER_EMAIL)
        self.assertEqual(len(self.email_sender.sent), auth.RATE_LIMIT_MAX_PER_EMAIL)
        status, _, _ = self.signup("other-spam@example.com")      # per-email limit does not block a different address
        self.assertEqual(status, 200)

    def test_disposable_domains_are_refused_before_anything_exists(self):
        for email in ("x@mailinator.com", "X@Inbox.Mailinator.COM", "y@yopmail.fr"):
            with self.subTest(email=email):
                status, _, body = self.signup(email)
                self.assertEqual((status, json.loads(body)["error"]), (422, "disposable_email_not_allowed"))
                self.assertNotIn("mailinator", json.loads(body)["detail"].lower())
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0], 0)
        self.assertEqual(self.email_sender.sent, [])
        # Signing in through the ordinary login link still works, but never a Trial.
        cookie = self.request_and_confirm_login("z@mailinator.com")
        self.assertEqual(self.jget("/trial", cookie)[2]["trial"]["state"], "not_eligible")
        status, _, body = self.jpost("/trial/activate", cookie)
        self.assertEqual((status, body["error"]), (403, "trial_not_eligible"))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM trial_grants").fetchone()[0], 0)

    def test_invalid_oversized_and_cross_origin_signups(self):
        for bad in ("nope", "", "a@" + "b" * 260 + ".com", None, 7):
            with self.subTest(email=bad):
                status, _, body = self.signup(bad)
                self.assertEqual((status, json.loads(body)["error"]), (400, "invalid_email"))
        status, _, _ = self.post_json("/auth/signup", {"email": "a@example.com"}, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.post_json("/auth/signup", {"email": "a@example.com"}, headers={"Origin": None})
        self.assertEqual(status, 403)
        status, _, _ = self.post_json("/trial/activate", {}, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(self.email_sender.sent, [])

    def test_html_signup_flow_and_pages(self):
        status, _, body = self.get("/auth/signup")
        self.assertEqual(status, 200)
        self.assertIn(b'action="/auth/signup"', body)
        self.assertIn(b'href="/auth/signup"', self.get("/auth/login")[2])
        status, _, body = self.post_form("/auth/signup", {"email": "form@example.com"})
        self.assertEqual(status, 200)
        self.assertIn(b"verification link has been sent", body)
        status, _, body = self.post_form("/auth/signup", {"email": "form@mailinator.com"})
        self.assertEqual(status, 422)
        self.assertIn(b"not eligible for the free Trial", body)
        status, _, body = self.post_form("/auth/signup", {"email": "<script>@x"})
        self.assertNotIn(b"<script>", body)

    def test_tokens_never_reach_logs(self):
        with _capture_stderr() as log:
            self.signup("logs@example.com")
            _, _, token = self.verify_last()
        self.assertNotIn(token, log.getvalue())
        self.assertIn("token=[REDACTED]", log.getvalue())

    def test_trial_activation_from_the_app_for_a_verified_login(self):
        cookie = self.request_and_confirm_login("later@example.com")
        self.assertEqual(self.jget("/trial", cookie)[2]["trial"]["state"], "available")
        status, _, body = self.jpost("/trial/activate", cookie)
        self.assertEqual(status, 200)
        self.assertEqual(self.jget("/trial", cookie)[2]["trial"]["workspace_id"], body["workspace_id"])
        self.assertEqual(self.jpost("/trial/activate", cookie)[0], 409)
        self.assertEqual(self.jget("/trial")[0], 401)
        self.assertEqual(self.jpost("/trial/activate", "session=nope")[0], 401)

    def test_concurrent_activation_grants_one_trial(self):
        cookie = self.request_and_confirm_login("burst@example.com")
        results, barrier = [], threading.Barrier(5)

        def go():
            barrier.wait()
            results.append(self.jpost("/trial/activate", cookie)[0])

        threads = [threading.Thread(target=go) for _ in range(5)]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertEqual(sorted(results), [200, 409, 409, 409, 409])
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 1)


class TrialAdmissionTests(_TrialHttpCase):
    def setUp(self):
        super().setUp()
        self.cookie = self.signup_and_verify("scan@example.com")
        self.ws = self.trial_ws(self.cookie)

    def test_500_accepted_501_and_0_refused(self):
        status, _, body = self.submit(self.cookie, self.ws, {"source": _sol(501), "dry_run": True})
        self.assertEqual((status, body["error"], body["effective_loc"], body["max_loc_per_scan"]), (413, "loc_per_scan_limit_exceeded", 501, 500))
        status, _, body = self.submit(self.cookie, self.ws, {"source": "// only a comment\n"})
        self.assertEqual((status, body["error"]), (422, "no_source_code"))
        status, _, body = self.submit(self.cookie, self.ws, {"source": _sol(500), "dry_run": True})
        self.assertEqual((status, body["effective_loc"], body["max_loc_per_scan"]), (200, 500, 500))
        status, _, body = self.submit(self.cookie, self.ws, {"source": _sol(500)})
        self.assertEqual(status, 200, body)
        usage = repo.get_job_usage(self.db(), body["job_id"])
        self.assertEqual((usage["plan"], usage["usage_model"], usage["status"]), ("trial", "trial", "reserved"))
        self.assertEqual(repo.get_trial_grant(self.db(), "scan@example.com")["status"], "reserved")

    def test_second_scan_is_refused_for_ever_and_a_failed_scan_gives_the_trial_back(self):
        first = self.submit(self.cookie, self.ws, {"source": _sol(50)})[2]["job_id"]
        status, _, body = self.submit(self.cookie, self.ws, {"source": _sol(50)})
        self.assertEqual((status, body["error"]), (402, "trial_already_used"))
        self.finish(first, ok=False)                                         # never served a result
        self.assertEqual(repo.get_trial_grant(self.db(), "scan@example.com")["status"], "available")
        second = self.submit(self.cookie, self.ws, {"source": _sol(50)})[2]["job_id"]
        self.finish(second)
        grant = repo.get_trial_grant(self.db(), "scan@example.com")
        self.assertEqual((grant["status"], grant["job_id"]), ("consumed", second))
        self.assertIsNotNone(grant["consumed_at"])
        for _ in range(2):
            status, _, body = self.submit(self.cookie, self.ws, {"source": _sol(50)})
            self.assertEqual((status, body["error"]), (402, "trial_already_used"))
        self.assertEqual(self.jget("/trial", self.cookie)[2]["trial"]["state"], "used")

    def test_two_concurrent_project_requests_create_exactly_one(self):
        results, barrier = [], threading.Barrier(2)

        def go(name):
            barrier.wait()
            status, _, body = self.jpost("/workspaces/%s/projects" % self.ws, self.cookie, {"name": name})
            results.append((status, body.get("error")))

        threads = [threading.Thread(target=go, args=(n,)) for n in ("Alpha", "Beta")]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertEqual(sorted(results, key=lambda r: r[0]), [(200, None), (409, "project_limit_reached")])
        self.assertEqual(len(self.jget("/workspaces/%s/projects" % self.ws, self.cookie)[2]["projects"]), 1)

    def test_one_project_only(self):
        status, _, body = self.jpost("/workspaces/%s/projects" % self.ws, self.cookie, {"name": "Mine"})
        self.assertEqual(status, 200)
        status, _, body = self.jpost("/workspaces/%s/projects" % self.ws, self.cookie, {"name": "Second"})
        self.assertEqual((status, body["error"], body["max_projects"]), (409, "project_limit_reached", 1))

    def test_multi_file_and_zip(self):
        status, _, body = self.submit(self.cookie, self.ws, {"files": [{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}], "dry_run": True})
        self.assertEqual((status, body["source_kind"], [f["path"] for f in body["files"]]), (200, "files", ["src/A.sol", "src/B.sol"]))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("src/A.sol", A_SOL)
            zf.writestr("src/B.sol", B_SOL)
        status, _, body = self.submit(self.cookie, self.ws, {"archive": {"format": "zip", "content_base64": base64.b64encode(buf.getvalue()).decode()}})
        self.assertEqual((status, body["source_kind"]), (200, "archive"))

    def test_idempotency_mode_and_github_separation(self):
        first = self.submit(self.cookie, self.ws, {"source": _sol(40), "idempotency_key": "k1"})
        second = self.submit(self.cookie, self.ws, {"source": _sol(40), "idempotency_key": "k1"})
        self.assertEqual((second[0], second[2]["job_id"], second[2]["duplicate"]), (200, first[2]["job_id"], True))
        status, _, body = self.submit(self.cookie, self.ws, {"mode": "standard", "source": _sol(40)})
        self.assertEqual((status, body["error"]), (403, "mode not included in the current plan"))
        for status, _, body in (self.jget("/workspaces/%s/github" % self.ws, self.cookie), self.submit(self.cookie, self.ws, {"github": {"repository_id": 1}})):
            self.assertEqual((status, body["error"], body["plan"]), (403, "feature_not_available", "trial"))

    def test_trial_is_bound_to_its_workspace(self):
        other_cookie = self.request_and_confirm_login("other@example.com")
        status, _, _ = self.submit(other_cookie, self.ws, {"source": _sol(10)})
        self.assertEqual(status, 403)
        conn = self.db()
        own = repo.create_workspace(conn, "Own", repo.get_user_by_email(conn, "other@example.com")["id"])
        status, _, body = self.submit(other_cookie, own, {"source": _sol(10)})
        self.assertEqual(status, 402)                                           # no entitlement: someone else's Trial is not usable here
        status, _, body = self.submit(self.cookie, own, {"source": _sol(10)})
        self.assertEqual(status, 403)


class TrialQueueGuardTests(_TrialHttpCase):
    MAX_PENDING = 1
    RATE = 3

    def test_pending_jobs_and_rate_limit_still_apply(self):
        cookie = self.signup_and_verify("guards@example.com")
        ws = self.trial_ws(cookie)
        conn = self.db()
        contract = repo.create_contract(conn, ws, "s3://x", "h", "n")
        repo.enqueue_job(conn, ws, contract, repo.get_user_by_email(conn, "guards@example.com")["id"], "quick")
        status, _, body = self.submit(cookie, ws, {"source": _sol(10)})
        self.assertEqual((status, body["error"]), (429, "too_many_pending_jobs"))
        self.submit(cookie, ws, {"source": _sol(10)})
        self.submit(cookie, ws, {"source": _sol(10)})
        status, headers, body = self.submit(cookie, ws, {"source": _sol(10)})
        self.assertEqual((status, body["error"]), (429, "submit_rate_limited"))
        self.assertIn("Retry-After", headers)
        self.assertEqual(repo.get_trial_grant(conn, "guards@example.com")["status"], "available")


class TrialReportAndHistoryTests(_TrialHttpCase):
    def setUp(self):
        super().setUp()
        self.cookie = self.signup_and_verify("report@example.com")
        self.ws = self.trial_ws(self.cookie)
        self.job = self.submit(self.cookie, self.ws, {"source": _sol(30)})[2]["job_id"]
        self.report = self.finish(self.job, advisory=True)

    def test_report_is_viewable_without_downloads_or_layer2(self):
        status, _, doc = self.jget("/workspaces/%s/reports/%s/document" % (self.ws, self.report), self.cookie)
        self.assertEqual((status, doc["trial"], doc["downloads"], doc["advisory"]), (200, True, False, None))
        self.assertEqual(doc["scored_report"], {"findings": []})
        for fmt in ("json", "markdown"):
            status, _, body = self.jget("/workspaces/%s/reports/%s/download?format=%s" % (self.ws, self.report, fmt), self.cookie)
            self.assertEqual((status, body["error"], body["feature"]), (403, "feature_not_available", "report_download"))
        status, _, body = self.jget("/workspaces/%s/reports/%s" % (self.ws, self.report), self.cookie)
        self.assertEqual(status, 200)
        self.assertNotIn("report_url", body["report"])
        rows = self.jget("/workspaces/%s/jobs" % self.ws, self.cookie)[2]["jobs"]
        self.assertEqual([r["id"] for r in rows], [self.job])

    def test_report_is_not_accessible_cross_tenant(self):
        other = self.request_and_confirm_login("intruder@example.com")
        for path in ("/workspaces/%s/reports/%s/document", "/workspaces/%s/reports/%s"):
            self.assertEqual(self.jget(path % (self.ws, self.report), other)[0], 403)
        conn = self.db()
        own = repo.create_workspace(conn, "Own", repo.get_user_by_email(conn, "intruder@example.com")["id"])
        self.assertEqual(self.jget("/workspaces/%s/reports/%s/document" % (own, self.report), other)[0], 404)

    def test_seven_day_history(self):
        conn = self.db()
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        conn.execute("UPDATE analysis_jobs SET created_at = ? WHERE id = ?", (old, self.job))
        conn.commit()
        self.assertEqual(self.jget("/workspaces/%s/jobs" % self.ws, self.cookie)[2]["jobs"], [])
        self.assertEqual(self.jget("/workspaces/%s/reports" % self.ws, self.cookie)[2]["reports"], [])
        for path in ("/workspaces/%s/reports/%s/document" % (self.ws, self.report), "/workspaces/%s/jobs/%s" % (self.ws, self.job)):
            status, _, body = self.jget(path, self.cookie)
            self.assertEqual((status, body["error"]), (410, "trial_history_expired"))
        self.assertEqual(retention.purge_expired_trial_results(conn, self.storage, dry_run=True), {"dry_run": True, "would_purge": 1})
        result = retention.purge_expired_trial_results(conn, self.storage, dry_run=False)
        self.assertEqual(result, {"dry_run": False, "purged": 2})
        self.assertIsNotNone(repo.get_report_by_id(conn, self.report)["purged_at"])
        self.assertEqual(retention.purge_expired_trial_results(conn, self.storage, dry_run=False)["purged"], 0)

    def test_worker_never_runs_layer2_for_a_trial_scan(self):
        config = ws_mod.WorkerConfig(docker_image="i", network_name="n", proxy_host="h", proxy_port=1, llm_api_key="k", llm_model="m", targeted_review_enabled=True)
        conn = self.db()
        self.assertFalse(ws_mod._config_for_job(conn, config, self.job).targeted_review_enabled)
        self.assertNotIn("TARGETED_REVIEW_ENABLED=1", ws_mod.build_docker_create_args(ws_mod._config_for_job(conn, config, self.job), "c"))
        self.assertTrue(config.targeted_review_enabled)                          # the shared config is never mutated
        paid = repo.create_workspace(conn, "Paid", repo.get_user_by_email(conn, "report@example.com")["id"])
        repo.create_entitlement(conn, paid, "standard", "active", billing_interval="monthly")
        contract = repo.create_contract(conn, paid, "s3://y", "h", "n")
        job = repo.enqueue_job_with_usage(conn, paid, contract, repo.get_user_by_email(conn, "report@example.com")["id"], "standard", None,
                                          repo.get_entitlement_by_workspace(conn, paid), 100)
        self.assertIs(ws_mod._config_for_job(conn, config, job), config)


class TrialBillingTests(_TrialHttpCase):
    def test_trial_creates_nothing_in_stripe_and_conversion_still_works(self):
        cookie = self.signup_and_verify("convert@example.com")
        ws = self.trial_ws(cookie)
        conn = self.db()
        ent = repo.get_entitlement_by_workspace(conn, ws)
        self.assertEqual((ent["stripe_customer_id"], ent["stripe_subscription_id"], ent["billing_interval"]), (None, None, None))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_credits").fetchone()[0], 0)
        status, _, body = self.jpost("/billing/checkout", cookie, {"workspace_id": ws, "plan": "trial", "interval": "one_time"})
        self.assertEqual((status, body["error"]), (400, "unknown plan or billing interval"))   # the Trial is never sold
        status, _, body = self.jpost("/billing/checkout", cookie, {"workspace_id": ws, "plan": "quick"})
        self.assertEqual(status, 200, body)                                       # an unused Trial is not an unused Quick scan
        status, _, body = self.jpost("/billing/checkout", cookie, {"workspace_id": ws, "plan": "standard", "interval": "monthly"})
        self.assertEqual(status, 200, body)
        # Quick paid on the Trial workspace -> Quick entitlement + 1 credit
        # (D-115: what was paid is verified against Stripe's line items).
        stripe_billing = _make_billing()
        stripe_billing._client.checkout.sessions.line_items.store["cs_test_conv"] = [(PRICE_ALLOWLIST["vericexa_quick_onetime"], 1)]
        http_app._apply_quick_payment(conn, {"id": "cs_test_conv", "client_reference_id": ws, "customer": "cus_conv", "metadata": {"plan": "quick", "workspace_id": ws}},
                                      None, stripe_billing)
        self.assertEqual(repo.get_entitlement_by_workspace(conn, ws)["plan"], "quick")
        status, _, body = self.submit(cookie, ws, {"source": _sol(2000)})
        self.assertEqual(status, 200, body)                                       # Quick's 3,000 LOC now apply
        self.assertEqual(repo.get_job_usage(conn, body["job_id"])["usage_model"], "scan_credit")
        self.assertEqual(self.jget("/trial", cookie)[2]["trial"]["state"], "used")   # the email's Trial is gone for good
        # A subscription event converts it again (Standard).
        stripe_billing._client.subscriptions.store["sub_conv"] = {"id": "sub_conv", "customer": "cus_conv", "status": "active", "metadata": {"workspace_id": ws},
                                                                  "items": {"data": [{"price": {"id": PRICE_ALLOWLIST["vericexa_standard_monthly"]}}]}}
        http_app._sync_subscription(conn, stripe_billing, "sub_conv", ws)   # D-115: Stripe's current state of the subscription
        self.assertEqual(repo.get_entitlement_by_workspace(conn, ws)["plan"], "standard")
        self.assertEqual(self.jpost("/workspaces/%s/projects" % ws, cookie, {"name": "P1"})[0], 200)
        self.assertEqual(self.jpost("/workspaces/%s/projects" % ws, cookie, {"name": "P2"})[0], 200)   # unlimited again

    def test_catalog_shows_the_trial_at_zero_and_paid_prices_unchanged(self):
        catalog = json.loads(self.get("/billing/plans")[2])["plans"]
        self.assertEqual([p["plan"] for p in catalog], ["trial", "quick", "standard", "pro"])
        trial_entry = catalog[0]
        self.assertEqual((trial_entry["checkout"], trial_entry["prices"], trial_entry["max_loc_per_scan"], trial_entry["max_projects"], trial_entry["features"]),
                         (False, [{"interval": "free", "amount_cents": 0, "currency": "usd", "service_months": None}], 500, 1, []))
        amounts = {p["plan"]: sorted((x["interval"], x["amount_cents"]) for x in p["prices"]) for p in catalog[1:]}
        self.assertEqual(amounts, {"quick": [("one_time", 2999)], "standard": [("annual", 199990), ("monthly", 19999)], "pro": [("annual", 289990), ("monthly", 28999)]})


class DenylistInjectionTests(_TrialHttpCase):
    POLICY = email_policy.DisposableDomainPolicy(["blocked.example"])

    def test_server_uses_the_injected_denylist(self):
        self.assertEqual(self.signup("a@blocked.example")[0], 422)
        self.assertEqual(self.signup("a@mailinator.com")[0], 200)               # not in this deployment's list


class WebAppTrialTests(unittest.TestCase):
    APP = (REPO_ROOT / "backend" / "webapp" / "app.js").read_text(encoding="utf-8")
    CORE = REPO_ROOT / "backend" / "webapp" / "app-core.js"

    def test_ui_shows_what_the_backend_says(self):
        self.assertIn('api("GET", "/trial")', self.APP)
        self.assertIn('api("POST", "/trial/activate", {})', self.APP)
        self.assertIn('d.downloads === false', self.APP)
        self.assertIn('p.checkout !== false', self.APP)
        for word in ("audit", "certif", "guarantee", "safe to deploy"):
            self.assertNotIn(word, self.APP.lower().replace("it is not a formal security audit", ""), word)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_core_helpers(self):
        script = ("var C = require(%s);\nprocess.stdout.write(JSON.stringify({"
                  "lines: C.planLimitLines(null, {usage_model: 'trial', max_loc_per_scan: 500, history_days: 7}),"
                  "money: [C.formatMoney(0, 'usd'), C.formatMoney(2999, 'usd')],"
                  "err: [C.describeError(402, {error: 'trial_already_used'}).message, C.describeError(409, {error: 'project_limit_reached', max_projects: 1}).details]}));"
                  % json.dumps(str(self.CORE)))
        out = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout)
        self.assertEqual(out["lines"], ["1 free scan per email address (no card, no subscription)", "Up to 500 effective LOC", "1 project",
                                        "Report viewable for 7 days (no downloads)"])
        self.assertEqual(out["money"], ["$0", "$29.99"])
        self.assertTrue(out["err"][0].startswith("This email address has already used its free Trial"))
        self.assertEqual(out["err"][1], ["Projects included: 1"])


if __name__ == "__main__":
    unittest.main()
