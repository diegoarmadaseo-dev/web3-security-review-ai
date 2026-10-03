"""Tests for the Commercial Foundation guards (docs/decisiones.md D-108):
the per-service-month technical budget, the pending-jobs cap per
workspace, the submit rate limit and Pro queue priority - backend/
repository.py, backend/worker_supervisor.py and backend/http_app.py. No
LLM call, no Docker, no Stripe: SQLite only (the real-Postgres versions of
the concurrency tests live in tests/test_backend_postgres_integration.py).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.alerting as alerting  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import backend.worker_supervisor as ws_mod  # noqa: E402
from tests.test_backend_commercial import _LedgerCase, _sol  # noqa: E402
from tests.test_backend_http_app import HOST, _CapturingEmailSender, _WorkspaceStorageTestCase  # noqa: E402
from tests.test_backend_worker_supervisor_no_docker import _FAKE_CONFIG, _CollectingAlertSender, _RaisingStorage  # noqa: E402

UTC = timezone.utc
_SUCCESS = {"status": "succeeded", "rendered": "# report", "risk_indicator": {"score": 5, "band": "LOW"}}


class _GuardCase(_LedgerCase):
    def tech(self, ws, now=None):
        return repo.technical_budget_summary(self.conn, ws, repo.get_entitlement_by_workspace(self.conn, ws), now)

    def job(self, job_id):
        return repo.get_job(self.conn, job_id)

    def expire_lease(self, job_id):
        self.conn.execute("UPDATE analysis_jobs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (job_id,))
        self.conn.commit()

    def run_worker(self, result=_SUCCESS):
        with mock.patch.object(ws_mod, "run_job_in_container", return_value=result):
            return ws_mod.claim_and_run_one_job(self.conn, "worker-x", _FAKE_CONFIG, _RaisingStorage())


# ---------------------------------------------------------------------------
# A) Technical budget
# ---------------------------------------------------------------------------

class TechnicalBudgetTests(_GuardCase):
    def test_ceiling_is_derived_from_the_catalog_and_quick_has_none(self):
        self.assertEqual(repo.technical_budget_limit_units("standard"), 20000 // 20 * 2)
        self.assertEqual(repo.technical_budget_limit_units("pro"), 60000 // 20 * 4)
        self.assertIsNone(repo.technical_budget_limit_units("quick"))
        self.assertIsNone(repo.technical_budget_limit_units("unknown"))
        # The commercial catalog itself is untouched by D-108.
        self.assertEqual([(p["max_loc_per_scan"], p["monthly_loc_quota"]) for p in (plans.PLANS[n] for n in plans.PLANS_ORDER)],
                         [(3000, None), (10000, 20000), (20000, 60000)])

    def test_normal_use_reaches_the_loc_allowance_before_the_technical_guard(self):
        # 1,000 successful Standard-mode scans of 20 effective LOC = exactly
        # the 20,000 LOC allowance AND exactly the 2,000-unit ceiling: the
        # next scan is refused by the COMMERCIAL quota, never the guard.
        ws = self.workspace("standard", "monthly")
        for _ in range(1000):
            self.finish(self.submit(ws, 20, mode="standard"))
        t = self.tech(ws)
        self.assertEqual((t["consumed_units"], t["limit_units"]), (2000, 2000))
        self.assertEqual(self.summary(ws)["loc_remaining"], 0)
        self.assertEqual(self.code(lambda: self.submit(ws, 20, mode="standard")), "loc_quota_exceeded")

    def test_reserved_at_admission_and_settled_with_the_job(self):
        ws = self.workspace("pro", "monthly")
        ok = self.submit(ws, 100, mode="pro")
        self.assertEqual((self.tech(ws)["reserved_units"], repo.get_job_usage(self.conn, ok)["tech_units"]), (4, 4))
        self.finish(ok)                                                                       # succeeded -> consumed
        ran_failed = self.submit(ws, 100, mode="standard")
        self.finish(ran_failed, "failed")                                                     # failed after running -> consumed
        never_ran = self.submit(ws, 100, mode="quick")
        self.finish(never_ran, "failed_on_claim")                                             # failed before running -> released
        canceled = self.submit(ws, 100, mode="quick")
        self.assertTrue(repo.transition_job_status(self.conn, canceled, "queued", "canceled")) # canceled -> released
        t = self.tech(ws)
        self.assertEqual((t["reserved_units"], t["consumed_units"]), (0, 4 + 2))
        s = self.summary(ws)
        self.assertEqual((s["loc_reserved"], s["loc_consumed"]), (0, 100))                    # only the success is billed LOC

    def test_requeue_keeps_the_reservation_and_a_reaped_failure_after_running_consumes(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 100, mode="standard")
        claimed = repo.claim_next_job(self.conn, "w1")
        self.assertTrue(repo.transition_job_status(self.conn, job, "claimed", "running"))
        self.expire_lease(job)
        self.assertEqual(repo.reap_expired_jobs(self.conn, max_attempts=3), {"requeued": 1, "failed": 0})
        self.assertEqual((self.tech(ws)["reserved_units"], self.tech(ws)["consumed_units"]), (2, 0))
        self.conn.execute("UPDATE analysis_jobs SET next_eligible_at = NULL WHERE id = ?", (job,))
        self.conn.commit()
        self.assertIsNotNone(repo.claim_next_job(self.conn, "w2"))
        self.expire_lease(job)                                                                # dies while 'claimed' on its last attempt
        self.assertEqual(repo.reap_expired_jobs(self.conn, max_attempts=1), {"requeued": 0, "failed": 1})
        self.assertEqual((self.tech(ws)["reserved_units"], self.tech(ws)["consumed_units"]), (0, 2))   # an earlier attempt ran
        self.assertEqual(self.summary(ws)["loc_reserved"], 0)
        self.assertIsNotNone(claimed)

    def test_exhausted_guard_refuses_atomically_with_its_own_code(self):
        ws = self.workspace("standard", "monthly")
        self.finish(self.submit(ws, 100, mode="standard"))
        period = self.tech(ws)["period_start"]
        self.conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units - 1 WHERE workspace_id = ? AND period_start = ?", (ws, period))
        self.conn.commit()
        jobs_before = self.conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0]
        self.assertEqual(self.code(lambda: self.submit(ws, 100, mode="standard")), "technical_budget_exhausted")   # needs 2, 1 left
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], jobs_before)     # no job
        self.assertEqual(self.summary(ws)["loc_reserved"], 0)                                                  # LOC rolled back too
        self.submit(ws, 100, mode="quick")                                                                      # 1 unit still fits

    def test_resets_with_the_service_month(self):
        anchor = datetime(2026, 3, 10, tzinfo=UTC)
        ws = self.workspace("standard", "annual", period_start=anchor.isoformat())
        march, april = datetime(2026, 3, 20, tzinfo=UTC), datetime(2026, 4, 20, tzinfo=UTC)
        self.finish(self.submit(ws, 100, now=march))
        self.conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        self.conn.commit()
        self.assertEqual(self.code(lambda: self.submit(ws, 100, now=march)), "technical_budget_exhausted")
        self.submit(ws, 100, now=april)                                                      # month 2 of the annual plan: fresh guard
        t = self.tech(ws, april)
        self.assertEqual((t["period_start"], t["reserved_units"], t["consumed_units"]), (datetime(2026, 4, 10, tzinfo=UTC).isoformat(), 1, 0))

    def test_quick_has_no_technical_budget_or_hidden_limit(self):
        ws = self.workspace("quick")
        for i in range(3):
            repo.grant_scan_credit(self.conn, "cs_tb_%d" % i, ws)
        for _ in range(3):
            self.finish(self.submit(ws, 3000))
        self.assertIsNone(self.tech(ws))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM technical_budget_periods").fetchone()[0], 0)
        self.assertEqual(self.summary(ws)["scans_consumed"], 3)

    def test_settlement_is_idempotent_for_technical_units(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 100, mode="standard")
        self.finish(job)
        self.assertFalse(repo._settle_job_usage(self.conn, job, "consume"))
        self.assertFalse(repo._settle_job_usage(self.conn, job, "release"))
        self.conn.commit()
        t = self.tech(ws)
        self.assertEqual((t["reserved_units"], t["consumed_units"]), (0, 2))

    def test_concurrent_admissions_never_overshoot_the_guard(self):
        ws = self.workspace("standard", "monthly")
        self.finish(self.submit(ws, 10, mode="standard"))
        self.conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units - 6 WHERE workspace_id = ?", (ws,))   # room for 3 x 2
        self.conn.commit()
        results, lock = [], threading.Lock()

        def worker():
            conn = repo.connect(self.db_path)
            conn.execute("PRAGMA busy_timeout = 10000")
            try:
                self.submit(ws, 10, conn=conn, mode="standard", max_pending=100)
                outcome = "ok"
            except repo.UsageLimitError as exc:
                outcome = exc.code
            finally:
                conn.close()
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ["ok"] * 3 + ["technical_budget_exhausted"] * 5)
        t = self.tech(ws)
        self.assertEqual(t["reserved_units"] + t["consumed_units"], t["limit_units"])


class WorkerUsesAdmissionBudgetTests(_GuardCase):
    def test_admitted_scan_is_never_failed_by_the_legacy_ceiling(self):
        ws = self.workspace("standard", "monthly")
        self.assertTrue(repo.reserve_workspace_budget(self.conn, ws, repo.DEFAULT_BUDGET_LIMIT_UNITS))   # legacy ledger exhausted
        job = self.submit(ws, 100, mode="standard")
        self.assertEqual(self.run_worker(), job)
        self.assertEqual(self.job(job)["status"], "succeeded")
        legacy = repo.get_workspace_budget(self.conn, ws)
        self.assertEqual((legacy["reserved_units"], legacy["consumed_units"]), (repo.DEFAULT_BUDGET_LIMIT_UNITS, 0))   # untouched
        t = self.tech(ws)
        self.assertEqual((t["reserved_units"], t["consumed_units"]), (0, 2))
        self.assertEqual(self.summary(ws)["loc_consumed"], 100)

    def test_admitted_scan_is_never_rejected_later_even_if_the_guard_fills_up(self):
        # The guard only decides at admission. Once admitted, a scan runs and
        # settles even if the period's guard is exhausted in the meantime.
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 100, mode="standard")
        self.conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        self.conn.commit()
        self.run_worker()
        self.assertEqual(self.job(job)["status"], "succeeded")
        t = self.tech(ws)
        self.assertEqual((t["reserved_units"], t["consumed_units"]), (0, t["limit_units"] + 2))
        self.assertEqual(self.summary(ws)["loc_consumed"], 100)
        self.assertEqual(self.code(lambda: self.submit(ws, 100, mode="standard")), "technical_budget_exhausted")   # only NEW admissions

    def test_units_are_not_reported_as_loc(self):
        ws = self.workspace("pro", "monthly")
        self.submit(ws, 7000, mode="pro")
        t, u = self.tech(ws), self.summary(ws)
        self.assertEqual(t["reserved_units"], repo.JOB_MODE_BUDGET_COST["pro"])         # a per-job weight, independent of the 7,000 LOC
        self.assertEqual(u["loc_reserved"], 7000)
        self.assertFalse(any(k.startswith("loc") for k in t))
        self.assertFalse(any("unit" in k for k in u))

    def test_quick_scan_runs_even_with_the_legacy_ceiling_exhausted(self):
        ws = self.workspace("quick")
        repo.grant_scan_credit(self.conn, "cs_worker", ws)
        self.assertTrue(repo.reserve_workspace_budget(self.conn, ws, repo.DEFAULT_BUDGET_LIMIT_UNITS))
        job = self.submit(ws, 3000)
        self.run_worker()
        self.assertEqual(self.job(job)["status"], "succeeded")
        self.assertEqual(self.summary(ws)["scans_consumed"], 1)

    def test_worker_failure_consumes_technical_units_and_releases_loc(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 100, mode="standard")
        self.run_worker({"status": "failed", "error": "engine error"})
        self.assertEqual(self.job(job)["status"], "failed")
        self.assertEqual((self.tech(ws)["reserved_units"], self.tech(ws)["consumed_units"]), (0, 2))
        self.assertEqual((self.summary(ws)["loc_reserved"], self.summary(ws)["loc_consumed"]), (0, 0))

    def test_reaper_does_not_touch_the_legacy_ledger_for_an_admitted_job(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 100, mode="standard")
        repo.claim_next_job(self.conn, "w1")
        self.assertTrue(repo.transition_job_status(self.conn, job, "claimed", "running"))
        self.expire_lease(job)
        self.assertEqual(repo.reap_expired_jobs(self.conn, max_attempts=0), {"requeued": 0, "failed": 1})   # first attempt is the last
        self.assertIsNone(repo.get_workspace_budget(self.conn, ws))                         # never created, never driven negative
        self.assertEqual((self.tech(ws)["reserved_units"], self.tech(ws)["consumed_units"]), (0, 2))

    def test_ledgerless_job_keeps_the_legacy_behaviour(self):
        ws = self.workspace("standard", "monthly")
        contract = repo.create_contract(self.conn, ws, "ref-legacy", "h", "A.sol")
        job = repo.enqueue_job(self.conn, ws, contract, self.user, "quick")
        self.assertTrue(repo.reserve_workspace_budget(self.conn, ws, repo.DEFAULT_BUDGET_LIMIT_UNITS))
        self.run_worker()
        self.assertEqual((self.job(job)["status"], self.job(job)["last_error"]), ("failed", "workspace budget exhausted"))


# ---------------------------------------------------------------------------
# B) Pending jobs per workspace
# ---------------------------------------------------------------------------

class PendingJobsCapTests(_GuardCase):
    def test_cap_refuses_atomically_and_frees_on_every_terminal_path(self):
        ws = self.workspace("standard", "monthly")
        jobs = [self.submit(ws, 10, max_pending=4) for _ in range(4)]
        jobs_before = self.conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0]
        self.assertEqual(self.code(lambda: self.submit(ws, 10, max_pending=4)), "too_many_pending_jobs")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], jobs_before)
        self.assertEqual(self.summary(ws)["loc_reserved"], 40)                               # the refused one reserved nothing
        self.finish(jobs[0])                                                                  # succeeded
        jobs.append(self.submit(ws, 10, max_pending=4))
        self.finish(jobs[1], "failed")                                                        # failed
        jobs.append(self.submit(ws, 10, max_pending=4))
        self.assertTrue(repo.transition_job_status(self.conn, jobs[2], "queued", "canceled"))  # canceled
        jobs.append(self.submit(ws, 10, max_pending=4))
        self.assertEqual(repo.count_pending_jobs(self.conn, ws), 4)
        self.assertEqual(self.code(lambda: self.submit(ws, 10, max_pending=4)), "too_many_pending_jobs")

    def test_reaper_requeue_stays_pending_and_reaper_failure_frees(self):
        ws = self.workspace("standard", "monthly")
        job = self.submit(ws, 10, max_pending=1)
        repo.claim_next_job(self.conn, "w1")
        self.assertTrue(repo.transition_job_status(self.conn, job, "claimed", "running"))
        self.expire_lease(job)
        repo.reap_expired_jobs(self.conn, max_attempts=3)                                    # requeued: still pending
        self.assertEqual(self.code(lambda: self.submit(ws, 10, max_pending=1)), "too_many_pending_jobs")
        self.conn.execute("UPDATE analysis_jobs SET next_eligible_at = NULL WHERE id = ?", (job,))
        self.conn.commit()
        repo.claim_next_job(self.conn, "w2")
        self.expire_lease(job)
        self.assertEqual(repo.reap_expired_jobs(self.conn, max_attempts=1), {"requeued": 0, "failed": 1})
        self.submit(ws, 10, max_pending=1)                                                   # freed

    def test_cap_is_per_workspace(self):
        a = self.workspace("standard", "monthly")
        b = self.workspace("standard", "monthly")
        self.submit(a, 10, max_pending=1)
        self.assertEqual(self.code(lambda: self.submit(a, 10, max_pending=1)), "too_many_pending_jobs")
        self.submit(b, 10, max_pending=1)                                                    # B unaffected by A

    def test_default_and_invalid_cap(self):
        self.assertEqual(repo.DEFAULT_MAX_PENDING_JOBS_PER_WORKSPACE, 5)
        ws = self.workspace("standard", "monthly")
        for bad in (0, -1, "5", None):
            with self.assertRaises(repo.RepositoryError):
                self.submit(ws, 10, max_pending=bad)
        self.assertEqual(repo.count_pending_jobs(self.conn, ws), 0)

    def test_concurrent_submissions_never_exceed_the_cap(self):
        ws = self.workspace("pro", "monthly")
        results, lock = [], threading.Lock()

        def worker():
            conn = repo.connect(self.db_path)
            conn.execute("PRAGMA busy_timeout = 10000")
            try:
                self.submit(ws, 10, conn=conn, max_pending=3)
                outcome = "ok"
            except repo.UsageLimitError as exc:
                outcome = exc.code
            finally:
                conn.close()
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ["ok"] * 3 + ["too_many_pending_jobs"] * 7)
        self.assertEqual(repo.count_pending_jobs(self.conn, ws), 3)
        self.assertEqual(self.summary(ws)["loc_reserved"], 30)


# ---------------------------------------------------------------------------
# C) Submit rate limit (repository level)
# ---------------------------------------------------------------------------

class SubmitRateLimitTests(_GuardCase):
    def test_sliding_window_per_user(self):
        a = self.workspace("standard", "monthly")
        b = self.workspace("standard", "monthly")
        t0 = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
        for i in range(5):
            self.assertEqual(repo.check_submit_rate_limit(self.conn, self.user, a if i % 2 else b, 5, now=t0 + timedelta(seconds=i)), 0)
        retry = repo.check_submit_rate_limit(self.conn, self.user, a, 5, now=t0 + timedelta(seconds=10))
        self.assertEqual(retry, 50)                                                           # oldest (t0) leaves the 60 s window at t0+60
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM submit_attempts").fetchone()[0], 5)   # refusal not recorded
        other = repo.create_user(self.conn, "other-rl@example.com")
        self.assertEqual(repo.check_submit_rate_limit(self.conn, other, a, 5, now=t0 + timedelta(seconds=10)), 0)   # per user
        self.assertEqual(repo.check_submit_rate_limit(self.conn, self.user, a, 5, now=t0 + timedelta(seconds=60, microseconds=1)), 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM submit_attempts WHERE user_id = ?", (self.user,)).fetchone()[0], 5)   # t0 pruned

    def test_retry_after_is_bounded(self):
        ws = self.workspace("standard", "monthly")
        t0 = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
        repo.check_submit_rate_limit(self.conn, self.user, ws, 1, now=t0)
        self.assertEqual(repo.check_submit_rate_limit(self.conn, self.user, ws, 1, now=t0), 60)
        self.assertEqual(repo.check_submit_rate_limit(self.conn, self.user, ws, 1, now=t0 + timedelta(seconds=59, microseconds=900000)), 1)
        with self.assertRaises(repo.RepositoryError):
            repo.check_submit_rate_limit(self.conn, self.user, ws, 0)

    def test_concurrent_attempts_never_exceed_the_limit(self):
        ws = self.workspace("standard", "monthly")
        results, lock = [], threading.Lock()

        def worker():
            conn = repo.connect(self.db_path)
            conn.execute("PRAGMA busy_timeout = 10000")
            try:
                retry = repo.check_submit_rate_limit(conn, self.user, ws, 4)
            finally:
                conn.close()
            with lock:
                results.append(retry)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(0), 4)                                             # exact under a burst
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM submit_attempts").fetchone()[0], 4)


# ---------------------------------------------------------------------------
# D) Pro priority
# ---------------------------------------------------------------------------

class ProPriorityTests(_GuardCase):
    def set_last_claimed(self, ws, value):
        self.conn.execute("UPDATE workspace_queue_state SET last_claimed_at = ? WHERE workspace_id = ?", (value, ws))
        self.conn.commit()

    def test_priority_comes_from_the_plan_at_admission(self):
        repo.grant_scan_credit(self.conn, "cs_prio", quick := self.workspace("quick"))
        std, pro = self.workspace("standard", "monthly"), self.workspace("pro", "monthly")
        self.assertEqual(self.job(self.submit(quick, 10))["priority"], 0)
        self.assertEqual(self.job(self.submit(std, 10))["priority"], 0)
        self.assertEqual(self.job(self.submit(pro, 10))["priority"], 1)

    def test_pro_beats_standard_when_both_wait_comparably(self):
        std = self.workspace("standard", "monthly")
        pro = self.workspace("pro", "monthly")                                                # registered AFTER standard
        s1 = self.submit(std, 10)
        p1 = self.submit(pro, 10)
        self.assertEqual(repo.claim_next_job(self.conn, "w1")["id"], p1)                     # both never served: priority first
        self.assertEqual(repo.claim_next_job(self.conn, "w2")["id"], s1)                     # standard is next, not starved

    def test_bonus_boundary_bounds_the_wait_of_standard(self):
        std = self.workspace("standard", "monthly")
        pro = self.workspace("pro", "monthly")
        s1, p1 = self.submit(std, 10), self.submit(pro, 10)
        now = datetime.now(UTC).replace(microsecond=0)
        self.set_last_claimed(pro, now.isoformat())
        self.set_last_claimed(std, (now - timedelta(seconds=repo.QUEUE_PRIORITY_BONUS_SECONDS - 1)).isoformat())
        self.assertEqual(repo.claim_next_job(self.conn, "w1")["id"], p1)                     # within the bonus: Pro first
        self.assertTrue(repo.transition_job_status(self.conn, p1, "claimed", "queued"))
        self.set_last_claimed(pro, now.isoformat())
        self.set_last_claimed(std, (now - timedelta(seconds=repo.QUEUE_PRIORITY_BONUS_SECONDS + 1)).isoformat())
        self.assertEqual(repo.claim_next_job(self.conn, "w2")["id"], s1)                     # waited longer than the bonus: Standard

    def test_sustained_load_gives_pro_more_turns_without_starving_standard(self):
        std = self.workspace("standard", "monthly")
        pro = self.workspace("pro", "monthly")
        for _ in range(5):
            self.submit(std, 10, max_pending=100)
            self.submit(pro, 10, max_pending=100)
        clock = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
        served = []
        for _ in range(9):                                                                    # one claim per simulated 3-minute job
            clock += timedelta(minutes=3)
            with mock.patch.object(repo, "datetime", wraps=datetime) as fake_dt:
                fake_dt.now.return_value = clock
                job = repo.claim_next_job(self.conn, "w")
            served.append("pro" if job["workspace_id"] == pro else "std")
        self.assertGreater(served.count("pro"), served.count("std"))
        self.assertGreaterEqual(served.count("std"), 3)                                     # every few turns, never starved
        self.assertNotIn(["pro"] * 3, [served[i:i + 3] for i in range(len(served) - 2)])

    def test_priority_never_crosses_workspaces(self):
        std = self.workspace("standard", "monthly")
        pro = self.workspace("pro", "monthly")
        s1, p1 = self.submit(std, 10), self.submit(pro, 10)
        claimed = repo.claim_next_job(self.conn, "w1")
        self.assertEqual((claimed["id"], claimed["workspace_id"]), (p1, pro))
        self.assertEqual(self.job(s1)["status"], "queued")
        self.assertIsNone(self.conn.execute("SELECT last_claimed_at FROM workspace_queue_state WHERE workspace_id = ?", (std,)).fetchone()[0])


# ---------------------------------------------------------------------------
# HTTP: deterministic responses
# ---------------------------------------------------------------------------

class _GuardsHttpCase(_WorkspaceStorageTestCase):
    MAX_PENDING = 2
    RATE = 4

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed = repo.connect(self.db_path)
        repo.init_schema(seed)
        seed.close()
        self.storage_dir = tempfile.mkdtemp(prefix="http-guards-")
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="test-only-secret")
        self.email_sender = _CapturingEmailSender()
        self.alerts = _CollectingAlertSender()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path), email_sender=self.email_sender, host_allowlist=[HOST],
            host=HOST, port=0, secure_cookies=False, storage=self.storage, alert_sender=self.alerts,
            max_pending_jobs_per_workspace=self.MAX_PENDING, submit_rate_limit_per_window=self.RATE,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.05)
        self.addCleanup(lambda: shutil.rmtree(self.storage_dir, ignore_errors=True))
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)

    def workspace(self, plan, email):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        ws = repo.create_workspace(conn, "Guards WS", repo.get_user_by_email(conn, email)["id"])
        repo.create_entitlement(conn, ws, plan, "active", billing_interval="monthly")
        conn.close()
        return cookie, ws

    def submit(self, cookie, ws, loc=10, mode="quick"):
        status, headers, body = self.post_json("/workspaces/%s/jobs" % ws, {"mode": mode, "source": _sol(loc)}, headers={"Cookie": cookie})
        return status, headers, json.loads(body)


class GuardsHttpTests(_GuardsHttpCase):
    def test_pending_cap_returns_429_and_frees_after_completion(self):
        cookie, ws = self.workspace("standard", "pend-http@example.com")
        first = self.submit(cookie, ws)
        self.assertEqual(first[0], 200)
        self.assertEqual(self.submit(cookie, ws)[0], 200)
        status, _, body = self.submit(cookie, ws)
        self.assertEqual((status, body["error"], body["max_pending_jobs"]), (429, "too_many_pending_jobs", 2))
        conn = repo.connect(self.db_path)
        self.assertTrue(repo.transition_job_status(conn, first[2]["job_id"], "queued", "canceled"))
        conn.close()
        self.assertEqual(self.submit(cookie, ws)[0], 200)

    def test_technical_budget_exhausted_returns_429_and_alerts(self):
        cookie, ws = self.workspace("standard", "tech-http@example.com")
        status, _, body = self.submit(cookie, ws, mode="standard")
        self.assertEqual(status, 200)
        conn = repo.connect(self.db_path)
        self.assertTrue(repo.transition_job_status(conn, body["job_id"], "queued", "canceled"))
        conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        conn.commit()
        conn.close()
        status, _, body = self.submit(cookie, ws, mode="standard")
        self.assertEqual((status, body["error"]), (429, "technical_budget_exhausted"))
        self.assertEqual([e[0] for e in self.alerts.events], [alerting.EVENT_TECHNICAL_BUDGET_EXHAUSTED])
        budget = json.loads(self.get("/workspaces/%s" % ws, headers={"Cookie": cookie})[2])["budget"]
        self.assertEqual(budget["consumed_units"], budget["limit_units"])


class SubmitRateLimitHttpTests(_GuardsHttpCase):
    MAX_PENDING = 50

    def test_rate_limit_returns_429_with_retry_after_before_reading_the_body(self):
        cookie, ws = self.workspace("standard", "rate-http@example.com")
        for _ in range(self.RATE):
            self.assertEqual(self.submit(cookie, ws)[0], 200)
        status, headers, body = self.submit(cookie, ws)
        self.assertEqual((status, body["error"]), (429, "submit_rate_limited"))
        self.assertEqual(headers["Retry-After"], str(body["retry_after_seconds"]))
        self.assertTrue(1 <= body["retry_after_seconds"] <= repo.SUBMIT_RATE_LIMIT_WINDOW_SECONDS)
        conn = repo.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()[0], self.RATE)
        conn.close()
        # Another user is unaffected; an anonymous caller still gets 401, not 429.
        cookie2, ws2 = self.workspace("standard", "rate-http-2@example.com")
        self.assertEqual(self.submit(cookie2, ws2)[0], 200)
        status, _, _ = self.post_json("/workspaces/%s/jobs" % ws, {"mode": "quick", "source": _sol(5)})
        self.assertEqual(status, 401)

    def attempts(self, email):
        conn = repo.connect(self.db_path)
        try:
            user = repo.get_user_by_email(conn, email)["id"]
            return conn.execute("SELECT COUNT(*) FROM submit_attempts WHERE user_id = ?", (user,)).fetchone()[0]
        finally:
            conn.close()

    def test_retries_with_the_same_idempotency_key_count_as_attempts(self):
        cookie, ws = self.workspace("standard", "rate-idem@example.com")
        payload = {"mode": "quick", "source": _sol(10), "idempotency_key": "same-key"}
        outcomes = [self.post_json("/workspaces/%s/jobs" % ws, payload, headers={"Cookie": cookie}) for _ in range(self.RATE)]
        bodies = [json.loads(o[2]) for o in outcomes]
        self.assertEqual([o[0] for o in outcomes], [200] * self.RATE)
        self.assertEqual(len({b["job_id"] for b in bodies}), 1)                             # idempotency: one job...
        self.assertEqual([b.get("duplicate", False) for b in bodies], [False] + [True] * (self.RATE - 1))
        self.assertEqual(self.attempts("rate-idem@example.com"), self.RATE)                  # ...but every request is an attempt
        status, headers, body = self.post_json("/workspaces/%s/jobs" % ws, payload, headers={"Cookie": cookie})
        self.assertEqual((status, json.loads(body)["error"]), (429, "submit_rate_limited"))
        self.assertIn("Retry-After", headers)
        conn = repo.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()[0], 1)
        self.assertEqual(repo.usage_summary(conn, ws, repo.get_entitlement_by_workspace(conn, ws))["loc_reserved"], 10)   # reserved once
        conn.close()

    def test_requests_ending_in_402_413_422_count_and_rate_limited_ones_do_not(self):
        cookie, ws = self.workspace("quick", "rate-errors@example.com")                    # no Quick credit purchased
        for _ in range(2):
            status, _, body = self.submit(cookie, ws, 10)
            self.assertEqual((status, body["error"]), (402, "no_scan_credit"))
        status, _, body = self.submit(cookie, ws, 3001)
        self.assertEqual((status, body["error"]), (413, "loc_per_scan_limit_exceeded"))
        self.assertEqual(self.attempts("rate-errors@example.com"), 3)
        status, _, raw = self.post_json("/workspaces/%s/jobs" % ws, {"mode": "quick", "source": "// no code\n"}, headers={"Cookie": cookie})
        self.assertEqual((status, json.loads(raw)["error"]), (422, "no_source_code"))
        self.assertEqual(self.attempts("rate-errors@example.com"), self.RATE)
        for _ in range(3):                                                                    # refused by the limit itself
            status, headers, body = self.submit(cookie, ws, 10)
            self.assertEqual((status, body["error"], headers["Retry-After"]), (429, "submit_rate_limited", str(body["retry_after_seconds"])))
        self.assertEqual(self.attempts("rate-errors@example.com"), self.RATE)                # no extra attempt recorded


if __name__ == "__main__":
    unittest.main()
