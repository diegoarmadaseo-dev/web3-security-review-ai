"""Real PostgreSQL integration tests for backend/db.py's adapter, driving
backend/repository.py, backend/migrate.py and backend/tenant_scope.py
against an actual running PostgreSQL 15 server (Phase 1 SaaS backend data
foundation, docs/decisiones.md D-077 - PostgreSQL adapter follow-up).

Distinct from backend/verify_postgres.sh + verify_postgres.sql, which
prove the RAW SQL schema is correct via psql directly (DDL apply/
rollback, JSONB/UUID/TIMESTAMPTZ column behavior, the R-08 CHECK, the
claim-queue index, a raw two-session FOR UPDATE SKIP LOCKED race) - this
file does NOT re-run those assertions. It proves a different thing those
scripts cannot: that the PYTHON adapter/repository code path itself
(placeholder translation, row-shape normalization, the dispatch in
claim_next_job()) is correct against a real server, not just against
SQLite. The two are complementary layers, not duplicates.

Starts ONE disposable `postgres:15` Docker container for the whole
module (setUpModule/tearDownModule - never a production database, never
a persistent volume) and resets its one database before every test
method, mirroring the fresh-`:memory:`-per-test isolation the SQLite
suite already relies on (see tests/test_backend_job_queue.py etc.).

Skips the entire module (never fails) if psycopg is not installed or
Docker is not installed/reachable - the SQLite suite must stay green
with or without either present.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

try:
    import psycopg
except ImportError:  # pragma: no cover - exercised by environments without psycopg installed.
    psycopg = None

import backend.auth as auth
import backend.db as db
import backend.http_app as http_app
import backend.migrate as migrate
import backend.object_storage as object_storage
import backend.repository as repo
import backend.tenant_scope as tenant_scope
import backend.verify_restore as verify_restore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS_DIR = os.path.join(REPO_ROOT, "backend", "migrations")

CONTAINER_NAME = "phase1-pytest-pg"
PG_PORT = "55433"  # distinct from backend/verify_postgres.sh's 55432 - never collides if both ran at once.
PG_PASSWORD = "pytest-throwaway"  # this container is --rm, localhost-only, torn down at module exit - never a real credential.
DB_NAME = "phase1pytest"
ADMIN_DSN = "postgresql://postgres:%s@127.0.0.1:%s/postgres" % (PG_PASSWORD, PG_PORT)
DSN = "postgresql://postgres:%s@127.0.0.1:%s/%s" % (PG_PASSWORD, PG_PORT, DB_NAME)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


def setUpModule():
    if psycopg is None or not _docker_available():
        raise unittest.SkipTest("psycopg is not installed or Docker is not installed/reachable")
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    subprocess.run(
        [
            "docker", "run", "--rm", "-d", "--name", CONTAINER_NAME,
            "-e", "POSTGRES_PASSWORD=%s" % PG_PASSWORD,
            "-e", "POSTGRES_DB=%s" % DB_NAME,
            "-p", "127.0.0.1:%s:5432" % PG_PORT,
            "postgres:15",
        ],
        check=True, capture_output=True,
    )
    for _ in range(30):
        result = subprocess.run(["docker", "exec", CONTAINER_NAME, "pg_isready", "-U", "postgres"], capture_output=True)
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
        raise RuntimeError("postgres:15 container did not become ready in time")


def tearDownModule():
    if psycopg is not None and _docker_available():
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)


def _reset_database_and_migrate():
    """Fresh, empty database + freshly-applied migration - the Postgres
    equivalent of the SQLite suite's repo.connect(':memory:') + init_schema()
    per test. WITH (FORCE) drops even if a stray connection is somehow
    still open (e.g. a background-thread connection from a previous test
    that hadn't finished closing)."""
    admin_conn = psycopg.connect(ADMIN_DSN, autocommit=True)
    try:
        admin_conn.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % DB_NAME)
        admin_conn.execute("CREATE DATABASE %s" % DB_NAME)
    finally:
        admin_conn.close()
    conn = db.connect_postgres(DSN)
    applied = migrate.apply_pending_migrations(conn, MIGRATIONS_DIR, now_iso=repo.utcnow_iso())
    return conn, applied


class MigrationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.conn, self.applied = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def test_fresh_database_applies_all_fourteen_migrations_in_order(self):
        # 0002_auth_tokens.sql (Phase 2), 0003_entitlement_status_expand.sql
        # and 0004_entitlement_event_provenance.sql (Phase 3),
        # 0005_job_queue_hardening.sql (Phase 4, D-079),
        # 0006_retention_purge.sql (Phase 6A, D-081),
        # 0007_billing_interval.sql (Phase 7, D-086), and
        # 0008_queue_fairness.sql (admission control / queue fairness,
        # post reap-atomicity-fix and worker-fencing hardening) and
        # 0009_commercial_usage.sql (D-107), 0010_commercial_guards.sql
        # (D-108), 0011_contract_files.sql (D-109) and
        # 0012_github_connections.sql (D-111), 0013_trial.sql (D-112) and
        # 0014_api_keys.sql (D-113) added alongside
        # 0001_initial_schema.sql (Phase 1).
        self.assertEqual(
            self.applied,
            [
                "0001_initial_schema", "0002_auth_tokens", "0003_entitlement_status_expand",
                "0004_entitlement_event_provenance", "0005_job_queue_hardening", "0006_retention_purge",
                "0007_billing_interval", "0008_queue_fairness", "0009_commercial_usage",
                "0010_commercial_guards", "0011_contract_files", "0012_github_connections", "0013_trial",
                "0014_api_keys",
            ],
        )

    def test_entitlement_status_check_accepts_the_phase_3_expanded_values(self):
        # The one thing 0003_entitlement_status_expand.sql actually
        # changes: a real Postgres CHECK constraint, which the SQLite
        # mirror cannot verify by construction (see that file's own
        # docstring on why the two schemas are deliberately separate) -
        # this is the one place that constraint is proven against a real
        # server rather than merely mirrored. entitlements.workspace_id
        # is itself UNIQUE, so each status needs its own real workspace.
        owner_id = repo.new_id()
        db.execute(self.conn, "INSERT INTO users (id, email, created_at, updated_at) VALUES (%s, %s, now(), now())", (owner_id, "owner@example.com"))
        seen_statuses = set()
        for status in ("incomplete_expired", "unpaid"):
            workspace_id = repo.new_id()
            db.execute(self.conn, "INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES (%s, %s, %s, now(), now())", (workspace_id, "WS-" + status, owner_id))
            self.conn.commit()
            repo.create_entitlement(self.conn, workspace_id, "quick", status)
            seen_statuses.add(repo.get_entitlement_by_workspace(self.conn, workspace_id)["status"])
        self.assertEqual(seen_statuses, {"incomplete_expired", "unpaid"})

    def test_all_twenty_six_tables_exist(self):
        cur = db.execute(
            self.conn,
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        )
        tables = {row["table_name"] for row in cur.fetchall()}
        expected = {
            "schema_migrations", "users", "workspaces", "workspace_members", "sessions",
            "entitlements", "projects", "contracts", "analysis_jobs", "reports",
            "audit_events", "webhook_events", "auth_tokens",
            "workspace_budgets",  # Phase 4, 0005_job_queue_hardening.sql (D-079).
            "workspace_queue_state",  # Admission control / queue fairness, 0008_queue_fairness.sql.
            "scan_credits", "usage_periods", "job_usage",  # D-107, 0009_commercial_usage.sql.
            "technical_budget_periods", "submit_attempts",  # D-108, 0010_commercial_guards.sql.
            "contract_files",  # D-109, 0011_contract_files.sql.
            "github_connections", "github_oauth_states", "contract_git_sources",  # D-111, 0012_github_connections.sql.
            "trial_grants",  # D-112, 0013_trial.sql.
            "api_keys",  # D-113, 0014_api_keys.sql.
        }
        self.assertEqual(tables, expected)

    def test_tracked_rerun_applies_nothing_new(self):
        # Unlike verify_postgres.sh's own raw-reapply test (which proves
        # the migration file is NOT accidentally idempotent on its own),
        # this proves migrate.py's *tracked* idempotency actually works
        # against real Postgres - previously only exercised against a
        # synthetic SQLite-compatible fixture (see
        # tests/test_backend_migrate.py's own docstring).
        second_run = migrate.apply_pending_migrations(self.conn, MIGRATIONS_DIR, now_iso=repo.utcnow_iso())
        self.assertEqual(second_run, [])


class RepositoryCrudIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def test_created_ids_and_timestamps_are_plain_strings_not_native_pg_types(self):
        # psycopg returns uuid.UUID/datetime.datetime objects for UUID/
        # TIMESTAMPTZ columns by default (verified directly against this
        # same image) - db.normalize_row() must erase that so callers see
        # the same shape regardless of backend, per repository.py's own
        # module docstring.
        user_id = repo.create_user(self.conn, "crud@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "hash", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        for value in (user_id, workspace_id, contract_id, job_id):
            self.assertIsInstance(value, str)

        job = repo.get_job(self.conn, job_id)
        self.assertIsInstance(job["id"], str)
        self.assertEqual(job["id"], job_id)
        self.assertIsInstance(job["workspace_id"], str)
        self.assertIsInstance(job["created_at"], str)
        self.assertEqual(job["status"], "queued")

    def test_report_r08_computed_requires_score_and_band(self):
        user_id = repo.create_user(self.conn, "r08@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "hash", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        report_id = repo.record_report(self.conn, job_id, workspace_id, "s3://r", score_status="computed", score=40, risk_band="HIGH")
        self.assertIsInstance(report_id, str)
        self.conn.commit()

        # A second, distinct job - reports.job_id is both FK and UNIQUE, so
        # reusing job_id here would hit that constraint instead of the R-08
        # CHECK this test targets (same fix already applied to
        # backend/verify_postgres.sql's own R-08 probe).
        job_id_2 = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        self.conn.commit()
        with self.assertRaises(psycopg.errors.CheckViolation):
            repo.record_report(self.conn, job_id_2, workspace_id, "s3://r2", score_status="computed", score=None, risk_band=None)
        self.conn.rollback()


class TenantIsolationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def test_non_member_and_nonexistent_workspace_both_resolve_to_none(self):
        owner = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", owner)
        outsider = repo.create_user(self.conn, "outsider@example.com")
        self.assertEqual(tenant_scope.resolve_workspace_role(self.conn, owner, workspace_id), "owner")
        self.assertIsNone(tenant_scope.resolve_workspace_role(self.conn, outsider, workspace_id))

    def test_contracts_are_isolated_by_workspace(self):
        user_a = repo.create_user(self.conn, "a@example.com")
        user_b = repo.create_user(self.conn, "b@example.com")
        workspace_a = repo.create_workspace(self.conn, "Workspace A", user_a)
        workspace_b = repo.create_workspace(self.conn, "Workspace B", user_b)
        repo.create_contract(self.conn, workspace_a, "s3://a", "hash-a", "A.sol")
        repo.create_contract(self.conn, workspace_b, "s3://b", "hash-b", "B.sol")

        cur = db.execute(self.conn, "SELECT name FROM contracts WHERE workspace_id = ?", (workspace_a,))
        rows = [db.normalize_row(r) for r in cur.fetchall()]
        self.assertEqual([r["name"] for r in rows], ["A.sol"])


class JobQueueIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def _seed_job(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "hash", "A.sol")
        return repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")

    def test_claim_then_full_transition_to_succeeded(self):
        job_id = self._seed_job()
        claimed = repo.claim_next_job(self.conn, "worker-1")
        self.assertEqual(claimed["id"], job_id)
        self.assertEqual(claimed["claimed_by"], "worker-1")
        self.assertIsNotNone(claimed["claimed_at"])

        self.assertTrue(repo.transition_job_status(self.conn, job_id, "claimed", "running"))
        self.assertTrue(repo.transition_job_status(self.conn, job_id, "running", "succeeded"))
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "succeeded")
        self.assertIsNotNone(job["started_at"])
        self.assertIsNotNone(job["completed_at"])

    def test_failed_transition_increments_attempt_count(self):
        job_id = self._seed_job()
        repo.claim_next_job(self.conn, "worker-1")
        repo.transition_job_status(self.conn, job_id, "claimed", "running")
        repo.transition_job_status(self.conn, job_id, "running", "failed", error="LLM timeout")
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["attempt_count"], 1)
        self.assertEqual(job["last_error"], "LLM timeout")

    def test_claiming_an_empty_queue_returns_none(self):
        self.assertIsNone(repo.claim_next_job(self.conn, "worker-1"))

    def test_webhook_dedup_second_delivery_returns_false(self):
        self.assertTrue(repo.record_webhook_event(self.conn, "evt_pg_1", "checkout.session.completed"))
        self.assertFalse(repo.record_webhook_event(self.conn, "evt_pg_1", "checkout.session.completed"))


class FencingIntegrationTests(unittest.TestCase):
    """Real-Postgres coverage for repo.finalize_job_attempt()'s fencing -
    tests/test_backend_job_queue.py's own FinalizeJobAttemptTests already
    proves this same property against SQLite; this file's own module
    docstring explains why that is never assumed to carry over
    unverified. Same (attempt_count, claimed_by)-keyed mechanism as
    ReapExpiredJobsTests' own atomicity fix - CHECK-violation exception
    classes differ from SQLite's (psycopg.errors.*, not sqlite3.
    IntegrityError) but the property under test (does a losing race ever
    raise, corrupt budget, or overwrite a newer attempt) is the same."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def _seed_job(self):
        user_id = repo.create_user(self.conn, "fencing-pg@example.com")
        workspace_id = repo.create_workspace(self.conn, "Fencing WS", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://fencing", "hash", "Fencing.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        return job_id, workspace_id

    def _expire_lease(self, job_id):
        db.execute(self.conn, "UPDATE analysis_jobs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (job_id,))
        self.conn.commit()

    def test_stale_attempt_after_reap_and_reclaim_cannot_finalize_on_real_postgres(self):
        job_id, workspace_id = self._seed_job()
        claimed = repo.claim_next_job(self.conn, "worker-A")
        self.assertEqual(claimed["id"], job_id)
        stale_attempt_count = claimed["attempt_count"]
        stale_claimed_by = claimed["claimed_by"]
        self.assertTrue(repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"]))
        self.assertTrue(repo.finalize_job_attempt(
            self.conn, job_id, workspace_id, stale_attempt_count, stale_claimed_by,
            from_status="claimed", to_status="running",
        )["applied"])

        self._expire_lease(job_id)
        self.assertEqual(repo.reap_expired_jobs(self.conn), {"requeued": 1, "failed": 0})
        # The reap above set a retry-backoff next_eligible_at (queue
        # fairness) - simulate that window having already passed, exactly
        # like _expire_lease() above simulates state claim_next_job()'s
        # own API can't produce.
        db.execute(self.conn, "UPDATE analysis_jobs SET next_eligible_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (job_id,))
        self.conn.commit()

        reclaimed = repo.claim_next_job(self.conn, "worker-C")
        self.assertEqual(reclaimed["id"], job_id)
        new_attempt_count = reclaimed["attempt_count"]
        self.assertNotEqual(new_attempt_count, stale_attempt_count)
        self.assertTrue(repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"]))
        self.assertTrue(repo.finalize_job_attempt(
            self.conn, job_id, workspace_id, new_attempt_count, "worker-C",
            from_status="claimed", to_status="running",
        )["applied"])
        budget_before = repo.get_workspace_budget(self.conn, workspace_id)

        try:
            result = repo.finalize_job_attempt(
                self.conn, job_id, workspace_id, stale_attempt_count, stale_claimed_by,
                from_status="running", to_status="succeeded",
                budget_units=repo.JOB_MODE_BUDGET_COST["quick"], budget_action="consume",
                report_storage_ref="s3://stale-pg-report", report_score_status="computed",
                report_score=42, report_risk_band="HIGH",
            )
        except Exception as exc:  # pragma: no cover - the whole point is that this never happens, on Postgres either.
            self.fail("finalize_job_attempt() raised on a losing-fencing race against real Postgres: %r" % (exc,))

        self.assertEqual(result, {"applied": False, "report_id": None})
        job_after = repo.get_job(self.conn, job_id)
        self.assertEqual(job_after["status"], "running")  # attempt N+1's own state - untouched.
        self.assertEqual(job_after["attempt_count"], new_attempt_count)
        self.assertEqual(job_after["claimed_by"], "worker-C")
        reports = db.execute(self.conn, "SELECT * FROM reports WHERE job_id = ?", (job_id,)).fetchall()
        self.assertEqual(reports, [])
        budget_after = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget_after["reserved_units"], budget_before["reserved_units"])
        self.assertEqual(budget_after["consumed_units"], budget_before["consumed_units"])

        # The connection must remain fully usable afterward - Postgres
        # (unlike SQLite) aborts a transaction on any error until
        # rollback(). finalize_job_attempt()'s own rollback() on the
        # rowcount==0 branch is not an error path, so this should never
        # be at risk, but proving it end to end is exactly the "do not
        # assume parity" discipline this file's own docstring asks for.
        self.assertTrue(repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"]))

    def test_worker_wins_the_race_on_real_postgres_reaper_then_finds_nothing(self):
        job_id, workspace_id = self._seed_job()
        claimed = repo.claim_next_job(self.conn, "worker-A")
        attempt_count = claimed["attempt_count"]
        claimed_by = claimed["claimed_by"]
        self.assertTrue(repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"]))
        self.assertTrue(repo.finalize_job_attempt(
            self.conn, job_id, workspace_id, attempt_count, claimed_by,
            from_status="claimed", to_status="running",
        )["applied"])

        result = repo.finalize_job_attempt(
            self.conn, job_id, workspace_id, attempt_count, claimed_by,
            from_status="running", to_status="succeeded",
            budget_units=repo.JOB_MODE_BUDGET_COST["quick"], budget_action="consume",
            report_storage_ref="s3://real-pg-report", report_score_status="computed",
            report_score=10, report_risk_band="LOW",
        )
        self.assertTrue(result["applied"])
        self.assertIsNotNone(result["report_id"])

        self._expire_lease(job_id)
        self.assertEqual(repo.reap_expired_jobs(self.conn), {"requeued": 0, "failed": 0})
        budget = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget["reserved_units"], 0)
        self.assertEqual(budget["consumed_units"], 1)


class ConcurrentClaimIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def test_two_real_connections_racing_for_one_job_exactly_one_wins(self):
        user_id = repo.create_user(self.conn, "race@example.com")
        workspace_id = repo.create_workspace(self.conn, "Race WS", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://race", "hash", "Race.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")

        barrier = threading.Barrier(2)
        results = {}

        def _claim(worker_id):
            worker_conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)  # maximize the chance both UPDATEs genuinely overlap.
                results[worker_id] = repo.claim_next_job(worker_conn, worker_id)
            finally:
                worker_conn.close()

        threads = [threading.Thread(target=_claim, args=(w,)) for w in ("worker-A", "worker-B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        winners = [w for w, r in results.items() if r is not None]
        losers = [w for w, r in results.items() if r is None]
        self.assertEqual(len(winners), 1, "expected exactly one winner, got: %r" % (results,))
        self.assertEqual(len(losers), 1)
        self.assertEqual(results[winners[0]]["id"], job_id)

        final = repo.get_job(self.conn, job_id)
        self.assertEqual(final["status"], "claimed")
        self.assertEqual(final["claimed_by"], winners[0])


class QueueFairnessIntegrationTests(unittest.TestCase):
    """Admission control / queue fairness against a REAL Postgres server
    with REAL concurrent connections and threads - tests/test_backend_
    job_queue.py's own QueueFairnessTests already proves the ORDERING
    logic (sequential calls, SQLite); this class proves the LOCKING
    discipline (FOR UPDATE OF s, j SKIP LOCKED - see claim_next_job()'s
    own Postgres docstring) actually holds under genuine concurrency,
    which a single-connection test cannot exercise."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def _seed(self, label, job_count=1):
        user_id = repo.create_user(self.conn, "%s@example.com" % label)
        workspace_id = repo.create_workspace(self.conn, label.upper(), user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://%s" % label, "hash-%s" % label, "%s.sol" % label)
        job_ids = [repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick") for _ in range(job_count)]
        return workspace_id, job_ids

    def test_two_real_workers_racing_serve_two_distinct_workspaces_not_the_same_one_twice(self):
        workspace_a, (a1, a2) = self._seed("a", job_count=2)
        workspace_b, (b1,) = self._seed("b", job_count=1)

        results, errors = {}, []
        barrier = threading.Barrier(2)

        def _claim(worker_id):
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)
                results[worker_id] = repo.claim_next_job(conn, worker_id)
            except Exception as exc:  # pragma: no cover - the whole point of this test is that this never happens.
                errors.append(exc)
            finally:
                conn.close()

        threads = [threading.Thread(target=_claim, args=(w,)) for w in ("worker-1", "worker-2")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], "unhandled error(s): %r" % (errors,))
        claimed_ids = {r["id"] for r in results.values() if r is not None}
        self.assertEqual(claimed_ids, {a1, b1}, "expected exactly A's oldest job + B's only job, got: %r" % (results,))
        self.assertNotIn(a2, claimed_ids)  # never A1+A2 while B was eligible and unserved.

    def test_five_real_workers_racing_across_five_workspaces_each_served_exactly_once(self):
        workspaces_and_jobs = [self._seed(label, job_count=2) for label in ("a", "b", "c", "d", "e")]

        results, errors = {}, []
        worker_ids = ["worker-%d" % i for i in range(1, 6)]
        barrier = threading.Barrier(len(worker_ids))

        def _claim(worker_id):
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)
                results[worker_id] = repo.claim_next_job(conn, worker_id)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                conn.close()

        threads = [threading.Thread(target=_claim, args=(w,)) for w in worker_ids]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        self.assertEqual(errors, [], "unhandled error(s): %r" % (errors,))
        claimed = [r for r in results.values() if r is not None]
        self.assertEqual(len(claimed), 5, "expected all 5 workers to claim something, got: %r" % (results,))
        claimed_workspaces = {job["workspace_id"] for job in claimed}
        self.assertEqual(
            claimed_workspaces, {ws for ws, _ in workspaces_and_jobs},
            "expected all 5 distinct workspaces served exactly once in the first round, got: %r" % (claimed_workspaces,),
        )
        claimed_ids = {job["id"] for job in claimed}
        self.assertEqual(len(claimed_ids), 5)  # also no double-claim of any single job.

    def test_concurrent_enqueues_for_a_brand_new_workspace_create_exactly_one_state_row(self):
        # tests/test_backend_job_queue.py's own QueueFairnessTests already
        # proves this SEQUENTIALLY (single connection) - this proves it
        # against real GENUINE concurrency: two real connections racing
        # to be the FIRST enqueue_job() call ever made for the same
        # brand-new workspace, both attempting their own "INSERT ...
        # ON CONFLICT (workspace_id) DO NOTHING" for workspace_queue_state
        # inside their own transaction, at the same time.
        user_id = repo.create_user(self.conn, "concurrent-enqueue@example.com")
        workspace_id = repo.create_workspace(self.conn, "Concurrent Enqueue WS", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://concurrent-enqueue", "hash", "C.sol")

        results, errors = {}, []
        barrier = threading.Barrier(2)

        def _enqueue(worker_id):
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)
                results[worker_id] = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
            except Exception as exc:  # pragma: no cover - the whole point of ON CONFLICT DO NOTHING is that this never happens.
                errors.append(exc)
            finally:
                conn.close()

        threads = [threading.Thread(target=_enqueue, args=(w,)) for w in ("enqueuer-1", "enqueuer-2")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], "unhandled error(s) racing to create workspace_queue_state: %r" % (errors,))
        self.assertEqual(len(results), 2)  # both enqueues succeeded - each created its OWN job.
        job_ids = set(results.values())
        self.assertEqual(len(job_ids), 2)  # two distinct jobs, not a collision.

        rows = db.execute(self.conn, "SELECT * FROM workspace_queue_state WHERE workspace_id = ?", (workspace_id,)).fetchall()
        self.assertEqual(len(rows), 1, "expected exactly one workspace_queue_state row, got: %r" % (rows,))
        # Both jobs must be genuine claim candidates - neither was silently
        # excluded by a missing/duplicated state row.
        first = repo.claim_next_job(self.conn, "worker-verify-1")
        second = repo.claim_next_job(self.conn, "worker-verify-2")
        self.assertEqual({first["id"], second["id"]}, job_ids)


class BudgetContentionIntegrationTests(unittest.TestCase):
    """The one gap the prior concurrency audit flagged and left open:
    two real connections racing for the LAST unit of a workspace's
    budget - a DIFFERENT race from ConcurrentClaimIntegrationTests'
    own (that one races for a JOB; this one races for a budget
    RESERVATION) and explicitly kept as its own regression, separate
    from queue fairness above."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def test_two_real_connections_racing_for_the_last_unit_exactly_one_wins(self):
        user_id = repo.create_user(self.conn, "budget-race@example.com")
        workspace_id = repo.create_workspace(self.conn, "Budget Race WS", user_id)
        # Exhaust the ceiling down to exactly 1 unit of headroom, so two
        # simultaneous 1-unit reservations can never BOTH legitimately fit.
        # The budget row does not exist yet (lazily created on first
        # reserve - workspace_budgets' own docstring) - reserve_workspace_
        # budget() itself creates it, so DEFAULT_BUDGET_LIMIT_UNITS (the
        # known ceiling a fresh row always starts with) is used directly
        # rather than reading a row that is not there yet.
        almost_all = repo.DEFAULT_BUDGET_LIMIT_UNITS - 1
        repo.reserve_workspace_budget(self.conn, workspace_id, almost_all)
        repo.consume_reserved_workspace_budget(self.conn, workspace_id, almost_all)

        results, errors = {}, []
        barrier = threading.Barrier(2)

        def _reserve(worker_id):
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)
                results[worker_id] = repo.reserve_workspace_budget(conn, workspace_id, 1)
            except Exception as exc:  # pragma: no cover - a CHECK violation here would be the bug this test guards against.
                errors.append(exc)
            finally:
                conn.close()

        threads = [threading.Thread(target=_reserve, args=(w,)) for w in ("worker-A", "worker-B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], "unhandled error(s) - a real CHECK violation would land here: %r" % (errors,))
        winners = [w for w, r in results.items() if r is True]
        losers = [w for w, r in results.items() if r is False]
        self.assertEqual(len(winners), 1, "expected exactly one winner, got: %r" % (results,))
        self.assertEqual(len(losers), 1)

        final = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(final["reserved_units"] + final["consumed_units"], final["limit_units"])  # exactly at the ceiling, never over.


class CommercialGuardsIntegrationTests(unittest.TestCase):
    """D-108 against a REAL Postgres server with REAL concurrent
    connections: the pending-jobs cap (per-workspace row lock), the
    technical budget reservation, the submit rate limit and the Pro
    priority ordering expression (timestamptz arithmetic, Postgres-only
    SQL). tests/test_backend_commercial_guards.py covers the same rules on
    SQLite."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)
        self.user_id = repo.create_user(self.conn, "guards-%s@example.com" % repo.new_id())

    def _workspace(self, plan):
        ws = repo.create_workspace(self.conn, "Guards WS", self.user_id)
        repo.create_entitlement(self.conn, ws, plan, "active", billing_interval="monthly")
        return ws

    def _submit(self, conn, ws, loc=10, mode="quick", max_pending=repo.DEFAULT_MAX_PENDING_JOBS_PER_WORKSPACE):
        contract = repo.create_contract(conn, ws, "s3://guards/%s" % repo.new_id(), "hash", "G.sol")
        ent = repo.get_entitlement_by_workspace(conn, ws)
        return repo.enqueue_job_with_usage(conn, ws, contract, self.user_id, mode, None, ent, loc, max_pending_jobs=max_pending)

    def _race(self, n, fn):
        results, errors, lock = [], [], threading.Lock()
        barrier = threading.Barrier(n)

        def run():
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=10)
                outcome = fn(conn)
            except repo.UsageLimitError as exc:
                outcome = exc.code
            except Exception as exc:  # pragma: no cover - a deadlock/CHECK violation would land here.
                errors.append(exc)
                return
            finally:
                conn.close()
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=run) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(errors, [])
        return results

    def test_concurrent_submissions_never_exceed_the_pending_cap(self):
        ws = self._workspace("pro")
        results = self._race(10, lambda conn: self._submit(conn, ws, max_pending=3) and "ok")
        self.assertEqual(sorted(results), ["ok"] * 3 + ["too_many_pending_jobs"] * 7)
        self.assertEqual(repo.count_pending_jobs(self.conn, ws), 3)
        usage = repo.usage_summary(self.conn, ws, repo.get_entitlement_by_workspace(self.conn, ws))
        self.assertEqual(usage["loc_reserved"], 30)

    def test_pending_cap_frees_on_terminal_transitions(self):
        ws = self._workspace("standard")
        job = self._submit(self.conn, ws, max_pending=1)
        with self.assertRaises(repo.UsageLimitError):
            self._submit(self.conn, ws, max_pending=1)
        self.assertTrue(repo.transition_job_status(self.conn, job, "queued", "canceled"))
        self._submit(self.conn, ws, max_pending=1)

    def test_concurrent_admissions_never_overshoot_the_technical_budget(self):
        ws = self._workspace("standard")
        first = self._submit(self.conn, ws, mode="standard")
        self.assertTrue(repo.transition_job_status(self.conn, first, "queued", "canceled"))
        db.execute(self.conn, "UPDATE technical_budget_periods SET consumed_units = limit_units - 6 WHERE workspace_id = ?", (ws,))
        self.conn.commit()
        results = self._race(8, lambda conn: self._submit(conn, ws, mode="standard", max_pending=100) and "ok")
        self.assertEqual(sorted(results), ["ok"] * 3 + ["technical_budget_exhausted"] * 5)
        tech = repo.technical_budget_summary(self.conn, ws, repo.get_entitlement_by_workspace(self.conn, ws))
        self.assertEqual(tech["reserved_units"] + tech["consumed_units"], tech["limit_units"])

    def test_technical_units_settle_with_the_job(self):
        ws = self._workspace("pro")
        job = self._submit(self.conn, ws, mode="pro")
        self.assertIsNotNone(repo.claim_next_job(self.conn, "w1"))
        self.assertTrue(repo.transition_job_status(self.conn, job, "claimed", "running"))
        self.assertTrue(repo.transition_job_status(self.conn, job, "running", "failed"))
        tech = repo.technical_budget_summary(self.conn, ws, repo.get_entitlement_by_workspace(self.conn, ws))
        self.assertEqual((tech["reserved_units"], tech["consumed_units"]), (0, 4))   # ran -> compute spent
        self.assertEqual(repo.get_job(self.conn, job)["priority"], 1)

    def test_concurrent_rate_limit_attempts_never_exceed_the_limit(self):
        ws = self._workspace("standard")
        results = self._race(12, lambda conn: repo.check_submit_rate_limit(conn, self.user_id, ws, 4))
        self.assertEqual(results.count(0), 4)                                             # exact: per-user lock, no burst over- or under-shoot
        self.assertTrue(all(1 <= r <= repo.SUBMIT_RATE_LIMIT_WINDOW_SECONDS for r in results if r))
        n = db.execute(self.conn, "SELECT COUNT(*) AS n FROM submit_attempts WHERE user_id = ?", (self.user_id,)).fetchone()["n"]
        self.assertEqual(n, 4)

    def test_pro_priority_ordering_and_bonus_boundary(self):
        std = self._workspace("standard")
        pro = self._workspace("pro")
        s1 = self._submit(self.conn, std)
        p1 = self._submit(self.conn, pro)
        self.assertEqual(repo.claim_next_job(self.conn, "w1")["id"], p1)                  # both never served: priority first
        self.assertTrue(repo.transition_job_status(self.conn, p1, "claimed", "queued"))
        bonus = repo.QUEUE_PRIORITY_BONUS_SECONDS
        for std_age, expected in ((bonus - 1, p1), (bonus + 1, s1)):
            db.execute(self.conn, "UPDATE workspace_queue_state SET last_claimed_at = now() WHERE workspace_id = ?", (pro,))
            db.execute(self.conn, "UPDATE workspace_queue_state SET last_claimed_at = now() - make_interval(secs => ?) WHERE workspace_id = ?", (std_age, std))
            self.conn.commit()
            claimed = repo.claim_next_job(self.conn, "w2")
            self.assertEqual(claimed["id"], expected)
            self.assertTrue(repo.transition_job_status(self.conn, claimed["id"], "claimed", "queued"))


class ProjectsMultiFileIntegrationTests(unittest.TestCase):
    """D-109 against a REAL Postgres server: project CRUD and isolation on
    UUID columns, the per-file manifest written atomically with its
    contract, the project filter on the job list, and workspace-scoped
    idempotency keys. tests/test_backend_projects_multifile.py covers the
    same rules (and the input validation) on SQLite."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)
        self.user_id = repo.create_user(self.conn, "d109-%s@example.com" % repo.new_id())
        self.ws = repo.create_workspace(self.conn, "WS", self.user_id)
        self.other = repo.create_workspace(self.conn, "Other", self.user_id)

    def test_project_crud_and_isolation(self):
        pid = repo.create_project(self.conn, self.ws, "Vault")
        with self.assertRaises(repo.ProjectNameTakenError):
            repo.create_project(self.conn, self.ws, "Vault")
        repo.create_project(self.conn, self.ws, "After a refused name")   # the connection is usable after the rollback
        foreign = repo.create_project(self.conn, self.other, "Vault")
        self.assertIsNone(repo.get_project(self.conn, self.ws, foreign))
        self.assertFalse(repo.rename_project(self.conn, self.ws, foreign, "x"))
        self.assertFalse(repo.delete_project(self.conn, self.ws, foreign))
        self.assertTrue(repo.rename_project(self.conn, self.ws, pid, "Vault 2"))
        self.assertTrue(repo.delete_project(self.conn, self.ws, pid))
        self.assertIsNone(repo.get_project(self.conn, self.ws, pid))
        self.assertEqual({p["name"] for p in repo.list_projects(self.conn, self.ws)}, {"After a refused name"})

    def test_manifest_is_atomic_and_jobs_filter_by_project(self):
        import backend.submission_input as si
        built = si.from_files([{"path": "src/A.sol", "content": "pragma solidity ^0.8.20;\ncontract A {}\n"},
                               {"path": "src/B.sol", "content": "pragma solidity ^0.8.20;\ncontract B {}\n"}], 2 * 1024 * 1024)
        pid = repo.create_project(self.conn, self.ws, "P")
        cid = repo.create_contract(self.conn, self.ws, "s3://x", "h", "n", project_id=pid, source_kind="files", files=built["files"])
        self.assertEqual([r["path"] for r in repo.list_contract_files(self.conn, self.ws, cid)], ["src/A.sol", "src/B.sol"])
        n_before = db.execute(self.conn, "SELECT COUNT(*) AS n FROM contracts").fetchone()["n"]
        with self.assertRaises(Exception):
            repo.create_contract(self.conn, self.ws, "s3://y", "h", "n", source_kind="files", files=built["files"] + [built["files"][0]])
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM contracts").fetchone()["n"], n_before)
        loose = repo.create_contract(self.conn, self.ws, "s3://z", "h", "n")
        in_project = repo.enqueue_job(self.conn, self.ws, cid, self.user_id, "quick", idempotency_key=repo.scoped_idempotency_key(self.ws, "k"))
        repo.enqueue_job(self.conn, self.ws, loose, self.user_id, "quick", idempotency_key=repo.scoped_idempotency_key(self.other, "k"))
        self.assertEqual([j["id"] for j in repo.list_jobs_by_workspace(self.conn, self.ws, project_id=pid)], [in_project])
        self.assertEqual(repo.list_jobs_by_workspace(self.conn, self.other, project_id=pid), [])


class TrialIntegrationTests(unittest.TestCase):
    """D-112 against a REAL Postgres server: 0013's rewritten CHECK
    constraints (plan 'trial', usage model 'trial'), one Trial per
    normalized email under real concurrency, the Trial scan reservation and
    its settlement, the sign-up token purpose, and that the grant record
    survives the account."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)
        self.user_id = repo.create_user(self.conn, "d112-%s@example.com" % repo.new_id())
        self.email = repo.get_user(self.conn, self.user_id)["email"]

    def test_grant_reserve_settle_and_constraints(self):
        ws = repo.grant_trial(self.conn, self.email, self.user_id)
        with self.assertRaises(repo.TrialAlreadyGrantedError):
            repo.grant_trial(self.conn, self.email, self.user_id)
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM workspaces").fetchone()["n"], 1)
        ent = repo.get_entitlement_by_workspace(self.conn, ws)
        self.assertEqual((ent["plan"], ent["status"]), ("trial", "active"))
        contract = repo.create_contract(self.conn, ws, "s3://x", "h", "n")
        job = repo.enqueue_job_with_usage(self.conn, ws, contract, self.user_id, "quick", None, ent, 500)
        self.assertEqual(repo.get_job_usage(self.conn, job)["usage_model"], "trial")
        with self.assertRaises(repo.UsageLimitError) as ctx:
            repo.enqueue_job_with_usage(self.conn, ws, repo.create_contract(self.conn, ws, "s3://y", "h", "n"), self.user_id, "quick", None, ent, 10)
        self.assertEqual(ctx.exception.code, "trial_already_used")
        with self.assertRaises(repo.UsageLimitError) as ctx:
            repo.enqueue_job_with_usage(self.conn, ws, contract, self.user_id, "quick", None, ent, 501)
        self.assertEqual(ctx.exception.code, "loc_per_scan_limit_exceeded")
        claimed = repo.claim_next_job(self.conn, "w")
        repo.finalize_job_attempt(self.conn, job, ws, claimed["attempt_count"], "w", "claimed", "running")
        repo.finalize_job_attempt(self.conn, job, ws, claimed["attempt_count"], "w", "running", "succeeded",
                                  report_storage_ref="reports/x", report_score_status="computed", report_score=90, report_risk_band="LOW")
        grant = repo.get_trial_grant(self.conn, self.email)
        self.assertEqual((grant["status"], str(grant["job_id"])), ("consumed", job))
        with self.assertRaises(db.integrity_error_class(self.conn)):     # the email key is stored normalized only
            db.execute(self.conn, "INSERT INTO trial_grants (normalized_email, workspace_id, status, granted_at, updated_at) VALUES (?, ?, 'available', now(), now())",
                       ("Upper@Example.com", ws))
        self.conn.rollback()
        token = auth.request_magic_link(self.conn, "signup-%s@example.com" % repo.new_id(), "127.0.0.1", purpose="signup")
        session = auth.consume_token_and_create_session(self.conn, token)
        self.assertEqual(session["purpose"], "signup")
        # The record outlives the account: the users row may go, the grant stays.
        db.execute(self.conn, "UPDATE users SET email = ? WHERE id = ?", ("deleted-%s@invalid.example" % self.user_id, self.user_id))
        self.conn.commit()
        again = repo.create_user(self.conn, self.email)
        with self.assertRaises(repo.TrialAlreadyGrantedError):
            repo.grant_trial(self.conn, self.email, again)

    def test_concurrent_trial_project_creations_yield_exactly_one(self):
        ws = repo.grant_trial(self.conn, self.email, self.user_id)
        results, barrier = [], threading.Barrier(6)

        def attempt(i):
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait()
                repo.create_project_capped(conn, ws, "P%d" % i, 1)
                results.append("ok")
            except repo.ProjectLimitError:
                results.append("limit")
            except Exception as exc:   # pragma: no cover
                results.append(repr(exc))
            finally:
                conn.close()

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
        [th.start() for th in threads]
        [th.join(30) for th in threads]
        self.assertEqual(sorted(results), ["limit"] * 5 + ["ok"])
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM projects WHERE workspace_id = ?", (ws,)).fetchone()["n"], 1)

    def test_concurrent_grants_yield_exactly_one(self):
        results, barrier = [], threading.Barrier(6)

        def attempt():
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait()
                repo.grant_trial(conn, self.email, self.user_id)
                results.append("ok")
            except repo.TrialAlreadyGrantedError:
                results.append("refused")
            except Exception as exc:   # pragma: no cover
                results.append(repr(exc))
            finally:
                conn.close()

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        [th.start() for th in threads]
        [th.join(30) for th in threads]
        self.assertEqual(sorted(results), ["ok"] + ["refused"] * 5)
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM entitlements WHERE plan = 'trial'").fetchone()["n"], 1)
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM workspaces").fetchone()["n"], 1)


class GitHubConnectionsIntegrationTests(unittest.TestCase):
    """D-111 against a REAL Postgres server: OAuth state single-use and
    expiry, one active connection per (workspace, user) with tokens wiped on
    revoke, the active-needs-token CHECK, and a GitHub scan's repository/
    ref/commit stored with its contract and shown in the job summaries."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)
        self.user_id = repo.create_user(self.conn, "d111-%s@example.com" % repo.new_id())
        self.other_user = repo.create_user(self.conn, "d111o-%s@example.com" % repo.new_id())
        self.ws = repo.create_workspace(self.conn, "WS", self.user_id)
        repo.create_entitlement(self.conn, self.ws, "standard", "active", billing_interval="monthly")

    def test_states_connections_and_git_sources(self):
        repo.create_github_oauth_state(self.conn, "hash-1", self.ws, self.user_id, 600)
        self.assertIsNone(repo.consume_github_oauth_state(self.conn, "hash-1", self.other_user))
        self.assertEqual(repo.consume_github_oauth_state(self.conn, "hash-1", self.user_id)["workspace_id"], self.ws)
        self.assertIsNone(repo.consume_github_oauth_state(self.conn, "hash-1", self.user_id))
        repo.create_github_oauth_state(self.conn, "hash-2", self.ws, self.user_id, 1, now=datetime.now(timezone.utc) - timedelta(minutes=5))
        self.assertIsNone(repo.consume_github_oauth_state(self.conn, "hash-2", self.user_id))

        first = repo.save_github_connection(self.conn, self.ws, self.user_id, 9001, "octo", "", "v1.a", None, "v1.r", None)
        second = repo.save_github_connection(self.conn, self.ws, self.user_id, 9001, "octo", "", "v1.b", None, None, None)
        self.assertEqual(repo.get_active_github_connection(self.conn, self.ws, self.user_id)["id"], second)
        old = repo.get_github_connection(self.conn, self.ws, first)
        self.assertEqual((old["status"], old["access_token_enc"], old["refresh_token_enc"]), ("revoked", None, None))
        with self.assertRaises(db.integrity_error_class(self.conn)):
            db.execute(self.conn, "INSERT INTO github_connections (id, workspace_id, user_id, github_account_id, github_login, status, created_at, updated_at) "
                       "VALUES (?, ?, ?, 1, 'x', 'active', now(), now())", (repo.new_id(), self.ws, self.other_user))
        self.conn.rollback()
        with self.assertRaises(db.integrity_error_class(self.conn)):     # a second ACTIVE connection for the same member
            db.execute(self.conn, "INSERT INTO github_connections (id, workspace_id, user_id, github_account_id, github_login, status, access_token_enc, created_at, updated_at) "
                       "VALUES (?, ?, ?, 1, 'x', 'active', 'v1.c', now(), now())", (repo.new_id(), self.ws, self.user_id))
        self.conn.rollback()
        self.assertTrue(repo.update_github_connection_tokens(self.conn, self.ws, second, "v1.n", repo.utcnow_iso(), "v1.m", None))
        self.assertTrue(repo.set_github_connection_status(self.conn, self.ws, second, "invalid"))
        self.assertIsNone(repo.get_active_github_connection(self.conn, self.ws, self.user_id))

        sha = "a" * 40
        contract = repo.create_contract(self.conn, self.ws, "s3://x", "h", "octo/vault@aaaa", source_kind="files",
                                        git_source={"connection_id": second, "repository_id": 101, "repository_full_name": "octo/vault", "ref": "main", "commit_sha": sha})
        self.assertEqual(repo.get_contract_git_source(self.conn, self.ws, contract)["commit_sha"], sha)
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        job = repo.enqueue_job_with_usage(self.conn, self.ws, contract, self.user_id, "quick", None, ent, 10)
        row = repo.list_job_summaries(self.conn, self.ws)[0]
        self.assertEqual((row["id"], row["git_repository"], row["git_ref"], row["git_commit_sha"]), (job, "octo/vault", "main", sha))
        with self.assertRaises(db.integrity_error_class(self.conn)):     # a truncated SHA is refused by the CHECK
            repo.create_contract(self.conn, self.ws, "s3://y", "h", "n", source_kind="files",
                                 git_source={"repository_id": 1, "repository_full_name": "a/b", "ref": "main", "commit_sha": "abc"})
        self.assertEqual(repo.revoke_workspace_github_connections(self.conn, self.ws), 0)


class WebAppQueriesIntegrationTests(unittest.TestCase):
    """D-110 against a REAL Postgres server: the job-summary join (project,
    usage, report - every join pinned to the workspace), the report-by-job
    lookup and the per-service-month scan count shown by the web app."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)
        self.user_id = repo.create_user(self.conn, "d110-%s@example.com" % repo.new_id())
        self.ws = repo.create_workspace(self.conn, "WS", self.user_id)
        self.other = repo.create_workspace(self.conn, "Other", self.user_id)
        repo.create_entitlement(self.conn, self.ws, "standard", "active", billing_interval="monthly")

    def test_job_summaries_report_lookup_and_scan_count(self):
        pid = repo.create_project(self.conn, self.ws, "P")
        contract = repo.create_contract(self.conn, self.ws, "s3://x", "h", "n", project_id=pid, source_kind="files")
        ent = repo.get_entitlement_by_workspace(self.conn, self.ws)
        job = repo.enqueue_job_with_usage(self.conn, self.ws, contract, self.user_id, "quick", None, ent, 120)
        claimed = repo.claim_next_job(self.conn, "w")
        repo.finalize_job_attempt(self.conn, job, self.ws, claimed["attempt_count"], "w", "claimed", "running")
        res = repo.finalize_job_attempt(self.conn, job, self.ws, claimed["attempt_count"], "w", "running", "succeeded",
                                        report_storage_ref="reports/x/y", report_score_status="computed", report_score=40, report_risk_band="HIGH")
        rows = repo.list_job_summaries(self.conn, self.ws, project_id=pid)
        self.assertEqual([(r["id"], r["project_name"], r["source_kind"], r["effective_loc"], r["report_id"], r["score"], r["risk_band"]) for r in rows],
                         [(job, "P", "files", 120, res["report_id"], 40, "HIGH")])
        self.assertEqual(repo.list_job_summaries(self.conn, self.other), [])
        self.assertEqual(repo.get_report_by_job(self.conn, self.ws, job)["id"], res["report_id"])
        self.assertIsNone(repo.get_report_by_job(self.conn, self.other, job))
        usage = repo.usage_summary(self.conn, self.ws, ent)
        self.assertEqual((usage["scans_in_period"], usage["scans_completed_in_period"]), (1, 1))
        self.assertEqual(repo.get_user(self.conn, self.user_id)["id"], self.user_id)


class AuthTokenIntegrationTests(unittest.TestCase):
    """Phase 2 identity/access (docs/decisiones.md D-077/D-078 follow-up):
    backend/auth.py against real PostgreSQL - UUID/TIMESTAMPTZ
    normalization for auth_tokens/sessions rows, and the same real
    concurrent-consume race ConcurrentClaimIntegrationTests already
    proved for job claiming, applied to magic-link token consumption."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def test_token_and_session_ids_are_plain_strings_not_native_pg_types(self):
        token = auth.request_magic_link(self.conn, "pg-auth@example.com", ip="10.0.0.1")
        session = auth.consume_token_and_create_session(self.conn, token)
        self.assertIsInstance(session["session_id"], str)
        self.assertIsInstance(session["user_id"], str)
        result = auth.validate_session(self.conn, session["session_token"])
        self.assertEqual(result["user_id"], session["user_id"])

    def test_single_use_consume_against_real_postgres(self):
        token = auth.request_magic_link(self.conn, "pg-single-use@example.com")
        first = auth.consume_token_and_create_session(self.conn, token)
        second = auth.consume_token_and_create_session(self.conn, token)
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_rate_limit_enforced_against_real_postgres(self):
        for i in range(auth.RATE_LIMIT_MAX_PER_EMAIL):
            auth.request_magic_link(self.conn, "pg-ratelimit@example.com", ip="10.0.0.%d" % i)
        with self.assertRaises(auth.RateLimitExceeded):
            auth.request_magic_link(self.conn, "pg-ratelimit@example.com", ip="10.0.0.99")

    def test_two_real_connections_racing_to_consume_the_same_token_exactly_one_wins(self):
        token = auth.request_magic_link(self.conn, "pg-race@example.com")
        self.conn.commit()

        barrier = threading.Barrier(2)
        results = {}

        def _consume(worker_id):
            worker_conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)
                results[worker_id] = auth.consume_token_and_create_session(worker_conn, token)
            finally:
                worker_conn.close()

        threads = [threading.Thread(target=_consume, args=(w,)) for w in ("A", "B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        winners = [w for w, r in results.items() if r is not None]
        losers = [w for w, r in results.items() if r is None]
        self.assertEqual(len(winners), 1, "expected exactly one winner, got: %r" % (results,))
        self.assertEqual(len(losers), 1)

    def test_cross_tenant_member_management_against_real_postgres(self):
        owner_a = repo.create_user(self.conn, "pg-owner-a@example.com")
        owner_b = repo.create_user(self.conn, "pg-owner-b@example.com")
        workspace_a = repo.create_workspace(self.conn, "PG Workspace A", owner_a)
        workspace_b = repo.create_workspace(self.conn, "PG Workspace B", owner_b)
        self.conn.commit()

        self.assertIsNone(tenant_scope.resolve_workspace_role(self.conn, owner_b, workspace_a))
        with self.assertRaises(tenant_scope.TenantScopeError):
            tenant_scope.require_workspace_role(self.conn, owner_b, workspace_a)

        member = repo.create_user(self.conn, "pg-member@example.com")
        repo.add_workspace_member(self.conn, workspace_a, member, "member")
        self.conn.commit()
        self.assertTrue(repo.remove_workspace_member(self.conn, workspace_a, member))
        self.assertFalse(repo.remove_workspace_member(self.conn, workspace_a, member))  # already gone - idempotent.
        self.assertIsNone(tenant_scope.resolve_workspace_role(self.conn, member, workspace_b))


class WebhookHardeningIntegrationTests(unittest.TestCase):
    """Phase 3 webhook hardening (docs/decisiones.md D-077 follow-up):
    the retry-after-failure fix in repository.record_webhook_event()/
    mark_webhook_event_processed() and backend/http_app.py's
    _handle_billing_webhook() specifically targets a real Postgres
    transaction-abort bug (unlike SQLite, Postgres aborts the WHOLE
    transaction on any error until an explicit ROLLBACK) - so, per this
    phase's own instructions, these tests run against a real server
    rather than the SQLite suite, which cannot reproduce the bug this
    exists to close at all (confirmed empirically during the audit that
    found it)."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

    def _process_once(self, event_id, event_type, obj):
        """Mirrors backend/http_app.py's _handle_billing_webhook() logic
        exactly (claim -> apply -> commit-or-rollback+record) without the
        HTTP layer, which is irrelevant to this transaction-level bug -
        same level AuthTokenIntegrationTests already tests auth.py at."""
        should_process = repo.record_webhook_event(self.conn, event_id, event_type)
        if not should_process:
            return "skipped-duplicate"
        try:
            http_app._apply_webhook_event(self.conn, event_type, obj, None)
            repo.mark_webhook_event_processed(self.conn, event_id)
            return "succeeded"
        except Exception as exc:
            self.conn.rollback()
            repo.mark_webhook_event_processed(self.conn, event_id, error=str(exc))
            return "failed: %s" % exc

    def _doomed_event(self):
        # References a workspace that does not exist -> a real
        # ForeignKeyViolation from inside create_entitlement(), the exact
        # failure class that triggered the original bug.
        return {
            "id": "sub_pg_1", "customer": "cus_pg_1", "status": "active",
            "metadata": {"workspace_id": "00000000-0000-0000-0000-000000000000", "plan": "standard"},
            "items": {"data": []},
        }

    def test_processing_failure_leaves_event_retryable_and_a_later_retry_succeeds(self):
        event_id, event_type = "evt_pg_retry_1", "customer.subscription.updated"
        first = self._process_once(event_id, event_type, self._doomed_event())
        self.assertTrue(first.startswith("failed:"), first)

        owner = repo.create_user(self.conn, "pg-retry-owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "PG Retry WS", owner)
        self.conn.commit()
        fixed_event = dict(self._doomed_event())
        fixed_event["metadata"] = {"workspace_id": workspace_id, "plan": "standard"}

        second = self._process_once(event_id, event_type, fixed_event)
        self.assertEqual(second, "succeeded")
        self.assertEqual(repo.get_entitlement_by_workspace(self.conn, workspace_id)["status"], "active")

    def test_first_attempt_failure_does_not_mark_event_successfully_processed(self):
        event_id, event_type = "evt_pg_retry_2", "customer.subscription.updated"
        self._process_once(event_id, event_type, self._doomed_event())
        cur = db.execute(self.conn, "SELECT processed_at, processing_error FROM webhook_events WHERE id = %s", (event_id,))
        row = db.normalize_row(cur.fetchone())
        self.assertIsNone(row["processed_at"])
        self.assertIsNotNone(row["processing_error"])

    def test_recovery_write_succeeds_immediately_after_a_real_postgres_abort_without_manual_rollback_it_would_not(self):
        # Proves the fix's mechanism directly: reproduce the abort, then
        # show the OLD code's exact call (no rollback first) really does
        # raise InFailedSqlTransaction on this connection - and that a
        # fresh attempt on a properly-rolled-back connection does not.
        should_process = repo.record_webhook_event(self.conn, "evt_pg_retry_3", "customer.subscription.updated")
        self.assertTrue(should_process)
        with self.assertRaises(Exception):
            http_app._apply_webhook_event(self.conn, "customer.subscription.updated", self._doomed_event(), None)
        with self.assertRaises(psycopg.errors.InFailedSqlTransaction):
            repo.mark_webhook_event_processed(self.conn, "evt_pg_retry_3", error="without rollback, this itself fails")
        self.conn.rollback()  # the actual fix backend/http_app.py applies before this same call.
        repo.mark_webhook_event_processed(self.conn, "evt_pg_retry_3", error="recorded cleanly after rollback")
        row = db.normalize_row(db.execute(self.conn, "SELECT processing_error FROM webhook_events WHERE id = %s", ("evt_pg_retry_3",)).fetchone())
        self.assertEqual(row["processing_error"], "recorded cleanly after rollback")

    def test_concurrent_retry_of_the_same_previously_failed_event_is_single_success(self):
        event_id, event_type = "evt_pg_retry_4", "customer.subscription.updated"
        self._process_once(event_id, event_type, self._doomed_event())  # first attempt fails, leaves it retryable.

        owner = repo.create_user(self.conn, "pg-retry-concurrent-owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "PG Retry Concurrent WS", owner)
        self.conn.commit()
        fixed_event = dict(self._doomed_event())
        fixed_event["metadata"] = {"workspace_id": workspace_id, "plan": "standard"}

        barrier = threading.Barrier(2)
        results = {}

        def _retry(worker_id):
            worker_conn = db.connect_postgres(DSN)
            try:
                barrier.wait(timeout=5)
                results[worker_id] = repo.record_webhook_event(worker_conn, event_id, event_type)
            finally:
                worker_conn.close()

        threads = [threading.Thread(target=_retry, args=(w,)) for w in ("A", "B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        winners = [w for w, claimed in results.items() if claimed]
        self.assertEqual(len(winners), 1, "expected exactly one claimant, got: %r" % (results,))


class _CapturingEmailSender:
    def __init__(self):
        self.sent = []

    def send(self, to_email, subject, body):
        self.sent.append((to_email, subject, body))

    def last_token(self):
        _, _, body = self.sent[-1]
        return body.rsplit("token=", 1)[-1]


class HttpJobSubmitConcurrencyIntegrationTests(unittest.TestCase):
    """Phase 5 blocker fix (docs/decisiones.md D-080 follow-up):
    backend/http_app.py's _handle_job_submit() idempotency-conflict
    recovery path against a REAL running server + real PostgreSQL -
    through the actual HTTP layer, not just repository.py directly (the
    bug lived specifically in the HTTP handler's own exception-recovery
    code, so a repository-level test - the same level
    ConcurrentClaimIntegrationTests/AuthTokenIntegrationTests already
    cover their own races at - would never have caught it; see
    WebhookHardeningIntegrationTests above for the identical bug CLASS,
    caught the same way, in a different handler).

    Bug (found during the Phase 5 final audit): a losing concurrent
    submitter hits a real Postgres IntegrityError on the idempotency_key
    UNIQUE constraint, which aborts the whole transaction; the recovery
    SELECT that used to run immediately after it then itself raised
    InFailedSqlTransaction, surfacing as a spurious HTTP 500 instead of
    the intended clean 200 duplicate:true response - never reproducible
    on SQLite (which never aborts a transaction on error), so invisible
    to the entire SQLite-backed suite regardless of how many concurrent
    threads it used."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)

        import tempfile
        import backend.object_storage as object_storage

        self.storage_dir = tempfile.mkdtemp(prefix="pg-http-concurrency-")
        self.addCleanup(shutil.rmtree, self.storage_dir, True)
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="pg-http-concurrency-secret")
        self.email_sender = _CapturingEmailSender()

        host = "127.0.0.1"
        self.httpd = http_app.run_server(
            connect_fn=lambda: db.connect_postgres(DSN),
            email_sender=self.email_sender,
            host_allowlist=[host],
            host=host,
            port=0,
            secure_cookies=False,
            storage=self.storage,
            # D-108: this class races ONE user's identical submissions (3
            # rounds x 10) to prove idempotency - the per-user submit rate
            # limit is raised so it never decides the outcome here; it has
            # its own tests in CommercialGuardsIntegrationTests.
            submit_rate_limit_per_window=100,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (host, self.port)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _request(self, method, path, body=None, cookie=None):
        import http.client
        import json as json_module

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": self.host_header, "Origin": "http://%s" % self.host_header}
        data = None
        if body is not None:
            data = json_module.dumps(body).encode("utf-8")
            headers["Content-Length"] = str(len(data))
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        if not raw:
            return resp.status, None
        try:
            return resp.status, json_module.loads(raw)
        except json_module.JSONDecodeError:
            return resp.status, raw  # e.g. GET /auth/verify's HTML confirm page - caller doesn't need it parsed.

    def _login(self, email):
        import json as json_module

        self._request("POST", "/auth/request-link", {"email": email})
        token = self.email_sender.last_token()
        self._request("GET", "/auth/verify?token=%s" % token)
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        from urllib.parse import urlencode
        body = urlencode({"token": token, "redirect": "/"}).encode("ascii")
        headers = {
            "Host": self.host_header, "Origin": "http://%s" % self.host_header,
            "Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body)),
        }
        conn.request("POST", "/auth/verify", body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        cookie = resp.getheader("Set-Cookie").split(";")[0]
        conn.close()
        return cookie

    def test_ten_concurrent_http_submits_same_idempotency_key_exactly_one_job_no_500s(self):
        cookie = self._login("pg-http-idem@example.com")
        status, payload = self._request("POST", "/workspaces", {"name": "PG HTTP Idem WS"}, cookie=cookie)
        self.assertEqual(status, 200, payload)
        workspace_id = payload["workspace_id"]
        repo.create_entitlement(self.conn, workspace_id, "standard", "active", billing_interval="monthly")
        self.conn.commit()

        for round_number in range(3):  # "repeat several times" - a fresh idempotency_key per round, same workspace/server.
            with self.subTest(round=round_number):
                idem_key = "pg-http-concurrent-key-round-%d" % round_number
                barrier = threading.Barrier(10)
                results = []
                lock = threading.Lock()

                def _submit():
                    barrier.wait(timeout=5)  # maximize the chance all 10 POSTs genuinely overlap.
                    status, payload = self._request(
                        "POST", "/workspaces/%s/jobs" % workspace_id,
                        {"mode": "quick", "source": "contract Concurrent%d {}" % round_number, "idempotency_key": idem_key},
                        cookie=cookie,
                    )
                    with lock:
                        results.append((status, payload))

                threads = [threading.Thread(target=_submit) for _ in range(10)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=15)

                statuses = [r[0] for r in results]
                self.assertEqual(len(results), 10, "not every thread finished: %r" % (results,))
                self.assertTrue(all(s == 200 for s in statuses), "expected every response to be 200, never a 500 from the race - got: %r" % statuses)

                job_ids = {r[1]["job_id"] for r in results}
                self.assertEqual(len(job_ids), 1, "expected exactly one distinct job_id across all 10 submitters - got: %r" % (results,))

                winners = [r for r in results if not r[1].get("duplicate")]
                losers = [r for r in results if r[1].get("duplicate") is True]
                self.assertEqual(len(winners), 1, "expected exactly one non-duplicate winner - got: %r" % (results,))
                self.assertEqual(len(losers), 9, "expected exactly nine duplicate:true losers - got: %r" % (results,))
                for _, payload in losers:
                    self.assertEqual(payload["status"], "queued")
                    self.assertEqual(payload["job_id"], list(job_ids)[0])

                # D-109: the client key is stored namespaced by its workspace (repo.scoped_idempotency_key()).
                cur = db.execute(self.conn, "SELECT COUNT(*) AS n FROM analysis_jobs WHERE idempotency_key = %s", (repo.scoped_idempotency_key(workspace_id, idem_key),))
                self.assertEqual(db.normalize_row(cur.fetchone())["n"], 1, "expected exactly one real row in analysis_jobs for this idempotency_key")

    def test_different_idempotency_keys_create_separate_jobs(self):
        cookie = self._login("pg-http-idem-2@example.com")
        status, payload = self._request("POST", "/workspaces", {"name": "PG HTTP Idem WS 2"}, cookie=cookie)
        self.assertEqual(status, 200, payload)
        workspace_id = payload["workspace_id"]
        repo.create_entitlement(self.conn, workspace_id, "standard", "active", billing_interval="monthly")
        self.conn.commit()

        status_1, payload_1 = self._request(
            "POST", "/workspaces/%s/jobs" % workspace_id,
            {"mode": "quick", "source": "contract One {}", "idempotency_key": "distinct-key-1"}, cookie=cookie,
        )
        status_2, payload_2 = self._request(
            "POST", "/workspaces/%s/jobs" % workspace_id,
            {"mode": "quick", "source": "contract Two {}", "idempotency_key": "distinct-key-2"}, cookie=cookie,
        )
        self.assertEqual((status_1, status_2), (200, 200), (payload_1, payload_2))
        self.assertNotEqual(payload_1["job_id"], payload_2["job_id"])
        self.assertNotIn("duplicate", payload_1)
        self.assertNotIn("duplicate", payload_2)
        cur = db.execute(self.conn, "SELECT COUNT(*) AS n FROM analysis_jobs WHERE workspace_id = %s", (workspace_id,))
        self.assertEqual(db.normalize_row(cur.fetchone())["n"], 2)


class PrivateApiIntegrationTests(unittest.TestCase):
    """D-113 against a REAL Postgres server: 0014 (api_keys, the
    request_fingerprint column and their CHECKs), key storage/lookup/
    revocation, the active-key ceiling under real concurrency, and through
    the real HTTP layer: concurrent same-idempotency-key API submissions,
    reuse with a different payload, the Quick credit reserved once under
    concurrency, cross-workspace isolation and the Trial refusal."""

    setUp = HttpJobSubmitConcurrencyIntegrationTests.setUp
    _request = HttpJobSubmitConcurrencyIntegrationTests._request
    _login = HttpJobSubmitConcurrencyIntegrationTests._login

    def _api(self, method, path, key, body=None, headers=None):
        import http.client
        import json as json_module
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = {"Host": self.host_header, "Authorization": "Bearer " + key}
        data = None
        if body is not None:
            data = json_module.dumps(body).encode("utf-8")
            hdrs.update({"Content-Type": "application/json", "Content-Length": str(len(data))})
        hdrs.update(headers or {})
        conn.request(method, "/api/v1" + path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json_module.loads(raw) if raw[:1] == b"{" else raw

    def _account(self, plan, email):
        cookie = self._login(email)
        status, payload = self._request("POST", "/workspaces", {"name": "PG API %s" % plan}, cookie=cookie)
        self.assertEqual(status, 200, payload)
        ws = payload["workspace_id"]
        repo.create_entitlement(self.conn, ws, plan, "active", billing_interval="monthly")
        if plan == "quick":
            repo.grant_scan_credit(self.conn, "cs_pg_%s" % email, ws)
        self.conn.commit()
        status, created = self._request("POST", "/workspaces/%s/api-keys" % ws, {"name": "pg"}, cookie=cookie)
        if plan == "trial":
            self.assertEqual((status, created["error"]), (403, "feature_not_available"))
            return cookie, ws, None
        self.assertEqual(status, 200, created)
        return cookie, ws, created["secret"]

    @staticmethod
    def _source(name):
        return "pragma solidity ^0.8.20;\ncontract %s {\n    uint256 public a;\n}\n" % name

    def test_key_storage_lookup_touch_revoke_and_constraints(self):
        import backend.api_keys as api_keys
        user = repo.create_user(self.conn, "pg-keys@example.com")
        ws = repo.create_workspace(self.conn, "K", user)
        key, prefix, key_hash = api_keys.generate()
        record = repo.create_api_key(self.conn, ws, user, "ci", prefix, key_hash, 25)
        self.assertNotIn("key_hash", record)
        row = repo.get_api_key_for_auth(self.conn, prefix)
        self.assertTrue(api_keys.matches(key, row["key_hash"]))
        self.assertIsNone(row["last_used_at"])
        repo.touch_api_key(self.conn, row["id"], 60)
        first = repo.get_api_key_for_auth(self.conn, prefix)["last_used_at"]
        self.assertIsNotNone(first)
        repo.touch_api_key(self.conn, row["id"], 60)                   # within the resolution: no write
        self.assertEqual(repo.get_api_key_for_auth(self.conn, prefix)["last_used_at"], first)
        self.assertEqual([str(k["id"]) for k in repo.list_api_keys(self.conn, ws)], [str(record["id"])])
        self.assertTrue(repo.revoke_api_key(self.conn, ws, record["id"], user))
        self.assertFalse(repo.revoke_api_key(self.conn, ws, record["id"], user))
        self.assertIsNotNone(repo.get_api_key_for_auth(self.conn, prefix)["revoked_at"])
        for bad in (("ABCDEFABCDEF", "0" * 64), ("abcdefabcdef", "plaintext-secret")):
            with self.assertRaises(db.integrity_error_class(self.conn)):
                db.execute(self.conn, "INSERT INTO api_keys (id, workspace_id, user_id, name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, 'x', ?, ?, now())",
                           (repo.new_id(), ws, user) + bad)
            self.conn.rollback()
        self.assertEqual(repo.revoke_workspace_api_keys(self.conn, ws), 0)

    def test_concurrent_key_creation_respects_the_ceiling(self):
        import backend.api_keys as api_keys
        user = repo.create_user(self.conn, "pg-ceiling@example.com")
        ws = repo.create_workspace(self.conn, "C", user)
        results, barrier = [], threading.Barrier(12)

        def attempt(i):
            conn = db.connect_postgres(DSN)
            try:
                barrier.wait()
                _, prefix, key_hash = api_keys.generate()
                repo.create_api_key(conn, ws, user, "k%d" % i, prefix, key_hash, 5)
                results.append("ok")
            except repo.ApiKeyLimitError:
                results.append("limit")
            except Exception as exc:   # pragma: no cover
                results.append(repr(exc))
            finally:
                conn.close()

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(12)]
        [th.start() for th in threads]
        [th.join(30) for th in threads]
        self.assertEqual(sorted(results), ["limit"] * 7 + ["ok"] * 5)
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM api_keys WHERE workspace_id = ?", (ws,)).fetchone()["n"], 5)

    def test_concurrent_api_submits_same_idempotency_key(self):
        _, ws, key = self._account("standard", "pg-api-idem@example.com")
        payload = {"mode": "standard", "source": self._source("C"), "idempotency_key": "pg-race"}
        results, barrier = [], threading.Barrier(10)

        def go():
            barrier.wait(timeout=5)
            results.append(self._api("POST", "/scans", key, payload))

        threads = [threading.Thread(target=go) for _ in range(10)]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertEqual([r[0] for r in results], [200] * 10, results)
        self.assertEqual(len({r[1]["job_id"] for r in results}), 1)
        self.assertEqual(sum(1 for r in results if not r[1].get("duplicate")), 1)
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()["n"], 1)
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM job_usage WHERE workspace_id = ?", (ws,)).fetchone()["n"], 1)
        status, body = self._api("POST", "/scans", key, dict(payload, source=self._source("Changed")))
        self.assertEqual((status, body["error"]["code"]), (409, "idempotency_key_reused"))
        fingerprint = db.execute(self.conn, "SELECT request_fingerprint FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()["request_fingerprint"]
        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")

    def test_quick_credit_is_reserved_once_under_concurrency(self):
        _, ws, key = self._account("quick", "pg-api-quick@example.com")
        results, barrier = [], threading.Barrier(6)

        def go(i):
            barrier.wait(timeout=5)
            results.append(self._api("POST", "/scans", key, {"mode": "quick", "source": self._source("Q%d" % i)}))

        threads = [threading.Thread(target=go, args=(i,)) for i in range(6)]
        [t.start() for t in threads]
        [t.join(30) for t in threads]
        self.assertEqual(sorted(r[0] for r in results), [200] + [402] * 5, results)
        self.assertEqual({r[1]["error"]["code"] for r in results if r[0] == 402}, {"no_scan_credit"})
        self.assertEqual(db.execute(self.conn, "SELECT COUNT(*) AS n FROM job_usage WHERE workspace_id = ?", (ws,)).fetchone()["n"], 1)

    def test_cross_workspace_isolation_and_trial_refusal(self):
        import backend.api_keys as api_keys
        _, ws_a, key_a = self._account("pro", "pg-api-a@example.com")
        _, ws_b, key_b = self._account("pro", "pg-api-b@example.com")
        status, project = self._api("POST", "/projects", key_b, {"name": "B"})
        self.assertEqual(status, 200, project)
        status, job = self._api("POST", "/scans", key_b, {"mode": "pro", "source": self._source("B")})
        self.assertEqual(status, 200, job)
        self.assertEqual(self._api("GET", "/projects/%s" % project["project"]["id"], key_a)[0], 404)
        self.assertEqual(self._api("GET", "/scans/%s" % job["job_id"], key_a)[0], 404)
        self.assertEqual(self._api("GET", "/scans", key_a)[1]["jobs"], [])
        self.assertEqual(self._api("GET", "/usage", key_a)[1]["workspace_id"], ws_a)
        _, ws_t, _ = self._account("trial", "pg-api-trial@example.com")
        planted, prefix, key_hash = api_keys.generate()
        user = repo.get_user_by_email(self.conn, "pg-api-trial@example.com")["id"]
        repo.create_api_key(self.conn, ws_t, user, "planted", prefix, key_hash, 25)
        status, body = self._api("GET", "/usage", planted)
        self.assertEqual((status, body["error"]["code"]), (403, "feature_not_available"))


class RestoreVerificationIntegrationTests(unittest.TestCase):
    """Phase 6A (docs/decisiones.md D-077 follow-up): backend/
    verify_restore.py's own drill, proven end-to-end against a REAL
    pg_dump of a REAL seeded database - not merely unit-tested against
    fake inputs. This is the one place in the suite that actually
    produces a dump (via `docker exec <container> pg_dump`, the module's
    own module this test lives in already having a real, disposable
    Postgres container running) purely to feed it to the tool under
    test; backend/verify_restore.py itself never produces a dump on its
    own - see that module's own docstring on why."""

    def setUp(self):
        self.conn, _ = _reset_database_and_migrate()
        self.addCleanup(self.conn.close)
        self.storage_dir = tempfile.mkdtemp(prefix="restore-verify-storage-")
        self.addCleanup(shutil.rmtree, self.storage_dir, True)
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="restore-verify-secret")

    def _seed_one_report(self):
        user_id = repo.create_user(self.conn, "restore-verify@example.com")
        workspace_id = repo.create_workspace(self.conn, "Restore Verify WS", user_id)
        storage_ref = object_storage.workspace_key(workspace_id, "sources", repo.new_id())
        self.storage.put_object(storage_ref, b"contract A {}", content_type="text/plain")
        contract_id = repo.create_contract(self.conn, workspace_id, storage_ref, "hash", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        report_key = object_storage.workspace_key(workspace_id, "reports", job_id)
        self.storage.put_object(report_key, b"# Report", content_type="text/markdown")
        repo.record_report(self.conn, job_id, workspace_id, report_key, score_status="not_computed")
        self.conn.commit()

    def _dump_current_database(self) -> str:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "pg_dump", "-U", "postgres", "--format=plain", DB_NAME],
            capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, "pg_dump itself failed: %r" % result.stderr[-500:])
        fd, dump_path = tempfile.mkstemp(suffix=".sql")
        with os.fdopen(fd, "wb") as handle:
            handle.write(result.stdout)
        self.addCleanup(lambda: os.remove(dump_path) if os.path.exists(dump_path) else None)
        return dump_path

    def test_restore_verification_succeeds_against_a_real_dump_of_a_seeded_database(self):
        self._seed_one_report()
        dump_path = self._dump_current_database()

        result = verify_restore.run_restore_verification(dump_path, storage_dir=self.storage_dir, port=55498)

        self.assertTrue(result["ok"])
        self.assertEqual(result["migrations_newly_applied_by_restore"], [])  # the dump was already fully migrated.
        self.assertGreaterEqual(result["table_row_counts"]["workspaces"], 1)
        self.assertGreaterEqual(result["table_row_counts"]["reports"], 1)
        self.assertEqual(result["report_accessibility"]["reports_checked"], 1)
        self.assertTrue(result["report_accessibility"]["storage_dir_checked"])

    def test_restore_verification_fails_loudly_when_a_reports_object_is_missing_from_the_storage_backup(self):
        self._seed_one_report()
        dump_path = self._dump_current_database()
        # Simulates a real, realistic failure mode: the database backup
        # and the object-storage backup fell out of sync (e.g. taken at
        # different times, or the storage backup itself failed) - the
        # drill must catch this, never silently report success.
        shutil.rmtree(self.storage_dir)
        os.makedirs(self.storage_dir)

        with self.assertRaises(verify_restore.RestoreVerificationError):
            verify_restore.run_restore_verification(dump_path, storage_dir=self.storage_dir, port=55497)

    def test_restore_verification_works_without_a_storage_dir_db_only_drill(self):
        self._seed_one_report()
        dump_path = self._dump_current_database()

        result = verify_restore.run_restore_verification(dump_path, storage_dir=None, port=55496)

        self.assertTrue(result["ok"])
        self.assertFalse(result["report_accessibility"]["storage_dir_checked"])


if __name__ == "__main__":
    unittest.main()
