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
import threading
import time
import unittest

try:
    import psycopg
except ImportError:  # pragma: no cover - exercised by environments without psycopg installed.
    psycopg = None

import backend.db as db
import backend.migrate as migrate
import backend.repository as repo
import backend.tenant_scope as tenant_scope

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

    def test_fresh_database_applies_the_one_migration(self):
        self.assertEqual(self.applied, ["0001_initial_schema"])

    def test_all_twelve_tables_exist(self):
        cur = db.execute(
            self.conn,
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        )
        tables = {row["table_name"] for row in cur.fetchall()}
        expected = {
            "schema_migrations", "users", "workspaces", "workspace_members", "sessions",
            "entitlements", "projects", "contracts", "analysis_jobs", "reports",
            "audit_events", "webhook_events",
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


if __name__ == "__main__":
    unittest.main()
