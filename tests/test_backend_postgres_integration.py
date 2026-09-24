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

import backend.auth as auth
import backend.db as db
import backend.http_app as http_app
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

    def test_fresh_database_applies_all_five_migrations_in_order(self):
        # 0002_auth_tokens.sql (Phase 2), 0003_entitlement_status_expand.sql
        # and 0004_entitlement_event_provenance.sql (Phase 3), and
        # 0005_job_queue_hardening.sql (Phase 4, D-079) added alongside
        # 0001_initial_schema.sql (Phase 1).
        self.assertEqual(
            self.applied,
            [
                "0001_initial_schema", "0002_auth_tokens", "0003_entitlement_status_expand",
                "0004_entitlement_event_provenance", "0005_job_queue_hardening",
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

    def test_all_fourteen_tables_exist(self):
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
            "metadata": {"workspace_id": "00000000-0000-0000-0000-000000000000", "plan": "quick"},
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
        fixed_event["metadata"] = {"workspace_id": workspace_id, "plan": "quick"}

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
        fixed_event["metadata"] = {"workspace_id": workspace_id, "plan": "quick"}

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


if __name__ == "__main__":
    unittest.main()
