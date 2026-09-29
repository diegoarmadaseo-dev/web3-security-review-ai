"""Phase 6A hardening tests for backend/worker_supervisor.py that need
NEITHER Docker NOR Postgres - the storage-failure path (get_object/
put_object raising) fails BEFORE run_job_in_container() is ever called,
and shutdown_event's "stop claiming new work" check happens before
claim_next_job() - so both are fully exercisable against SQLite with a
fake ObjectStorage, and must run in every environment (unlike tests/
test_backend_worker_supervisor.py, deliberately kept separate: that
file's module-level setUpModule() skips its ENTIRE module without
Docker, which would otherwise also hide these Docker-independent tests).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

import backend.alerting as alerting
import backend.object_storage as object_storage
import backend.repository as repo
import backend.worker_supervisor as ws


class _CollectingAlertSender:
    def __init__(self):
        self.events = []

    def emit(self, event_type, severity, detail):
        self.events.append((event_type, severity, detail))


class _RaisingStorage:
    """A real ObjectStorage-shaped object whose get_object/put_object
    always raise - simulates a real S3/network failure without needing
    a real (or even fake) network."""

    def __init__(self, fail_get=False, fail_put=False):
        self._fail_get = fail_get
        self._fail_put = fail_put

    def put_object(self, key, data, content_type="application/octet-stream"):
        if self._fail_put:
            raise ConnectionError("simulated object storage outage (put)")

    def get_object(self, key):
        if self._fail_get:
            raise ConnectionError("simulated object storage outage (get)")
        return b"unused"

    def delete_object(self, key):
        pass

    def object_exists(self, key):
        return False

    def generate_signed_url(self, key, expires_in_seconds):
        return "unused"


def _seed_queued_job(conn, email="worker-hardening@example.com"):
    user_id = repo.create_user(conn, email)
    workspace_id = repo.create_workspace(conn, "WS", user_id)
    storage_ref = object_storage.workspace_key(workspace_id, "sources", repo.new_id())
    contract_id = repo.create_contract(conn, workspace_id, storage_ref, "hash", "A.sol")
    job_id = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
    return {"workspace_id": workspace_id, "job_id": job_id, "storage_ref": storage_ref}


_FAKE_CONFIG = ws.WorkerConfig(docker_image="unused:local", network_name="unused", proxy_host="127.0.0.1", proxy_port=1, llm_api_key="unused", llm_model="unused")


class StorageFailureHandlingTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_source_fetch_failure_fails_the_job_cleanly_never_crashes(self):
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage(fail_get=True)
        alert_sender = _CollectingAlertSender()

        job_id = ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage, alert_sender=alert_sender)

        self.assertEqual(job_id, seeded["job_id"])
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "failed")
        self.assertIn("object storage error", job["last_error"])

    def test_source_fetch_failure_releases_the_reserved_budget(self):
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage(fail_get=True)

        ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage)

        budget = repo.get_workspace_budget(self.conn, seeded["workspace_id"])
        self.assertEqual(int(budget["reserved_units"]), 0)
        self.assertEqual(int(budget["consumed_units"]), 0)

    def test_source_fetch_failure_emits_a_storage_failure_alert(self):
        _seed_queued_job(self.conn)
        storage = _RaisingStorage(fail_get=True)
        alert_sender = _CollectingAlertSender()

        ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage, alert_sender=alert_sender)

        self.assertEqual(len(alert_sender.events), 1)
        event_type, severity, detail = alert_sender.events[0]
        self.assertEqual(event_type, alerting.EVENT_STORAGE_FAILURE)
        self.assertEqual(detail["phase"], "fetch_source")

    def test_alert_sender_being_none_never_breaks_the_failure_path(self):
        _seed_queued_job(self.conn)
        storage = _RaisingStorage(fail_get=True)
        # Must not raise - alert_sender is optional everywhere.
        job_id = ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage, alert_sender=None)
        self.assertIsNotNone(job_id)

    def test_empty_queue_returns_none_and_never_touches_storage(self):
        storage = _RaisingStorage(fail_get=True, fail_put=True)
        result = ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage)
        self.assertIsNone(result)


class FencingThroughClaimAndRunOneJobTests(unittest.TestCase):
    """claim_and_run_one_job()'s fencing (repo.finalize_job_attempt(),
    keyed on the (attempt_count, claimed_by) pair captured right after
    its own claim_next_job() call) exercised through the REAL function,
    not just at the repository layer (tests/test_backend_job_queue.py's
    own FinalizeJobAttemptTests already covers that layer directly).
    Neither Docker nor a real container is needed - run_job_in_container()
    is mocked, its side effect standing in for "a concurrent reaper
    reclaimed this exact job while the container was still legitimately
    running" (the real-world trigger: a container that runs past
    LEASE_DURATION_SECONDS - see backend/main.py's own wall-clock/lease
    validation, added alongside this fencing work, for why that should
    be rare in a correctly configured deployment, but never structurally
    impossible)."""

    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def _steal_lease_via_real_reap(self, job_id):
        self.conn.execute("UPDATE analysis_jobs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (job_id,))
        self.conn.commit()
        self.assertEqual(repo.reap_expired_jobs(self.conn), {"requeued": 1, "failed": 0})

    def test_lease_stolen_before_running_transition_releases_budget_and_never_runs_container(self):
        seeded = _seed_queued_job(self.conn)
        real_reserve = repo.reserve_workspace_budget
        container_calls = []

        def _reserve_then_steal_lease(conn, workspace_id, units, **kwargs):
            result = real_reserve(conn, workspace_id, units, **kwargs)
            self._steal_lease_via_real_reap(seeded["job_id"])
            return result

        def _should_never_run(*args, **kwargs):
            container_calls.append((args, kwargs))
            return {"status": "succeeded", "rendered": "unused"}

        with mock.patch.object(repo, "reserve_workspace_budget", side_effect=_reserve_then_steal_lease), \
                mock.patch.object(ws, "run_job_in_container", side_effect=_should_never_run):
            job_id = ws.claim_and_run_one_job(self.conn, "worker-stale", _FAKE_CONFIG, _RaisingStorage())

        self.assertEqual(job_id, seeded["job_id"])
        self.assertEqual(container_calls, [])  # never reached - fencing failed before the container could start.
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "queued")  # left exactly as the reap set it.
        self.assertEqual(job["attempt_count"], 1)
        budget = repo.get_workspace_budget(self.conn, seeded["workspace_id"])
        self.assertEqual(budget["reserved_units"], 0)  # worker-stale released its own now-orphaned reservation.

    def test_lease_stolen_during_container_run_success_path_writes_nothing(self):
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage()  # get_object/put_object both succeed - the job "legitimately" gets all the way to a real result.

        def _run_then_steal_lease(config, job_id, mode, source):
            self._steal_lease_via_real_reap(job_id)
            return {"status": "succeeded", "rendered": "# report", "risk_indicator": {"score": 10, "band": "LOW"}}

        with mock.patch.object(ws, "run_job_in_container", side_effect=_run_then_steal_lease):
            job_id = ws.claim_and_run_one_job(self.conn, "worker-stale", _FAKE_CONFIG, storage)

        self.assertEqual(job_id, seeded["job_id"])
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "queued")  # left exactly as the reap set it - never overwritten to 'succeeded'.
        reports = self.conn.execute("SELECT * FROM reports WHERE job_id = ?", (seeded["job_id"],)).fetchall()
        self.assertEqual(reports, [])  # no duplicate/orphaned report row from the stale attempt.
        budget = repo.get_workspace_budget(self.conn, seeded["workspace_id"])
        self.assertEqual(budget["reserved_units"], 0)
        self.assertEqual(budget["consumed_units"], 0)  # the stale worker's own consume never landed.

    def test_normal_success_path_writes_exactly_one_report_and_consumes_budget_once(self):
        # Regression coverage: before this fencing work, NO no-docker test
        # exercised the success path at all (only Docker-gated tests in
        # tests/test_backend_worker_supervisor.py did) - claim_and_run_
        # one_job()'s success branch was rewritten to route through
        # finalize_job_attempt() here, so this proves the normal,
        # uncontested path still behaves identically to before.
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage()

        with mock.patch.object(ws, "run_job_in_container", return_value={"status": "succeeded", "rendered": "# report", "risk_indicator": {"score": 5, "band": "LOW"}}):
            job_id = ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage)

        self.assertEqual(job_id, seeded["job_id"])
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "succeeded")
        self.assertIsNotNone(job["completed_at"])
        reports = self.conn.execute("SELECT * FROM reports WHERE job_id = ?", (seeded["job_id"],)).fetchall()
        self.assertEqual(len(reports), 1)
        budget = repo.get_workspace_budget(self.conn, seeded["workspace_id"])
        self.assertEqual(budget["reserved_units"], 0)
        self.assertEqual(budget["consumed_units"], 1)

    def test_normal_failure_path_still_releases_budget_and_fails_the_job(self):
        # Same regression intent as above, for the (uncontested) failure
        # branch - now routed through finalize_job_attempt() with
        # budget_action="release" instead of a direct release_workspace_
        # budget() + transition_job_status() pair.
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage()

        with mock.patch.object(ws, "run_job_in_container", return_value={"status": "failed", "error": "LLM provider error"}):
            job_id = ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, storage)

        self.assertEqual(job_id, seeded["job_id"])
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["attempt_count"], 1)
        self.assertIn("LLM provider error", job["last_error"])
        budget = repo.get_workspace_budget(self.conn, seeded["workspace_id"])
        self.assertEqual(budget["reserved_units"], 0)

    def test_budget_exhausted_path_fails_cleanly_never_crashes(self):
        # PRE-EXISTING gap found and fixed while building the fencing
        # mechanism: _VALID_TRANSITIONS["claimed"] never included "failed"
        # until now, so this exact call site (reserve_workspace_budget()
        # returning False) has raised RepositoryError, uncaught, since it
        # was written - confirmed by no test anywhere ever exercising it.
        # Unrelated to fencing itself; fixed as a necessary prerequisite
        # for this call site to work at all, and now covered.
        seeded = _seed_queued_job(self.conn)
        self.assertTrue(repo.reserve_workspace_budget(self.conn, seeded["workspace_id"], repo.DEFAULT_BUDGET_LIMIT_UNITS))  # exhaust the ceiling.

        job_id = ws.claim_and_run_one_job(self.conn, "worker-a", _FAKE_CONFIG, _RaisingStorage())

        self.assertEqual(job_id, seeded["job_id"])
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["last_error"], "workspace budget exhausted")
        budget = repo.get_workspace_budget(self.conn, seeded["workspace_id"])
        self.assertEqual(budget["reserved_units"], repo.DEFAULT_BUDGET_LIMIT_UNITS)  # the pre-existing reservation is untouched - never released (nothing was reserved for THIS job).
        self.assertEqual(budget["consumed_units"], 0)


class ShutdownEventTests(unittest.TestCase):
    """Unlike StorageFailureHandlingTests above, run_worker_supervisor_
    loop() itself closes the connection connect_fn() gives it at the end
    of every iteration (a fresh connection per iteration - see that
    function's own docstring) - a shared :memory: connection would be
    closed out from under a test's own later assertions, and a second
    :memory: connection is a completely separate, empty database (SQLite
    :memory: databases are never shared across connections). A real,
    temp-file-backed SQLite database is what lets connect_fn() open a
    genuinely fresh connection each call while this test's OWN separate
    connection (self.conn, seeding/verification only, never passed to
    the loop) still sees the same persisted data - the same reason
    tests/test_backend_http_app.py's own _HttpAppTestCase never uses
    :memory: either."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        self.conn = repo.connect(self.db_path)
        repo.init_schema(self.conn)
        # Cleanups run LIFO: register removal FIRST so close() (registered
        # LAST) runs FIRST - Windows cannot delete a file with any open
        # sqlite3 handle on it (same convention tests/test_backend_http_
        # app.py's own _HttpAppTestCase.setUp() already documents).
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self.conn.close)

    def _connect_fn(self):
        return repo.connect(self.db_path)

    def test_shutdown_event_set_before_the_loop_leaves_the_seeded_job_queued(self):
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage()
        shutdown_event = threading.Event()
        shutdown_event.set()

        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="worker-shutdown", config=_FAKE_CONFIG, storage=storage,
            poll_interval_seconds=0, max_iterations=None, shutdown_event=shutdown_event,
        )

        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "queued")  # never claimed - the loop broke before ever calling claim_next_job().

    def test_a_job_claimed_before_shutdown_still_reaches_its_natural_terminal_state(self):
        # shutdown_event is checked ONLY at the top of each iteration
        # (before reaping/claiming) - a job claimed and run WITHIN one
        # iteration always completes normally, matching "no job is
        # falsely marked succeeded" by construction (nothing here ever
        # force-terminates claim_and_run_one_job mid-call).
        seeded = _seed_queued_job(self.conn)
        storage = _RaisingStorage(fail_get=True)  # deterministic, fast failure - proves the job reaches a REAL terminal state either way.
        shutdown_event = threading.Event()  # NOT set yet - this run must still process the one seeded job.

        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="worker-inflight", config=_FAKE_CONFIG, storage=storage,
            poll_interval_seconds=0, max_iterations=1, shutdown_event=shutdown_event,
        )

        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertEqual(job["status"], "failed")  # a real terminal state - never left 'claimed'/'running' mid-shutdown.

    def test_repeated_retry_alert_emitted_when_reaper_requeues_a_lease(self):
        import backend.db as db
        from datetime import datetime, timedelta, timezone

        seeded = _seed_queued_job(self.conn)
        claimed = repo.claim_next_job(self.conn, "worker-lease")
        self.assertEqual(claimed["id"], seeded["job_id"])
        expired_lease = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        db.execute(self.conn, "UPDATE analysis_jobs SET lease_expires_at = ? WHERE id = ?", (expired_lease, seeded["job_id"]))
        self.conn.commit()

        alert_sender = _CollectingAlertSender()
        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="worker-reap", config=_FAKE_CONFIG, storage=_RaisingStorage(fail_get=True),
            poll_interval_seconds=0, max_iterations=1, shutdown_event=threading.Event(), alert_sender=alert_sender,
        )
        # This same iteration's reap requeues the job (status='queued',
        # attempt_count=1) AND THEN immediately re-claims that same
        # now-queued job via the same iteration's own claim_and_run_
        # one_job() call, which fails it again (the deliberately-broken
        # storage) - realistic, not a test bug: a reaped job is
        # immediately eligible to be claimed again, same as any other
        # queued job. The alert firing (from the reap step) and the job
        # never being left stuck in 'claimed'/'running' are what this
        # test actually verifies.
        self.assertTrue(any(e[0] == alerting.EVENT_WORKER_REPEATED_RETRY for e in alert_sender.events), "events=%r" % (alert_sender.events,))
        job = repo.get_job(self.conn, seeded["job_id"])
        self.assertIn(job["status"], ("queued", "failed"))


class RetentionSchedulerTests(unittest.TestCase):
    """Phase 6B (docs/decisiones.md D-077 follow-up): proves run_worker_
    supervisor_loop() actually invokes backend.retention's purge
    functions - not just that retention.py works in isolation (already
    covered by tests/test_backend_retention.py)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        self.conn = repo.connect(self.db_path)
        repo.init_schema(self.conn)
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self.conn.close)

        self.storage_dir = tempfile.mkdtemp(prefix="retention-scheduler-tests-")
        self.addCleanup(shutil.rmtree, self.storage_dir, True)
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="retention-scheduler-secret")

    def _connect_fn(self):
        return repo.connect(self.db_path)

    def _seed_old_contract(self):
        from datetime import datetime, timedelta, timezone
        import backend.db as db

        user_id = repo.create_user(self.conn, "retention-scheduler@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        storage_ref = object_storage.workspace_key(workspace_id, "sources", repo.new_id())
        self.storage.put_object(storage_ref, b"contract Old {}", content_type="text/plain")
        contract_id = repo.create_contract(self.conn, workspace_id, storage_ref, "hash", "A.sol")
        old_iso = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        db.execute(self.conn, "UPDATE contracts SET created_at = ? WHERE id = ?", (old_iso, contract_id))
        self.conn.commit()
        return {"contract_id": contract_id, "storage_ref": storage_ref}

    def test_retention_days_none_never_purges_anything(self):
        seeded = self._seed_old_contract()
        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="w-retention-off", config=_FAKE_CONFIG, storage=self.storage,
            poll_interval_seconds=0, max_iterations=1, retention_days=None,
        )
        self.assertTrue(self.storage.object_exists(seeded["storage_ref"]))  # still there - retention disabled.

    def test_retention_days_set_purges_expired_content_on_the_first_iteration(self):
        seeded = self._seed_old_contract()
        alert_sender = _CollectingAlertSender()
        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="w-retention-on", config=_FAKE_CONFIG, storage=self.storage,
            poll_interval_seconds=0, max_iterations=1, retention_days=30,
            retention_check_interval_seconds=3600, alert_sender=alert_sender,
        )
        self.assertFalse(self.storage.object_exists(seeded["storage_ref"]))
        contract = repo.get_contract(self.conn, seeded["contract_id"])
        self.assertIsNotNone(contract["deleted_at"])
        self.assertTrue(any(e[0] == alerting.EVENT_RETENTION_PURGE for e in alert_sender.events), "events=%r" % (alert_sender.events,))

    def test_retention_dry_run_never_deletes_but_still_checks(self):
        seeded = self._seed_old_contract()
        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="w-retention-dry", config=_FAKE_CONFIG, storage=self.storage,
            poll_interval_seconds=0, max_iterations=1, retention_days=30, retention_dry_run=True,
        )
        self.assertTrue(self.storage.object_exists(seeded["storage_ref"]))  # dry_run - never actually deleted.
        contract = repo.get_contract(self.conn, seeded["contract_id"])
        self.assertIsNone(contract["deleted_at"])

    def test_retention_check_interval_prevents_a_redundant_second_scan(self):
        seeded = self._seed_old_contract()
        # First iteration purges it AND resets the next-check deadline far
        # into the future (retention_check_interval_seconds=3600) - a
        # SECOND iteration right after must not scan again at all. Proven
        # indirectly: purging an already-purged contract is itself
        # idempotent (tests/test_backend_retention.py), so this asserts
        # the more specific, scheduler-level property - no additional
        # EVENT_RETENTION_PURGE alert fires on the second iteration,
        # since nothing new should even be looked at.
        alert_sender = _CollectingAlertSender()
        ws.run_worker_supervisor_loop(
            connect_fn=self._connect_fn, worker_id="w-retention-interval", config=_FAKE_CONFIG, storage=self.storage,
            poll_interval_seconds=0, max_iterations=2, retention_days=30,
            retention_check_interval_seconds=3600, alert_sender=alert_sender,
        )
        purge_events = [e for e in alert_sender.events if e[0] == alerting.EVENT_RETENTION_PURGE]
        self.assertEqual(len(purge_events), 1, "events=%r" % (alert_sender.events,))


if __name__ == "__main__":
    unittest.main()
