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
import tempfile
import threading
import unittest

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


if __name__ == "__main__":
    unittest.main()
