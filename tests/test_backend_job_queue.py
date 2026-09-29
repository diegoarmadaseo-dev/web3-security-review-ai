"""Tests for the analysis_jobs queue in backend/repository.py (Phase 1
SaaS backend data foundation, docs/decisiones.md D-077): claim-race
safety and the job state machine. No worker implementation exists yet -
these tests exercise only the queue's own data-layer contract.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import unittest

import backend.repository as repo


def _seed_job(conn):
    user_id = repo.create_user(conn, "u@example.com")
    workspace_id = repo.create_workspace(conn, "Acme", user_id)
    contract_id = repo.create_contract(conn, workspace_id, "s3://x", "hash", "A.sol")
    job_id = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
    return job_id


class EnqueueJobTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_new_job_starts_queued(self):
        job_id = _seed_job(self.conn)
        self.assertEqual(repo.get_job(self.conn, job_id)["status"], "queued")

    def test_invalid_mode_is_rejected_before_touching_the_database(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "hash", "A.sol")
        with self.assertRaises(repo.RepositoryError):
            repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "ultra-mode")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], 0)


class ClaimNextJobTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_claim_on_an_empty_queue_returns_none(self):
        self.assertIsNone(repo.claim_next_job(self.conn, "worker-1"))

    def test_claim_returns_the_oldest_queued_job_first(self):
        older = _seed_job(self.conn)
        # sqlite stores millisecond-ish precision timestamps as text; force
        # a distinct, later created_at so ordering is unambiguous rather
        # than relying on two calls in the same instant sorting the way we
        # want by luck.
        newer_user = repo.create_user(self.conn, "u2@example.com")
        newer_workspace = repo.create_workspace(self.conn, "Acme 2", newer_user)
        newer_contract = repo.create_contract(self.conn, newer_workspace, "s3://y", "hash2", "B.sol")
        self.conn.execute(
            "INSERT INTO analysis_jobs (id, workspace_id, contract_id, requested_by_user_id, mode, created_at) "
            "VALUES (?, ?, ?, ?, 'quick', ?)",
            (repo.new_id(), newer_workspace, newer_contract, newer_user, "2099-01-01T00:00:00+00:00"),
        )
        self.conn.commit()
        claimed = repo.claim_next_job(self.conn, "worker-1")
        self.assertEqual(claimed["id"], older)

    def test_claiming_the_only_queued_job_twice_the_second_call_finds_nothing_left(self):
        job_id = _seed_job(self.conn)
        first = repo.claim_next_job(self.conn, "worker-1")
        second = repo.claim_next_job(self.conn, "worker-2")
        self.assertEqual(first["id"], job_id)
        self.assertIsNone(second)

    def test_claim_sets_claimed_by_and_claimed_at(self):
        _seed_job(self.conn)
        claimed = repo.claim_next_job(self.conn, "worker-42")
        self.assertEqual(claimed["claimed_by"], "worker-42")
        self.assertIsNotNone(claimed["claimed_at"])

    def test_race_simulation_only_one_of_two_concurrent_conditional_updates_wins(self):
        # Directly exercises the idempotent-claim mechanism itself (the
        # "UPDATE ... WHERE status = 'queued'" pattern), independent of
        # claim_next_job()'s own SELECT step - this is the property that
        # maps to Postgres's real FOR UPDATE SKIP LOCKED claim query,
        # which SQLite has no equivalent locking model for (see
        # backend/schema_sqlite.sql's docstring).
        job_id = _seed_job(self.conn)
        first = self.conn.execute(
            "UPDATE analysis_jobs SET status = 'claimed', claimed_by = 'worker-A' WHERE id = ? AND status = 'queued'",
            (job_id,),
        )
        self.conn.commit()
        second = self.conn.execute(
            "UPDATE analysis_jobs SET status = 'claimed', claimed_by = 'worker-B' WHERE id = ? AND status = 'queued'",
            (job_id,),
        )
        self.conn.commit()
        self.assertEqual(first.rowcount, 1)
        self.assertEqual(second.rowcount, 0)
        self.assertEqual(repo.get_job(self.conn, job_id)["claimed_by"], "worker-A")  # worker-B never overwrote it.


class TransitionJobStatusTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.job_id = _seed_job(self.conn)

    def test_full_happy_path_queued_to_succeeded(self):
        self.assertTrue(repo.transition_job_status(self.conn, self.job_id, "queued", "claimed"))
        self.assertTrue(repo.transition_job_status(self.conn, self.job_id, "claimed", "running"))
        self.assertTrue(repo.transition_job_status(self.conn, self.job_id, "running", "succeeded"))
        job = repo.get_job(self.conn, self.job_id)
        self.assertEqual(job["status"], "succeeded")
        self.assertIsNotNone(job["started_at"])
        self.assertIsNotNone(job["completed_at"])

    def test_failed_transition_increments_attempt_count(self):
        repo.transition_job_status(self.conn, self.job_id, "queued", "claimed")
        repo.transition_job_status(self.conn, self.job_id, "claimed", "running")
        repo.transition_job_status(self.conn, self.job_id, "running", "failed", error="LLM timeout")
        job = repo.get_job(self.conn, self.job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["attempt_count"], 1)
        self.assertEqual(job["last_error"], "LLM timeout")

    def test_disallowed_transition_raises_before_touching_the_database(self):
        # queued -> running is not a valid direct transition (must pass
        # through 'claimed' first).
        with self.assertRaises(repo.RepositoryError):
            repo.transition_job_status(self.conn, self.job_id, "queued", "running")
        self.assertEqual(repo.get_job(self.conn, self.job_id)["status"], "queued")  # untouched.

    def test_stale_duplicate_transition_returns_false_never_raises(self):
        self.assertTrue(repo.transition_job_status(self.conn, self.job_id, "queued", "claimed"))
        # A second, late-arriving caller still thinks the job is 'queued'.
        self.assertFalse(repo.transition_job_status(self.conn, self.job_id, "queued", "claimed"))
        self.assertEqual(repo.get_job(self.conn, self.job_id)["status"], "claimed")  # first call's result stands.

    def test_a_dead_workers_claim_can_be_requeued(self):
        repo.transition_job_status(self.conn, self.job_id, "queued", "claimed")
        self.assertTrue(repo.transition_job_status(self.conn, self.job_id, "claimed", "queued"))
        self.assertEqual(repo.get_job(self.conn, self.job_id)["status"], "queued")

    def test_unknown_from_status_is_rejected(self):
        with self.assertRaises(repo.RepositoryError):
            repo.transition_job_status(self.conn, self.job_id, "not-a-real-status", "claimed")


class ReapExpiredJobsTests(unittest.TestCase):
    """Regression coverage for a confirmed budget-reservation leak: a
    worker process that dies while a job is 'running' never reaches
    claim_and_run_one_job()'s own consume_reserved_workspace_budget()/
    release_workspace_budget() call for the units it already reserved,
    and reap_expired_jobs() used to leave that reservation orphaned in
    workspace_budgets forever (DEFAULT_BUDGET_LIMIT_UNITS never resets on
    any cycle - see that constant's own docstring). See reap_expired_
    jobs()'s own updated docstring for the full reasoning behind why only
    a job found in 'running' (never 'claimed') has its budget released -
    a 'claimed' job's reservation status is genuinely ambiguous without a
    schema change, which this fix does not make."""

    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def _expire_lease(self, job_id):
        # repo.claim_next_job() always sets a fresh, non-expired lease -
        # reaching an EXPIRED one for a test needs a direct write, same
        # convention ClaimNextJobTests.test_claim_returns_the_oldest_
        # queued_job_first() above already uses for state claim_next_job()'s
        # own API can't produce.
        self.conn.execute(
            "UPDATE analysis_jobs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            (job_id,),
        )
        self.conn.commit()

    def _drive_to_running(self, job_id, workspace_id, mode):
        """Mirrors worker_supervisor.claim_and_run_one_job()'s own
        sequence up to (but not including) the container run - claim,
        reserve budget, transition to running - so a test can then
        simulate a worker crash by expiring the lease directly, matching
        the exact state a real crash would leave behind."""
        claimed = repo.claim_next_job(self.conn, "worker-test")
        self.assertEqual(claimed["id"], job_id)
        reserved = repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST[mode])
        self.assertTrue(reserved)
        repo.transition_job_status(self.conn, job_id, "claimed", "running")

    def test_running_job_with_attempts_remaining_is_requeued_and_budget_released(self):
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        self._drive_to_running(job_id, workspace_id, "quick")
        self._expire_lease(job_id)

        result = repo.reap_expired_jobs(self.conn)

        self.assertEqual(result, {"requeued": 1, "failed": 0})
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "queued")
        self.assertEqual(job["attempt_count"], 1)
        self.assertIsNone(job["lease_expires_at"])
        budget = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget["reserved_units"], 0)
        self.assertEqual(budget["consumed_units"], 0)

    def test_claimed_job_with_attempts_remaining_is_requeued_but_budget_left_untouched(self):
        # Simulates a crash between reserve_workspace_budget() succeeding
        # and the claimed->running transition - the job is still
        # 'claimed', and a real reservation DOES exist, but this function
        # cannot safely know that from the schema alone (see its own
        # docstring) - it must not guess, so it leaves the reservation
        # exactly as it found it.
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        claimed = repo.claim_next_job(self.conn, "worker-test")
        self.assertEqual(claimed["id"], job_id)
        reserved = repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"])
        self.assertTrue(reserved)
        self._expire_lease(job_id)

        result = repo.reap_expired_jobs(self.conn)

        self.assertEqual(result, {"requeued": 1, "failed": 0})
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "queued")
        budget = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget["reserved_units"], 1)  # left exactly as found - not released, not double-charged.

    def test_running_job_at_max_attempts_fails_and_budget_released(self):
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        self._drive_to_running(job_id, workspace_id, "quick")
        self._expire_lease(job_id)

        result = repo.reap_expired_jobs(self.conn, max_attempts=0)  # already "at" the ceiling.

        self.assertEqual(result, {"requeued": 0, "failed": 1})
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIsNotNone(job["completed_at"])
        self.assertIn("lease expired", job["last_error"])
        budget = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget["reserved_units"], 0)

    def test_claimed_job_at_max_attempts_fails_but_budget_left_untouched(self):
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        claimed = repo.claim_next_job(self.conn, "worker-test")
        self.assertEqual(claimed["id"], job_id)
        reserved = repo.reserve_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"])
        self.assertTrue(reserved)
        self._expire_lease(job_id)

        result = repo.reap_expired_jobs(self.conn, max_attempts=0)

        self.assertEqual(result, {"requeued": 0, "failed": 1})
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "failed")
        budget = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget["reserved_units"], 1)  # same reasoning as the requeue case above.

    def test_job_with_lease_not_yet_expired_is_untouched(self):
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        self._drive_to_running(job_id, workspace_id, "quick")
        # Lease is fresh (claim_next_job() just set it) - never expired.

        result = repo.reap_expired_jobs(self.conn)

        self.assertEqual(result, {"requeued": 0, "failed": 0})
        job = repo.get_job(self.conn, job_id)
        self.assertEqual(job["status"], "running")
        budget = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget["reserved_units"], 1)

    def test_multiple_workspaces_reconciled_independently(self):
        job_a = _seed_job(self.conn)
        workspace_a = repo.get_job(self.conn, job_a)["workspace_id"]
        self._drive_to_running(job_a, workspace_a, "quick")
        self._expire_lease(job_a)

        user_b = repo.create_user(self.conn, "b@example.com")
        workspace_b = repo.create_workspace(self.conn, "Beta", user_b)
        contract_b = repo.create_contract(self.conn, workspace_b, "s3://y", "hashb", "B.sol")
        job_b = repo.enqueue_job(self.conn, workspace_b, contract_b, user_b, "pro")
        self._drive_to_running(job_b, workspace_b, "pro")
        self._expire_lease(job_b)

        result = repo.reap_expired_jobs(self.conn)

        self.assertEqual(result, {"requeued": 2, "failed": 0})
        self.assertEqual(repo.get_workspace_budget(self.conn, workspace_a)["reserved_units"], 0)
        self.assertEqual(repo.get_workspace_budget(self.conn, workspace_b)["reserved_units"], 0)

    def test_repeated_reap_call_does_not_release_budget_twice(self):
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        self._drive_to_running(job_id, workspace_id, "quick")
        self._expire_lease(job_id)

        first = repo.reap_expired_jobs(self.conn)
        second = repo.reap_expired_jobs(self.conn)

        self.assertEqual(first, {"requeued": 1, "failed": 0})
        self.assertEqual(second, {"requeued": 0, "failed": 0})  # nothing left to reap - job is 'queued', lease is NULL.
        self.assertEqual(repo.get_workspace_budget(self.conn, workspace_id)["reserved_units"], 0)

    def test_concurrent_reap_style_race_releases_budget_at_most_once(self):
        # Simulates two reapers (e.g. two ROLE=worker processes) racing to
        # reap the SAME expired job. A single :memory: SQLite connection
        # (this file's own convention) cannot run genuinely concurrent
        # connections against the same in-memory database, so this uses
        # the SAME technique ClaimNextJobTests.test_race_simulation_only_
        # one_of_two_concurrent_conditional_updates_wins above already
        # established: manually perform the competing write first, then
        # run the real call and confirm it correctly finds nothing left.
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        self._drive_to_running(job_id, workspace_id, "quick")
        self._expire_lease(job_id)

        # "Reaper A" wins the race first - the exact same conditional
        # UPDATE + release reap_expired_jobs() itself performs per row.
        winning_update = self.conn.execute(
            "UPDATE analysis_jobs SET status = 'queued', claimed_by = NULL, claimed_at = NULL, "
            "lease_expires_at = NULL, attempt_count = attempt_count + 1 "
            "WHERE id = ? AND status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at < '2999-01-01T00:00:00+00:00'",
            (job_id,),
        )
        self.conn.commit()
        self.assertEqual(winning_update.rowcount, 1)
        repo.release_workspace_budget(self.conn, workspace_id, repo.JOB_MODE_BUDGET_COST["quick"])

        # "Reaper B" - the real function - must find nothing left to reap
        # for this job (status is no longer claimed/running) and must NOT
        # release the same budget a second time.
        result = repo.reap_expired_jobs(self.conn)

        self.assertEqual(result, {"requeued": 0, "failed": 0})
        self.assertEqual(repo.get_workspace_budget(self.conn, workspace_id)["reserved_units"], 0)

    def test_budget_write_failure_rolls_back_the_job_transition_too(self):
        # Proves REAL transactional atomicity against the actual database
        # engine - not by mocking commit() or counting calls, but by
        # making the SECOND write (workspace_budgets) genuinely fail (a
        # real CHECK constraint violation - schema_sqlite.sql's own
        # `CHECK (reserved_units >= 0 ...)`), then reading persisted state
        # back from the same connection with fresh SELECTs (never reusing
        # a pre-attempt Python object) to confirm the FIRST write
        # (analysis_jobs), though it would have succeeded in isolation,
        # did not survive either - it shared a transaction with the write
        # that failed. A single :memory: connection is this file's own
        # established convention throughout (a second connection to the
        # same :memory: database would be a separate, empty database, not
        # a way to observe it independently) - the independence here is
        # that every assertion below is a fresh query issued AFTER the
        # failed call returned, never a value cached from before it ran.
        job_id = _seed_job(self.conn)
        workspace_id = repo.get_job(self.conn, job_id)["workspace_id"]
        self._drive_to_running(job_id, workspace_id, "quick")
        self._expire_lease(job_id)

        # Sabotage, bypassing the normal API entirely, purely to
        # manufacture a genuine constraint violation on the write
        # reap_expired_jobs() is about to attempt (subtracting 1 from an
        # already-0 reserved_units would go negative).
        self.conn.execute("UPDATE workspace_budgets SET reserved_units = 0 WHERE workspace_id = ?", (workspace_id,))
        self.conn.commit()

        with self.assertRaises(Exception):
            repo.reap_expired_jobs(self.conn)

        job_after = repo.get_job(self.conn, job_id)
        self.assertEqual(job_after["status"], "running")  # the job UPDATE did NOT persist.
        self.assertEqual(job_after["attempt_count"], 0)
        self.assertIsNotNone(job_after["lease_expires_at"])  # still the expired one - never cleared.

        budget_after = repo.get_workspace_budget(self.conn, workspace_id)
        self.assertEqual(budget_after["reserved_units"], 0)  # exactly the sabotaged value - the failed write never landed either.

        # A second attempt hits the exact same sabotage and fails the
        # exact same way - proving repeated failed attempts never
        # accumulate any partial state either, on top of the first one.
        with self.assertRaises(Exception):
            repo.reap_expired_jobs(self.conn)
        job_after_retry = repo.get_job(self.conn, job_id)
        self.assertEqual(job_after_retry["status"], "running")
        self.assertEqual(job_after_retry["attempt_count"], 0)
        self.assertEqual(repo.get_workspace_budget(self.conn, workspace_id)["reserved_units"], 0)


if __name__ == "__main__":
    unittest.main()
