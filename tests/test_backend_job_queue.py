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


if __name__ == "__main__":
    unittest.main()
