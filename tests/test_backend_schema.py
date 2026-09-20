"""Tests for backend/schema_sqlite.sql (Phase 1 SaaS backend data
foundation, docs/decisiones.md D-077): foreign key, unique and CHECK
constraint enforcement, exercised through backend/repository.py.

These tests run against the SQLite test-mirror schema, not PostgreSQL -
see backend/schema_sqlite.sql's own docstring for the deliberate,
documented differences. What they verify (a constraint fires, in which
direction) is schema-logic, common to both engines; the exact SQL dialect
is not.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import sqlite3
import unittest

import backend.repository as repo


class SchemaConstraintTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    # -- users ----------------------------------------------------------

    def test_user_email_must_be_unique(self):
        repo.create_user(self.conn, "person@example.com")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_user(self.conn, "person@example.com")

    def test_user_email_must_be_lowercase(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO users (id, email, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (repo.new_id(), "Person@Example.com", repo.utcnow_iso(), repo.utcnow_iso()),
            )

    # -- workspaces / workspace_members ----------------------------------

    def test_workspace_owner_must_reference_a_real_user(self):
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_workspace(self.conn, "Acme", owner_user_id="does-not-exist")

    def test_workspace_creation_also_inserts_owner_as_member(self):
        user_id = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        row = self.conn.execute(
            "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?", (workspace_id, user_id)
        ).fetchone()
        self.assertEqual(row["role"], "owner")

    def test_workspace_member_role_is_constrained(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        other = repo.create_user(self.conn, "other@example.com")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO workspace_members (workspace_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
                (workspace_id, other, "superadmin", repo.utcnow_iso()),
            )

    def test_a_user_cannot_be_added_twice_to_the_same_workspace(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        other = repo.create_user(self.conn, "other@example.com")
        repo.add_workspace_member(self.conn, workspace_id, other, "member")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.add_workspace_member(self.conn, workspace_id, other, "admin")

    # -- sessions ---------------------------------------------------------

    def test_session_expiry_must_be_after_creation(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (repo.new_id(), user_id, "hash1", "2026-01-02T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
            )

    def test_session_token_hash_must_be_unique(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        created, expires = "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"
        self.conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, 'dup', ?, ?)",
            (repo.new_id(), user_id, created, expires),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, 'dup', ?, ?)",
                (repo.new_id(), user_id, created, expires),
            )

    # -- entitlements -------------------------------------------------------

    def test_entitlement_plan_is_constrained(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_entitlement(self.conn, workspace_id, plan="enterprise", status="active")

    def test_entitlement_status_is_constrained(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_entitlement(self.conn, workspace_id, plan="pro", status="lifetime_free")

    def test_only_one_entitlement_per_workspace(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        repo.create_entitlement(self.conn, workspace_id, plan="quick", status="active")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_entitlement(self.conn, workspace_id, plan="pro", status="active")

    def test_stripe_subscription_id_is_unique_across_workspaces(self):
        u1 = repo.create_user(self.conn, "u1@example.com")
        u2 = repo.create_user(self.conn, "u2@example.com")
        w1 = repo.create_workspace(self.conn, "A", u1)
        w2 = repo.create_workspace(self.conn, "B", u2)
        repo.create_entitlement(self.conn, w1, "pro", "active", stripe_subscription_id="sub_123")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_entitlement(self.conn, w2, "pro", "active", stripe_subscription_id="sub_123")

    # -- projects (partial unique index) -----------------------------------

    def test_two_live_projects_cannot_share_a_name_in_one_workspace(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        repo.create_project(self.conn, workspace_id, "Vault")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_project(self.conn, workspace_id, "Vault")

    def test_a_soft_deleted_project_does_not_block_the_name_being_reused(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        first_id = repo.create_project(self.conn, workspace_id, "Vault")
        self.conn.execute("UPDATE projects SET deleted_at = ? WHERE id = ?", (repo.utcnow_iso(), first_id))
        self.conn.commit()
        second_id = repo.create_project(self.conn, workspace_id, "Vault")  # must not raise.
        self.assertNotEqual(first_id, second_id)

    def test_the_same_project_name_is_fine_in_a_different_workspace(self):
        u1 = repo.create_user(self.conn, "u1@example.com")
        u2 = repo.create_user(self.conn, "u2@example.com")
        w1 = repo.create_workspace(self.conn, "A", u1)
        w2 = repo.create_workspace(self.conn, "B", u2)
        repo.create_project(self.conn, w1, "Vault")
        repo.create_project(self.conn, w2, "Vault")  # must not raise.

    # -- contracts / analysis_jobs / reports -------------------------------

    def test_contract_workspace_must_reference_a_real_workspace(self):
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_contract(self.conn, workspace_id="ghost", storage_ref="s3://x", content_hash="abc", name="A.sol")

    def test_job_mode_is_constrained(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        with self.assertRaises(repo.RepositoryError):
            repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, mode="ultra")

    def test_job_idempotency_key_is_unique(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick", idempotency_key="req-1")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick", idempotency_key="req-1")

    def test_job_attempt_count_cannot_go_negative(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE analysis_jobs SET attempt_count = -1 WHERE id = ?", (job_id,))

    def test_report_score_out_of_range_is_rejected(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.record_report(self.conn, job_id, workspace_id, "s3://r", score_status="computed", score=101, risk_band="HIGH")

    def test_report_not_computed_status_cannot_carry_a_score(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.record_report(self.conn, job_id, workspace_id, "s3://r", score_status="not_computed", score=50)

    def test_report_computed_status_requires_a_score(self):
        # docs/decisiones.md D-077 follow-up (report-schema.json R-08
        # alignment): 'computed' with a NULL score used to be silently
        # allowed - must now be rejected, matching R-08's "requires
        # riskIndicator.score/band to be non-null" exactly.
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.record_report(self.conn, job_id, workspace_id, "s3://r", score_status="computed", score=None, risk_band="HIGH")

    def test_report_computed_status_requires_a_risk_band(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.record_report(self.conn, job_id, workspace_id, "s3://r", score_status="computed", score=40, risk_band=None)

    def test_report_fully_valid_computed_report_succeeds(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        report_id = repo.record_report(self.conn, job_id, workspace_id, "s3://r", score_status="computed", score=40, risk_band="HIGH")
        self.assertIsNotNone(report_id)

    def test_report_job_id_is_unique_one_report_per_job(self):
        user_id = repo.create_user(self.conn, "u@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        contract_id = repo.create_contract(self.conn, workspace_id, "s3://x", "abc", "A.sol")
        job_id = repo.enqueue_job(self.conn, workspace_id, contract_id, user_id, "quick")
        repo.record_report(self.conn, job_id, workspace_id, "s3://r1", score_status="not_computed")
        with self.assertRaises(sqlite3.IntegrityError):
            repo.record_report(self.conn, job_id, workspace_id, "s3://r2", score_status="not_computed")

    # -- audit_events / webhook_events ---------------------------------------

    def test_audit_event_allows_null_workspace_and_actor_for_system_events(self):
        event_id = repo.append_audit_event(self.conn, workspace_id=None, actor_user_id=None, event_type="system.startup")
        self.assertIsNotNone(event_id)

    def test_webhook_event_id_is_unique_at_the_db_level_too(self):
        self.assertTrue(repo.record_webhook_event(self.conn, "evt_1", "checkout.session.completed"))
        self.assertFalse(repo.record_webhook_event(self.conn, "evt_1", "checkout.session.completed"))


if __name__ == "__main__":
    unittest.main()
