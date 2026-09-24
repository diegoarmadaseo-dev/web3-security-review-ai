"""Tests for backend/retention.py (Phase 6A production hardening, docs/
decisiones.md D-077 follow-up): age-based content purging and explicit
workspace deletion, against SQLite (fast - no dependency this module
itself has on which backend db.py talks to; the Postgres-specific
dialect concerns are already covered elsewhere, e.g. tests/
test_backend_postgres_integration.py's own migration tests).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import backend.auth as auth
import backend.object_storage as object_storage
import backend.repository as repo
import backend.retention as retention


def _seed_contract_and_report(conn, storage, workspace_id, user_id, created_at_override=None):
    """Creates a contract + a succeeded job + a report for it, with real
    object-storage content - created_at_override lets a test backdate
    the row past a retention cutoff without needing to actually sleep."""
    storage_ref = object_storage.workspace_key(workspace_id, "sources", repo.new_id())
    storage.put_object(storage_ref, b"contract Source {}", content_type="text/plain")
    contract_id = repo.create_contract(conn, workspace_id, storage_ref, "hash", "A.sol")
    job_id = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
    report_key = object_storage.workspace_key(workspace_id, "reports", job_id)
    storage.put_object(report_key, b"# Report content", content_type="text/markdown")
    report_id = repo.record_report(conn, job_id, workspace_id, report_key, score_status="not_computed")
    if created_at_override is not None:
        import backend.db as db
        db.execute(conn, "UPDATE contracts SET created_at = ? WHERE id = ?", (created_at_override, contract_id))
        db.execute(conn, "UPDATE reports SET created_at = ? WHERE id = ?", (created_at_override, report_id))
        conn.commit()
    return {"contract_id": contract_id, "job_id": job_id, "report_id": report_id, "storage_ref": storage_ref, "report_key": report_key}


class _RetentionTestCase(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.storage_dir = tempfile.mkdtemp(prefix="retention-tests-")
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="retention-test-secret")

    def _old_cutoff(self):
        return (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()


class PurgeExpiredContractsTests(_RetentionTestCase):
    def test_dry_run_reports_but_never_mutates(self):
        user_id = repo.create_user(self.conn, "purge-c1@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        seeded = _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id, created_at_override=self._old_cutoff())

        result = retention.purge_expired_contracts(self.conn, self.storage, retention_days=30, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["would_purge"], 1)
        self.assertEqual(result["contract_ids"], [seeded["contract_id"]])
        # Never mutated: the object is still there, the row is still live.
        self.assertTrue(self.storage.object_exists(seeded["storage_ref"]))
        contract = repo.get_contract(self.conn, seeded["contract_id"])
        self.assertIsNone(contract["deleted_at"])

    def test_real_run_deletes_object_and_marks_row_never_deletes_row(self):
        user_id = repo.create_user(self.conn, "purge-c2@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        seeded = _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id, created_at_override=self._old_cutoff())

        result = retention.purge_expired_contracts(self.conn, self.storage, retention_days=30, dry_run=False)
        self.assertEqual(result["purged"], 1)
        self.assertFalse(self.storage.object_exists(seeded["storage_ref"]))
        contract = repo.get_contract(self.conn, seeded["contract_id"])
        self.assertIsNotNone(contract)  # row survives - only content is gone.
        self.assertIsNotNone(contract["deleted_at"])

    def test_recent_contract_is_never_purged(self):
        user_id = repo.create_user(self.conn, "purge-c3@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        seeded = _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id)  # created_at = now, well within any retention window.

        result = retention.purge_expired_contracts(self.conn, self.storage, retention_days=30, dry_run=False)
        self.assertEqual(result["purged"], 0)
        self.assertTrue(self.storage.object_exists(seeded["storage_ref"]))

    def test_repeated_purge_is_idempotent(self):
        user_id = repo.create_user(self.conn, "purge-c4@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id, created_at_override=self._old_cutoff())

        first = retention.purge_expired_contracts(self.conn, self.storage, retention_days=30, dry_run=False)
        second = retention.purge_expired_contracts(self.conn, self.storage, retention_days=30, dry_run=False)
        self.assertEqual(first["purged"], 1)
        self.assertEqual(second["purged"], 0)  # already-purged row no longer matches - never double-processed, never an error.

    def test_purge_is_tenant_safe_only_the_expired_workspaces_content_is_touched(self):
        user_a = repo.create_user(self.conn, "purge-a@example.com")
        user_b = repo.create_user(self.conn, "purge-b@example.com")
        ws_a = repo.create_workspace(self.conn, "WS A", user_a)
        ws_b = repo.create_workspace(self.conn, "WS B", user_b)
        old_a = _seed_contract_and_report(self.conn, self.storage, ws_a, user_a, created_at_override=self._old_cutoff())
        fresh_b = _seed_contract_and_report(self.conn, self.storage, ws_b, user_b)  # NOT expired.

        result = retention.purge_expired_contracts(self.conn, self.storage, retention_days=30, dry_run=False)
        self.assertEqual(result["contract_ids"], [old_a["contract_id"]])
        self.assertFalse(self.storage.object_exists(old_a["storage_ref"]))
        self.assertTrue(self.storage.object_exists(fresh_b["storage_ref"]))  # workspace B's content untouched.

    def test_negative_retention_days_is_rejected(self):
        with self.assertRaises(ValueError):
            retention.purge_expired_contracts(self.conn, self.storage, retention_days=-1, dry_run=True)


class PurgeExpiredReportsTests(_RetentionTestCase):
    def test_purge_deletes_content_keeps_metadata_row(self):
        user_id = repo.create_user(self.conn, "purge-r1@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        seeded = _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id, created_at_override=self._old_cutoff())

        result = retention.purge_expired_reports(self.conn, self.storage, retention_days=30, dry_run=False)
        self.assertEqual(result["purged"], 1)
        self.assertFalse(self.storage.object_exists(seeded["report_key"]))
        row = repo.get_report_by_id(self.conn, seeded["report_id"])
        self.assertIsNotNone(row)  # metadata (score_status/created_at/job_id) survives - "audit/job history where appropriate".
        self.assertIsNotNone(row["purged_at"])

    def test_repeated_purge_is_idempotent(self):
        user_id = repo.create_user(self.conn, "purge-r2@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id, created_at_override=self._old_cutoff())

        first = retention.purge_expired_reports(self.conn, self.storage, retention_days=30, dry_run=False)
        second = retention.purge_expired_reports(self.conn, self.storage, retention_days=30, dry_run=False)
        self.assertEqual((first["purged"], second["purged"]), (1, 0))


class DeleteWorkspaceDataTests(_RetentionTestCase):
    def test_dry_run_reports_but_never_mutates(self):
        user_id = repo.create_user(self.conn, "del-dry@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        seeded = _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id)

        result = retention.delete_workspace_data(self.conn, self.storage, workspace_id, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["would_delete_contracts"], 1)
        self.assertTrue(self.storage.object_exists(seeded["storage_ref"]))
        self.assertIsNone(repo.get_workspace(self.conn, workspace_id)["deleted_at"])

    def test_real_deletion_purges_content_removes_membership_soft_deletes_workspace(self):
        user_id = repo.create_user(self.conn, "del-real@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        seeded = _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id)

        result = retention.delete_workspace_data(self.conn, self.storage, workspace_id, dry_run=False)
        self.assertEqual(result["deleted_contracts"], 1)
        self.assertEqual(result["purged_reports"], 1)
        self.assertEqual(result["removed_members"], 1)
        self.assertTrue(result["workspace_marked_deleted"])
        self.assertFalse(self.storage.object_exists(seeded["storage_ref"]))
        self.assertFalse(self.storage.object_exists(seeded["report_key"]))
        self.assertIsNotNone(repo.get_workspace(self.conn, workspace_id)["deleted_at"])

    def test_repeated_deletion_is_idempotent(self):
        user_id = repo.create_user(self.conn, "del-repeat@example.com")
        workspace_id = repo.create_workspace(self.conn, "WS", user_id)
        _seed_contract_and_report(self.conn, self.storage, workspace_id, user_id)

        first = retention.delete_workspace_data(self.conn, self.storage, workspace_id, dry_run=False)
        second = retention.delete_workspace_data(self.conn, self.storage, workspace_id, dry_run=False)
        self.assertEqual((first["deleted_contracts"], first["purged_reports"], first["removed_members"]), (1, 1, 1))
        self.assertEqual((second["deleted_contracts"], second["purged_reports"], second["removed_members"]), (0, 0, 0))
        self.assertFalse(second["workspace_marked_deleted"])  # already deleted - conditional UPDATE matches nothing the second time.

    def test_deletion_never_touches_a_different_tenants_data(self):
        user_a = repo.create_user(self.conn, "del-cross-a@example.com")
        user_b = repo.create_user(self.conn, "del-cross-b@example.com")
        ws_a = repo.create_workspace(self.conn, "WS A", user_a)
        ws_b = repo.create_workspace(self.conn, "WS B", user_b)
        seeded_a = _seed_contract_and_report(self.conn, self.storage, ws_a, user_a)
        seeded_b = _seed_contract_and_report(self.conn, self.storage, ws_b, user_b)

        retention.delete_workspace_data(self.conn, self.storage, ws_a, dry_run=False)

        self.assertFalse(self.storage.object_exists(seeded_a["storage_ref"]))
        self.assertTrue(self.storage.object_exists(seeded_b["storage_ref"]))  # workspace B completely untouched.
        self.assertIsNone(repo.get_workspace(self.conn, ws_b)["deleted_at"])

    def test_session_revoked_only_for_a_member_left_with_zero_remaining_workspaces(self):
        import backend.tenant_scope as tenant_scope

        sole_member = repo.create_user(self.conn, "sole-member@example.com")
        multi_member = repo.create_user(self.conn, "multi-member@example.com")
        ws_target = repo.create_workspace(self.conn, "Target WS", sole_member)
        ws_other = repo.create_workspace(self.conn, "Other WS", multi_member)
        repo.add_workspace_member(self.conn, ws_target, multi_member, "member")  # multi_member belongs to BOTH workspaces.

        session_sole = auth.create_session(self.conn, sole_member)
        session_multi = auth.create_session(self.conn, multi_member)
        self.conn.commit()

        retention.delete_workspace_data(self.conn, self.storage, ws_target, dry_run=False)

        # sole_member had ONLY this workspace -> zero remaining -> session revoked.
        self.assertIsNone(auth.validate_session(self.conn, session_sole["session_token"]))
        # multi_member still belongs to ws_other -> session must survive.
        self.assertIsNotNone(auth.validate_session(self.conn, session_multi["session_token"]))
        self.assertEqual(tenant_scope.resolve_workspace_role(self.conn, multi_member, ws_other), "owner")


if __name__ == "__main__":
    unittest.main()
