"""Tests for backend/tenant_scope.py (Phase 1 SaaS backend data
foundation, docs/decisiones.md D-077): workspace-membership resolution,
and that scoping a query by workspace_id actually isolates one tenant's
rows from another's.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import unittest

import backend.repository as repo
import backend.tenant_scope as tenant_scope


class ResolveWorkspaceRoleTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_owner_resolves_to_owner_role(self):
        user_id = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", user_id)
        self.assertEqual(tenant_scope.resolve_workspace_role(self.conn, user_id, workspace_id), "owner")

    def test_added_member_resolves_to_their_assigned_role(self):
        owner = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", owner)
        member = repo.create_user(self.conn, "member@example.com")
        repo.add_workspace_member(self.conn, workspace_id, member, "member")
        self.assertEqual(tenant_scope.resolve_workspace_role(self.conn, member, workspace_id), "member")

    def test_non_member_resolves_to_none(self):
        owner = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", owner)
        outsider = repo.create_user(self.conn, "outsider@example.com")
        self.assertIsNone(tenant_scope.resolve_workspace_role(self.conn, outsider, workspace_id))

    def test_nonexistent_workspace_resolves_to_none_not_an_error(self):
        # Deliberately indistinguishable from "not a member of a real
        # workspace" - never leaks which workspace IDs actually exist.
        user_id = repo.create_user(self.conn, "u@example.com")
        self.assertIsNone(tenant_scope.resolve_workspace_role(self.conn, user_id, "does-not-exist"))

    def test_require_workspace_role_raises_for_non_member(self):
        owner = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", owner)
        outsider = repo.create_user(self.conn, "outsider@example.com")
        with self.assertRaises(tenant_scope.TenantScopeError):
            tenant_scope.require_workspace_role(self.conn, outsider, workspace_id)

    def test_require_workspace_role_raises_when_role_not_in_allowed_set(self):
        owner = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", owner)
        member = repo.create_user(self.conn, "member@example.com")
        repo.add_workspace_member(self.conn, workspace_id, member, "member")
        with self.assertRaises(tenant_scope.TenantScopeError):
            tenant_scope.require_workspace_role(self.conn, member, workspace_id, allowed_roles=("owner", "admin"))

    def test_require_workspace_role_returns_the_role_on_success(self):
        owner = repo.create_user(self.conn, "owner@example.com")
        workspace_id = repo.create_workspace(self.conn, "Acme", owner)
        self.assertEqual(tenant_scope.require_workspace_role(self.conn, owner, workspace_id), "owner")


class CrossTenantDataIsolationTests(unittest.TestCase):
    """Proves the 'every tenant-owned row has workspace_id' schema rule
    actually delivers isolation when a query is scoped by it - the
    concrete, data-level counterpart to the membership-resolution tests
    above."""

    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.user_a = repo.create_user(self.conn, "a@example.com")
        self.user_b = repo.create_user(self.conn, "b@example.com")
        self.workspace_a = repo.create_workspace(self.conn, "Workspace A", self.user_a)
        self.workspace_b = repo.create_workspace(self.conn, "Workspace B", self.user_b)

    def test_contracts_are_isolated_by_workspace(self):
        repo.create_contract(self.conn, self.workspace_a, "s3://a", "hash-a", "A.sol")
        repo.create_contract(self.conn, self.workspace_b, "s3://b", "hash-b", "B.sol")
        rows = self.conn.execute("SELECT name FROM contracts WHERE workspace_id = ?", (self.workspace_a,)).fetchall()
        self.assertEqual([r["name"] for r in rows], ["A.sol"])

    def test_jobs_and_reports_are_isolated_by_workspace(self):
        contract_a = repo.create_contract(self.conn, self.workspace_a, "s3://a", "hash-a", "A.sol")
        contract_b = repo.create_contract(self.conn, self.workspace_b, "s3://b", "hash-b", "B.sol")
        job_a = repo.enqueue_job(self.conn, self.workspace_a, contract_a, self.user_a, "quick")
        repo.enqueue_job(self.conn, self.workspace_b, contract_b, self.user_b, "quick")
        repo.record_report(self.conn, job_a, self.workspace_a, "s3://report-a", score_status="not_computed")

        jobs_visible_to_a = self.conn.execute("SELECT id FROM analysis_jobs WHERE workspace_id = ?", (self.workspace_a,)).fetchall()
        reports_visible_to_b = self.conn.execute("SELECT id FROM reports WHERE workspace_id = ?", (self.workspace_b,)).fetchall()
        self.assertEqual(len(jobs_visible_to_a), 1)
        self.assertEqual(reports_visible_to_b, [])  # B's own scope never sees A's report.

    def test_a_user_of_workspace_a_cannot_be_resolved_as_a_member_of_workspace_b(self):
        self.assertIsNone(tenant_scope.resolve_workspace_role(self.conn, self.user_a, self.workspace_b))


if __name__ == "__main__":
    unittest.main()
