#!/usr/bin/env python3
"""Data lifecycle: age-based retention purging and explicit workspace
deletion (Phase 6A production hardening, docs/decisiones.md D-077
follow-up).

NOT A LEGAL/COMPLIANCE CLAIM. This module implements TECHNICAL
primitives only - it never decides, invents or hardcodes a retention
PERIOD (every function here takes retention_days/cutoff as an explicit
caller-supplied argument, never a default rooted in a specific number of
days) and never asserts that running it satisfies any particular privacy
law or contractual term. Which period to configure, and whether these
primitives are ever actually wired into a scheduled job, is a business/
legal decision for a later phase - see docs/decisiones.md's Phase 6
entries for the open legal-readiness gaps this deliberately does not
resolve.

TWO DISTINCT MECHANISMS, both here because they share the same object-
storage-delete-plus-DB-mark shape:

  * purge_expired_contracts()/purge_expired_reports() - AGE-based,
    content-only: deletes the object-storage bytes (source code / a
    rendered report) once older than a caller-chosen cutoff, but always
    KEEPS the database row - contracts.deleted_at / reports.purged_at
    mark that the content is gone, never the metadata (score, risk_band,
    created_at, job linkage). "Audit/job history where appropriate"
    (Phase 6A's own scoping) means history stays queryable indefinitely
    by this mechanism; only the underlying report/source CONTENT is
    time-limited.

  * delete_workspace_data() - EXPLICIT, workspace-scoped: the technical
    primitives an account/workspace-deletion request needs (revoke
    sessions, remove memberships, purge every contract/report's content,
    soft-delete the workspace itself). Scoped to exactly ONE workspace_id
    per call - by construction, this can never touch another tenant's
    data, and repeating it on an already-deleted workspace is a safe
    no-op (every underlying repository.py call is itself idempotent).
    audit_events rows are deliberately NEVER deleted here (workspace_id
    is a nullable FK, not cascaded) - preserving them is the safer
    default absent an explicit legal retention rule; a later phase may
    need to shorten or further restrict that once one exists.

TENANT SAFETY: neither function accepts or infers a workspace_id filter
from anything other than its own explicit parameter (delete_workspace_
data) or an age cutoff applied uniformly across every workspace (the
purge functions) - there is no code path here that could accidentally
scope a purge to, or exclude, one tenant unfairly.

IDEMPOTENT AND DRY-RUN-SAFE: every purge/delete function accepts
dry_run (purge_*) - a dry run never calls storage.delete_object() or any
repository write; it only reports what WOULD be affected. Object storage
deletion itself is already idempotent (see backend/object_storage.py's
LocalFilesystemStorage.delete_object()/S3Storage's own S3 DELETE
semantics - deleting an already-absent key is not an error on either
adapter), and every DB mark is a conditional UPDATE that already-marked
rows fail to match again.

No LLM calls, no network access of its own beyond the ObjectStorage
adapter it is handed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import backend.auth as auth
import backend.object_storage as object_storage
import backend.plans as plans
import backend.repository as repo


def _cutoff_iso(retention_days: int, now: Optional[datetime] = None) -> str:
    if retention_days < 0:
        raise ValueError("retention_days must be >= 0, got %r" % (retention_days,))
    reference = now or datetime.now(timezone.utc)
    return (reference - timedelta(days=retention_days)).isoformat()


def purge_expired_contracts(
    conn: Any, storage: object_storage.ObjectStorage, retention_days: int, dry_run: bool = True, now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Deletes the object-storage SOURCE content of every contract older
    than retention_days (by created_at), across every workspace uniformly
    - see module docstring on tenant safety. dry_run=True (the default)
    performs no mutation at all, just reports what would be purged -
    callers that actually want to purge must pass dry_run=False
    explicitly."""
    cutoff = _cutoff_iso(retention_days, now)
    expired = repo.list_expired_contracts(conn, cutoff)
    contract_ids = [c["id"] for c in expired]
    if dry_run:
        return {"dry_run": True, "would_purge": len(expired), "contract_ids": contract_ids}
    purged = 0
    for contract in expired:
        storage.delete_object(contract["storage_ref"])
        if repo.mark_contract_deleted(conn, contract["id"]):
            purged += 1
    return {"dry_run": False, "purged": purged, "contract_ids": contract_ids}


def _delete_report_companions(storage: object_storage.ObjectStorage, report_storage_ref: str) -> None:
    """Objects stored next to a report with ids derived from it (Layer 2
    targeted code review, docs/decisiones.md D-105; the structured report
    JSON, D-110) follow the report's own retention. delete_object() is
    idempotent for a key that was never written."""
    import backend.targeted_review as targeted_review  # stdlib-only module

    for key in targeted_review.companion_keys(report_storage_ref) + [object_storage.report_json_key(report_storage_ref)]:
        storage.delete_object(key)


def purge_expired_reports(
    conn: Any, storage: object_storage.ObjectStorage, retention_days: int, dry_run: bool = True, now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Same shape as purge_expired_contracts() above, for report CONTENT
    - see module docstring on why the report row's own metadata is never
    deleted by this function."""
    cutoff = _cutoff_iso(retention_days, now)
    expired = repo.list_expired_reports(conn, cutoff)
    report_ids = [r["id"] for r in expired]
    if dry_run:
        return {"dry_run": True, "would_purge": len(expired), "report_ids": report_ids}
    purged = 0
    for report in expired:
        storage.delete_object(report["storage_ref"])
        _delete_report_companions(storage, report["storage_ref"])
        if repo.mark_report_purged(conn, report["id"]):
            purged += 1
    return {"dry_run": False, "purged": purged, "report_ids": report_ids}


def purge_expired_trial_results(
    conn: Any, storage: object_storage.ObjectStorage, dry_run: bool = True, now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """D-112: a free-Trial scan's source and report CONTENT is kept 7 days
    (plans.TRIAL history_days), independently of RETENTION_DAYS. Same
    purge-content-keep-rows discipline as purge_expired_contracts()/
    purge_expired_reports(); never touches a scan still queued or running.
    The HTTP layer already hides and refuses these results after 7 days."""
    days = int(plans.TRIAL["history_days"])
    candidates = repo.list_expired_trial_results(conn, _cutoff_iso(days, now))
    if dry_run:
        return {"dry_run": True, "would_purge": len(candidates)}
    purged = 0
    for row in candidates:
        if row.get("contract_deleted_at") is None:
            storage.delete_object(row["contract_storage_ref"])
            if repo.mark_contract_deleted(conn, row["contract_id"]):
                purged += 1
        if row.get("report_id") and row.get("report_purged_at") is None:
            if row.get("report_storage_ref"):
                storage.delete_object(row["report_storage_ref"])
                _delete_report_companions(storage, row["report_storage_ref"])
            if repo.mark_report_purged(conn, row["report_id"]):
                purged += 1
    return {"dry_run": False, "purged": purged}


def delete_workspace_data(
    conn: Any, storage: object_storage.ObjectStorage, workspace_id: str, dry_run: bool = False,
) -> Dict[str, Any]:
    """Technical primitives for an account/workspace-deletion request -
    see module docstring for the exact scope and what is deliberately
    preserved. Idempotent: calling this again on an already-deleted
    workspace_id finds zero remaining non-deleted contracts/reports/
    memberships and returns all-zero counts, never an error.

    "Revoke sessions" is scoped narrowly and deliberately: only for a
    member who, after this workspace's own membership row is removed,
    belongs to ZERO remaining workspaces - forcibly logging out a user
    who still has access to a DIFFERENT workspace just because this one
    was deleted would be wrong, and this module has no way to know
    whether a broader "delete this person's whole account" action is
    actually what is wanted (a real product/legal decision, not
    something to infer here)."""
    all_contracts = repo.list_workspace_contracts(conn, workspace_id)
    all_reports = repo.list_workspace_reports(conn, workspace_id)
    members = repo.list_workspace_members(conn, workspace_id)

    if dry_run:
        return {
            "dry_run": True,
            "workspace_id": workspace_id,
            "would_delete_contracts": len(all_contracts),
            "would_delete_reports": len(all_reports),
            "would_remove_members": len(members),
        }

    deleted_contracts = 0
    for contract in all_contracts:
        storage.delete_object(contract["storage_ref"])
        if repo.mark_contract_deleted(conn, contract["id"]):
            deleted_contracts += 1

    purged_reports = 0
    for report in all_reports:
        storage.delete_object(report["storage_ref"])
        _delete_report_companions(storage, report["storage_ref"])
        if repo.mark_report_purged(conn, report["id"]):
            purged_reports += 1

    removed_members = 0
    sessions_revoked = 0
    for member in members:
        if repo.remove_workspace_member(conn, workspace_id, member["user_id"]):
            removed_members += 1
        remaining_workspaces = repo.list_workspaces_by_user(conn, member["user_id"])
        if not remaining_workspaces:
            sessions_revoked += auth.revoke_all_sessions_for_user(conn, member["user_id"])

    # D-111: a deleted workspace keeps no usable GitHub credential - every
    # active connection is revoked and its encrypted tokens wiped.
    github_connections_revoked = repo.revoke_workspace_github_connections(conn, workspace_id)
    # D-113: and no usable Private API key.
    api_keys_revoked = repo.revoke_workspace_api_keys(conn, workspace_id)

    workspace_deleted = repo.mark_workspace_deleted(conn, workspace_id)

    return {
        "github_connections_revoked": github_connections_revoked,
        "api_keys_revoked": api_keys_revoked,
        "dry_run": False,
        "workspace_id": workspace_id,
        "deleted_contracts": deleted_contracts,
        "purged_reports": purged_reports,
        "removed_members": removed_members,
        "sessions_revoked": sessions_revoked,
        "workspace_marked_deleted": workspace_deleted,
    }
