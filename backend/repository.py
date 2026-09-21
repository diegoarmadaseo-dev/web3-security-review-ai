#!/usr/bin/env python3
"""Minimal data-access layer over the Phase 1 SaaS backend schema
(docs/decisiones.md D-077 - Capafy removal/independent-architecture line
of work).

Supports SQLite (standard library, via connect()/init_schema() below) and
PostgreSQL 13+ (via backend/db.connect_postgres(), needs psycopg - see
backend/requirements.txt) through backend/db.py's adapter: every query in
this module is written ONCE, using '?' placeholders, and submitted via
db.execute(conn, sql, params) rather than conn.execute()/conn.cursor()
directly - see backend/db.py's own docstring for exactly what it
normalizes (placeholder syntax, row value shapes) and what it does NOT
(the job-claim query itself is genuinely different per backend - see
claim_next_job() below).

EVERY row this module inserts gets its id and every timestamp generated
IN PYTHON (new_id()/utcnow_iso()) rather than relying on either engine's
own server-side defaults - this is deliberate, not an oversight: it keeps
every function's behavior identical regardless of which of the two schema
files (Postgres migration vs. SQLite mirror) it eventually runs against.

NO SECRETS, API KEYS OR PAYMENT DATA ever pass through this module - only
opaque references (Stripe customer/subscription IDs, storage keys, a
session TOKEN HASH the caller already computed, never a raw token).

This module does NOT itself enforce tenant scoping - see tenant_scope.py.
Every function below that takes a workspace_id trusts its caller to have
already resolved that workspace_id against the authenticated user via
tenant_scope.resolve_workspace_role()/require_workspace_role().

No LLM calls. Python 3.8+. The SQLite path (connect()/init_schema())
remains standard-library-only and needs no network access; the
PostgreSQL path needs psycopg and a reachable server - see
backend/db.py.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import backend.db as db

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_SCHEMA_PATH = os.path.join(SCRIPT_DIR, "schema_sqlite.sql")

REPOSITORY_VERSION = "2026.1"


class RepositoryError(Exception):
    """Raised only for malformed/invalid input this module itself
    validates before touching the database - never for a constraint the
    database itself already enforces (sqlite3.IntegrityError is left to
    propagate unchanged, never re-wrapped, so a caller can tell exactly
    which constraint fired)."""


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: str = ":memory:") -> sqlite3.Connection:
    """Opens a sqlite3 connection with foreign-key enforcement turned on
    (OFF by default per sqlite3 connection - a test or caller that opens
    its own connection without this would silently test nothing) and
    Row-based access (dict-like column access by name)."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Bootstraps a fresh connection with schema_sqlite.sql wholesale -
    convenience for tests/dev. Production against Postgres instead applies
    backend/migrations/*.sql via migrate.py, incrementally and tracked."""
    with open(SQLITE_SCHEMA_PATH, "r", encoding="utf-8") as handle:
        conn.executescript(handle.read())
    conn.commit()


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def create_user(conn: Any, email: str) -> str:
    if not isinstance(email, str) or not email.strip():
        raise RepositoryError("email must be a non-empty string")
    user_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO users (id, email, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (user_id, email.strip().lower(), now, now),
    )
    conn.commit()
    return user_id


def create_workspace(conn: Any, name: str, owner_user_id: str) -> str:
    """Creates the workspace AND inserts its owner as a workspace_members
    row with role='owner' in the same call - a workspace without its
    owner as a member would be a logically broken state, never a
    two-step operation a caller could leave half-done."""
    if not isinstance(name, str) or not name.strip():
        raise RepositoryError("name must be a non-empty string")
    workspace_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (workspace_id, name.strip(), owner_user_id, now, now),
    )
    db.execute(
        conn,
        "INSERT INTO workspace_members (workspace_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
        (workspace_id, owner_user_id, now),
    )
    conn.commit()
    return workspace_id


def add_workspace_member(conn: Any, workspace_id: str, user_id: str, role: str) -> None:
    if role not in ("owner", "admin", "member"):
        raise RepositoryError("role must be one of owner/admin/member, got %r" % role)
    db.execute(
        conn,
        "INSERT INTO workspace_members (workspace_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
        (workspace_id, user_id, role, utcnow_iso()),
    )
    conn.commit()


def update_workspace_member_role(conn: Any, workspace_id: str, user_id: str, role: str) -> bool:
    """Returns True if a membership row existed and was updated, False if
    this user is not a member of this workspace at all (never raises for
    that - the caller already resolved membership via tenant_scope before
    calling this, so "not a member" here would itself be a caller bug,
    but this function still reports it rather than silently no-op'ing)."""
    if role not in ("owner", "admin", "member"):
        raise RepositoryError("role must be one of owner/admin/member, got %r" % role)
    cur = db.execute(
        conn,
        "UPDATE workspace_members SET role = ? WHERE workspace_id = ? AND user_id = ?",
        (role, workspace_id, user_id),
    )
    conn.commit()
    return cur.rowcount > 0


def remove_workspace_member(conn: Any, workspace_id: str, user_id: str) -> bool:
    """Returns True if a membership row existed and was removed, False if
    this user was already not a member (idempotent, never raises for
    that). Does NOT prevent removing a workspace's last owner - a
    business rule for a later phase to add if needed, not a data-layer
    concern."""
    cur = db.execute(
        conn,
        "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
        (workspace_id, user_id),
    )
    conn.commit()
    return cur.rowcount > 0


def get_user_by_email(conn: Any, email: str) -> Optional[Dict[str, Any]]:
    """Case-insensitive by construction, never by a LOWER() query - every
    row's email is already stored lowercase (users_email_lowercase CHECK,
    both schema files) and every caller normalizes before calling (see
    backend/auth.py's normalize_email()), so an exact match is correct
    and sargable on both backends."""
    cur = db.execute(conn, "SELECT * FROM users WHERE email = ?", (email,))
    return db.normalize_row(cur.fetchone())


def mark_email_verified(conn: Any, user_id: str) -> None:
    """Idempotent: sets email_verified_at only if it is still NULL, so a
    second successful login never overwrites the ORIGINAL verification
    timestamp with a later one."""
    db.execute(
        conn,
        "UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL",
        (utcnow_iso(), user_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Billing mirror
# ---------------------------------------------------------------------------

def create_entitlement(
    conn: Any,
    workspace_id: str,
    plan: str,
    status: str,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
    current_period_end: Optional[str] = None,
) -> str:
    entitlement_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO entitlements "
        "(id, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entitlement_id, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, now, now),
    )
    conn.commit()
    return entitlement_id


def update_entitlement_status(
    conn: Any,
    workspace_id: str,
    status: str,
    current_period_end: Optional[str] = None,
) -> bool:
    """Returns True if a row was updated, False if this workspace has no
    entitlement row yet (a later phase's webhook handler must create one
    via create_entitlement() first on the initial checkout completion)."""
    cur = db.execute(
        conn,
        "UPDATE entitlements SET status = ?, current_period_end = COALESCE(?, current_period_end), updated_at = ? WHERE workspace_id = ?",
        (status, current_period_end, utcnow_iso(), workspace_id),
    )
    conn.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Application data
# ---------------------------------------------------------------------------

def create_project(conn: Any, workspace_id: str, name: str) -> str:
    project_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO projects (id, workspace_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (project_id, workspace_id, name, now, now),
    )
    conn.commit()
    return project_id


def create_contract(
    conn: Any,
    workspace_id: str,
    storage_ref: str,
    content_hash: str,
    name: str,
    project_id: Optional[str] = None,
) -> str:
    contract_id = new_id()
    db.execute(
        conn,
        "INSERT INTO contracts (id, workspace_id, project_id, name, storage_ref, content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (contract_id, workspace_id, project_id, name, storage_ref, content_hash, utcnow_iso()),
    )
    conn.commit()
    return contract_id


# ---------------------------------------------------------------------------
# Job queue
# ---------------------------------------------------------------------------

def enqueue_job(
    conn: Any,
    workspace_id: str,
    contract_id: str,
    requested_by_user_id: str,
    mode: str,
    idempotency_key: Optional[str] = None,
) -> str:
    if mode not in ("quick", "standard", "pro"):
        raise RepositoryError("mode must be one of quick/standard/pro, got %r" % mode)
    job_id = new_id()
    db.execute(
        conn,
        "INSERT INTO analysis_jobs (id, workspace_id, contract_id, requested_by_user_id, mode, idempotency_key, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (job_id, workspace_id, contract_id, requested_by_user_id, mode, idempotency_key, utcnow_iso()),
    )
    conn.commit()
    return job_id


def get_job(conn: Any, job_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT * FROM analysis_jobs WHERE id = ?", (job_id,))
    return db.normalize_row(cur.fetchone())


def claim_next_job(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    """Claims the oldest still-queued job for worker_id, or returns None
    if there is nothing queued OR another claimant won the race for the
    one job this call saw. Dispatches to a genuinely different query per
    backend - this is the one place in this module that cannot be reduced
    to a placeholder/value translation (see backend/db.py's docstring):
    Postgres gets the real, verified `FOR UPDATE SKIP LOCKED` claim query;
    SQLite keeps its existing conditional-UPDATE-and-check-rowcount
    pattern, which is the only claim safety SQLite's locking model can
    express (see schema_sqlite.sql's docstring)."""
    if db.is_postgres(conn):
        return _claim_next_job_postgres(conn, worker_id)
    return _claim_next_job_sqlite(conn, worker_id)


def _claim_next_job_sqlite(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT id FROM analysis_jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1")
    row = cur.fetchone()
    if row is None:
        return None
    job_id = row["id"]
    now = utcnow_iso()
    cur = db.execute(
        conn,
        "UPDATE analysis_jobs SET status = 'claimed', claimed_by = ?, claimed_at = ? WHERE id = ? AND status = 'queued'",
        (worker_id, now, job_id),
    )
    conn.commit()
    if cur.rowcount == 0:
        return None  # lost the race between our SELECT and our UPDATE.
    return get_job(conn, job_id)


def _claim_next_job_postgres(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    # Same query verified by backend/verify_postgres.sh's step [5] (a real
    # two-session concurrent race, exactly one winner) - RETURNING * in
    # place of a hardcoded column list so this never drifts from the
    # table's actual columns.
    now = utcnow_iso()
    cur = db.execute(
        conn,
        "UPDATE analysis_jobs SET status = 'claimed', claimed_by = ?, claimed_at = ? "
        "WHERE id = (SELECT id FROM analysis_jobs WHERE status = 'queued' "
        "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
        (worker_id, now),
    )
    row = cur.fetchone()
    conn.commit()
    return db.normalize_row(row)


_VALID_TRANSITIONS = {
    "queued": {"claimed", "canceled"},
    "claimed": {"running", "queued", "canceled"},  # "queued" covers a reaper requeueing a dead worker's claim.
    "running": {"succeeded", "failed"},
}


def transition_job_status(
    conn: Any,
    job_id: str,
    from_status: str,
    to_status: str,
    error: Optional[str] = None,
) -> bool:
    """Idempotent state transition: succeeds (returns True) only if the
    job is CURRENTLY in from_status; returns False (never raises) for a
    stale/duplicate/out-of-order call - the same conditional-UPDATE-and-
    check-rowcount pattern claim_next_job() uses. Rejects a transition
    the state machine does not allow (_VALID_TRANSITIONS) before ever
    touching the database, so an invalid transition is a programming
    error (RepositoryError), never a silently-accepted no-op."""
    if to_status not in _VALID_TRANSITIONS.get(from_status, set()):
        raise RepositoryError("invalid job transition %r -> %r" % (from_status, to_status))
    now = utcnow_iso()
    timestamp_column = {"running": "started_at", "succeeded": "completed_at", "failed": "completed_at"}.get(to_status)
    if timestamp_column:
        cur = db.execute(
            conn,
            "UPDATE analysis_jobs SET status = ?, %s = ?, last_error = COALESCE(?, last_error), "
            "attempt_count = attempt_count + CASE WHEN ? = 'failed' THEN 1 ELSE 0 END "
            "WHERE id = ? AND status = ?" % timestamp_column,
            (to_status, now, error, to_status, job_id, from_status),
        )
    else:
        cur = db.execute(
            conn,
            "UPDATE analysis_jobs SET status = ?, last_error = COALESCE(?, last_error) WHERE id = ? AND status = ?",
            (to_status, error, job_id, from_status),
        )
    conn.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Reports, audit log, webhook idempotency
# ---------------------------------------------------------------------------

def record_report(
    conn: Any,
    job_id: str,
    workspace_id: str,
    storage_ref: str,
    score_status: str,
    score: Optional[int] = None,
    risk_band: Optional[str] = None,
) -> str:
    if score_status not in ("computed", "not_computed"):
        raise RepositoryError("score_status must be computed/not_computed, got %r" % score_status)
    report_id = new_id()
    db.execute(
        conn,
        "INSERT INTO reports (id, job_id, workspace_id, storage_ref, score_status, score, risk_band, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (report_id, job_id, workspace_id, storage_ref, score_status, score, risk_band, utcnow_iso()),
    )
    conn.commit()
    return report_id


def append_audit_event(
    conn: Any,
    workspace_id: Optional[str],
    actor_user_id: Optional[str],
    event_type: str,
    metadata: str = "{}",
) -> str:
    if not isinstance(event_type, str) or not event_type.strip():
        raise RepositoryError("event_type must be a non-empty string")
    event_id = new_id()
    db.execute(
        conn,
        "INSERT INTO audit_events (id, workspace_id, actor_user_id, event_type, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (event_id, workspace_id, actor_user_id, event_type, metadata, utcnow_iso()),
    )
    conn.commit()
    return event_id


def record_webhook_event(conn: Any, event_id: str, event_type: str) -> bool:
    """Returns True if this is the first time event_id has been seen
    (caller should process it), or False if it was already recorded
    (caller must skip processing - a duplicate Stripe webhook delivery,
    never a reason to double-grant/double-charge). Never raises for a
    duplicate; that is the expected, normal outcome this function exists
    to detect cheaply."""
    try:
        db.execute(
            conn,
            "INSERT INTO webhook_events (id, event_type, received_at) VALUES (?, ?, ?)",
            (event_id, event_type, utcnow_iso()),
        )
        conn.commit()
        return True
    except db.integrity_error_class(conn):
        conn.rollback()
        return False
