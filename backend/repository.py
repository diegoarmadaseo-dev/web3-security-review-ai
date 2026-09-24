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
from datetime import datetime, timedelta, timezone
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
    stripe_event_created_at: Optional[str] = None,
) -> str:
    """stripe_event_created_at (docs/decisiones.md D-077 follow-up,
    Phase 3 webhook hardening) establishes the ordering baseline this
    row's FUTURE updates are checked against - see
    update_entitlement_status()'s own docstring. Optional/defaults to
    None for callers that don't have a Stripe event to attribute this
    creation to (e.g. existing tests) - a NULL baseline is treated as
    "no provenance yet, any event supersedes it", never as a reason to
    reject a legitimate first update."""
    entitlement_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO entitlements "
        "(id, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, stripe_event_created_at, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entitlement_id, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, stripe_event_created_at, now, now),
    )
    conn.commit()
    return entitlement_id


def update_entitlement_status(
    conn: Any,
    workspace_id: str,
    status: str,
    current_period_end: Optional[str] = None,
    stripe_event_created_at: Optional[str] = None,
) -> bool:
    """Returns True if a row was updated, False if this workspace has no
    entitlement row yet (caller must create one via create_entitlement()
    first) OR - Phase 3 webhook hardening, docs/decisiones.md D-077
    follow-up - the incoming stripe_event_created_at is stale/tied
    against the row's own stored value and was correctly ignored. Both
    "no row" and "stale, ignored" report False on purpose: a caller like
    backend/http_app.py's _upsert_entitlement() that needs to tell them
    apart (to decide whether to fall back to create_entitlement()) must
    check existence itself first via get_entitlement_by_workspace() -
    this function alone cannot and should not guess which case applies.

    ORDERING RULE (Stripe explicitly documents that webhook delivery is
    at-least-once and NOT guaranteed in order): when
    stripe_event_created_at is given, the update is applied ONLY if the
    row has no baseline yet (stripe_event_created_at IS NULL) or the
    incoming value is STRICTLY greater than the stored one - a tie is
    deliberately treated as NOT newer (rejected), the simplest
    deterministic tie-break that requires no further guessing about
    which of two same-second events is "really" later. When
    stripe_event_created_at is omitted (None), no ordering check is
    applied at all (the pre-Phase-3-hardening behavior) - existing
    callers that never had a Stripe event to attribute an update to
    (there are none in this codebase today outside tests) keep working
    unchanged."""
    if stripe_event_created_at is None:
        cur = db.execute(
            conn,
            "UPDATE entitlements SET status = ?, current_period_end = COALESCE(?, current_period_end), updated_at = ? WHERE workspace_id = ?",
            (status, current_period_end, utcnow_iso(), workspace_id),
        )
    else:
        cur = db.execute(
            conn,
            "UPDATE entitlements SET status = ?, current_period_end = COALESCE(?, current_period_end), "
            "stripe_event_created_at = ?, updated_at = ? "
            "WHERE workspace_id = ? AND (stripe_event_created_at IS NULL OR stripe_event_created_at < ?)",
            (status, current_period_end, stripe_event_created_at, utcnow_iso(), workspace_id, stripe_event_created_at),
        )
    conn.commit()
    return cur.rowcount > 0


def get_entitlement_by_workspace(conn: Any, workspace_id: str) -> Optional[Dict[str, Any]]:
    """Returns this workspace's entitlement row, or None if it has never
    completed a checkout (an expected, normal state - e.g. every
    freshly-created workspace - never an error)."""
    cur = db.execute(conn, "SELECT * FROM entitlements WHERE workspace_id = ?", (workspace_id,))
    return db.normalize_row(cur.fetchone())


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


def get_contract(conn: Any, contract_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT * FROM contracts WHERE id = ?", (contract_id,))
    return db.normalize_row(cur.fetchone())


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


def get_job_by_idempotency_key(conn: Any, idempotency_key: str) -> Optional[Dict[str, Any]]:
    """Phase 4: lets a caller that hit enqueue_job()'s idempotency_key
    UNIQUE constraint look up the job that already owns it, so a
    duplicate submission returns the SAME job rather than an error - see
    backend/http_app.py's _handle_job_submit()."""
    cur = db.execute(conn, "SELECT * FROM analysis_jobs WHERE idempotency_key = ?", (idempotency_key,))
    return db.normalize_row(cur.fetchone())


LEASE_DURATION_SECONDS = 15 * 60  # generous for one analysis job; matches auth.py's own "short-lived by design" philosophy at job scale, not login-token scale.


def claim_next_job(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    """Claims the oldest still-queued job for worker_id, or returns None
    if there is nothing queued OR another claimant won the race for the
    one job this call saw. Dispatches to a genuinely different query per
    backend - this is the one place in this module that cannot be reduced
    to a placeholder/value translation (see backend/db.py's docstring):
    Postgres gets the real, verified `FOR UPDATE SKIP LOCKED` claim query;
    SQLite keeps its existing conditional-UPDATE-and-check-rowcount
    pattern, which is the only claim safety SQLite's locking model can
    express (see schema_sqlite.sql's docstring). Stamps lease_expires_at
    (Phase 4) so a crashed/hung worker's claim can later be found and
    reclaimed by reap_expired_jobs() - see that function's docstring."""
    if db.is_postgres(conn):
        return _claim_next_job_postgres(conn, worker_id)
    return _claim_next_job_sqlite(conn, worker_id)


def _lease_expiry(now: datetime) -> str:
    return (now + timedelta(seconds=LEASE_DURATION_SECONDS)).isoformat()


def _claim_next_job_sqlite(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT id FROM analysis_jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1")
    row = cur.fetchone()
    if row is None:
        return None
    job_id = row["id"]
    now = datetime.now(timezone.utc)
    cur = db.execute(
        conn,
        "UPDATE analysis_jobs SET status = 'claimed', claimed_by = ?, claimed_at = ?, lease_expires_at = ? WHERE id = ? AND status = 'queued'",
        (worker_id, now.isoformat(), _lease_expiry(now), job_id),
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
    now = datetime.now(timezone.utc)
    cur = db.execute(
        conn,
        "UPDATE analysis_jobs SET status = 'claimed', claimed_by = ?, claimed_at = ?, lease_expires_at = ? "
        "WHERE id = (SELECT id FROM analysis_jobs WHERE status = 'queued' "
        "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
        (worker_id, now.isoformat(), _lease_expiry(now)),
    )
    row = cur.fetchone()
    conn.commit()
    return db.normalize_row(row)


_MAX_JOB_ATTEMPTS = 3  # matches analyze_pipeline.py's own documented "3 attempts total" cap - see backend/llm_client.py.


def reap_expired_jobs(conn: Any, max_attempts: int = _MAX_JOB_ATTEMPTS) -> Dict[str, int]:
    """Finds every claimed/running job whose lease has expired (a
    crashed or hung worker never reported completion in time - Phase 4)
    and either requeues it (attempt_count below max_attempts) or marks
    it permanently failed (attempts exhausted). Both branches are plain
    conditional UPDATEs keyed on the SAME status+lease_expires_at WHERE
    clause already proven safe throughout this module: if the worker
    that actually owns the job finishes (any terminal transition) at the
    last moment, its UPDATE and this one cannot both match the same row
    - whichever commits first wins, the other's WHERE clause no longer
    matches, exactly claim_next_job()'s own race safety. Requeuing
    counts as a failed attempt (attempt_count + 1) - a job that never
    stops timing out must still eventually hit max_attempts, or it could
    loop through the queue forever. Returns {"requeued": n, "failed": n}
    for the caller (backend/worker_supervisor.py) to log."""
    now = utcnow_iso()
    requeue_cur = db.execute(
        conn,
        "UPDATE analysis_jobs SET status = 'queued', claimed_by = NULL, claimed_at = NULL, lease_expires_at = NULL, "
        "attempt_count = attempt_count + 1 "
        "WHERE status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ? AND attempt_count < ?",
        (now, max_attempts),
    )
    conn.commit()
    fail_cur = db.execute(
        conn,
        "UPDATE analysis_jobs SET status = 'failed', completed_at = ?, lease_expires_at = NULL, "
        "attempt_count = attempt_count + 1, "
        "last_error = 'lease expired: worker did not report completion within the allotted time' "
        "WHERE status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ? AND attempt_count >= ?",
        (now, now, max_attempts),
    )
    conn.commit()
    return {"requeued": requeue_cur.rowcount, "failed": fail_cur.rowcount}


# ---------------------------------------------------------------------------
# Workspace spend control (Phase 4 - a units ledger, never money/billing;
# Stripe/entitlements remain Phase 3 and are untouched by this section)
# ---------------------------------------------------------------------------

# Placeholders pending real per-plan business tiering (same caveat already
# disclosed for Phase 3's own unset prices/currency/trial values) - a flat
# default ceiling and a relative per-mode cost, not tied to any real
# dollar figure.
DEFAULT_BUDGET_LIMIT_UNITS = 100
JOB_MODE_BUDGET_COST = {"quick": 1, "standard": 2, "pro": 4}


def get_workspace_budget(conn: Any, workspace_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT * FROM workspace_budgets WHERE workspace_id = ?", (workspace_id,))
    return db.normalize_row(cur.fetchone())


def _ensure_workspace_budget_row(conn: Any, workspace_id: str, default_limit_units: int) -> None:
    """Lazily creates a workspace's budget row on first use, exactly the
    same try-INSERT/catch-conflict pattern record_webhook_event() already
    uses for a different table - a concurrent double-create is expected
    and harmless (the loser's row already exists, nothing to do)."""
    try:
        now = utcnow_iso()
        db.execute(
            conn,
            "INSERT INTO workspace_budgets (workspace_id, period_start, limit_units, updated_at) VALUES (?, ?, ?, ?)",
            (workspace_id, now, default_limit_units, now),
        )
        conn.commit()
    except db.integrity_error_class(conn):
        conn.rollback()


def reserve_workspace_budget(conn: Any, workspace_id: str, units: int, default_limit_units: int = DEFAULT_BUDGET_LIMIT_UNITS) -> bool:
    """Atomically reserves `units` against this workspace's ceiling
    BEFORE the LLM call that would spend them - the same conditional-
    UPDATE-and-check-rowcount claim pattern used throughout this module
    (claim_next_job(), record_webhook_event()'s retry reclaim). Returns
    True if the reservation fits (reserved+consumed+units <= limit_units,
    checked in the WHERE clause itself, so two concurrent callers racing
    for the last few units can never both succeed), False if it would
    exceed the ceiling - the caller (backend/llm_client.py) must treat
    False as "budget exhausted", never retry the same reservation in a
    loop. Creates the workspace's budget row on first use."""
    _ensure_workspace_budget_row(conn, workspace_id, default_limit_units)
    cur = db.execute(
        conn,
        "UPDATE workspace_budgets SET reserved_units = reserved_units + ?, updated_at = ? "
        "WHERE workspace_id = ? AND reserved_units + consumed_units + ? <= limit_units",
        (units, utcnow_iso(), workspace_id, units),
    )
    conn.commit()
    return cur.rowcount > 0


def consume_reserved_workspace_budget(conn: Any, workspace_id: str, units: int) -> None:
    """Converts a prior successful reservation into actual spend - called
    only after the LLM call this units figure was reserved for actually
    happened. The workspace_budgets_non_negative CHECK constraint is the
    real backstop against a caller bug consuming more than was reserved
    (see migration 0005's docstring) - this function trusts its own
    caller the same way update_entitlement_status() trusts its own."""
    db.execute(
        conn,
        "UPDATE workspace_budgets SET reserved_units = reserved_units - ?, consumed_units = consumed_units + ?, updated_at = ? WHERE workspace_id = ?",
        (units, units, utcnow_iso(), workspace_id),
    )
    conn.commit()


def release_workspace_budget(conn: Any, workspace_id: str, units: int) -> None:
    """Gives back a reservation that was never spent - a job that failed,
    was canceled, or never reached the LLM call at all. Same CHECK-
    constraint backstop as consume_reserved_workspace_budget()."""
    db.execute(
        conn,
        "UPDATE workspace_budgets SET reserved_units = reserved_units - ?, updated_at = ? WHERE workspace_id = ?",
        (units, utcnow_iso(), workspace_id),
    )
    conn.commit()


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
    """Returns True if the caller should (re)process event_id now, False
    if it must be skipped. Three cases, in order (Phase 3 webhook
    hardening, docs/decisiones.md D-077 follow-up - the original version
    of this function only ever handled the first two):

      1. First-ever delivery: the INSERT succeeds outright - True.
      2. A row already exists and previously SUCCEEDED
         (processed_at IS NOT NULL): never reprocessed - False. This is
         the only state "duplicate" is allowed to mean; see
         mark_webhook_event_processed()'s docstring on why success is the
         ONLY thing that permanently closes an event out.
      3. A row already exists but never succeeded (processed_at IS NULL
         - either a prior attempt FAILED and left processing_error set,
         or a concurrent attempt is mid-flight right now with
         processing_error still NULL): the UPDATE below attempts to
         atomically RECLAIM it for a retry, but its WHERE clause only
         matches the "previously failed" case (processing_error IS NOT
         NULL) - a concurrently in-flight attempt (processing_error IS
         NULL, nothing to flip yet) is correctly left alone, so two
         callers racing to retry the SAME failed event can never both
         win: the UPDATE clears processing_error to NULL as PART of
         claiming it, so a second, concurrent identical UPDATE re-reads
         processing_error as already NULL once the first one commits and
         correctly matches zero rows.

    Never raises for a duplicate or a losing race; both are expected,
    normal outcomes this function exists to detect cheaply."""
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
    cur = db.execute(
        conn,
        "UPDATE webhook_events SET processing_error = NULL WHERE id = ? AND processed_at IS NULL AND processing_error IS NOT NULL",
        (event_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def mark_webhook_event_processed(conn: Any, event_id: str, error: Optional[str] = None) -> None:
    """Records the outcome of processing a webhook event this call site
    already confirmed (via record_webhook_event() returning True) it
    owns. error=None for success: sets processed_at, the ONLY thing that
    permanently closes an event.id out of future reprocessing (see
    record_webhook_event()'s docstring) - a non-None error records the
    failure reason but deliberately leaves processed_at NULL, so the
    event remains eligible for a future retry to reclaim (Phase 3
    webhook hardening, docs/decisiones.md D-077 follow-up - the previous
    version of this function always set processed_at regardless of
    success/failure, which silently made every failure permanent; see
    that follow-up's decision entry for the concrete Postgres transaction-
    abort bug this caused and how it was found).

    On the FAILURE path specifically, the caller (backend/http_app.py's
    _handle_billing_webhook) is expected to have already called
    conn.rollback() before this runs - on Postgres, ANY error inside a
    transaction aborts the WHOLE transaction until an explicit ROLLBACK
    (unlike SQLite), so writing this recovery row on the SAME,
    still-aborted connection would itself raise InFailedSqlTransaction,
    permanently losing the very failure this call exists to record. This
    function does not call rollback() itself because it has no way to
    know whether the caller's transaction was ever actually aborted
    (SQLite never aborts it, and even on Postgres not every exception
    involves the database) - an unconditional rollback here would be
    correct on Postgres but silently discard an unrelated, still-good
    write on SQLite, so the caller (which knows exactly what failed and
    why) owns that decision."""
    if error is None:
        db.execute(conn, "UPDATE webhook_events SET processed_at = ?, processing_error = NULL WHERE id = ?", (utcnow_iso(), event_id))
    else:
        db.execute(conn, "UPDATE webhook_events SET processing_error = ? WHERE id = ?", (error, event_id))
    conn.commit()
