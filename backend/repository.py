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


def get_workspace(conn: Any, workspace_id: str) -> Optional[Dict[str, Any]]:
    cur = db.execute(conn, "SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
    return db.normalize_row(cur.fetchone())


def list_workspaces_by_user(conn: Any, user_id: str) -> List[Dict[str, Any]]:
    """Every workspace user_id is a MEMBER of (owner/admin/member alike),
    resolved through workspace_members - never workspaces.owner_user_id
    alone, since a user can belong to a workspace they don't own (see
    add_workspace_member()). Each row carries its own membership_role
    alongside the workspace's own columns, so a caller (backend/
    http_app.py) never needs a second query to know what the caller can
    do there. Deterministic order (created_at then id, the same tiebreak
    list_jobs_by_workspace()/list_reports_by_workspace() below use) -
    never left to whatever order the database happens to return."""
    cur = db.execute(
        conn,
        "SELECT w.*, wm.role AS membership_role FROM workspaces w "
        "JOIN workspace_members wm ON wm.workspace_id = w.id "
        "WHERE wm.user_id = ? ORDER BY w.created_at, w.id",
        (user_id,),
    )
    return [db.normalize_row(row) for row in cur.fetchall()]


def list_workspace_members(conn: Any, workspace_id: str) -> List[Dict[str, Any]]:
    """Every membership row for workspace_id (user_id + role + created_at)
    - used by backend/retention.py's delete_workspace_data() to find
    every user who needs their membership removed as part of a workspace
    deletion; not tenant-scoping-sensitive itself (workspace_id is
    already a WHERE clause, and this returns no cross-workspace data)."""
    cur = db.execute(conn, "SELECT * FROM workspace_members WHERE workspace_id = ?", (workspace_id,))
    return [db.normalize_row(row) for row in cur.fetchall()]


def mark_workspace_deleted(conn: Any, workspace_id: str) -> bool:
    """Idempotent, same conditional-UPDATE pattern as
    mark_contract_deleted()/mark_report_purged() above."""
    cur = db.execute(conn, "UPDATE workspaces SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL", (utcnow_iso(), utcnow_iso(), workspace_id))
    conn.commit()
    return cur.rowcount > 0


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
    billing_interval: Optional[str] = None,
) -> str:
    """stripe_event_created_at (docs/decisiones.md D-077 follow-up,
    Phase 3 webhook hardening) establishes the ordering baseline this
    row's FUTURE updates are checked against - see
    update_entitlement_status()'s own docstring. Optional/defaults to
    None for callers that don't have a Stripe event to attribute this
    creation to (e.g. existing tests) - a NULL baseline is treated as
    "no provenance yet, any event supersedes it", never as a reason to
    reject a legitimate first update.

    billing_interval ('monthly'/'annual', migrations/0007_billing_interval.sql,
    docs/decisiones.md D-086) is likewise optional/None - a checkout.
    session.completed event that predates this column's own deploy, or a
    test that doesn't care about interval, leaves it NULL rather than
    guessing one. The caller (backend/http_app.py's webhook dispatch) is
    the only place allowed to derive a real value, and only ever from the
    Stripe event's own metadata - see that module's own docstring on why
    interval, like plan, can never be client-supplied."""
    entitlement_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO entitlements "
        "(id, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, stripe_event_created_at, billing_interval, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entitlement_id, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, stripe_event_created_at, billing_interval, now, now),
    )
    conn.commit()
    return entitlement_id


def update_entitlement_status(
    conn: Any,
    workspace_id: str,
    status: str,
    current_period_end: Optional[str] = None,
    stripe_event_created_at: Optional[str] = None,
    billing_interval: Optional[str] = None,
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
    unchanged.

    billing_interval (D-086) uses the same COALESCE-on-None pattern as
    current_period_end - a status-only update (e.g. invoice.paid, which
    carries no interval of its own) never wipes out a previously-recorded
    value."""
    if stripe_event_created_at is None:
        cur = db.execute(
            conn,
            "UPDATE entitlements SET status = ?, current_period_end = COALESCE(?, current_period_end), "
            "billing_interval = COALESCE(?, billing_interval), updated_at = ? WHERE workspace_id = ?",
            (status, current_period_end, billing_interval, utcnow_iso(), workspace_id),
        )
    else:
        cur = db.execute(
            conn,
            "UPDATE entitlements SET status = ?, current_period_end = COALESCE(?, current_period_end), "
            "billing_interval = COALESCE(?, billing_interval), "
            "stripe_event_created_at = ?, updated_at = ? "
            "WHERE workspace_id = ? AND (stripe_event_created_at IS NULL OR stripe_event_created_at < ?)",
            (status, current_period_end, billing_interval, stripe_event_created_at, utcnow_iso(), workspace_id, stripe_event_created_at),
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


def list_workspace_contracts(conn: Any, workspace_id: str) -> List[Dict[str, Any]]:
    """Every non-deleted contract belonging to workspace_id - used by
    backend/retention.py's delete_workspace_data() (an explicit, whole-
    workspace deletion), distinct from list_expired_contracts() below
    (age-based, across every workspace uniformly)."""
    cur = db.execute(conn, "SELECT * FROM contracts WHERE workspace_id = ? AND deleted_at IS NULL", (workspace_id,))
    return [db.normalize_row(row) for row in cur.fetchall()]


def list_expired_contracts(conn: Any, cutoff_iso: str) -> List[Dict[str, Any]]:
    """Every contract created before cutoff_iso and not already marked
    deleted - see backend/retention.py, the one caller. cutoff_iso is
    always supplied by the caller (never computed here), the same
    pure-function-of-its-inputs discipline utcnow_iso()'s own callers
    already follow elsewhere in this module."""
    cur = db.execute(conn, "SELECT * FROM contracts WHERE created_at < ? AND deleted_at IS NULL", (cutoff_iso,))
    return [db.normalize_row(row) for row in cur.fetchall()]


def mark_contract_deleted(conn: Any, contract_id: str) -> bool:
    """Idempotent: returns True only if this call actually set
    deleted_at (WHERE deleted_at IS NULL) - a second call on an already-
    deleted contract returns False, never raises, same conditional-
    UPDATE-and-check-rowcount pattern this module uses throughout."""
    cur = db.execute(conn, "UPDATE contracts SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL", (utcnow_iso(), contract_id))
    conn.commit()
    return cur.rowcount > 0


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
    """ADMISSION CONTROL / QUEUE FAIRNESS: ensures workspace_id's
    workspace_queue_state row exists in the SAME transaction as the job
    INSERT below, before it - a job must never reach 'queued' while its
    workspace has no fairness-cursor row, or claim_next_job()'s own INNER
    JOIN would silently exclude that workspace from ever being selected
    (a self-inflicted, permanent starvation this function alone can
    prevent). "INSERT ... ON CONFLICT DO NOTHING" (not a try/INSERT-
    except-IntegrityError pattern like reserve_workspace_budget()'s own
    _ensure_workspace_budget_row()) deliberately never raises for a
    concurrent duplicate - an IntegrityError here would poison the whole
    Postgres transaction (see this codebase's own established finding on
    that), which would wrongly also lose the job INSERT that follows in
    this SAME transaction. Same ON CONFLICT syntax on both backends - no
    placeholder-style translation exists for it in backend/db.py, and
    none is needed; both engines accept it identically."""
    if mode not in ("quick", "standard", "pro"):
        raise RepositoryError("mode must be one of quick/standard/pro, got %r" % mode)
    job_id = new_id()
    now = utcnow_iso()
    db.execute(
        conn,
        "INSERT INTO workspace_queue_state (workspace_id, created_at, last_claimed_at) VALUES (?, ?, NULL) "
        "ON CONFLICT (workspace_id) DO NOTHING",
        (workspace_id, now),
    )
    db.execute(
        conn,
        "INSERT INTO analysis_jobs (id, workspace_id, contract_id, requested_by_user_id, mode, idempotency_key, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (job_id, workspace_id, contract_id, requested_by_user_id, mode, idempotency_key, now),
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


DEFAULT_LIST_LIMIT = 20
MAX_LIST_LIMIT = 100  # Phase 5 pagination bound - see list_jobs_by_workspace()/list_reports_by_workspace().
JOB_STATUSES = ("queued", "claimed", "running", "succeeded", "failed", "canceled")  # analysis_jobs' own CHECK-constrained values, named once here so backend/http_app.py never hardcodes a second copy for its own filter validation.


def list_jobs_by_workspace(
    conn: Any,
    workspace_id: str,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Tenant-scoped by construction (workspace_id is a WHERE clause, not
    a filter applied after a broader query) - the caller must still have
    already resolved workspace_id against the authenticated user via
    tenant_scope, same trust boundary as every other function in this
    module (see module docstring). status, if given, must already be one
    of JOB_STATUSES - this raises RepositoryError for anything else
    rather than silently returning zero rows for a typo'd filter.
    Deterministic order: created_at DESC (newest first, the useful order
    for a history view) then id DESC as a tiebreaker - two jobs created
    within the same wall-clock instant (this module's own timestamps
    have real-world, not database-sequence, resolution) must still sort
    identically on every call, including across pages."""
    if not (1 <= limit <= MAX_LIST_LIMIT):
        raise RepositoryError("limit must be between 1 and %d, got %r" % (MAX_LIST_LIMIT, limit))
    if offset < 0:
        raise RepositoryError("offset must be >= 0, got %r" % (offset,))
    if status is not None and status not in JOB_STATUSES:
        raise RepositoryError("status must be one of %r, got %r" % (JOB_STATUSES, status))
    if status is None:
        cur = db.execute(
            conn,
            "SELECT * FROM analysis_jobs WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (workspace_id, limit, offset),
        )
    else:
        cur = db.execute(
            conn,
            "SELECT * FROM analysis_jobs WHERE workspace_id = ? AND status = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (workspace_id, status, limit, offset),
        )
    return [db.normalize_row(row) for row in cur.fetchall()]


LEASE_DURATION_SECONDS = 15 * 60  # generous for one analysis job; matches auth.py's own "short-lived by design" philosophy at job scale, not login-token scale.

# Admission control / queue fairness (read-only design audit, this phase's
# own docstring below) - retry backoff for reap_expired_jobs()'s requeue
# branch. Growing (doubles per prior attempt) so a job that keeps timing
# out gives progressively more room to genuinely new work, capped so the
# growth never becomes unbounded - though in practice _MAX_JOB_ATTEMPTS=3
# already bounds it to at most two requeue backoffs (5s, 10s) before a
# third failure goes to the terminal 'failed' branch instead, which never
# sets next_eligible_at at all (a terminal job is never a claim candidate
# again). The cap exists as belt-and-suspenders in case _MAX_JOB_ATTEMPTS
# is ever raised - not something the current values alone rely on.
QUEUE_FAIRNESS_BACKOFF_BASE_SECONDS = 5
QUEUE_FAIRNESS_BACKOFF_MAX_SECONDS = 60


def _compute_next_eligible_at(now: datetime, attempt_count_before_requeue: int) -> str:
    backoff = min(
        QUEUE_FAIRNESS_BACKOFF_BASE_SECONDS * (2 ** attempt_count_before_requeue),
        QUEUE_FAIRNESS_BACKOFF_MAX_SECONDS,
    )
    return (now + timedelta(seconds=backoff)).isoformat()


def claim_next_job(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    """Claims one job for worker_id, or returns None if there is nothing
    eligible OR another claimant won the race for the one job this call
    saw. Dispatches to a genuinely different query per backend - this is
    the one place in this module that cannot be reduced to a placeholder/
    value translation (see backend/db.py's docstring). Stamps
    lease_expires_at (Phase 4) so a crashed/hung worker's claim can later
    be found and reclaimed by reap_expired_jobs() - see that function's
    docstring.

    ADMISSION CONTROL / QUEUE FAIRNESS (read-only design audit, post reap-
    atomicity-fix and worker-fencing hardening): a confirmed audit found
    plain "oldest queued job globally" selection let one workspace occupy
    every idle worker while a different workspace's job waited, with no
    bound - and reap_expired_jobs()'s requeue never touched created_at,
    so a repeatedly-expiring job kept its original (favorable) FIFO
    position ahead of genuinely newer jobs from other workspaces. This
    function now selects the oldest ELIGIBLE job (next_eligible_at IS
    NULL OR already past - see reap_expired_jobs()'s own docstring for
    who sets it and why) belonging to the LEAST RECENTLY CLAIMED eligible
    workspace (workspace_queue_state.last_claimed_at), never the
    globally-oldest job outright. Deterministic tie-break chain, in
    order: workspace last_claimed_at (NULL = never claimed, sorts first
    on both backends - see the SQLite function's own note on why no
    explicit NULLS FIRST is written there), that workspace's OWN
    workspace_queue_state.created_at (breaks ties between two workspaces
    both never claimed), the job's own created_at, and finally the job's
    own id as a last-resort tie-break for a genuine created_at
    collision - never relying on timestamp resolution alone. Budget
    (workspace_budgets) and plan/entitlement are NEVER inputs to this
    ordering - fairness here is completely independent of both, by
    design (see the read-only design audit for why)."""
    if db.is_postgres(conn):
        return _claim_next_job_postgres(conn, worker_id)
    return _claim_next_job_sqlite(conn, worker_id)


def _lease_expiry(now: datetime) -> str:
    return (now + timedelta(seconds=LEASE_DURATION_SECONDS)).isoformat()


_CLAIM_CANDIDATE_ORDER_SQL = (
    "s.last_claimed_at ASC, s.created_at ASC, j.created_at ASC, j.id ASC"
)


def _claim_next_job_sqlite(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    """No FOR UPDATE/SKIP LOCKED exists in SQLite. An explicit BEGIN
    IMMEDIATE (rather than sqlite3's own default DEFERRED transaction)
    acquires the RESERVED write lock BEFORE the fairness-ordered SELECT
    below even runs - closing the exact TOCTOU window a plain SELECT-
    then-conditional-UPDATE would leave open (two concurrent callers both
    reading the SAME, not-yet-updated workspace_queue_state.
    last_claimed_at before either commits - the gap a dedicated
    concurrency review of the first draft of this design found and this
    function was corrected to close). A second concurrent caller's own
    BEGIN IMMEDIATE blocks (or raises sqlite3.OperationalError under a
    zero busy_timeout) until this one commits or rolls back - full
    serialization of EVERY claim against every other, not the
    per-workspace granularity the Postgres path achieves; an accepted
    trade-off given SQLite's own single-writer model, and given
    production never actually uses this path - backend/main.py's
    _connect_fn() is hardcoded to db.connect_postgres(), never a silent
    SQLite fallback (that module's own docstring). This path is
    test/dev-only, not the concurrent-production story.

    No explicit NULLS FIRST in the ORDER BY below (unlike the Postgres
    version) - SQLite's own default null-ordering for ASC already sorts
    NULL as smaller than any other value, so a never-claimed workspace's
    NULL last_claimed_at already sorts first without needing (and without
    SQLite versions bundled with Python 3.8-3.9 even supporting) that
    keyword - Postgres's own default is the OPPOSITE (NULLS LAST for
    ASC), which is exactly why that version spells it out explicitly.
    Never assume the two are equivalent."""
    db.execute(conn, "BEGIN IMMEDIATE")
    try:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        cur = db.execute(
            conn,
            "SELECT j.id, j.workspace_id FROM analysis_jobs j "
            "JOIN workspace_queue_state s ON s.workspace_id = j.workspace_id "
            "WHERE j.status = 'queued' AND (j.next_eligible_at IS NULL OR j.next_eligible_at <= ?) "
            "ORDER BY " + _CLAIM_CANDIDATE_ORDER_SQL + " LIMIT 1",
            (now_iso,),
        )
        row = cur.fetchone()
        if row is None:
            conn.commit()
            return None
        job_id, workspace_id = row["id"], row["workspace_id"]
        cur = db.execute(
            conn,
            "UPDATE analysis_jobs SET status = 'claimed', claimed_by = ?, claimed_at = ?, lease_expires_at = ? "
            "WHERE id = ? AND status = 'queued'",
            (worker_id, now_iso, _lease_expiry(now), job_id),
        )
        if cur.rowcount == 0:
            # Should not happen under BEGIN IMMEDIATE's full serialization -
            # kept anyway for the same CAS discipline every other claim/
            # transition function in this module already applies.
            conn.commit()
            return None
        db.execute(
            conn,
            "UPDATE workspace_queue_state SET last_claimed_at = ? WHERE workspace_id = ?",
            (now_iso, workspace_id),
        )
        conn.commit()  # the ONE commit - job claim and fairness cursor land together, or neither does.
        return get_job(conn, job_id)
    except Exception:
        conn.rollback()
        raise


def _claim_next_job_postgres(conn: Any, worker_id: str) -> Optional[Dict[str, Any]]:
    """FOR UPDATE OF s, j SKIP LOCKED (s = workspace_queue_state, j =
    analysis_jobs) - locking s, not just j, is what makes fairness itself
    safe under concurrency: it is the fix for a confirmed gap in this
    design's first draft, which only locked j and therefore let two
    concurrent claimers both select the SAME least-recently-served
    workspace's two DIFFERENT jobs (SKIP LOCKED on j alone only prevents
    two callers from picking the identical row, not two rows from the
    identical workspace). Locking s means a workspace whose row a
    concurrent caller already holds becomes entirely unavailable to this
    one (every job joined to that s row is excluded by SKIP LOCKED, since
    the join is 1:1 on workspace_id) - this caller's own ORDER BY then
    naturally falls through to the next least-recently-served ELIGIBLE
    workspace instead, never blocking. FOR UPDATE OF j is kept alongside
    (defense in depth, matching the exclusivity the pre-fairness version
    of this query already had). Different workspaces' own state rows are
    independent - two callers converging on two different workspaces
    never contend with each other at all; no single shared cursor row
    exists anywhere in this design.

    last_claimed_at is updated on the SAME connection, before the ONE
    commit below - no other transaction can observe this workspace's
    fairness state as anything other than "still locked by an in-flight
    claim" or "already reflects this claim", never a stale in-between
    value, closing the exact race a design review's first pass found."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    cur = db.execute(
        conn,
        "WITH candidate AS ("
        "  SELECT j.id, j.workspace_id FROM analysis_jobs j "
        "  JOIN workspace_queue_state s ON s.workspace_id = j.workspace_id "
        "  WHERE j.status = 'queued' AND (j.next_eligible_at IS NULL OR j.next_eligible_at <= ?) "
        "  ORDER BY s.last_claimed_at ASC NULLS FIRST, s.created_at ASC, j.created_at ASC, j.id ASC "
        "  FOR UPDATE OF s, j SKIP LOCKED LIMIT 1"
        ") "
        "UPDATE analysis_jobs SET status = 'claimed', claimed_by = ?, claimed_at = ?, lease_expires_at = ? "
        "FROM candidate WHERE analysis_jobs.id = candidate.id "
        "RETURNING analysis_jobs.*",
        (now_iso, worker_id, now_iso, _lease_expiry(now)),
    )
    row = cur.fetchone()
    if row is not None:
        db.execute(
            conn,
            "UPDATE workspace_queue_state SET last_claimed_at = ? WHERE workspace_id = ?",
            (now_iso, row["workspace_id"]),
        )
    conn.commit()
    return db.normalize_row(row)


_MAX_JOB_ATTEMPTS = 3  # matches analyze_pipeline.py's own documented "3 attempts total" cap - see backend/llm_client.py.


def reap_expired_jobs(conn: Any, max_attempts: int = _MAX_JOB_ATTEMPTS) -> Dict[str, int]:
    """Finds every claimed/running job whose lease has expired (a
    crashed or hung worker never reported completion in time - Phase 4)
    and either requeues it (attempt_count below max_attempts) or marks
    it permanently failed (attempts exhausted). Returns
    {"requeued": n, "failed": n} for the caller (backend/
    worker_supervisor.py) to log - contract unchanged.

    BUDGET RECONCILIATION (fixes a confirmed leak): a worker process that
    dies while a job is 'running' never reaches claim_and_run_one_job()'s
    own consume_reserved_workspace_budget()/release_workspace_budget()
    call for the units it already reserved - this function used to leave
    that reservation orphaned in workspace_budgets forever, since
    DEFAULT_BUDGET_LIMIT_UNITS never resets on any cycle (see that
    constant's own comment). A job found in 'running' status here is an
    UNAMBIGUOUS signal that a reservation exists and is still
    outstanding: the only path into 'running' is claim_next_job() ->
    reserve_workspace_budget() returning True -> transition_job_status(
    claimed, running), with nothing else in between - if the reservation
    had failed, the job would be 'failed', never 'running'. This function
    now releases that job's exact JOB_MODE_BUDGET_COST[mode] units
    whenever it reaps a job found in 'running'.

    A job still found in 'claimed' (never reached 'running') is
    DELIBERATELY left alone budget-wise: reserve_workspace_budget() and
    the claimed->running transition are two separate commits with nothing
    atomic tying them together, so a crash in that narrow window can land
    on EITHER side of the reservation - a 'claimed' job here might have a
    real outstanding reservation, or might have none at all, and nothing
    in this schema (no per-job reservation flag - none was authorized for
    this fix) can tell the two apart without guessing. Under-releasing
    (leaving that rare, narrow-window reservation orphaned - the same
    class of leak this fix otherwise closes for the dominant 'running'
    case) and over-releasing (silently returning units to the ceiling
    that this job never actually reserved, corrupting a DIFFERENT job's
    still-real reservation in the same workspace) are not symmetric
    failure modes: the first only ever makes the ceiling too strict,
    never lets a workspace spend beyond it; the second would. This is the
    correct, honest boundary of what can be fixed without a schema
    change.

    RACE SAFETY (two reapers - e.g. two ROLE=worker processes - calling
    this concurrently, or a reaper racing the job's own still-alive owner
    finishing it for real at the last moment): identical in spirit to
    claim_next_job()'s own conditional-UPDATE-and-check-rowcount pattern,
    now applied per candidate row instead of in one bulk statement -
    releasing budget must be gated on "did MY update actually perform
    the transition", which a bulk UPDATE's aggregate rowcount cannot tell
    a caller per-row. Each candidate found by the initial SELECT is
    re-updated by id, re-checking the EXACT same status/lease_expires_at
    conditions that SELECT used; whichever caller's UPDATE lands first
    flips the row's status out of ('claimed', 'running'), so every other
    concurrent UPDATE for that same id matches zero rows - see the
    rowcount==0 branch below, an immediate rollback()+continue, exactly
    like repository.record_webhook_event()'s own losing-race path. This
    also covers the SELECT-to-UPDATE gap being crossed by the job's own
    real completion rather than another reaper: if the true owner
    finishes first, this function's UPDATE finds the row already
    'succeeded'/'failed' and skips it entirely, exactly as before.

    TRANSACTIONAL ATOMICITY (fixes a confirmed gap in an earlier version
    of this fix: the job's own UPDATE and the budget release used to be
    two independent commits - a process death in the narrow window
    between them left the job already 'queued'/'failed' with its
    reservation still orphaned FOREVER, since a job no longer in
    'claimed'/'running' is never a reap candidate again; the exact same
    permanent-leak shape this whole fix exists to close, just moved to a
    new trigger). Neither repo.connect() (SQLite - no isolation_level
    override, so it keeps sqlite3's own deferred-transaction default,
    never autocommit) nor db.connect_postgres() (autocommit explicitly
    False) commits anything on its own between two db.execute() calls -
    only an explicit conn.commit()/conn.rollback() ever closes a
    transaction on either backend. So the job UPDATE and (when
    applicable) the workspace_budgets UPDATE below are issued back to
    back on this SAME connection with NO commit() between them, and
    closed out by exactly ONE commit() - both writes land together, or
    (on any exception, or if the caller's own process dies before that
    one commit) neither does, and the row is found exactly as before by
    whichever reap call retries it next. The workspace_budgets write is
    inlined here (the same statement release_workspace_budget() itself
    runs) rather than calling that function, specifically because its
    own commit() would defeat this - release_workspace_budget() and its
    one other call site (claim_and_run_one_job()'s own release-on-failure
    path, a single-write operation with nothing else to stay atomic
    with) are both unchanged."""
    now = utcnow_iso()
    candidates_cur = db.execute(
        conn,
        "SELECT id, workspace_id, mode, status, attempt_count FROM analysis_jobs "
        "WHERE status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
        (now,),
    )
    candidates = [db.normalize_row(row) for row in candidates_cur.fetchall()]

    requeued = 0
    failed = 0
    for job in candidates:
        will_requeue = job["attempt_count"] < max_attempts
        if will_requeue:
            # ADMISSION CONTROL / QUEUE FAIRNESS: next_eligible_at is the
            # ONLY new thing this branch does - a retry-backoff
            # eligibility gate (see _compute_next_eligible_at()'s own
            # comment for the formula), added to this SAME UPDATE
            # statement, inside the SAME single-commit transaction this
            # function's own TRANSACTIONAL ATOMICITY section above
            # already established. No new query, no new commit boundary -
            # the atomicity property this function exists to guarantee is
            # completely unaffected by this one extra SET clause.
            next_eligible_at = _compute_next_eligible_at(datetime.now(timezone.utc), job["attempt_count"])
            cur = db.execute(
                conn,
                "UPDATE analysis_jobs SET status = 'queued', claimed_by = NULL, claimed_at = NULL, "
                "lease_expires_at = NULL, attempt_count = attempt_count + 1, next_eligible_at = ? "
                "WHERE id = ? AND status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
                (next_eligible_at, job["id"], now),
            )
        else:
            cur = db.execute(
                conn,
                "UPDATE analysis_jobs SET status = 'failed', completed_at = ?, lease_expires_at = NULL, "
                "attempt_count = attempt_count + 1, "
                "last_error = 'lease expired: worker did not report completion within the allotted time' "
                "WHERE id = ? AND status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
                (now, job["id"], now),
            )
        if cur.rowcount == 0:
            conn.rollback()  # another reaper (or the job's own real completion) already won this exact row.
            continue
        try:
            if job["status"] == "running":
                # Same statement release_workspace_budget() itself runs -
                # inlined, never that function, so this stays in the ONE
                # transaction the job UPDATE above already opened (see
                # this function's own TRANSACTIONAL ATOMICITY docstring
                # section) - that function's own commit() would close
                # this transaction out from under the job UPDATE too
                # early, independently of whether this write succeeds.
                db.execute(
                    conn,
                    "UPDATE workspace_budgets SET reserved_units = reserved_units - ?, updated_at = ? WHERE workspace_id = ?",
                    (JOB_MODE_BUDGET_COST.get(job["mode"], 1), utcnow_iso(), job["workspace_id"]),
                )
            conn.commit()  # the ONE commit for this row - job transition and budget release land together, or neither does.
        except Exception:
            conn.rollback()
            raise
        if will_requeue:
            requeued += 1
        else:
            failed += 1

    return {"requeued": requeued, "failed": failed}


# ---------------------------------------------------------------------------
# Plan authorization (D-086) - P0: an entitlement's own plan is the ONLY
# thing that decides which analysis modes a workspace may request. Quick
# unlocks quick only; Standard adds patch/gas via the standard mode;
# Pro adds every currently-implemented mode/capability - cumulative by
# design, matching the commercial model confirmed in docs/decisiones.md
# D-086, never merely a single exact-match mode. The one enforcement
# point is backend/http_app.py's _handle_job_submit() - see that
# function's own docstring; this mapping is the single source of truth
# it reads, never a second hand-copied version.
# ---------------------------------------------------------------------------

PLAN_ALLOWED_MODES = {
    "quick": frozenset({"quick"}),
    "standard": frozenset({"quick", "standard"}),
    "pro": frozenset({"quick", "standard", "pro"}),
}

# ---------------------------------------------------------------------------
# Workspace spend control (Phase 4 - a units ledger, never money/billing;
# Stripe/entitlements remain Phase 3 and are untouched by this section)
# ---------------------------------------------------------------------------

# An INTERNAL cost/abuse safeguard only - never a commercial monthly
# allowance, never advertised as one (docs/decisiones.md D-086 reconfirms
# this explicitly). Flat across every plan and never reset on any cycle -
# a relative per-mode cost against one shared ceiling per workspace, not
# tied to any real dollar figure or to the (now confirmed, D-086) plan
# prices at all.
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
    # "queued" covers a reaper requeueing a dead worker's claim. "failed"
    # covers claim_and_run_one_job()'s own budget-exhausted path (reserve_
    # workspace_budget() returning False before the job ever reaches
    # 'running') - PRE-EXISTING GAP found and fixed while building
    # finalize_job_attempt() below: that call site has passed ("claimed",
    # "failed") since it was written, which this dict rejected, so it has
    # always raised RepositoryError uncaught (never reached fencing logic
    # at all) - confirmed by no test ever exercising it. Unrelated to
    # fencing itself; fixed as a necessary prerequisite for that call site
    # to work at all.
    "claimed": {"running", "queued", "canceled", "failed"},
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


def finalize_job_attempt(
    conn: Any,
    job_id: str,
    workspace_id: str,
    expected_attempt_count: int,
    expected_claimed_by: str,
    from_status: str,
    to_status: str,
    error: Optional[str] = None,
    budget_units: Optional[int] = None,
    budget_action: Optional[str] = None,
    report_storage_ref: Optional[str] = None,
    report_score_status: Optional[str] = None,
    report_score: Optional[int] = None,
    report_risk_band: Optional[str] = None,
) -> Dict[str, Any]:
    """Fenced counterpart to transition_job_status(), for the ONE caller
    (claim_and_run_one_job()) that must finalize a job it claimed a
    possibly-long time ago - after the wall-clock-bounded container run,
    reap_expired_jobs() may already have reclaimed this exact job (lease
    expired while the container was still legitimately running) and even
    handed it to a NEW worker for a NEW attempt by the time this call
    happens. Confirmed real gap (found by a dedicated concurrency audit
    after the reap atomicity fix above): job_id + status='running' alone
    is NOT sufficient fencing, because a reaped-and-re-claimed job is
    ALSO 'running' again by the time the stale caller gets here - it just
    belongs to a different attempt. attempt_count is bumped by
    reap_expired_jobs() exactly once per reap (both its requeue and its
    fail branch) and is otherwise untouched between a claim and that
    claim's own finalization (claim_next_job() and this function's own
    'running' transition never touch it), so it strictly increases across
    any two distinct claims of the same job_id and stays constant across
    all of ONE claim's own lifetime - a claim's own (attempt_count,
    claimed_by) pair, captured once right after claim_next_job() returns
    and threaded through unchanged by the caller, is a valid fencing
    token for exactly that one attempt. claimed_by is included too (the
    caller's own preference) as cheap defense in depth, though
    attempt_count alone is already sufficient by the argument above.

    Returns {"applied": bool, "report_id": Optional[str]}. "applied" is
    False exactly when the fencing check lost the race (rowcount 0 on the
    conditional UPDATE below) - an EXPECTED, not exceptional, outcome:
    the caller must treat this as "stand down silently", writing no
    report and touching no budget, never as an error to raise or an
    alert to fire (reap_expired_jobs() already alerts on the requeue that
    caused this, when it happens via EVENT_WORKER_REPEATED_RETRY - see
    worker_supervisor.py). Genuinely never raises for THIS reason; an
    exception from the report INSERT or the budget UPDATE below (only
    ever reached after the fencing check already passed - a real
    CHECK-constraint violation or similar) is a different, real
    infrastructure/data problem that must NOT be swallowed - rolled back
    and re-raised unchanged, same discipline as reap_expired_jobs()'s own
    exception handling.

    TRANSACTIONAL ATOMICITY: identical reasoning to reap_expired_jobs()'s
    own docstring - neither backend auto-commits between two db.execute()
    calls on the same connection, so the fencing UPDATE, the optional
    report INSERT, and the optional budget UPDATE below are issued back
    to back with NO commit() between them, closed by exactly ONE
    commit(). record_report()/consume_reserved_workspace_budget()/
    release_workspace_budget() are deliberately never called here (each
    does its own commit(), which would defeat this) - the same SQL each
    one runs is inlined instead, exactly like reap_expired_jobs() already
    inlines release_workspace_budget()'s own statement. Those three
    functions and transition_job_status() itself are all unchanged."""
    if to_status not in _VALID_TRANSITIONS.get(from_status, set()):
        raise RepositoryError("invalid job transition %r -> %r" % (from_status, to_status))
    if budget_action not in (None, "consume", "release"):
        raise RepositoryError("budget_action must be one of consume/release/None, got %r" % (budget_action,))
    if report_storage_ref is not None and report_score_status not in ("computed", "not_computed"):
        raise RepositoryError("score_status must be computed/not_computed, got %r" % (report_score_status,))

    now = utcnow_iso()
    timestamp_column = {"running": "started_at", "succeeded": "completed_at", "failed": "completed_at"}.get(to_status)
    if timestamp_column:
        cur = db.execute(
            conn,
            "UPDATE analysis_jobs SET status = ?, %s = ?, last_error = COALESCE(?, last_error), "
            "attempt_count = attempt_count + CASE WHEN ? = 'failed' THEN 1 ELSE 0 END "
            "WHERE id = ? AND status = ? AND attempt_count = ? AND claimed_by = ?" % timestamp_column,
            (to_status, now, error, to_status, job_id, from_status, expected_attempt_count, expected_claimed_by),
        )
    else:
        cur = db.execute(
            conn,
            "UPDATE analysis_jobs SET status = ?, last_error = COALESCE(?, last_error) "
            "WHERE id = ? AND status = ? AND attempt_count = ? AND claimed_by = ?",
            (to_status, error, job_id, from_status, expected_attempt_count, expected_claimed_by),
        )
    if cur.rowcount == 0:
        conn.rollback()  # fencing lost - a concurrent reap already reclaimed this attempt (possibly for a new one).
        return {"applied": False, "report_id": None}

    report_id = None
    try:
        if report_storage_ref is not None:
            report_id = new_id()
            db.execute(
                conn,
                "INSERT INTO reports (id, job_id, workspace_id, storage_ref, score_status, score, risk_band, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (report_id, job_id, workspace_id, report_storage_ref, report_score_status, report_score, report_risk_band, now),
            )
        if budget_action == "consume":
            db.execute(
                conn,
                "UPDATE workspace_budgets SET reserved_units = reserved_units - ?, consumed_units = consumed_units + ?, updated_at = ? WHERE workspace_id = ?",
                (budget_units, budget_units, now, workspace_id),
            )
        elif budget_action == "release":
            db.execute(
                conn,
                "UPDATE workspace_budgets SET reserved_units = reserved_units - ?, updated_at = ? WHERE workspace_id = ?",
                (budget_units, now, workspace_id),
            )
        conn.commit()  # the ONE commit for this attempt - transition, report and budget land together, or none do.
    except Exception:
        conn.rollback()
        raise
    return {"applied": True, "report_id": report_id}


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


def list_reports_by_workspace(conn: Any, workspace_id: str, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0) -> List[Dict[str, Any]]:
    """Same tenant-scoping trust, pagination bounds and deterministic
    order as list_jobs_by_workspace() above - see that function's
    docstring; not repeated here."""
    if not (1 <= limit <= MAX_LIST_LIMIT):
        raise RepositoryError("limit must be between 1 and %d, got %r" % (MAX_LIST_LIMIT, limit))
    if offset < 0:
        raise RepositoryError("offset must be >= 0, got %r" % (offset,))
    cur = db.execute(
        conn,
        "SELECT * FROM reports WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        (workspace_id, limit, offset),
    )
    return [db.normalize_row(row) for row in cur.fetchall()]


def get_report_by_id(conn: Any, report_id: str) -> Optional[Dict[str, Any]]:
    """Returns this report's row regardless of workspace - the caller
    (backend/http_app.py's report-detail handler) MUST compare the
    returned row's own workspace_id against the URL's already-tenant-
    scope-verified workspace_id itself before using anything else on it;
    this function takes no workspace_id to filter by because a report is
    looked up by its own id, exactly like get_job()/get_contract() above
    - the tenant check is the caller's job, not a second, redundant WHERE
    clause here (same division of responsibility this module's own
    docstring already establishes)."""
    cur = db.execute(conn, "SELECT * FROM reports WHERE id = ?", (report_id,))
    return db.normalize_row(cur.fetchone())


def list_workspace_reports(conn: Any, workspace_id: str) -> List[Dict[str, Any]]:
    """Every non-purged report belonging to workspace_id - used by
    backend/retention.py's delete_workspace_data(), distinct from
    list_expired_reports() below (age-based, across every workspace)."""
    cur = db.execute(conn, "SELECT * FROM reports WHERE workspace_id = ? AND purged_at IS NULL", (workspace_id,))
    return [db.normalize_row(row) for row in cur.fetchall()]


def list_expired_reports(conn: Any, cutoff_iso: str) -> List[Dict[str, Any]]:
    """Every report created before cutoff_iso whose object-storage
    CONTENT has not already been purged - see mark_report_purged()'s own
    docstring on why the METADATA row is kept regardless."""
    cur = db.execute(conn, "SELECT * FROM reports WHERE created_at < ? AND purged_at IS NULL", (cutoff_iso,))
    return [db.normalize_row(row) for row in cur.fetchall()]


def mark_report_purged(conn: Any, report_id: str) -> bool:
    """Marks that this report's object-storage CONTENT has been deleted
    - the row itself (score/risk_band/created_at/job_id) is deliberately
    NEVER deleted by this function or by backend/retention.py, which is
    the only caller: audit/job history stays queryable even once content
    retention expires (Phase 6A's own explicit "audit/job history where
    appropriate" scoping - see backend/migrations/0006_retention_purge.sql).
    Idempotent, same conditional-UPDATE pattern as mark_contract_deleted()."""
    cur = db.execute(conn, "UPDATE reports SET purged_at = ? WHERE id = ? AND purged_at IS NULL", (utcnow_iso(), report_id))
    conn.commit()
    return cur.rowcount > 0


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
