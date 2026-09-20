#!/usr/bin/env python3
"""Central PostgreSQL/SQLite dialect adapter for the Phase 1 SaaS backend
(docs/decisiones.md D-077 follow-up - Postgres adapter).

The ONE place this backend's two supported databases differ mechanically:
  * parameter placeholder syntax ('?' vs '%s') - repository.py/migrate.py/
    tenant_scope.py always write '?' (sqlite3's own style); execute()
    translates it to '%s' for a psycopg connection, and ONLY there, so no
    other module needs an "if postgres" branch just to run a query.
  * row value shapes - psycopg returns native uuid.UUID/datetime.datetime
    objects for UUID/TIMESTAMPTZ columns (verified empirically against a
    real postgres:15 container); sqlite3 returns plain str for everything
    (it has no native UUID/TIMESTAMPTZ type). repository.py's own module
    docstring establishes that a row's shape is identical regardless of
    backend - normalize_row() is the one place that difference is erased,
    never left for each caller to handle itself.
  * the job-claim query itself - Postgres's real "FOR UPDATE SKIP LOCKED"
    has no SQLite equivalent at all (see schema_sqlite.sql's docstring),
    so repository.claim_next_job() dispatches on is_postgres() to one of
    two genuinely different queries - the one branch point in this
    codebase that cannot be reduced to a placeholder/value translation,
    because the two engines' locking models are not the same thing.

psycopg is imported lazily/optionally: an environment that only ever uses
the SQLite backend (e.g. running the existing test suite) never needs it
installed - this module degrades to SQLite-only support. It never
silently substitutes SQLite for a caller that explicitly asked for
PostgreSQL - see connect_postgres(), which raises instead.

No network access at import time. No secrets/credentials handled here -
callers supply a complete DSN/path themselves.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

try:
    import psycopg
    from psycopg.rows import dict_row as _pg_dict_row
except ImportError:  # psycopg is optional - see module docstring.
    psycopg = None
    _pg_dict_row = None


class DBAdapterError(Exception):
    """Raised only for misuse of this adapter itself (e.g. requesting the
    PostgreSQL backend when psycopg is not installed) - never for a
    database constraint, which always propagates as the driver's own
    exception type, unchanged."""


def is_postgres(conn: Any) -> bool:
    return psycopg is not None and isinstance(conn, psycopg.Connection)


def connect_postgres(dsn: str) -> Any:
    """Opens a psycopg connection with dict-shaped rows (matching
    sqlite3.Row's name-based access - see normalize_row() for the one
    remaining value-shape difference) and explicit, non-autocommit
    transactions (matching this codebase's own always-call-commit()
    discipline). Raises DBAdapterError if psycopg is not installed - never
    falls back to SQLite; a caller that asked for PostgreSQL and can't get
    it must find out immediately, not silently get a different database."""
    if psycopg is None:
        raise DBAdapterError(
            'psycopg is not installed - run: pip install "psycopg[binary]>=3.1,<4" '
            "(see backend/requirements.txt). The SQLite backend (repository.connect()) "
            "needs no extra dependency and is unaffected."
        )
    conn = psycopg.connect(dsn, row_factory=_pg_dict_row)
    conn.autocommit = False
    return conn


def _translate_placeholders(sql: str) -> str:
    """This codebase's single canonical placeholder is '?' (sqlite3's own
    style); psycopg needs '%s'. Every '?' in every SQL string this backend
    builds is a bind parameter, never a literal character in a string or
    comment (confirmed by inspection - there is no user-controlled SQL
    text anywhere in this codebase), so an unconditional replace is exact.
    None of this codebase's SQL contains a literal '%' either, so there is
    no escaping concern in the other direction."""
    return sql.replace("?", "%s")


def execute(conn: Any, sql: str, params: tuple = ()) -> Any:
    """The one place SQL is actually submitted, for both backends -
    callers always write '?' placeholders and call this instead of
    conn.execute()/conn.cursor().execute() directly. Returns the cursor
    (.rowcount/.fetchone() behave the same way on both backends' cursor
    objects - verified empirically)."""
    if is_postgres(conn):
        sql = _translate_placeholders(sql)
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def integrity_error_class(conn: Any) -> type:
    """The exception class a caller should catch for "this INSERT/UPDATE
    violated a constraint" on whichever backend conn is -
    repository.record_webhook_event() is the one call site that needs
    this today (a duplicate webhook_events.id is an expected, normal
    outcome there, never an error to propagate)."""
    if is_postgres(conn):
        return psycopg.errors.IntegrityError
    return sqlite3.IntegrityError


def normalize_row(row: Optional[Any]) -> Optional[Dict[str, Any]]:
    """Converts a fetched row to the same plain-string shape regardless of
    backend - see this module's docstring. A no-op for a sqlite3.Row (its
    values are already plain str/int/None, so the isinstance checks below
    never match), so this is always safe to call unconditionally, for
    either backend."""
    if row is None:
        return None
    result = dict(row)
    for key, value in result.items():
        if isinstance(value, uuid.UUID):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
    return result
