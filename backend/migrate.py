#!/usr/bin/env python3
"""Minimal, forward-only SQL migration runner for the standalone SaaS
backend's data foundation (Phase 1, docs/decisiones.md D-077 - Capafy
removal/independent-architecture line of work).

Applies every *.sql file in a migrations directory, in filename order, that
is not yet recorded in the `schema_migrations` table it expects the FIRST
migration to create. Deliberately does nothing cleverer than that: no
down-migrations/rollback, no checksums, no dependency graph - a Phase 1
foundation only needs "apply what's new, in order, exactly once."

Nothing in this module imports sqlite3 or any driver directly - it only
calls methods on whatever connection object its caller passes in.
`_execute_sql_script` also works against a plain DB-API 2.0 connection
(falls back to `cursor().execute(...)` when there is no `executescript` -
confirmed empirically that a psycopg connection can run a full
multi-statement migration file this way, via Postgres's own simple query
protocol). `_record_applied`/`_already_applied` go through
backend/db.py's adapter (placeholder translation, dict-safe row access)
instead of hardcoding sqlite3's "?" paramstyle - this module now runs
against both SQLite and real PostgreSQL 13+ (see backend/db.py,
backend/requirements.txt).

No network access itself - a caller-supplied connection does whatever
network access its own backend needs (none, for SQLite).
"""
from __future__ import annotations

import os
from typing import Any, List, Sequence

import backend.db as db


class MigrationError(Exception):
    """Raised only for a malformed migrations directory or a migration
    file that fails to apply - never for "nothing new to apply", a
    normal, expected result."""


def _execute_sql_script(conn: Any, sql_text: str) -> None:
    executescript = getattr(conn, "executescript", None)
    if callable(executescript):
        executescript(sql_text)
    else:
        conn.cursor().execute(sql_text)


def _already_applied(conn: Any) -> set:
    try:
        cur = conn.cursor()
        cur.execute("SELECT version FROM schema_migrations")
        rows = cur.fetchall()
    except Exception:
        # schema_migrations does not exist yet - this is only true for a
        # completely fresh database, before migration 0001 (which creates
        # that table itself) has ever been applied. MUST roll back before
        # returning: unlike sqlite3, PostgreSQL aborts the entire
        # transaction on any error within it - every later statement on
        # this connection (the migration itself) would otherwise fail
        # with InFailedSqlTransaction, not because of anything wrong with
        # it, but because this expected, caught error was never rolled
        # back (verified against a real postgres:15 container).
        conn.rollback()
        return set()
    # Dict-safe: a plain sqlite3 connection (no row_factory - e.g. this
    # module's own tests) returns tuples (row[0]); repository.connect()'s
    # sqlite3.Row and backend.db.connect_postgres()'s dict rows both
    # support name-based access instead - same defensive pattern as
    # tenant_scope.resolve_workspace_role().
    return {(row["version"] if hasattr(row, "keys") else row[0]) for row in rows}


def _record_applied(conn: Any, version: str, applied_at: str) -> None:
    db.execute(
        conn,
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        (version, applied_at),
    )


def discover_migrations(migrations_dir: str) -> List[str]:
    if not os.path.isdir(migrations_dir):
        raise MigrationError("migrations directory not found: %r" % migrations_dir)
    names = sorted(f for f in os.listdir(migrations_dir) if f.endswith(".sql"))
    if not names:
        raise MigrationError("no *.sql migration files found in %r" % migrations_dir)
    return names


def apply_pending_migrations(conn: Any, migrations_dir: str, now_iso: str) -> List[str]:
    """Applies every not-yet-applied *.sql file in migrations_dir, in
    filename order. Returns the list of version strings actually applied
    (empty if the database was already up to date). `now_iso` is supplied
    by the caller (never computed here) so this function stays a pure,
    deterministic operation over its inputs."""
    applied = _already_applied(conn)
    newly_applied: List[str] = []
    for filename in discover_migrations(migrations_dir):
        version = filename[:-4]  # strip ".sql"
        if version in applied:
            continue
        path = os.path.join(migrations_dir, filename)
        with open(path, "r", encoding="utf-8") as handle:
            sql_text = handle.read()
        try:
            _execute_sql_script(conn, sql_text)
            _record_applied(conn, version, now_iso)
            conn.commit()
        except Exception as exc:
            conn.rollback()
            raise MigrationError("migration %r failed to apply: %s" % (version, exc)) from exc
        newly_applied.append(version)
    return newly_applied
