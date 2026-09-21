"""Tests for backend/migrate.py (Phase 1 SaaS backend data foundation,
docs/decisiones.md D-077) and a structural drift check between the two
parallel schema files this phase maintains (backend/migrations/*.sql,
authoritative PostgreSQL; backend/schema_sqlite.sql, the SQLite test
mirror - see that file's own docstring for why two files exist).

migrate.py's own mechanics are tested here against a small, deliberately
SQLite-compatible fixture migrations directory, never against the real
backend/migrations/*.sql files - those are genuine PostgreSQL DDL
(gen_random_uuid(), JSONB, CREATE EXTENSION). What IS tested here is
migrate.py's own discovery/ordering/tracking/idempotency logic, which is
dialect-agnostic by construction; the real *.sql files ARE actually
applied against a live PostgreSQL 15 container elsewhere (see
tests/test_backend_postgres_integration.py's MigrationIntegrationTests,
docs/decisiones.md D-078) - that gap is closed, not an open blocker.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import unittest

import backend.migrate as migrate

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTGRES_MIGRATIONS_DIR = os.path.join(REPO_ROOT, "backend", "migrations")
SQLITE_MIRROR = os.path.join(REPO_ROOT, "backend", "schema_sqlite.sql")

_CREATE_TABLE_RE = re.compile(r"CREATE TABLE\s+(\w+)\s*\(", re.IGNORECASE)


def _table_names(sql_text: str) -> set:
    return set(_CREATE_TABLE_RE.findall(sql_text))


class DiscoverMigrationsTests(unittest.TestCase):
    def test_missing_directory_raises(self):
        with self.assertRaises(migrate.MigrationError):
            migrate.discover_migrations("/no/such/directory/at/all")

    def test_empty_directory_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(migrate.MigrationError):
                migrate.discover_migrations(tmp)

    def test_files_are_returned_in_sorted_filename_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("0002_second.sql", "0001_first.sql", "0010_tenth.sql"):
                open(os.path.join(tmp, name), "w", encoding="utf-8").close()
            self.assertEqual(migrate.discover_migrations(tmp), ["0001_first.sql", "0002_second.sql", "0010_tenth.sql"])


class ApplyPendingMigrationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)

    def _write(self, filename: str, sql_text: str) -> None:
        with open(os.path.join(self.tmp.name, filename), "w", encoding="utf-8") as handle:
            handle.write(sql_text)

    def test_applies_migrations_in_order_and_records_them(self):
        self._write("0001_init.sql", "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);\nCREATE TABLE widgets (id TEXT PRIMARY KEY);")
        self._write("0002_add_gadgets.sql", "CREATE TABLE gadgets (id TEXT PRIMARY KEY);")
        applied = migrate.apply_pending_migrations(self.conn, self.tmp.name, now_iso="2026-01-01T00:00:00+00:00")
        self.assertEqual(applied, ["0001_init", "0002_add_gadgets"])
        tables = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("widgets", tables)
        self.assertIn("gadgets", tables)

    def test_re_running_applies_nothing_new(self):
        self._write("0001_init.sql", "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);\nCREATE TABLE widgets (id TEXT PRIMARY KEY);")
        migrate.apply_pending_migrations(self.conn, self.tmp.name, now_iso="2026-01-01T00:00:00+00:00")
        second_run = migrate.apply_pending_migrations(self.conn, self.tmp.name, now_iso="2026-01-02T00:00:00+00:00")
        self.assertEqual(second_run, [])

    def test_a_new_migration_added_later_is_picked_up_on_the_next_run(self):
        self._write("0001_init.sql", "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);\nCREATE TABLE widgets (id TEXT PRIMARY KEY);")
        migrate.apply_pending_migrations(self.conn, self.tmp.name, now_iso="2026-01-01T00:00:00+00:00")
        self._write("0002_add_gadgets.sql", "CREATE TABLE gadgets (id TEXT PRIMARY KEY);")
        second_run = migrate.apply_pending_migrations(self.conn, self.tmp.name, now_iso="2026-01-02T00:00:00+00:00")
        self.assertEqual(second_run, ["0002_add_gadgets"])

    def test_a_failing_migration_rolls_back_and_raises_cleanly(self):
        self._write("0001_init.sql", "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);\nTHIS IS NOT VALID SQL;")
        with self.assertRaises(migrate.MigrationError):
            migrate.apply_pending_migrations(self.conn, self.tmp.name, now_iso="2026-01-01T00:00:00+00:00")


class SchemaFileDriftTests(unittest.TestCase):
    """The two schema files (Postgres migrations, SQLite test mirror) are
    deliberately separate (see schema_sqlite.sql's docstring) - this is
    the regression guard against them silently drifting apart, the same
    concern D-058's single-source-of-truth discipline exists for
    elsewhere in this repository, applied here to a case where a true
    single source isn't possible across two SQL dialects.

    Compares against the UNION of every file in backend/migrations/
    (via migrate.discover_migrations() itself, so this can never drift
    from what migrate.py actually applies) rather than a single
    hardcoded filename - the SQLite mirror represents the cumulative
    schema across ALL migrations, not just the first one (a real gap
    this test itself had until Phase 2 added a second migration file
    and caught it: it used to compare only 0001_initial_schema.sql,
    silently never checking any later file against the mirror at all)."""

    def test_both_schema_files_define_the_same_set_of_tables(self):
        postgres_tables: set = set()
        for filename in migrate.discover_migrations(POSTGRES_MIGRATIONS_DIR):
            with open(os.path.join(POSTGRES_MIGRATIONS_DIR, filename), "r", encoding="utf-8") as handle:
                postgres_tables |= _table_names(handle.read())
        with open(SQLITE_MIRROR, "r", encoding="utf-8") as handle:
            sqlite_tables = _table_names(handle.read())
        self.assertEqual(postgres_tables, sqlite_tables)
        self.assertIn("analysis_jobs", postgres_tables)  # sanity: the extraction itself actually found real tables.
        self.assertIn("auth_tokens", postgres_tables)  # sanity: a later migration file is actually being read too.


if __name__ == "__main__":
    unittest.main()
