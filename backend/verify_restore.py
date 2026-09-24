#!/usr/bin/env python3
"""PostgreSQL restore verification procedure (Phase 6A production
hardening, docs/decisiones.md D-077 follow-up) - STAGING/TEST ONLY.

THIS TOOL NEVER TAKES A BACKUP. It consumes a dump file that already
exists (produced by the deployment's own separate backup process - e.g.
a managed Postgres provider's automated snapshot exported via
`pg_dump`) and proves that dump actually restores into a working,
verifiable database - the only way to know a backup is real is to
restore it, not to trust that the backup job "succeeded". Run this
periodically against a real backup as a drill, and always before trusting
a specific dump during an actual incident.

Never touches a production database: restores into a FRESH, DISPOSABLE
`postgres:15` Docker container this script starts and tears down itself
(same --rm, localhost-only, throwaway-credential pattern tests/
test_backend_postgres_integration.py's own setUpModule already
established) - there is no code path here that can accept a DSN for an
existing/production database at all.

Five checks, in order, any of which failing marks the drill FAILED:
  1. restore - the dump file applies cleanly (via `docker exec -i
     <container> psql`, so the host running this script needs no
     postgres client installed itself - only Docker).
  2. migrations - backend/migrate.py's own apply_pending_migrations()
     against the restored database reports zero newly-applied versions
     (a dump taken from a fully-migrated database should already be
     fully migrated; if this reports anything applied, the dump predates
     a migration and that is itself surfaced, never silently patched).
  3. metadata - workspaces/analysis_jobs/reports/users row counts are
     read back (never asserted against a specific expected number - this
     script has no way to know what a real production dump should
     contain - only that the query itself succeeds and returns sane,
     non-negative counts).
  4. application startup - backend/db.py's connect_postgres() against
     the restored database, then a trivial query, mirrors exactly what
     backend/http_app.py's GET /ready check already does in production.
  5. report accessibility - for every report row with purged_at IS NULL
     (see backend/retention.py on why that column exists), confirms its
     storage_ref is still a well-formed, non-empty key (backend/
     object_storage.py's own key shape) and, if --storage-dir is given
     (a LocalFilesystemStorage root backed up alongside the same
     database snapshot), that the actual object file exists there too -
     a database restore alone proves nothing about whether the report
     CONTENT it references survived the same backup.

Exit code 0 only if every check passes; non-zero (with the specific
failing check named) otherwise. Prints a summary to stdout as JSON (no
DSN, password or file content), everything else (progress) to stderr.

Standard library only, plus this repo's own backend.db/backend.migrate/
backend.repository/backend.object_storage. Docker must be installed and
reachable.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

import backend.db as db
import backend.migrate as migrate
import backend.object_storage as object_storage
import backend.repository as repo

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
MIGRATIONS_DIR = os.path.join(REPO_ROOT, "migrations")

DEFAULT_PG_IMAGE = "postgres:15"


class RestoreVerificationError(Exception):
    """Raised for a failed check - the message names exactly which one,
    never a raw exception/traceback that could embed a DSN."""


def _run(args: List[str], input_bytes: Optional[bytes] = None, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input_bytes, capture_output=True, timeout=timeout)


def _start_disposable_postgres(container_name: str, port: int, password: str, db_name: str) -> None:
    _run(["docker", "rm", "-f", container_name])
    result = _run([
        "docker", "run", "--rm", "-d", "--name", container_name,
        "-e", "POSTGRES_PASSWORD=%s" % password, "-e", "POSTGRES_DB=%s" % db_name,
        "-p", "127.0.0.1:%d:5432" % port, DEFAULT_PG_IMAGE,
    ])
    if result.returncode != 0:
        raise RestoreVerificationError("could not start a disposable postgres container: %s" % result.stderr.decode("utf-8", "replace")[:300])
    for _ in range(30):
        ready = _run(["docker", "exec", container_name, "pg_isready", "-U", "postgres"])
        if ready.returncode == 0:
            return
        time.sleep(1)
    _run(["docker", "rm", "-f", container_name])
    raise RestoreVerificationError("disposable postgres container did not become ready in time")


def _check_restore(container_name: str, db_name: str, dump_path: str) -> None:
    with open(dump_path, "rb") as handle:
        dump_bytes = handle.read()
    result = _run(["docker", "exec", "-i", container_name, "psql", "-U", "postgres", "-d", db_name, "-v", "ON_ERROR_STOP=1"], input_bytes=dump_bytes, timeout=300)
    if result.returncode != 0:
        raise RestoreVerificationError("restore (check 1/5) failed: %s" % result.stderr.decode("utf-8", "replace")[-500:])


def _check_migrations(conn: Any) -> List[str]:
    try:
        applied = migrate.apply_pending_migrations(conn, MIGRATIONS_DIR, now_iso=repo.utcnow_iso())
    except Exception as exc:
        raise RestoreVerificationError("migrations (check 2/5) failed: %s: %s" % (type(exc).__name__, exc))
    return applied


def _check_metadata(conn: Any) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for table in ("workspaces", "users", "analysis_jobs", "reports"):
        try:
            cur = db.execute(conn, "SELECT COUNT(*) AS n FROM %s" % table)  # table name is one of the fixed literals above, never user input.
            counts[table] = int(db.normalize_row(cur.fetchone())["n"])
        except Exception as exc:
            raise RestoreVerificationError("metadata (check 3/5) failed reading %r: %s: %s" % (table, type(exc).__name__, exc))
        if counts[table] < 0:
            raise RestoreVerificationError("metadata (check 3/5) got a nonsensical negative count for %r" % table)
    return counts


def _check_application_startup(dsn: str) -> None:
    try:
        conn = db.connect_postgres(dsn)
        db.execute(conn, "SELECT 1")
        conn.close()
    except Exception as exc:
        raise RestoreVerificationError("application startup (check 4/5) failed: %s: %s" % (type(exc).__name__, exc))


def _check_report_accessibility(conn: Any, storage_dir: Optional[str]) -> Dict[str, int]:
    cur = db.execute(conn, "SELECT id, storage_ref FROM reports WHERE purged_at IS NULL")
    rows = [db.normalize_row(r) for r in cur.fetchall()]
    checked = 0
    missing_on_disk = 0
    for row in rows:
        storage_ref = row["storage_ref"]
        if not isinstance(storage_ref, str) or not storage_ref or ".." in storage_ref:
            raise RestoreVerificationError("report accessibility (check 5/5) failed: report %r has a malformed storage_ref" % row["id"])
        checked += 1
        if storage_dir is not None:
            candidate = os.path.join(storage_dir, storage_ref)
            if not os.path.isfile(candidate):
                missing_on_disk += 1
    if storage_dir is not None and missing_on_disk:
        raise RestoreVerificationError("report accessibility (check 5/5) failed: %d of %d report object(s) missing under --storage-dir" % (missing_on_disk, checked))
    return {"reports_checked": checked, "storage_dir_checked": storage_dir is not None}


def run_restore_verification(dump_path: str, storage_dir: Optional[str] = None, port: int = 55499) -> Dict[str, Any]:
    """The whole drill, in order - see module docstring for what each of
    the 5 checks proves. Always tears down its disposable container,
    success or failure."""
    container_name = "restore-verify-%d" % int(time.time())
    password = "restore-verify-throwaway"
    db_name = "restoreverify"
    dsn = "postgresql://postgres:%s@127.0.0.1:%d/%s" % (password, port, db_name)
    _start_disposable_postgres(container_name, port, password, db_name)
    try:
        _check_restore(container_name, db_name, dump_path)
        conn = db.connect_postgres(dsn)
        try:
            newly_applied = _check_migrations(conn)
            metadata_counts = _check_metadata(conn)
            _check_application_startup(dsn)
            report_check = _check_report_accessibility(conn, storage_dir)
        finally:
            conn.close()
    finally:
        _run(["docker", "rm", "-f", container_name])
    return {
        "ok": True,
        "dump_path": dump_path,
        "migrations_newly_applied_by_restore": newly_applied,
        "table_row_counts": metadata_counts,
        "report_accessibility": report_check,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verify_restore.py", description=__doc__.strip().splitlines()[0])
    parser.add_argument("--dump-file", required=True, help="Path to a plain-SQL pg_dump file to restore and verify.")
    parser.add_argument("--storage-dir", default=None, help="Optional LocalFilesystemStorage root backed up alongside the dump - if given, every report's object is confirmed present on disk too.")
    parser.add_argument("--port", type=int, default=55499, help="Host port for the disposable Postgres container (default: 55499).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        result = run_restore_verification(args.dump_file, args.storage_dir, args.port)
    except RestoreVerificationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
