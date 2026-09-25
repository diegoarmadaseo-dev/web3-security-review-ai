#!/usr/bin/env python3
"""Reproducible PostgreSQL backup script (Phase 6C, docs/decisiones.md
D-084) - produces a plain-SQL pg_dump snapshot compatible with backend/
verify_restore.py's own --dump-file (that tool restores via `docker exec
... psql`, which cannot read pg_dump's binary custom format - see that
module's own docstring point 1 - so this script always dumps plain SQL,
never -Fc/-Fd/-Ft).

PROVIDER-INDEPENDENT WHERE PRACTICAL: shells out to the `pg_dump` client
binary against whatever --database-url (or DATABASE_URL) points at - a
managed provider (RDS, Cloud SQL, a self-hosted server, ...) all speak the
same wire protocol, so nothing here is provider-specific.

PG_DUMP VERSION MUST MATCH THE RESTORE TARGET, CONFIRMED EMPIRICALLY: this
is about the RESTORE side, not the source server - pg_dump connecting to
an OLDER source server is fine (well-supported). The real constraint is
that pg_dump's OWN OUTPUT PREAMBLE can name a session parameter that only
its own server version understands (e.g. pg_dump 17 emits `SET
transaction_timeout = 0;`, which a Postgres 15 server rejects with
"unrecognized configuration parameter" - reproduced while building this
script). backend/verify_restore.py always restores into a fresh
`postgres:15` container, so the pg_dump binary used for a real backup
should be major version 15 (matching every other Postgres version this
codebase standardizes on) - this script cannot detect or paper over a
mismatched pg_dump on PATH and does not try to.

NEVER LOGS THE DSN OR RAW pg_dump STDERR: the connection string (which
embeds the password) is passed to the pg_dump subprocess as an argument,
never printed by this script itself. A failure's own stderr is captured
but only its LAST LINE, truncated to a bounded length, is ever included
in this script's own error output - never the full text, which could
itself echo back the target host/user on a connection failure (same
"never surface a provider's own raw error text" discipline backend/
alerting.WebhookAlertSender and backend/email_sender.SMTPEmailSender
already apply, for the same reason - see those modules' own docstrings).

RETENTION IS CONFIGURABLE, NEVER INVENTED: --retention-days is optional
and has NO default - omit it and old backups are never deleted by this
script (same "unset = disabled, never a guessed value" discipline
backend/retention.py's own RETENTION_DAYS already established - this
script deliberately does not invent a "reasonable" default like 30 days).
When given, only files matching this script's own naming pattern inside
--output-dir are ever considered for deletion, and age is computed from
the UTC timestamp embedded in the FILENAME itself (never filesystem
mtime, which a copy/rsync/restore can silently change) - never a file
this script did not itself create, and never anything outside
--output-dir.

NEVER OVERWRITES OR LEAVES A PARTIAL FILE AT THE FINAL NAME: pg_dump
writes to a `.partial` temporary path first; only a SUCCESSFUL run
renames it to the final, timestamped name - a failed or interrupted dump
can never be mistaken for a complete backup by a later restore drill.

NEVER OVERWRITES THE PRODUCTION DATABASE: this script only ever performs
`pg_dump` (a read-only operation against the source database) - it has no
code path that writes to --database-url at all. Restoring a produced
dump is backend/verify_restore.py's job, against its own disposable
container, never this database.

Standard library only. Requires the `pg_dump` client binary on PATH -
this is a thin, auditable wrapper around it, not a reimplementation.

Run from the repository root: python -m backend.backup_postgres --help
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

EXIT_OK = 0
EXIT_FAILED = 1

TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_FILENAME_RE = re.compile(r"^vericexa-(\d{8}T\d{6}Z)\.sql$")
_STDERR_TAIL_MAX_CHARS = 200


class BackupError(Exception):
    """Raised for any failure this script itself detects (pg_dump not on
    PATH, missing DSN, pg_dump exiting non-zero) - the CLI turns this into
    a clean {"ok": false, "error": ...} and a non-zero exit, never a raw
    traceback."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def backup_filename(timestamp: datetime) -> str:
    return "vericexa-%s.sql" % timestamp.strftime(TIMESTAMP_FORMAT)


def run_backup(database_url: str, output_dir: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Runs `pg_dump --format=plain <database_url>` and writes the result
    to output_dir/vericexa-<UTC timestamp>.sql - see module docstring on
    why plain format, the temp-file-then-rename step, and DSN/stderr
    handling. Returns {"ok": True, "file": <path>, "bytes": <int>}.
    Raises BackupError on any failure - never returns a partial result."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = now or _utc_now()
    final_name = backup_filename(timestamp)
    final_path = os.path.join(output_dir, final_name)
    temp_path = final_path + ".partial"
    try:
        with open(temp_path, "wb") as handle:
            result = subprocess.run(
                ["pg_dump", "--format=plain", "--no-password", database_url],
                stdout=handle, stderr=subprocess.PIPE, timeout=3600,
            )
    except FileNotFoundError as exc:
        raise BackupError("pg_dump is not installed / not on PATH: %s" % type(exc).__name__) from exc
    except subprocess.TimeoutExpired as exc:
        _cleanup_partial(temp_path)
        raise BackupError("pg_dump timed out after %s seconds" % exc.timeout) from exc
    if result.returncode != 0:
        _cleanup_partial(temp_path)
        stderr_tail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        summary = stderr_tail[-1][:_STDERR_TAIL_MAX_CHARS] if stderr_tail else "no stderr output"
        raise BackupError("pg_dump exited with code %d: %s" % (result.returncode, summary))
    byte_size = os.path.getsize(temp_path)
    if byte_size == 0:
        _cleanup_partial(temp_path)
        raise BackupError("pg_dump produced an empty file - refusing to publish it as a backup")
    os.replace(temp_path, final_path)  # atomic on the same filesystem - never a visible partial at final_path.
    return {"ok": True, "file": final_path, "bytes": byte_size}


def _cleanup_partial(temp_path: str) -> None:
    try:
        os.remove(temp_path)
    except OSError:
        pass


def purge_old_backups(output_dir: str, retention_days: int, now: Optional[datetime] = None) -> List[str]:
    """Deletes only files in output_dir matching THIS script's own
    vericexa-<timestamp>.sql pattern whose embedded timestamp is older
    than retention_days - never anything else in that directory, never
    based on filesystem mtime (see module docstring). Returns the list of
    deleted filenames. retention_days must be a real, explicit value the
    caller supplies - see module docstring on why no default exists."""
    if retention_days <= 0:
        raise BackupError("retention_days must be a positive integer, got %r" % (retention_days,))
    cutoff = (now or _utc_now()) - timedelta(days=retention_days)
    deleted = []
    for name in sorted(os.listdir(output_dir)):
        match = _FILENAME_RE.match(name)
        if not match:
            continue
        try:
            file_timestamp = datetime.strptime(match.group(1), TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if file_timestamp < cutoff:
            os.remove(os.path.join(output_dir, name))
            deleted.append(name)
    return deleted


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backup_postgres.py",
        description="Take a plain-SQL pg_dump backup, compatible with backend/verify_restore.py's --dump-file.",
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write the timestamped backup file into (created if missing).")
    parser.add_argument("--database-url", default=None, help="Postgres DSN to dump (default: the DATABASE_URL environment variable - never a hardcoded/invented value).")
    parser.add_argument("--retention-days", type=int, default=None, help="Delete this script's OWN older backup files after this many days (default: never delete anything - no value is invented, see module docstring).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        print(json.dumps({"ok": False, "error": "no database URL: pass --database-url or set DATABASE_URL"}, ensure_ascii=False))
        return EXIT_FAILED
    try:
        result = run_backup(database_url, args.output_dir)
        if args.retention_days is not None:
            result["purged"] = purge_old_backups(args.output_dir, args.retention_days)
    except BackupError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return EXIT_FAILED
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
