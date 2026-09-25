"""Tests for backend/backup_postgres.py (Phase 6C, docs/decisiones.md
D-084). subprocess.run is the one boundary mocked here - same "mock the
one boundary with no safe real alternative in this environment" discipline
tests/test_backend_email_sender.py already applies to smtplib.SMTP (this
host has no locally-installed pg_dump; the script's real subprocess/file
behavior against a genuine Postgres server + backend/verify_restore.py was
verified by hand while building it - see this module's own docstring on
the pg_dump-version-vs-restore-target finding that verification produced).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

import backend.backup_postgres as backup


def _fake_run_writing(content: bytes, returncode: int = 0, stderr: bytes = b""):
    """Builds a subprocess.run replacement that writes `content` into the
    stdout file handle the real pg_dump invocation would have written its
    dump into - mirrors what redirecting a real subprocess's stdout to a
    file actually does, without needing a real pg_dump on PATH."""

    def _run(cmd, stdout=None, stderr=None, timeout=None):
        if stdout is not None:
            stdout.write(content)
        return subprocess.CompletedProcess(cmd, returncode, stdout=None, stderr=stderr_bytes)

    stderr_bytes = stderr
    return _run


class RunBackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_successful_dump_is_written_with_the_expected_timestamped_name(self):
        now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"-- dump content --")):
            result = backup.run_backup("postgresql://u:p@host/db", self._tmp.name, now=now)
        self.assertTrue(result["ok"])
        self.assertEqual(os.path.basename(result["file"]), "vericexa-20260925T120000Z.sql")
        self.assertTrue(os.path.isfile(result["file"]))
        with open(result["file"], "rb") as handle:
            self.assertEqual(handle.read(), b"-- dump content --")

    def test_no_partial_file_left_behind_after_success(self):
        now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"content")):
            backup.run_backup("postgresql://u:p@host/db", self._tmp.name, now=now)
        self.assertEqual(os.listdir(self._tmp.name), ["vericexa-20260925T120000Z.sql"])

    def test_nonzero_exit_raises_and_never_leaves_a_file_at_the_final_name(self):
        now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"partial", returncode=1, stderr=b"pg_dump: error: connection failed\n")):
            with self.assertRaises(backup.BackupError):
                backup.run_backup("postgresql://u:p@host/db", self._tmp.name, now=now)
        self.assertEqual(os.listdir(self._tmp.name), [])

    def test_failure_error_message_is_bounded_and_never_the_full_raw_stderr(self):
        now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        long_stderr = ("pg_dump: error: connection to server failed: " + "x" * 500 + "\n").encode("utf-8")
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"", returncode=1, stderr=long_stderr)):
            with self.assertRaises(backup.BackupError) as ctx:
                backup.run_backup("postgresql://u:p@host/db", self._tmp.name, now=now)
        self.assertLessEqual(len(str(ctx.exception)), backup._STDERR_TAIL_MAX_CHARS + 80)

    def test_empty_dump_output_is_rejected_never_published_as_a_backup(self):
        now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"")):
            with self.assertRaises(backup.BackupError):
                backup.run_backup("postgresql://u:p@host/db", self._tmp.name, now=now)
        self.assertEqual(os.listdir(self._tmp.name), [])

    def test_missing_pg_dump_binary_raises_a_clean_backuperror(self):
        with mock.patch("backend.backup_postgres.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(backup.BackupError):
                backup.run_backup("postgresql://u:p@host/db", self._tmp.name)

    def test_database_url_is_never_written_to_the_scripts_own_stdout(self):
        # The DSN is passed to the subprocess as an argument (real pg_dump
        # needs it) but this script's own printed output/exceptions must
        # never repeat it - see module docstring.
        now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        secret_dsn = "postgresql://realuser:realpassword123@prod-host/proddb"
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"x", returncode=1, stderr=b"generic failure\n")):
            with self.assertRaises(backup.BackupError) as ctx:
                backup.run_backup(secret_dsn, self._tmp.name, now=now)
        self.assertNotIn("realpassword123", str(ctx.exception))


class PurgeOldBackupsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _touch(self, name: str) -> None:
        with open(os.path.join(self._tmp.name, name), "w") as handle:
            handle.write("x")

    def test_deletes_only_files_older_than_retention_days(self):
        self._touch("vericexa-20260101T000000Z.sql")  # old
        self._touch("vericexa-20260924T000000Z.sql")  # recent
        now = datetime(2026, 9, 25, 0, 0, 0, tzinfo=timezone.utc)
        deleted = backup.purge_old_backups(self._tmp.name, retention_days=7, now=now)
        self.assertEqual(deleted, ["vericexa-20260101T000000Z.sql"])
        self.assertEqual(sorted(os.listdir(self._tmp.name)), ["vericexa-20260924T000000Z.sql"])

    def test_never_touches_a_file_not_matching_this_scripts_own_naming_pattern(self):
        self._touch("some-other-file.sql")
        self._touch("vericexa-not-a-real-timestamp.sql")
        now = datetime(2026, 9, 25, 0, 0, 0, tzinfo=timezone.utc)
        deleted = backup.purge_old_backups(self._tmp.name, retention_days=1, now=now)
        self.assertEqual(deleted, [])
        self.assertEqual(len(os.listdir(self._tmp.name)), 2)

    def test_zero_or_negative_retention_days_raises_rather_than_deleting_everything(self):
        self._touch("vericexa-20260101T000000Z.sql")
        with self.assertRaises(backup.BackupError):
            backup.purge_old_backups(self._tmp.name, retention_days=0)
        self.assertEqual(len(os.listdir(self._tmp.name)), 1)  # untouched.


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_missing_database_url_fails_clearly_without_running_pg_dump(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("backend.backup_postgres.subprocess.run") as run_mock:
                exit_code = backup.main(["--output-dir", self._tmp.name])
        self.assertEqual(exit_code, backup.EXIT_FAILED)
        run_mock.assert_not_called()

    def test_database_url_env_var_is_honored_when_no_cli_flag_given(self):
        with mock.patch.dict(os.environ, {"DATABASE_URL": "postgresql://u:p@host/db"}, clear=True):
            with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"content")):
                exit_code = backup.main(["--output-dir", self._tmp.name])
        self.assertEqual(exit_code, backup.EXIT_OK)

    def test_retention_days_triggers_purge_after_a_successful_backup(self):
        old_name = "vericexa-20200101T000000Z.sql"
        with open(os.path.join(self._tmp.name, old_name), "w") as handle:
            handle.write("old")
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"content")):
            exit_code = backup.main(["--output-dir", self._tmp.name, "--database-url", "postgresql://u:p@host/db", "--retention-days", "1"])
        self.assertEqual(exit_code, backup.EXIT_OK)
        self.assertNotIn(old_name, os.listdir(self._tmp.name))

    def test_no_retention_days_means_nothing_is_ever_purged(self):
        old_name = "vericexa-20200101T000000Z.sql"
        with open(os.path.join(self._tmp.name, old_name), "w") as handle:
            handle.write("old")
        with mock.patch("backend.backup_postgres.subprocess.run", _fake_run_writing(b"content")):
            exit_code = backup.main(["--output-dir", self._tmp.name, "--database-url", "postgresql://u:p@host/db"])
        self.assertEqual(exit_code, backup.EXIT_OK)
        self.assertIn(old_name, os.listdir(self._tmp.name))
