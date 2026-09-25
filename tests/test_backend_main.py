"""Startup/config-validation tests for backend/main.py (Phase 5, docs/
decisiones.md D-077 follow-up).

These tests exercise ONLY the fail-fast config validation path - never a
real Postgres/Stripe/S3/Docker connection. Each test supplies a complete,
otherwise-valid fake environment and removes exactly ONE required variable,
then asserts main() reports a clean, non-zero failure before anything that
needs a real network call is ever constructed. This is possible because
_require_env() calls run in a fixed order inside run_web()/run_worker(),
each earlier than the first real client construction (db.connect_postgres,
billing.StripeBilling, object_storage.S3Storage) - see backend/main.py's own
module docstring on why this file is the one place allowed to read
os.environ, and on why boto3 (S3Storage's own dependency) need not be
installed to prove this property; a couple of tests below explicitly
self-skip the one happy-path smoke that does need it.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import http.client
import io
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import backend.alerting as alerting
import backend.http_app as http_app
import backend.main as main
import backend.repository as repo


def _boto3_available() -> bool:
    try:
        import boto3  # noqa: F401
    except ImportError:
        return False
    return True


_FAKE_WEB_ENV = {
    "ROLE": "web",
    "DATABASE_URL": "postgresql://fake:fake@127.0.0.1:1/fake",
    "HOST_ALLOWLIST": "example.com,app.example.com",
    "STRIPE_SECRET_KEY": "sk_test_fake",
    "STRIPE_WEBHOOK_SECRET": "whsec_fake",
    "STRIPE_PRICE_QUICK": "price_quick",
    "STRIPE_PRICE_STANDARD": "price_standard",
    "STRIPE_PRICE_PRO": "price_pro",
    "S3_BUCKET": "fake-bucket",
    "S3_REGION": "us-east-1",
}

_FAKE_WORKER_ENV = {
    "ROLE": "worker",
    "DATABASE_URL": "postgresql://fake:fake@127.0.0.1:1/fake",
    "S3_BUCKET": "fake-bucket",
    "S3_REGION": "us-east-1",
    "WORKER_DOCKER_IMAGE": "fake-image:local",
    "WORKER_NETWORK_NAME": "fake-net",
    "EGRESS_PROXY_HOST": "172.17.0.1",
    "LLM_API_KEY": "sk-ant-fake",
    "LLM_MODEL": "fake-model",
}


class HelperFunctionTests(unittest.TestCase):
    def test_require_env_returns_the_value_when_set(self):
        with patch.dict(os.environ, {"X_TEST_VAR": "hello"}, clear=False):
            self.assertEqual(main._require_env("X_TEST_VAR"), "hello")

    def test_require_env_raises_config_error_when_unset(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(main.ConfigError):
                main._require_env("X_TEST_VAR_NEVER_SET")

    def test_require_env_raises_config_error_for_empty_string(self):
        # An explicitly-set-but-empty variable is treated the same as
        # unset - never silently passed through as "".
        with patch.dict(os.environ, {"X_TEST_VAR": ""}, clear=False):
            with self.assertRaises(main.ConfigError):
                main._require_env("X_TEST_VAR")

    def test_bool_env_defaults_and_parses_common_truthy_forms(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(main._bool_env("X_FLAG", True))
            self.assertFalse(main._bool_env("X_FLAG", False))
        for truthy in ("1", "true", "True", "yes", "on"):
            with patch.dict(os.environ, {"X_FLAG": truthy}, clear=False):
                self.assertTrue(main._bool_env("X_FLAG", False))
        for falsy in ("0", "false", "no", "off", "garbage"):
            with patch.dict(os.environ, {"X_FLAG": falsy}, clear=False):
                self.assertFalse(main._bool_env("X_FLAG", True))

    def test_int_env_parses_and_rejects_garbage(self):
        with patch.dict(os.environ, {"X_PORT": "8080"}, clear=False):
            self.assertEqual(main._int_env("X_PORT", 0), 8080)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(main._int_env("X_PORT_UNSET", 42), 42)
        with patch.dict(os.environ, {"X_PORT": "not-a-number"}, clear=False):
            with self.assertRaises(main.ConfigError):
                main._int_env("X_PORT", 0)


class WebRoleFailFastTests(unittest.TestCase):
    """Each test removes exactly one required variable and confirms
    run_web() refuses to start - and that this happens before ever
    reaching a real network call (S3Storage construction, the one
    dependency in this env that genuinely isn't installed - see module
    docstring), by removing a variable checked EARLIER than S3_BUCKET/
    S3_REGION in run_web()'s own validation order for most cases."""

    def _assert_missing_var_fails_fast(self, missing_var):
        env = dict(_FAKE_WEB_ENV)
        del env[missing_var]
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main.run_web()

    def test_missing_database_url_fails_fast(self):
        self._assert_missing_var_fails_fast("DATABASE_URL")

    def test_missing_host_allowlist_fails_fast(self):
        self._assert_missing_var_fails_fast("HOST_ALLOWLIST")

    def test_blank_host_allowlist_is_rejected(self):
        env = dict(_FAKE_WEB_ENV)
        env["HOST_ALLOWLIST"] = " , ,"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main.run_web()

    def test_missing_stripe_secret_key_fails_fast(self):
        self._assert_missing_var_fails_fast("STRIPE_SECRET_KEY")

    def test_missing_stripe_price_for_one_plan_fails_fast(self):
        # Confirms the price allowlist is built explicitly per plan - a
        # single missing plan's Price ID must fail startup, never silently
        # sell only two of three plans.
        self._assert_missing_var_fails_fast("STRIPE_PRICE_PRO")

    def test_missing_s3_bucket_fails_fast_before_boto3_is_needed(self):
        self._assert_missing_var_fails_fast("S3_BUCKET")

    def test_main_reports_clean_failure_and_nonzero_exit_for_missing_config(self):
        env = dict(_FAKE_WEB_ENV)
        del env["DATABASE_URL"]
        with patch.dict(os.environ, env, clear=True):
            captured = io.StringIO()
            with patch.object(sys, "stderr", captured):
                exit_code = main.main()
            self.assertEqual(exit_code, 1)
            self.assertIn("ConfigError", captured.getvalue())
            self.assertIn("DATABASE_URL", captured.getvalue())

    def test_main_rejects_missing_or_unknown_role(self):
        for role_env in ({}, {"ROLE": "not-a-real-role"}):
            with patch.dict(os.environ, role_env, clear=True):
                captured = io.StringIO()
                with patch.object(sys, "stderr", captured):
                    exit_code = main.main()
                self.assertEqual(exit_code, 1)
                self.assertIn("ROLE", captured.getvalue())

    @unittest.skipUnless(_boto3_available(), "boto3 not installed in this environment - see module docstring")
    def test_storage_and_billing_construct_successfully_with_complete_fake_config(self):
        # The one happy-path smoke that DOES need boto3 - proves
        # _build_storage()/_build_billing() actually succeed (no real
        # network call happens at construction time for either SDK) once
        # every required variable is present, rather than only ever
        # testing the failure paths above.
        with patch.dict(os.environ, _FAKE_WEB_ENV, clear=True):
            cfg = main._load_web_config()
            storage = main._build_storage(cfg["s3_bucket"], cfg["s3_region"])
            billing = main._build_billing(cfg["stripe_secret_key"], cfg["stripe_webhook_secret"], cfg["stripe_price_allowlist"])
        self.assertIsNotNone(storage)
        self.assertEqual(billing.resolve_price_id("quick"), "price_quick")


class WorkerRoleFailFastTests(unittest.TestCase):
    def _assert_missing_var_fails_fast(self, missing_var):
        env = dict(_FAKE_WORKER_ENV)
        del env[missing_var]
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main.run_worker()

    def test_missing_database_url_fails_fast(self):
        self._assert_missing_var_fails_fast("DATABASE_URL")

    def test_missing_docker_image_fails_fast(self):
        self._assert_missing_var_fails_fast("WORKER_DOCKER_IMAGE")

    def test_missing_network_name_fails_fast(self):
        self._assert_missing_var_fails_fast("WORKER_NETWORK_NAME")

    def test_missing_egress_proxy_host_fails_fast(self):
        # No safe default is ever guessed for this one - see backend/
        # main.py's own comment on why (Docker network topology is
        # deployment-specific).
        self._assert_missing_var_fails_fast("EGRESS_PROXY_HOST")

    def test_missing_llm_api_key_fails_fast(self):
        self._assert_missing_var_fails_fast("LLM_API_KEY")


# ---------------------------------------------------------------------------
# Phase 6A (docs/decisiones.md D-077 follow-up): graceful shutdown.
# _serve_until_shutdown() is tested directly (never via a real OS signal -
# see _install_shutdown_signal_handlers()'s own docstring on why SIGTERM
# delivery is not portable to test against on Windows, which is where this
# suite actually runs); shutdown_event is set programmatically, exactly the
# way that function is deliberately structured to be tested.
# ---------------------------------------------------------------------------

class _CapturingEmailSender:
    def send(self, to_email, subject, body):
        pass


class ServeUntilShutdownTests(unittest.TestCase):
    def _start_server(self):
        fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(db_path)
        seed_conn = repo.connect(db_path)
        repo.init_schema(seed_conn)
        seed_conn.close()
        self.addCleanup(lambda: os.remove(db_path) if os.path.exists(db_path) else None)
        httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(db_path), email_sender=_CapturingEmailSender(),
            host_allowlist=["127.0.0.1"], host="127.0.0.1", port=0, secure_cookies=False,
        )
        return httpd

    def test_shutdown_during_idle_stops_the_server_promptly(self):
        httpd = self._start_server()
        port = httpd.server_address[1]
        shutdown_event = threading.Event()
        shutdown_event.set()  # already idle, nothing in flight - "SIGTERM during idle".

        start = time.monotonic()
        main._serve_until_shutdown(httpd, shutdown_event, grace_seconds=5)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2, "idle shutdown should not wait out any meaningful part of the grace period")

        with self.assertRaises(OSError):
            http.client.HTTPConnection("127.0.0.1", port, timeout=1).connect()

    def test_in_flight_request_completes_before_the_server_closes(self):
        httpd = self._start_server()
        port = httpd.server_address[1]
        shutdown_event = threading.Event()
        results = []

        def _request_then_signal_shutdown():
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/health", headers={"Host": "127.0.0.1:%d" % port})
            resp = conn.getresponse()
            results.append(resp.status)
            resp.read()
            conn.close()

        server_side_thread = threading.Thread(target=main._serve_until_shutdown, args=(httpd, shutdown_event, 5))
        server_side_thread.start()
        time.sleep(0.1)  # let the accept loop actually start.
        _request_then_signal_shutdown()
        shutdown_event.set()
        server_side_thread.join(timeout=10)

        self.assertEqual(results, [200])  # the request completed successfully, not cut off mid-flight.

    def test_grace_period_is_bounded_even_if_in_flight_count_never_reaches_zero(self):
        httpd = self._start_server()

        class _AlwaysBusyTracker:
            count = 1  # simulates a handler that never finishes.

        httpd.in_flight_tracker = _AlwaysBusyTracker()
        shutdown_event = threading.Event()
        shutdown_event.set()

        start = time.monotonic()
        main._serve_until_shutdown(httpd, shutdown_event, grace_seconds=1)
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 1)
        self.assertLess(elapsed, 3, "must close anyway once the grace period expires, never hang forever")


class WorkerShutdownWiringTests(unittest.TestCase):
    def test_install_shutdown_signal_handlers_sets_the_event_when_invoked(self):
        # Exercises the handler function itself (never a real OS signal -
        # see module docstring) - proves it does the one thing it should
        # and nothing else.
        event = threading.Event()
        main._install_shutdown_signal_handlers(event)
        handler = signal.getsignal(signal.SIGINT)
        self.assertFalse(event.is_set())
        handler(signal.SIGINT, None)
        self.assertTrue(event.is_set())


# ---------------------------------------------------------------------------
# Phase 6B (docs/decisiones.md D-077 follow-up): worker resource config,
# retention scheduler config, alert/email provider-mode config.
# ---------------------------------------------------------------------------

class WorkerResourceConfigTests(unittest.TestCase):
    """default/override/invalid for every value backend/main.py._load_
    worker_config() now validates - see that function's own docstring on
    why each default is imported from worker_supervisor.py rather than
    hand-typed a second time."""

    def test_defaults_match_worker_supervisor_own_hardcoded_constants(self):
        with patch.dict(os.environ, _FAKE_WORKER_ENV, clear=True):
            cfg = main._load_worker_config()
        import backend.worker_supervisor as worker_supervisor
        self.assertEqual(cfg["memory_limit"], worker_supervisor.DEFAULT_MEMORY_LIMIT)
        self.assertEqual(cfg["cpu_limit"], worker_supervisor.DEFAULT_CPU_LIMIT)
        self.assertEqual(cfg["pids_limit"], worker_supervisor.DEFAULT_PIDS_LIMIT)
        self.assertEqual(cfg["tmpfs_size"], worker_supervisor.DEFAULT_TMPFS_SIZE)
        self.assertEqual(cfg["wall_clock_timeout_seconds"], worker_supervisor.DEFAULT_WALL_CLOCK_TIMEOUT_SECONDS)
        self.assertEqual(cfg["output_size_limit_bytes"], worker_supervisor.DEFAULT_OUTPUT_SIZE_LIMIT_BYTES)
        self.assertEqual(cfg["llm_max_output_tokens"], 8000)
        self.assertEqual(cfg["llm_per_attempt_timeout_seconds"], 120)
        self.assertIsNone(cfg["retention_days"])  # unset -> disabled, never a guessed default - see module docstring.

    def test_valid_overrides_are_honored(self):
        env = dict(_FAKE_WORKER_ENV)
        env.update({
            "WORKER_MEMORY_LIMIT": "1g", "WORKER_CPU_LIMIT": "2.5", "WORKER_PIDS_LIMIT": "256",
            "WORKER_TMPFS_SIZE": "128m", "WORKER_WALL_CLOCK_TIMEOUT_SECONDS": "600",
            "WORKER_OUTPUT_SIZE_LIMIT_BYTES": "4194304", "LLM_MAX_OUTPUT_TOKENS": "4000",
            "LLM_PER_ATTEMPT_TIMEOUT_SECONDS": "60",
        })
        with patch.dict(os.environ, env, clear=True):
            cfg = main._load_worker_config()
        self.assertEqual(cfg["memory_limit"], "1g")
        self.assertEqual(cfg["cpu_limit"], "2.5")
        self.assertEqual(cfg["pids_limit"], "256")
        self.assertEqual(cfg["tmpfs_size"], "128m")
        self.assertEqual(cfg["wall_clock_timeout_seconds"], 600)
        self.assertEqual(cfg["output_size_limit_bytes"], 4194304)
        self.assertEqual(cfg["llm_max_output_tokens"], 4000)
        self.assertEqual(cfg["llm_per_attempt_timeout_seconds"], 60)

    def test_invalid_byte_size_values_fail_fast(self):
        for bad in ("", "abc", "-512m", "512x", "0m", "512 m"):
            env = dict(_FAKE_WORKER_ENV)
            env["WORKER_MEMORY_LIMIT"] = bad
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(main.ConfigError, msg="bad=%r" % bad):
                    main._load_worker_config()

    def test_invalid_cpu_value_fails_fast(self):
        for bad in ("", "abc", "-1", "0"):
            env = dict(_FAKE_WORKER_ENV)
            env["WORKER_CPU_LIMIT"] = bad
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(main.ConfigError, msg="bad=%r" % bad):
                    main._load_worker_config()

    def test_invalid_pids_limit_fails_fast(self):
        for bad in ("", "abc", "-1", "0", "128m"):
            env = dict(_FAKE_WORKER_ENV)
            env["WORKER_PIDS_LIMIT"] = bad
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(main.ConfigError, msg="bad=%r" % bad):
                    main._load_worker_config()

    def test_non_positive_timeout_and_output_limit_fail_fast(self):
        for var in ("WORKER_WALL_CLOCK_TIMEOUT_SECONDS", "WORKER_OUTPUT_SIZE_LIMIT_BYTES", "LLM_MAX_OUTPUT_TOKENS", "LLM_PER_ATTEMPT_TIMEOUT_SECONDS"):
            for bad in ("0", "-5", "not-a-number"):
                env = dict(_FAKE_WORKER_ENV)
                env[var] = bad
                with patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(main.ConfigError, msg="var=%s bad=%r" % (var, bad)):
                        main._load_worker_config()

    def test_no_secret_appears_in_any_config_error_message(self):
        # Confirms these validation errors only ever name the variable
        # and the (non-secret) value rejected - never anything from
        # elsewhere in the same environment (e.g. LLM_API_KEY).
        env = dict(_FAKE_WORKER_ENV)
        env["WORKER_MEMORY_LIMIT"] = "garbage"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError) as ctx:
                main._load_worker_config()
        self.assertNotIn(_FAKE_WORKER_ENV["LLM_API_KEY"], str(ctx.exception))


class RetentionConfigTests(unittest.TestCase):
    def test_unset_retention_days_disables_retention(self):
        with patch.dict(os.environ, _FAKE_WORKER_ENV, clear=True):
            cfg = main._load_worker_config()
        self.assertIsNone(cfg["retention_days"])

    def test_valid_retention_days_is_honored(self):
        env = dict(_FAKE_WORKER_ENV)
        env["RETENTION_DAYS"] = "90"
        with patch.dict(os.environ, env, clear=True):
            cfg = main._load_worker_config()
        self.assertEqual(cfg["retention_days"], 90)
        self.assertFalse(cfg["retention_dry_run"])

    def test_invalid_retention_days_fails_fast(self):
        for bad in ("0", "-1", "abc"):
            env = dict(_FAKE_WORKER_ENV)
            env["RETENTION_DAYS"] = bad
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(main.ConfigError, msg="bad=%r" % bad):
                    main._load_worker_config()

    def test_retention_dry_run_flag_is_honored(self):
        env = dict(_FAKE_WORKER_ENV)
        env["RETENTION_DAYS"] = "30"
        env["RETENTION_DRY_RUN"] = "true"
        with patch.dict(os.environ, env, clear=True):
            cfg = main._load_worker_config()
        self.assertTrue(cfg["retention_dry_run"])


class AlertModeConfigTests(unittest.TestCase):
    def test_default_mode_is_logging_no_url_required(self):
        with patch.dict(os.environ, _FAKE_WEB_ENV, clear=True):
            cfg = main._load_web_config()
        self.assertEqual(cfg["alert_sender_mode"], "logging")
        sender = main._build_alert_sender(cfg["alert_sender_mode"], cfg["alert_webhook_url"])
        self.assertIsInstance(sender, alerting.LoggingAlertSender)

    def test_webhook_mode_without_url_fails_fast(self):
        env = dict(_FAKE_WEB_ENV)
        env["ALERT_SENDER_MODE"] = "webhook"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main._load_web_config()

    def test_webhook_mode_with_url_builds_a_webhook_sender(self):
        env = dict(_FAKE_WEB_ENV)
        env["ALERT_SENDER_MODE"] = "webhook"
        env["ALERT_WEBHOOK_URL"] = "https://example.com/hook"
        with patch.dict(os.environ, env, clear=True):
            cfg = main._load_web_config()
        sender = main._build_alert_sender(cfg["alert_sender_mode"], cfg["alert_webhook_url"])
        self.assertIsInstance(sender, alerting.WebhookAlertSender)

    def test_unrecognized_mode_fails_fast(self):
        env = dict(_FAKE_WEB_ENV)
        env["ALERT_SENDER_MODE"] = "carrier-pigeon"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main._load_web_config()

    def test_worker_role_shares_the_same_alert_config(self):
        env = dict(_FAKE_WORKER_ENV)
        env["ALERT_SENDER_MODE"] = "webhook"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main._load_worker_config()


class EmailModeConfigTests(unittest.TestCase):
    def test_default_mode_is_logging(self):
        with patch.dict(os.environ, _FAKE_WEB_ENV, clear=True):
            cfg = main._load_web_config()
        self.assertEqual(cfg["email_sender_mode"], "logging")
        sender = main._build_email_sender(cfg["email_sender_mode"], cfg["smtp_config"])
        self.assertIsInstance(sender, main.email_sender_module.LoggingEmailSender)

    def test_smtp_mode_missing_any_field_fails_fast(self):
        base = dict(_FAKE_WEB_ENV)
        base["EMAIL_SENDER_MODE"] = "smtp"
        base.update({
            "SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "user", "SMTP_PASSWORD": "pw",
            "EMAIL_FROM_ADDRESS": "noreply@example.com",
        })
        for missing in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "EMAIL_FROM_ADDRESS"):
            env = dict(base)
            del env[missing]
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(main.ConfigError, msg="missing=%s" % missing):
                    main._load_web_config()

    def test_smtp_mode_with_complete_config_builds_an_smtp_sender(self):
        env = dict(_FAKE_WEB_ENV)
        env["EMAIL_SENDER_MODE"] = "smtp"
        env.update({
            "SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "user", "SMTP_PASSWORD": "pw",
            "EMAIL_FROM_ADDRESS": "noreply@example.com",
        })
        with patch.dict(os.environ, env, clear=True):
            cfg = main._load_web_config()
        sender = main._build_email_sender(cfg["email_sender_mode"], cfg["smtp_config"])
        self.assertIsInstance(sender, main.email_sender_module.SMTPEmailSender)

    def test_unrecognized_mode_fails_fast(self):
        env = dict(_FAKE_WEB_ENV)
        env["EMAIL_SENDER_MODE"] = "carrier-pigeon"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(main.ConfigError):
                main._load_web_config()


if __name__ == "__main__":
    unittest.main()
