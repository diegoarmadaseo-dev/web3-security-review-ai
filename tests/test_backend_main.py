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

import io
import os
import sys
import unittest
from unittest.mock import patch

import backend.main as main


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


if __name__ == "__main__":
    unittest.main()
