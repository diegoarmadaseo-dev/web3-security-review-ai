"""Tests for backend/auth.py (Phase 2 identity/access, docs/decisiones.md
D-077/D-078 follow-up): magic-link token issuance/consumption, session
issuance/validation/revocation, rate limiting, email normalization,
redirect-path safety. Pure logic against a SQLite connection - see
tests/test_backend_http_app.py for the HTTP-layer wiring (scanner/
prefetch behavior, cookies, host validation) and
tests/test_backend_postgres_integration.py for the real-Postgres
concurrent-consume race (this file's own concurrency test is the same
sequential-logical proof tests/test_backend_job_queue.py already uses
for claim_next_job, since SQLite has no FOR UPDATE SKIP LOCKED
equivalent to race for real).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import hashlib
import unittest

import backend.auth as auth
import backend.db as db
import backend.repository as repo


class NormalizeEmailTests(unittest.TestCase):
    def test_trims_and_lowercases(self):
        self.assertEqual(auth.normalize_email("  User@Example.COM  "), "user@example.com")

    def test_rejects_non_string(self):
        with self.assertRaises(auth.AuthError):
            auth.normalize_email(None)

    def test_rejects_missing_at_sign(self):
        with self.assertRaises(auth.AuthError):
            auth.normalize_email("not-an-email")

    def test_rejects_empty_string(self):
        with self.assertRaises(auth.AuthError):
            auth.normalize_email("")

    def test_rejects_missing_domain_dot(self):
        with self.assertRaises(auth.AuthError):
            auth.normalize_email("user@localhost")


class ValidateRedirectPathTests(unittest.TestCase):
    def test_valid_relative_path_is_kept(self):
        self.assertEqual(auth.validate_redirect_path("/dashboard"), "/dashboard")

    def test_none_falls_back_to_default(self):
        self.assertEqual(auth.validate_redirect_path(None), auth.DEFAULT_REDIRECT_PATH)

    def test_absolute_url_is_rejected(self):
        self.assertEqual(auth.validate_redirect_path("https://evil.example/phish"), auth.DEFAULT_REDIRECT_PATH)

    def test_protocol_relative_url_is_rejected(self):
        self.assertEqual(auth.validate_redirect_path("//evil.example/phish"), auth.DEFAULT_REDIRECT_PATH)

    def test_embedded_scheme_is_rejected(self):
        self.assertEqual(auth.validate_redirect_path("/redirect?to=javascript://evil"), auth.DEFAULT_REDIRECT_PATH)

    def test_backslash_is_rejected(self):
        self.assertEqual(auth.validate_redirect_path("/\\evil.example"), auth.DEFAULT_REDIRECT_PATH)

    def test_path_without_leading_slash_is_rejected(self):
        self.assertEqual(auth.validate_redirect_path("evil.example"), auth.DEFAULT_REDIRECT_PATH)

    def test_crlf_is_rejected(self):
        self.assertEqual(auth.validate_redirect_path("/x\r\nSet-Cookie: evil=1"), auth.DEFAULT_REDIRECT_PATH)


class RequestMagicLinkTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_returns_a_43_char_base64url_token(self):
        token = auth.request_magic_link(self.conn, "u@example.com", ip="1.2.3.4")
        self.assertEqual(len(token), 43)  # base64url(32 random bytes), no '=' padding.
        self.assertNotIn("=", token)
        self.assertNotIn("+", token)
        self.assertNotIn("/", token)

    def test_only_the_sha256_hash_is_ever_stored_never_the_raw_token(self):
        token = auth.request_magic_link(self.conn, "u@example.com")
        cur = db.execute(self.conn, "SELECT token_hash FROM auth_tokens WHERE email = ?", ("u@example.com",))
        stored_hash = db.normalize_row(cur.fetchone())["token_hash"]
        self.assertEqual(stored_hash, hashlib.sha256(token.encode("ascii")).hexdigest())
        self.assertNotEqual(stored_hash, token)

    def test_works_identically_for_an_email_with_no_existing_account(self):
        # Anti-enumeration at the data layer: no account lookup happens
        # before issuing a token - see module docstring.
        token = auth.request_magic_link(self.conn, "never-seen-before@example.com")
        self.assertEqual(len(token), 43)
        self.assertIsNone(repo.get_user_by_email(self.conn, "never-seen-before@example.com"))

    def test_two_requests_produce_two_distinct_tokens(self):
        first = auth.request_magic_link(self.conn, "u@example.com")
        second = auth.request_magic_link(self.conn, "u@example.com")
        self.assertNotEqual(first, second)

    def test_invalid_email_raises_before_touching_the_database(self):
        with self.assertRaises(auth.AuthError):
            auth.request_magic_link(self.conn, "not-an-email")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0], 0)


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_per_email_limit_is_enforced(self):
        for _ in range(auth.RATE_LIMIT_MAX_PER_EMAIL):
            auth.request_magic_link(self.conn, "u@example.com", ip="1.1.1.%d" % _)
        with self.assertRaises(auth.RateLimitExceeded):
            auth.request_magic_link(self.conn, "u@example.com", ip="9.9.9.9")

    def test_per_ip_limit_is_enforced_across_different_emails(self):
        for i in range(auth.RATE_LIMIT_MAX_PER_IP):
            auth.request_magic_link(self.conn, "user%d@example.com" % i, ip="5.5.5.5")
        with self.assertRaises(auth.RateLimitExceeded):
            auth.request_magic_link(self.conn, "one-more@example.com", ip="5.5.5.5")

    def test_different_emails_and_ips_are_not_cross_limited(self):
        for i in range(auth.RATE_LIMIT_MAX_PER_EMAIL):
            auth.request_magic_link(self.conn, "shared-victim@example.com", ip="6.6.6.%d" % i)
        # A different email from a fresh IP is unaffected.
        token = auth.request_magic_link(self.conn, "someone-else@example.com", ip="7.7.7.7")
        self.assertEqual(len(token), 43)

    def test_missing_ip_only_checks_the_per_email_limit(self):
        for _ in range(auth.RATE_LIMIT_MAX_PER_EMAIL):
            auth.request_magic_link(self.conn, "noip@example.com", ip=None)
        with self.assertRaises(auth.RateLimitExceeded):
            auth.request_magic_link(self.conn, "noip@example.com", ip=None)


class PeekAndConsumeTokenTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_peek_valid_token_returns_valid_and_never_consumes(self):
        token = auth.request_magic_link(self.conn, "u@example.com")
        for _ in range(5):  # simulate a scanner hitting it repeatedly.
            self.assertEqual(auth.peek_token(self.conn, token), auth.TOKEN_VALID)
        cur = db.execute(self.conn, "SELECT consumed_at FROM auth_tokens WHERE email = ?", ("u@example.com",))
        self.assertIsNone(db.normalize_row(cur.fetchone())["consumed_at"])

    def test_peek_unknown_token_is_invalid(self):
        self.assertEqual(auth.peek_token(self.conn, "not-a-real-token"), auth.TOKEN_INVALID_OR_EXPIRED)

    def test_peek_empty_or_non_string_token_is_invalid(self):
        self.assertEqual(auth.peek_token(self.conn, ""), auth.TOKEN_INVALID_OR_EXPIRED)

    def test_peek_expired_token_is_invalid(self):
        token = auth.request_magic_link(self.conn, "u@example.com")
        # Both columns moved into the past together (preserving
        # expires_at > created_at, which the CHECK constraint enforces)
        # rather than only expires_at - the same fixture mistake already
        # caught once for sessions_expiry_after_creation.
        db.execute(
            self.conn,
            "UPDATE auth_tokens SET created_at = ?, expires_at = ? WHERE email = ?",
            ("2000-01-01T00:00:00+00:00", "2000-01-01T00:05:00+00:00", "u@example.com"),
        )
        self.conn.commit()
        self.assertEqual(auth.peek_token(self.conn, token), auth.TOKEN_INVALID_OR_EXPIRED)

    def test_consume_creates_a_session_and_a_new_user(self):
        token = auth.request_magic_link(self.conn, "brand-new@example.com")
        self.assertIsNone(repo.get_user_by_email(self.conn, "brand-new@example.com"))
        session = auth.consume_token_and_create_session(self.conn, token)
        self.assertIsNotNone(session)
        self.assertEqual(len(session["session_token"]), 43)
        user = repo.get_user_by_email(self.conn, "brand-new@example.com")
        self.assertIsNotNone(user)
        self.assertEqual(session["user_id"], user["id"])
        self.assertIsNotNone(user["email_verified_at"])

    def test_consume_reuses_an_existing_user_and_does_not_overwrite_verified_at(self):
        user_id = repo.create_user(self.conn, "existing@example.com")
        first_verify = "2020-01-01T00:00:00+00:00"
        db.execute(self.conn, "UPDATE users SET email_verified_at = ? WHERE id = ?", (first_verify, user_id))
        self.conn.commit()
        token = auth.request_magic_link(self.conn, "existing@example.com")
        session = auth.consume_token_and_create_session(self.conn, token)
        self.assertEqual(session["user_id"], user_id)
        user = repo.get_user_by_email(self.conn, "existing@example.com")
        self.assertEqual(user["email_verified_at"], first_verify)

    def test_consume_is_single_use_second_attempt_returns_none(self):
        token = auth.request_magic_link(self.conn, "u@example.com")
        first = auth.consume_token_and_create_session(self.conn, token)
        second = auth.consume_token_and_create_session(self.conn, token)
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_sequential_conditional_consume_only_one_of_two_callers_wins(self):
        # Same logical proof as test_backend_job_queue.py's own race
        # simulation for claim_next_job - two conditional UPDATEs against
        # the SAME row, second one must see rowcount=0.
        token = auth.request_magic_link(self.conn, "u@example.com")
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        first = self.conn.execute(
            "UPDATE auth_tokens SET consumed_at = '2026-01-01T00:00:00+00:00' WHERE token_hash = ? AND consumed_at IS NULL",
            (token_hash,),
        )
        self.conn.commit()
        second = self.conn.execute(
            "UPDATE auth_tokens SET consumed_at = '2026-01-01T00:00:01+00:00' WHERE token_hash = ? AND consumed_at IS NULL",
            (token_hash,),
        )
        self.conn.commit()
        self.assertEqual(first.rowcount, 1)
        self.assertEqual(second.rowcount, 0)

    def test_consume_expired_token_returns_none_and_does_not_create_a_session(self):
        token = auth.request_magic_link(self.conn, "u@example.com")
        db.execute(
            self.conn,
            "UPDATE auth_tokens SET created_at = ?, expires_at = ? WHERE email = ?",
            ("2000-01-01T00:00:00+00:00", "2000-01-01T00:05:00+00:00", "u@example.com"),
        )
        self.conn.commit()
        self.assertIsNone(auth.consume_token_and_create_session(self.conn, token))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_consume_unknown_token_returns_none(self):
        self.assertIsNone(auth.consume_token_and_create_session(self.conn, "not-a-real-token"))

    def test_consume_empty_token_returns_none(self):
        self.assertIsNone(auth.consume_token_and_create_session(self.conn, ""))


class SessionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.user_id = repo.create_user(self.conn, "u@example.com")

    def test_only_the_sha256_hash_is_stored_never_the_raw_session_token(self):
        session = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        cur = db.execute(self.conn, "SELECT token_hash FROM sessions WHERE id = ?", (session["session_id"],))
        stored_hash = db.normalize_row(cur.fetchone())["token_hash"]
        self.assertEqual(stored_hash, hashlib.sha256(session["session_token"].encode("ascii")).hexdigest())

    def test_two_logins_never_reuse_a_session_token_no_fixation(self):
        first = auth.create_session(self.conn, self.user_id)
        second = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        self.assertNotEqual(first["session_token"], second["session_token"])
        self.assertNotEqual(first["session_id"], second["session_id"])

    def test_validate_valid_session_returns_user_id(self):
        session = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        result = auth.validate_session(self.conn, session["session_token"])
        self.assertEqual(result["user_id"], self.user_id)

    def test_validate_unknown_token_returns_none(self):
        self.assertIsNone(auth.validate_session(self.conn, "not-a-real-session-token"))

    def test_validate_expired_session_returns_none(self):
        session = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        db.execute(
            self.conn,
            "UPDATE sessions SET created_at = ?, expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", "2000-01-01T00:05:00+00:00", session["session_id"]),
        )
        self.conn.commit()
        self.assertIsNone(auth.validate_session(self.conn, session["session_token"]))

    def test_revoke_then_validate_returns_none(self):
        session = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        self.assertTrue(auth.revoke_session(self.conn, session["session_token"]))
        self.assertIsNone(auth.validate_session(self.conn, session["session_token"]))

    def test_revoking_twice_the_second_call_returns_false(self):
        session = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        self.assertTrue(auth.revoke_session(self.conn, session["session_token"]))
        self.assertFalse(auth.revoke_session(self.conn, session["session_token"]))

    def test_revoking_an_unknown_token_returns_false_never_raises(self):
        self.assertFalse(auth.revoke_session(self.conn, "not-a-real-session-token"))

    def test_validate_touches_last_seen_at(self):
        session = auth.create_session(self.conn, self.user_id)
        self.conn.commit()
        auth.validate_session(self.conn, session["session_token"])
        cur = db.execute(self.conn, "SELECT last_seen_at FROM sessions WHERE id = ?", (session["session_id"],))
        self.assertIsNotNone(db.normalize_row(cur.fetchone())["last_seen_at"])


if __name__ == "__main__":
    unittest.main()
