"""End-to-end HTTP tests for backend/http_app.py (Phase 2 identity/access,
docs/decisiones.md D-077/D-078 follow-up): real requests via
http.client against a real running server, same convention
tests/test_website_server.py already established for website/server.py.

Deep token/session logic is unit-tested in tests/test_backend_auth.py;
this file proves the HTTP WIRING - routing, cookies, status codes,
redirects, and the scanner/prefetch safety property that only exists at
this layer (GET never consumes, only a POST does).

Each test gets its own fresh server + fresh file-backed SQLite database
(never :memory: - a connection-per-request server needs every request's
connection to see the SAME data, which a shared :memory: connection
across threads cannot do safely).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

import backend.http_app as http_app
import backend.repository as repo
import backend.tenant_scope as tenant_scope

HOST = "127.0.0.1"


@contextlib.contextmanager
def _capture_stderr():
    """Swaps sys.stderr for the duration of the block - the background
    server thread writes access-log lines to the SAME process-global
    sys.stderr (never thread-local), so this reliably captures them."""
    captured = io.StringIO()
    original = sys.stderr
    sys.stderr = captured
    try:
        yield captured
    finally:
        sys.stderr = original


def _apply_header_overrides(hdrs, overrides):
    """Merges overrides into hdrs, but a None value REMOVES that key
    instead of sending the literal string "None" - lets a test omit a
    default header entirely (e.g. Origin) by passing {"Origin": None}."""
    if not overrides:
        return
    for key, value in overrides.items():
        if value is None:
            hdrs.pop(key, None)
        else:
            hdrs[key] = value


class _CapturingEmailSender:
    def __init__(self):
        self.sent = []

    def send(self, to_email, subject, body):
        self.sent.append((to_email, subject, body))

    def last_token(self):
        _, _, body = self.sent[-1]
        match = re.search(r"token=([A-Za-z0-9_-]+)", body)
        return match.group(1) if match else None


class _HttpAppTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)  # repo.connect creates it fresh.
        seed_conn = repo.connect(self.db_path)
        repo.init_schema(seed_conn)
        seed_conn.close()

        self.email_sender = _CapturingEmailSender()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path),
            email_sender=self.email_sender,
            host_allowlist=[HOST],  # hostname only - the ephemeral port is irrelevant to the check.
            host=HOST,
            port=0,
            secure_cookies=False,  # plain-HTTP local test - see http_app.py's module docstring.
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header  # the Origin a normal same-origin browser request sends.
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        # Cleanups run LIFO: register removal first so shutdown (registered
        # last) runs FIRST - the server and its in-flight connections must
        # be fully stopped before the file is removed (Windows cannot
        # delete a file with any open sqlite3 handle on it).
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)

    def _shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _conn(self):
        return http.client.HTTPConnection(HOST, self.port, timeout=5)

    def post_json(self, path, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        conn = self._conn()
        # Origin defaults to this server's own origin - a normal
        # same-origin browser request always sends one; tests targeting
        # the CSRF defense itself override or omit it explicitly.
        hdrs = {"Content-Type": "application/json", "Content-Length": str(len(body)), "Host": self.host_header, "Origin": self.same_origin}
        _apply_header_overrides(hdrs, headers)
        conn.request("POST", path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result

    def post_form(self, path, fields, headers=None):
        body = urlencode(fields).encode("ascii")
        conn = self._conn()
        hdrs = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body)), "Host": self.host_header, "Origin": self.same_origin}
        _apply_header_overrides(hdrs, headers)
        conn.request("POST", path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result

    def get(self, path, headers=None):
        conn = self._conn()
        hdrs = {"Host": self.host_header}
        if headers:
            hdrs.update(headers)
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result

    def delete(self, path, headers=None):
        conn = self._conn()
        hdrs = {"Host": self.host_header, "Origin": self.same_origin}
        _apply_header_overrides(hdrs, headers)
        conn.request("DELETE", path, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result

    def request_and_confirm_login(self, email):
        """Full happy-path login: request-link, extract the token the
        email "sent", GET (safe peek), POST (actual consume). Returns the
        Set-Cookie header value from the final POST."""
        self.post_json("/auth/request-link", {"email": email})
        token = self.email_sender.last_token()
        self.get("/auth/verify?token=%s" % token)  # simulated scanner/human preview - must not consume.
        status, headers, _ = self.post_form("/auth/verify", {"token": token, "redirect": "/dashboard"})
        self.assertEqual(status, 303)
        return headers["Set-Cookie"].split(";")[0]  # "session=<token>"


class RequestLinkTests(_HttpAppTestCase):
    def test_unknown_and_known_email_get_identical_generic_response(self):
        seed_conn = repo.connect(self.db_path)
        repo.create_user(seed_conn, "known-1@example.com")
        seed_conn.close()  # Windows cannot delete a file with an open sqlite3 handle, see tearDown cleanup.
        s1, _, b1 = self.post_json("/auth/request-link", {"email": "unknown-1@example.com"})
        s2, _, b2 = self.post_json("/auth/request-link", {"email": "known-1@example.com"})
        self.assertEqual((s1, b1), (s2, b2))

    def test_malformed_email_returns_400(self):
        status, _, _ = self.post_json("/auth/request-link", {"email": "not-an-email"})
        self.assertEqual(status, 400)

    def test_invalid_json_body_returns_400(self):
        conn = self._conn()
        body = b"{not json"
        conn.request(
            "POST", "/auth/request-link", body=body,
            headers={"Content-Length": str(len(body)), "Host": self.host_header, "Origin": self.same_origin},
        )
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 400)

    def test_missing_content_length_returns_400(self):
        conn = self._conn()
        conn.putrequest("POST", "/auth/request-link")
        conn.putheader("Host", self.host_header)
        conn.putheader("Origin", self.same_origin)  # a same-origin request, so this hits the Content-Length check specifically.
        conn.endheaders()
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 400)

    def test_oversized_body_returns_413(self):
        conn = self._conn()
        body = b"x" * (http_app.MAX_BODY_BYTES + 1)
        conn.request(
            "POST", "/auth/request-link", body=body,
            headers={"Content-Length": str(len(body)), "Host": self.host_header, "Origin": self.same_origin},
        )
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 413)

    def test_untrusted_host_header_returns_400(self):
        status, _, _ = self.post_json("/auth/request-link", {"email": "u@example.com"}, headers={"Host": "evil.example"})
        self.assertEqual(status, 400)

    def test_email_actually_sent_contains_a_verify_link_with_a_token(self):
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        self.assertEqual(len(self.email_sender.sent), 1)
        to_email, _, body = self.email_sender.sent[0]
        self.assertEqual(to_email, "u@example.com")
        self.assertIn("/auth/verify?token=", body)

    def test_rate_limit_returns_429_after_threshold(self):
        import backend.auth as auth
        for i in range(auth.RATE_LIMIT_MAX_PER_EMAIL):
            status, _, _ = self.post_json("/auth/request-link", {"email": "ratelimited@example.com"})
            self.assertEqual(status, 200)
        status, _, _ = self.post_json("/auth/request-link", {"email": "ratelimited@example.com"})
        self.assertEqual(status, 429)


class VerifyFlowTests(_HttpAppTestCase):
    def test_get_verify_valid_token_returns_confirm_page_html(self):
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        token = self.email_sender.last_token()
        status, headers, body = self.get("/auth/verify?token=%s" % token)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"Confirm sign-in", body)

    def test_get_verify_invalid_token_returns_generic_invalid_page(self):
        status, _, body = self.get("/auth/verify?token=not-a-real-token")
        self.assertEqual(status, 200)
        self.assertIn(b"invalid or has expired", body)

    def test_repeated_get_scans_never_consume_then_post_still_succeeds(self):
        # The scanner/prefetch safety property itself: simulate an email
        # security gateway hitting the GET link 5 times before the human
        # ever clicks anything.
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        token = self.email_sender.last_token()
        for _ in range(5):
            status, _, _ = self.get("/auth/verify?token=%s" % token)
            self.assertEqual(status, 200)
        status, headers, _ = self.post_form("/auth/verify", {"token": token, "redirect": "/dashboard"})
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/dashboard")

    def test_post_verify_sets_httponly_samesite_cookie(self):
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        token = self.email_sender.last_token()
        _, headers, _ = self.post_form("/auth/verify", {"token": token})
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("%s=" % http_app.SESSION_COOKIE_NAME, cookie)
        # secure_cookies=False for this local-HTTP test suite - see setUp.
        self.assertNotIn("Secure", cookie)

    def test_post_verify_second_time_with_same_token_returns_invalid_page(self):
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        token = self.email_sender.last_token()
        first_status, _, _ = self.post_form("/auth/verify", {"token": token})
        second_status, _, second_body = self.post_form("/auth/verify", {"token": token})
        self.assertEqual(first_status, 303)
        self.assertEqual(second_status, 200)
        self.assertIn(b"invalid or has expired", second_body)

    def test_post_verify_with_open_redirect_attempt_falls_back_to_default(self):
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        token = self.email_sender.last_token()
        _, headers, _ = self.post_form("/auth/verify", {"token": token, "redirect": "https://evil.example/phish"})
        self.assertEqual(headers["Location"], http_app.auth.DEFAULT_REDIRECT_PATH)

    def test_post_verify_unknown_token_returns_invalid_page_never_500(self):
        status, _, body = self.post_form("/auth/verify", {"token": "not-a-real-token"})
        self.assertEqual(status, 200)
        self.assertIn(b"invalid or has expired", body)


class LogoutTests(_HttpAppTestCase):
    def test_logout_revokes_session_and_clears_cookie(self):
        cookie = self.request_and_confirm_login("u@example.com")
        status, headers, body = self.post_json("/auth/logout", {}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        cleared = headers["Set-Cookie"]
        self.assertIn("Max-Age=0", cleared)
        # The now-revoked session cookie no longer authenticates anything.
        status2, _, body2 = self.post_json(
            "/workspaces/does-not-matter/members", {"email": "x@example.com", "role": "member"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status2, 401)

    def test_logout_without_a_cookie_is_a_harmless_no_op(self):
        status, _, body = self.post_json("/auth/logout", {})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])


class MemberManagementTests(_HttpAppTestCase):
    def setUp(self):
        super().setUp()
        conn = repo.connect(self.db_path)
        self.owner_a = repo.create_user(conn, "owner-a@example.com")
        self.workspace_a = repo.create_workspace(conn, "Workspace A", self.owner_a)
        self.owner_b = repo.create_user(conn, "owner-b@example.com")
        self.workspace_b = repo.create_workspace(conn, "Workspace B", self.owner_b)
        conn.close()

    def _login_as(self, email):
        return self.request_and_confirm_login(email)

    def test_add_member_requires_authentication(self):
        status, _, _ = self.post_json(
            "/workspaces/%s/members" % self.workspace_a, {"email": "new@example.com", "role": "member"}
        )
        self.assertEqual(status, 401)

    def test_owner_can_add_a_brand_new_member(self):
        cookie = self._login_as("owner-a@example.com")
        status, _, body = self.post_json(
            "/workspaces/%s/members" % self.workspace_a,
            {"email": "brand-new-member@example.com", "role": "member"},
            headers={"Cookie": cookie},
        )
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result["ok"])
        conn = repo.connect(self.db_path)
        role = tenant_scope.resolve_workspace_role(conn, result["user_id"], self.workspace_a)
        conn.close()
        self.assertEqual(role, "member")

    def test_plain_member_cannot_add_members(self):
        conn = repo.connect(self.db_path)
        member_user = repo.create_user(conn, "plain-member@example.com")
        repo.add_workspace_member(conn, self.workspace_a, member_user, "member")
        conn.close()
        cookie = self._login_as("plain-member@example.com")
        status, _, _ = self.post_json(
            "/workspaces/%s/members" % self.workspace_a, {"email": "x@example.com", "role": "member"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 403)

    def test_owner_of_workspace_b_cannot_add_members_to_workspace_a(self):
        cookie = self._login_as("owner-b@example.com")
        status, _, _ = self.post_json(
            "/workspaces/%s/members" % self.workspace_a, {"email": "x@example.com", "role": "member"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 403)

    def test_adding_an_already_existing_member_returns_409(self):
        cookie = self._login_as("owner-a@example.com")
        self.post_json(
            "/workspaces/%s/members" % self.workspace_a, {"email": "dup@example.com", "role": "member"}, headers={"Cookie": cookie}
        )
        status, _, _ = self.post_json(
            "/workspaces/%s/members" % self.workspace_a, {"email": "dup@example.com", "role": "member"}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 409)

    def test_owner_can_remove_a_member(self):
        conn = repo.connect(self.db_path)
        target = repo.create_user(conn, "removable@example.com")
        repo.add_workspace_member(conn, self.workspace_a, target, "member")
        conn.close()
        cookie = self._login_as("owner-a@example.com")
        status, _, body = self.delete("/workspaces/%s/members/%s" % (self.workspace_a, target), headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["removed"])

    def test_cross_tenant_member_removal_is_forbidden(self):
        # owner-b (member/owner only of workspace B) tries to remove
        # owner-a's own membership from workspace A.
        cookie = self._login_as("owner-b@example.com")
        status, _, _ = self.delete("/workspaces/%s/members/%s" % (self.workspace_a, self.owner_a), headers={"Cookie": cookie})
        self.assertEqual(status, 403)

    def test_remove_requires_authentication(self):
        status, _, _ = self.delete("/workspaces/%s/members/%s" % (self.workspace_a, self.owner_a))
        self.assertEqual(status, 401)


class MiscRoutingTests(_HttpAppTestCase):
    def test_unknown_path_returns_404(self):
        status, _, _ = self.get("/no/such/path")
        self.assertEqual(status, 404)

    def test_unknown_post_path_returns_404(self):
        status, _, _ = self.post_json("/no/such/path", {})
        self.assertEqual(status, 404)


class CsrfDefenseTests(_HttpAppTestCase):
    """Regression coverage for the Phase 2 final-audit blocker fixes
    (docs/decisiones.md D-077/D-078 follow-up): Origin/Host CSRF defense
    on every state-changing handler, and the login-CSRF scenario it
    specifically closes."""

    def test_valid_same_origin_post_succeeds(self):
        status, _, _ = self.post_json("/auth/request-link", {"email": "same-origin@example.com"})
        self.assertEqual(status, 200)

    def test_cross_origin_post_to_request_link_is_rejected(self):
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://evil.example"}
        )
        self.assertEqual(status, 403)

    def test_missing_origin_on_request_link_is_rejected(self):
        status, _, _ = self.post_json("/auth/request-link", {"email": "u@example.com"}, headers={"Origin": None})
        self.assertEqual(status, 403)

    def test_invalid_origin_value_on_request_link_is_rejected(self):
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "not-a-valid-origin-string"}
        )
        self.assertEqual(status, 403)

    def test_cross_origin_post_to_logout_is_rejected(self):
        cookie = self.request_and_confirm_login("logout-csrf@example.com")
        status, _, _ = self.post_json("/auth/logout", {}, headers={"Cookie": cookie, "Origin": "http://evil.example"})
        self.assertEqual(status, 403)

    def test_cross_origin_member_add_is_rejected(self):
        conn = repo.connect(self.db_path)
        owner = repo.create_user(conn, "csrf-owner@example.com")
        workspace_id = repo.create_workspace(conn, "CSRF WS", owner)
        conn.close()
        cookie = self.request_and_confirm_login("csrf-owner@example.com")
        status, _, _ = self.post_json(
            "/workspaces/%s/members" % workspace_id,
            {"email": "x@example.com", "role": "member"},
            headers={"Cookie": cookie, "Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403)

    def test_cross_origin_member_remove_is_rejected(self):
        conn = repo.connect(self.db_path)
        owner = repo.create_user(conn, "csrf-owner-2@example.com")
        workspace_id = repo.create_workspace(conn, "CSRF WS 2", owner)
        conn.close()
        cookie = self.request_and_confirm_login("csrf-owner-2@example.com")
        status, _, _ = self.delete(
            "/workspaces/%s/members/%s" % (workspace_id, owner), headers={"Cookie": cookie, "Origin": "http://evil.example"}
        )
        self.assertEqual(status, 403)

    def test_malformed_requests_still_rejected_the_same_way_as_before(self):
        # Confirms adding the Origin check didn't change unrelated
        # error-handling behavior - a same-origin request with a bad
        # body still gets the SAME status it always did.
        status, _, _ = self.post_json("/auth/request-link", {"email": "not-an-email"})
        self.assertEqual(status, 400)
        status2, _, _ = self.post_json("/no/such/path", {})
        self.assertEqual(status2, 404)

    def test_login_csrf_attacker_owned_token_relayed_via_cross_origin_post_is_rejected(self):
        """The exact blocker scenario: an attacker requests a magic link
        for THEIR OWN email, obtains the raw token, then a victim's
        browser is tricked into a cross-site POST relaying that token to
        /auth/verify. Must be rejected before the token is ever consumed
        - the attacker's token must still be valid/usable afterward by
        its rightful owner (proving the rejected attempt had NO side
        effect), and no session cookie for the attacker's account may
        ever reach the "victim" request."""
        self.post_json("/auth/request-link", {"email": "attacker@example.com"})
        attacker_token = self.email_sender.last_token()

        status, headers, body = self.post_form(
            "/auth/verify", {"token": attacker_token, "redirect": "/dashboard"}, headers={"Origin": "http://evil-attacker-site.example"}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

        # The token was never consumed by the rejected cross-origin
        # attempt - the attacker (its rightful owner) can still use it
        # via a genuine same-origin request.
        legit_status, legit_headers, _ = self.post_form("/auth/verify", {"token": attacker_token})
        self.assertEqual(legit_status, 303)
        self.assertIn("Set-Cookie", legit_headers)

    def test_login_csrf_with_missing_origin_is_also_rejected(self):
        self.post_json("/auth/request-link", {"email": "attacker2@example.com"})
        token = self.email_sender.last_token()
        status, headers, _ = self.post_form("/auth/verify", {"token": token}, headers={"Origin": None})
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    # -------------------------------------------------------------
    # Origin hardening: full scheme+host+port semantics, not hostname
    # alone (docs/decisiones.md D-077/D-078 follow-up, closure-audit fix).
    # -------------------------------------------------------------

    def test_exact_same_host_scheme_and_port_is_allowed(self):
        status, _, _ = self.post_json("/auth/request-link", {"email": "exact-origin@example.com"})
        self.assertEqual(status, 200)  # self.same_origin already carries this server's real host:scheme:port.

    def test_different_port_is_rejected(self):
        other_port = self.port + 1 if self.port < 65535 else self.port - 1
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://%s:%d" % (HOST, other_port)}
        )
        self.assertEqual(status, 403)

    def test_different_scheme_is_rejected(self):
        # This test server runs secure_cookies=False (expected scheme
        # "http") - an Origin claiming "https" on the exact same host:port
        # must still be rejected, since it isn't the scheme this server
        # actually expects.
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "https://%s" % self.host_header}
        )
        self.assertEqual(status, 403)

    def test_subdomain_style_origin_is_rejected(self):
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://evil.%s" % self.host_header}
        )
        self.assertEqual(status, 403)

    def test_userinfo_prefix_trick_is_rejected(self):
        # "http://<our real host>@evil.example" - the REAL host per URL
        # parsing rules is evil.example (after the '@'); a naive check
        # fooled by the allowlisted-looking prefix would wrongly allow
        # this.
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://%s@evil.example" % self.host_header}
        )
        self.assertEqual(status, 403)

    def test_percent_encoded_host_is_rejected(self):
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://%s%%2e" % HOST}
        )
        self.assertEqual(status, 403)

    def test_malformed_origin_is_rejected(self):
        # Invalid IPv6 bracket syntax - confirmed to make urlparse itself
        # raise ValueError; _check_same_origin must catch it and fail
        # closed, never crash the request.
        status, _, _ = self.post_json("/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://[::1"})
        self.assertEqual(status, 403)

    def test_non_numeric_port_in_origin_is_rejected(self):
        status, _, _ = self.post_json(
            "/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "http://%s:abc" % HOST}
        )
        self.assertEqual(status, 403)

    def test_literal_null_origin_is_rejected(self):
        status, _, _ = self.post_json("/auth/request-link", {"email": "u@example.com"}, headers={"Origin": "null"})
        self.assertEqual(status, 403)


class TokenLoggingSafetyTests(_HttpAppTestCase):
    def test_raw_token_never_appears_in_the_access_log(self):
        self.post_json("/auth/request-link", {"email": "log-safety@example.com"})
        token = self.email_sender.last_token()
        with _capture_stderr() as captured:
            self.get("/auth/verify?token=%s" % token)
            self.post_form("/auth/verify", {"token": token})
        log_output = captured.getvalue()
        self.assertNotIn(token, log_output)
        self.assertIn("[REDACTED]", log_output)  # confirms redaction actually ran, not just an empty log.

    def test_normal_non_sensitive_paths_are_still_logged(self):
        with _capture_stderr() as captured:
            self.get("/no/such/path")
        self.assertIn("/no/such/path", captured.getvalue())

    def test_cookie_and_session_token_values_are_never_logged(self):
        cookie = self.request_and_confirm_login("log-safety-2@example.com")
        session_token = cookie.split("=", 1)[1]
        with _capture_stderr() as captured:
            self.post_json("/auth/logout", {}, headers={"Cookie": cookie})
        self.assertNotIn(session_token, captured.getvalue())

    def test_percent_encoded_token_name_is_redacted(self):
        # The confirmed blocker: %74oken= decodes to "token" via the SAME
        # parse_qs the real handlers use, so it must be redacted too.
        self.post_json("/auth/request-link", {"email": "encoded-name@example.com"})
        token = self.email_sender.last_token()
        with _capture_stderr() as captured:
            self.get("/auth/verify?%%74oken=%s" % token)
        log_output = captured.getvalue()
        self.assertNotIn(token, log_output)
        self.assertIn("[REDACTED]", log_output)

    def test_uppercase_token_name_is_redacted(self):
        self.post_json("/auth/request-link", {"email": "uppercase-name@example.com"})
        token = self.email_sender.last_token()
        with _capture_stderr() as captured:
            self.get("/auth/verify?Token=%s" % token)
            self.get("/auth/verify?TOKEN=%s" % token)
        log_output = captured.getvalue()
        self.assertNotIn(token, log_output)
        self.assertEqual(log_output.count("[REDACTED]"), 2)

    def test_duplicate_token_params_are_both_redacted(self):
        self.post_json("/auth/request-link", {"email": "dup-a@example.com"})
        token_a = self.email_sender.last_token()
        self.post_json("/auth/request-link", {"email": "dup-b@example.com"})
        token_b = self.email_sender.last_token()
        with _capture_stderr() as captured:
            self.get("/auth/verify?token=%s&token=%s" % (token_a, token_b))
        log_output = captured.getvalue()
        self.assertNotIn(token_a, log_output)
        self.assertNotIn(token_b, log_output)
        self.assertEqual(log_output.count("[REDACTED]"), 2)

    def test_percent_encoded_token_value_is_redacted(self):
        with _capture_stderr() as captured:
            self.get("/auth/verify?token=abc%26def%2Fghi")
        log_output = captured.getvalue()
        self.assertNotIn("abc%26def%2Fghi", log_output)
        self.assertIn("[REDACTED]", log_output)

    def test_malformed_query_string_never_leaks_and_never_crashes(self):
        with _capture_stderr() as captured:
            status, _, _ = self.get("/auth/verify?token=SECRETVALUE&&=&%zz=broken")
        self.assertEqual(status, 200)  # the server must not crash on this - a clean response either way.
        log_output = captured.getvalue()
        self.assertNotIn("SECRETVALUE", log_output)

    def test_non_sensitive_query_parameters_are_preserved_untouched(self):
        with _capture_stderr() as captured:
            self.get("/auth/verify?redirect=%2Fdashboard&token=SOMEVALUE")
        log_output = captured.getvalue()
        self.assertIn("redirect=%2Fdashboard", log_output)  # untouched, exactly as sent.
        self.assertNotIn("SOMEVALUE", log_output)


class RedactQueryStringUnitTests(unittest.TestCase):
    """Direct tests of backend.http_app._redact_query_string(). Two
    distinct properties, not one:
      1. anything the real handlers' qs.get("token") lookup (case-
         SENSITIVE, since urllib.parse.parse_qs never lowercases keys)
         would actually resolve as "token" MUST be redacted - this is
         the original blocker and can never regress.
      2. redaction is deliberately BROADER than that (this hardening
         turn's own explicit instruction: "redact token case-
         insensitively") - a casing qs.get("token") itself would not
         even recognize today is still redacted, as a safety margin
         against this module's own parsing ever changing later."""

    def test_redacts_everything_the_real_handlers_would_treat_as_token(self):
        import backend.http_app as http_app
        from urllib.parse import parse_qs

        for query in ("token=X", "%74oken=X", "to%6Ben=X"):
            self.assertIn("token", parse_qs(query))  # sanity: qs.get("token") really would find this.
            path = "/auth/verify?%s" % query
            self.assertNotEqual(http_app._redact_query_string(path), path, "should have redacted %r" % query)

    def test_also_redacts_case_variants_broader_than_strictly_necessary(self):
        import backend.http_app as http_app

        for query in ("Token=X", "TOKEN=X", "ToKeN=X"):
            path = "/auth/verify?%s" % query
            self.assertNotEqual(http_app._redact_query_string(path), path, "should have redacted %r" % query)

    def test_unrelated_parameter_names_are_left_alone(self):
        import backend.http_app as http_app

        for query in ("not_token=X", "tokens=X", "my_token=X", "redirect=/dashboard"):
            path = "/auth/verify?%s" % query
            self.assertEqual(http_app._redact_query_string(path), path, "should NOT have redacted %r" % query)

    def test_no_query_string_is_untouched(self):
        import backend.http_app as http_app
        self.assertEqual(http_app._redact_query_string("/auth/verify"), "/auth/verify")

    def test_non_sensitive_query_is_untouched(self):
        import backend.http_app as http_app
        path = "/auth/verify?redirect=/dashboard"
        self.assertEqual(http_app._redact_query_string(path), path)


if __name__ == "__main__":
    unittest.main()
