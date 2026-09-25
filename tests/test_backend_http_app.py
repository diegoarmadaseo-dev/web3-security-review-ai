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
import shutil
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

import backend.alerting as alerting
import backend.billing as billing_module
import backend.http_app as http_app
import backend.object_storage as object_storage
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


# ---------------------------------------------------------------------------
# Phase 5 (docs/decisiones.md D-077 follow-up): workspace creation/read, job
# and report read, and the new /auth/login entry point.
# ---------------------------------------------------------------------------

class LoginEntryPointTests(_HttpAppTestCase):
    def test_login_page_renders_a_form(self):
        status, headers, body = self.get("/auth/login")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn(b'action="/auth/request-link"', body)

    def test_form_encoded_request_link_returns_an_html_confirmation(self):
        body = urlencode({"email": "form-user@example.com"}).encode("ascii")
        conn = self._conn()
        hdrs = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
            "Host": self.host_header,
            "Origin": self.same_origin,
        }
        conn.request("POST", "/auth/request-link", body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", resp.getheader("Content-Type", ""))
        self.assertIn(b"Check your email", data)
        self.assertEqual(len(self.email_sender.sent), 1)

    def test_json_request_link_behavior_is_unchanged_by_the_new_form_path(self):
        status, headers, body = self.post_json("/auth/request-link", {"email": "json-user@example.com"})
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        self.assertEqual(json.loads(body), {"ok": True, "message": "If that email is registered, a sign-in link has been sent."})


class WorkspaceCreationTests(_HttpAppTestCase):
    def _user_id_for(self, conn, email):
        return repo.get_user_by_email(conn, email)["id"]

    def test_create_requires_authentication(self):
        status, _, _ = self.post_json("/workspaces", {"name": "My Workspace"})
        self.assertEqual(status, 401)

    def test_authenticated_user_can_create_a_workspace_as_owner(self):
        cookie = self.request_and_confirm_login("creator@example.com")
        status, _, body = self.post_json("/workspaces", {"name": "My Workspace"}, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result["ok"])
        conn = repo.connect(self.db_path)
        role = tenant_scope.resolve_workspace_role(conn, self._user_id_for(conn, "creator@example.com"), result["workspace_id"])
        conn.close()
        self.assertEqual(role, "owner")

    def test_owner_is_always_the_authenticated_caller_never_client_supplied(self):
        cookie = self.request_and_confirm_login("real-owner@example.com")
        conn = repo.connect(self.db_path)
        impostor_id = repo.create_user(conn, "impostor@example.com")
        conn.close()
        status, _, body = self.post_json(
            "/workspaces", {"name": "WS", "owner_user_id": impostor_id, "user_id": impostor_id}, headers={"Cookie": cookie}
        )
        self.assertEqual(status, 200)
        workspace_id = json.loads(body)["workspace_id"]
        conn = repo.connect(self.db_path)
        role_real_owner = tenant_scope.resolve_workspace_role(conn, self._user_id_for(conn, "real-owner@example.com"), workspace_id)
        role_impostor = tenant_scope.resolve_workspace_role(conn, impostor_id, workspace_id)
        conn.close()
        self.assertEqual(role_real_owner, "owner")
        self.assertIsNone(role_impostor)

    def test_blank_or_non_string_name_is_rejected(self):
        cookie = self.request_and_confirm_login("badname@example.com")
        for bad_name in ("", "   ", None, 123, ["x"]):
            status, _, _ = self.post_json("/workspaces", {"name": bad_name}, headers={"Cookie": cookie})
            self.assertEqual(status, 400, "bad_name=%r" % (bad_name,))

    def test_overlong_name_is_rejected(self):
        cookie = self.request_and_confirm_login("longname@example.com")
        status, _, _ = self.post_json("/workspaces", {"name": "x" * 201}, headers={"Cookie": cookie})
        self.assertEqual(status, 400)

    def test_workspace_creation_cap_returns_429_once_exceeded(self):
        cookie = self.request_and_confirm_login("prolific@example.com")
        for i in range(http_app._MAX_WORKSPACES_PER_USER):
            status, _, _ = self.post_json("/workspaces", {"name": "WS %d" % i}, headers={"Cookie": cookie})
            self.assertEqual(status, 200)
        status, _, _ = self.post_json("/workspaces", {"name": "one too many"}, headers={"Cookie": cookie})
        self.assertEqual(status, 429)

    def test_repeated_magic_link_verification_never_creates_a_workspace(self):
        # The explicit design choice this phase made instead of auto-
        # provision-on-first-login - see http_app.py's own module
        # docstring: /auth/verify's POST handler only ever creates a
        # session, regardless of how many times it is called for the
        # same or a fresh token.
        for _ in range(3):
            self.request_and_confirm_login("repeat-login@example.com")
        conn = repo.connect(self.db_path)
        user_id = self._user_id_for(conn, "repeat-login@example.com")
        workspaces = repo.list_workspaces_by_user(conn, user_id)
        conn.close()
        self.assertEqual(workspaces, [])


class WorkspaceReadTests(_HttpAppTestCase):
    def _user_id_for(self, conn, email):
        return repo.get_user_by_email(conn, email)["id"]

    def test_list_requires_authentication(self):
        status, _, _ = self.get("/workspaces")
        self.assertEqual(status, 401)

    def test_list_returns_only_the_callers_own_workspaces(self):
        cookie_a = self.request_and_confirm_login("list-a@example.com")
        self.post_json("/workspaces", {"name": "A1"}, headers={"Cookie": cookie_a})
        self.post_json("/workspaces", {"name": "A2"}, headers={"Cookie": cookie_a})
        cookie_b = self.request_and_confirm_login("list-b@example.com")
        self.post_json("/workspaces", {"name": "B1"}, headers={"Cookie": cookie_b})

        status, _, body = self.get("/workspaces", headers={"Cookie": cookie_a})
        self.assertEqual(status, 200)
        names = {w["name"] for w in json.loads(body)["workspaces"]}
        self.assertEqual(names, {"A1", "A2"})

    def test_get_requires_authentication(self):
        cookie = self.request_and_confirm_login("owner-g@example.com")
        _, _, body = self.post_json("/workspaces", {"name": "G"}, headers={"Cookie": cookie})
        workspace_id = json.loads(body)["workspace_id"]
        status, _, _ = self.get("/workspaces/%s" % workspace_id)
        self.assertEqual(status, 401)

    def test_get_returns_workspace_entitlement_and_limits(self):
        cookie = self.request_and_confirm_login("owner-h@example.com")
        _, _, body = self.post_json("/workspaces", {"name": "H"}, headers={"Cookie": cookie})
        workspace_id = json.loads(body)["workspace_id"]
        conn = repo.connect(self.db_path)
        repo.create_entitlement(conn, workspace_id, "standard", "active")
        conn.close()

        status, _, body = self.get("/workspaces/%s" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["workspace"]["name"], "H")
        self.assertEqual(result["workspace"]["membership_role"], "owner")
        self.assertEqual(result["entitlement"]["plan"], "standard")
        self.assertEqual(result["entitlement"]["status"], "active")
        # No job has ever been submitted for this brand-new workspace -
        # workspace_budgets is lazily created on first spend (see
        # repository._ensure_workspace_budget_row's own docstring), so
        # there is genuinely nothing to report yet.
        self.assertIsNone(result["budget"])

    def test_get_without_entitlement_has_null_entitlement_and_limits(self):
        cookie = self.request_and_confirm_login("owner-i@example.com")
        _, _, body = self.post_json("/workspaces", {"name": "I"}, headers={"Cookie": cookie})
        workspace_id = json.loads(body)["workspace_id"]
        status, _, body = self.get("/workspaces/%s" % workspace_id, headers={"Cookie": cookie})
        result = json.loads(body)
        self.assertIsNone(result["entitlement"])
        self.assertIsNone(result["limits"])

    def test_cross_tenant_get_is_forbidden_and_indistinguishable_from_nonexistent(self):
        cookie_a = self.request_and_confirm_login("cross-a@example.com")
        _, _, body = self.post_json("/workspaces", {"name": "CrossA"}, headers={"Cookie": cookie_a})
        workspace_id = json.loads(body)["workspace_id"]
        cookie_b = self.request_and_confirm_login("cross-b@example.com")

        status_real, _, body_real = self.get("/workspaces/%s" % workspace_id, headers={"Cookie": cookie_b})
        status_fake, _, body_fake = self.get("/workspaces/does-not-exist-at-all", headers={"Cookie": cookie_b})
        self.assertEqual(status_real, 403)
        self.assertEqual(status_fake, 403)
        self.assertEqual(json.loads(body_real), json.loads(body_fake))


class _WorkspaceStorageTestCase(_HttpAppTestCase):
    """Same fixture as _HttpAppTestCase, plus real object storage
    (LocalFilesystemStorage - see backend/object_storage.py) wired into
    the server, needed for report signed-URL tests below."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed_conn = repo.connect(self.db_path)
        repo.init_schema(seed_conn)
        seed_conn.close()

        self.storage_dir = tempfile.mkdtemp(prefix="http-app-ws-tests-")
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="test-only-secret")

        self.email_sender = _CapturingEmailSender()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path),
            email_sender=self.email_sender,
            host_allowlist=[HOST],
            host=HOST,
            port=0,
            secure_cookies=False,
            storage=self.storage,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.addCleanup(lambda: shutil.rmtree(self.storage_dir, ignore_errors=True))
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)


class JobSubmitAuthorizationTests(_WorkspaceStorageTestCase):
    """P0 (D-086): repo.PLAN_ALLOWED_MODES is enforced server-side in
    _handle_job_submit() - a plan may never run a mode above its own
    tier, regardless of what the client requests. Never trusts the
    frontend - every case here is a raw HTTP POST, no UI involved."""

    def _workspace_with_plan(self, email, plan, status="active"):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        user_id = repo.get_user_by_email(conn, email)["id"]
        workspace_id = repo.create_workspace(conn, "Plan WS", user_id)
        repo.create_entitlement(conn, workspace_id, plan, status)
        conn.close()
        return cookie, workspace_id

    def _submit(self, cookie, workspace_id, mode):
        return self.post_json(
            "/workspaces/%s/jobs" % workspace_id, {"mode": mode, "source": "contract A {}"}, headers={"Cookie": cookie}
        )

    def test_quick_plan_can_request_quick(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-1@example.com", "quick")
        status, _, _ = self._submit(cookie, workspace_id, "quick")
        self.assertEqual(status, 200)

    def test_quick_plan_cannot_request_standard(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-2@example.com", "quick")
        status, _, body = self._submit(cookie, workspace_id, "standard")
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"], "mode not included in the current plan")

    def test_quick_plan_cannot_request_pro(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-3@example.com", "quick")
        status, _, _ = self._submit(cookie, workspace_id, "pro")
        self.assertEqual(status, 403)

    def test_standard_plan_can_request_quick_and_standard(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-4@example.com", "standard")
        self.assertEqual(self._submit(cookie, workspace_id, "quick")[0], 200)
        self.assertEqual(self._submit(cookie, workspace_id, "standard")[0], 200)

    def test_standard_plan_cannot_request_pro(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-5@example.com", "standard")
        status, _, _ = self._submit(cookie, workspace_id, "pro")
        self.assertEqual(status, 403)

    def test_pro_plan_can_request_every_mode(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-6@example.com", "pro")
        for mode in ("quick", "standard", "pro"):
            with self.subTest(mode=mode):
                status, _, _ = self._submit(cookie, workspace_id, mode)
                self.assertEqual(status, 200)

    def test_inactive_subscription_is_denied_before_the_plan_check_even_runs(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-7@example.com", "pro", status="canceled")
        status, _, body = self._submit(cookie, workspace_id, "quick")
        self.assertEqual(status, 402)
        self.assertEqual(json.loads(body)["error"], "this workspace has no active subscription")

    def test_trialing_status_uses_the_same_plan_authorization_as_active(self):
        cookie, workspace_id = self._workspace_with_plan("job-auth-8@example.com", "quick", status="trialing")
        self.assertEqual(self._submit(cookie, workspace_id, "quick")[0], 200)
        self.assertEqual(self._submit(cookie, workspace_id, "pro")[0], 403)

    def test_client_cannot_bypass_by_sending_an_extra_plan_field(self):
        # _handle_job_submit() never reads a client-supplied "plan" at
        # all - the entitlement's OWN stored plan (a database fact) is
        # the only thing consulted. This proves that explicitly.
        cookie, workspace_id = self._workspace_with_plan("job-auth-9@example.com", "quick")
        status, _, _ = self.post_json(
            "/workspaces/%s/jobs" % workspace_id,
            {"mode": "pro", "source": "contract A {}", "plan": "pro"},
            headers={"Cookie": cookie},
        )
        self.assertEqual(status, 403)


class JobReadTests(_WorkspaceStorageTestCase):
    def _seed_workspace_with_job(self, email):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        user_id = repo.get_user_by_email(conn, email)["id"]
        workspace_id = repo.create_workspace(conn, "Seeded WS", user_id)
        contract_id = repo.create_contract(conn, workspace_id, "sources/x/seed", "hash", "A.sol")
        job_id = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
        repo.transition_job_status(conn, job_id, "queued", "claimed")
        conn.close()
        return cookie, workspace_id, job_id

    def test_list_requires_authentication(self):
        _, workspace_id, _ = self._seed_workspace_with_job("jl-1@example.com")
        status, _, _ = self.get("/workspaces/%s/jobs" % workspace_id)
        self.assertEqual(status, 401)

    def test_list_returns_the_seeded_job(self):
        cookie, workspace_id, job_id = self._seed_workspace_with_job("jl-2@example.com")
        status, _, body = self.get("/workspaces/%s/jobs" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        jobs = json.loads(body)["jobs"]
        self.assertEqual([j["id"] for j in jobs], [job_id])
        self.assertEqual(jobs[0]["status"], "claimed")

    def test_list_cross_tenant_is_forbidden(self):
        _, workspace_id, _ = self._seed_workspace_with_job("jl-3@example.com")
        cookie_b = self.request_and_confirm_login("jl-3b@example.com")
        status, _, _ = self.get("/workspaces/%s/jobs" % workspace_id, headers={"Cookie": cookie_b})
        self.assertEqual(status, 403)

    def test_nonexistent_workspace_returns_403_never_404(self):
        # Same anti-enumeration property as workspace GET - a made-up
        # workspace_id must never be distinguishable from a real one the
        # caller simply isn't a member of.
        cookie = self.request_and_confirm_login("jl-nonexist@example.com")
        status, _, _ = self.get("/workspaces/totally-made-up/jobs", headers={"Cookie": cookie})
        self.assertEqual(status, 403)

    def test_rejects_invalid_status_filter(self):
        cookie, workspace_id, _ = self._seed_workspace_with_job("jl-4@example.com")
        status, _, _ = self.get("/workspaces/%s/jobs?status=not-a-real-status" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual(status, 400)

    def test_status_filter_narrows_results(self):
        cookie, workspace_id, job_id = self._seed_workspace_with_job("jl-5@example.com")
        status, _, body = self.get("/workspaces/%s/jobs?status=claimed" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual([j["id"] for j in json.loads(body)["jobs"]], [job_id])
        status, _, body = self.get("/workspaces/%s/jobs?status=succeeded" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual(json.loads(body)["jobs"], [])

    def test_pagination_is_deterministic_and_non_overlapping(self):
        cookie = self.request_and_confirm_login("jl-6@example.com")
        conn = repo.connect(self.db_path)
        user_id = repo.get_user_by_email(conn, "jl-6@example.com")["id"]
        workspace_id = repo.create_workspace(conn, "Pagination WS", user_id)
        contract_id = repo.create_contract(conn, workspace_id, "sources/x/pg", "hash", "A.sol")
        for _ in range(5):
            repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
        conn.close()

        _, _, body = self.get("/workspaces/%s/jobs?limit=2&offset=0" % workspace_id, headers={"Cookie": cookie})
        page1 = [j["id"] for j in json.loads(body)["jobs"]]
        _, _, body = self.get("/workspaces/%s/jobs?limit=2&offset=2" % workspace_id, headers={"Cookie": cookie})
        page2 = [j["id"] for j in json.loads(body)["jobs"]]
        _, _, body = self.get("/workspaces/%s/jobs?limit=2&offset=0" % workspace_id, headers={"Cookie": cookie})
        page1_again = [j["id"] for j in json.loads(body)["jobs"]]

        self.assertEqual(len(page1), 2)
        self.assertEqual(len(page2), 2)
        self.assertEqual(page1, page1_again)  # deterministic across repeated, identical calls.
        self.assertEqual(len(set(page1) & set(page2)), 0)  # non-overlapping pages.

    def test_invalid_pagination_params_return_400(self):
        cookie, workspace_id, _ = self._seed_workspace_with_job("jl-7@example.com")
        for query in ("limit=0", "limit=101", "limit=abc", "offset=-1"):
            status, _, _ = self.get("/workspaces/%s/jobs?%s" % (workspace_id, query), headers={"Cookie": cookie})
            self.assertEqual(status, 400, "query=%r" % query)


class ReportReadTests(_WorkspaceStorageTestCase):
    def _seed_workspace_with_report(self, email):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        user_id = repo.get_user_by_email(conn, email)["id"]
        workspace_id = repo.create_workspace(conn, "Report WS", user_id)
        contract_id = repo.create_contract(conn, workspace_id, "sources/x/rep", "hash", "A.sol")
        job_id = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
        repo.transition_job_status(conn, job_id, "queued", "claimed")
        repo.transition_job_status(conn, job_id, "claimed", "running")
        storage_ref = object_storage.workspace_key(workspace_id, "reports", job_id)
        self.storage.put_object(storage_ref, b"# Report\nSome content.", content_type="text/markdown")
        report_id = repo.record_report(conn, job_id, workspace_id, storage_ref, score_status="computed", score=10, risk_band="LOW")
        repo.transition_job_status(conn, job_id, "running", "succeeded")
        conn.close()
        return cookie, workspace_id, report_id

    def test_list_requires_authentication(self):
        _, workspace_id, _ = self._seed_workspace_with_report("rl-1@example.com")
        status, _, _ = self.get("/workspaces/%s/reports" % workspace_id)
        self.assertEqual(status, 401)

    def test_list_never_includes_a_raw_storage_path(self):
        cookie, workspace_id, report_id = self._seed_workspace_with_report("rl-2@example.com")
        status, _, body = self.get("/workspaces/%s/reports" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        reports = json.loads(body)["reports"]
        self.assertEqual([r["id"] for r in reports], [report_id])
        self.assertNotIn("storage_ref", reports[0])

    def test_list_cross_tenant_is_forbidden(self):
        _, workspace_id, _ = self._seed_workspace_with_report("rl-3@example.com")
        cookie_b = self.request_and_confirm_login("rl-3b@example.com")
        status, _, _ = self.get("/workspaces/%s/reports" % workspace_id, headers={"Cookie": cookie_b})
        self.assertEqual(status, 403)

    def test_get_returns_metadata_and_a_working_signed_url(self):
        cookie, workspace_id, report_id = self._seed_workspace_with_report("rg-1@example.com")
        status, _, body = self.get("/workspaces/%s/reports/%s" % (workspace_id, report_id), headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        report = json.loads(body)["report"]
        self.assertEqual(report["id"], report_id)
        self.assertNotIn("storage_ref", report)
        self.assertIn("report_url", report)
        fetched = self.storage.verify_signed_url(report["report_url"])
        self.assertEqual(fetched, b"# Report\nSome content.")

    def test_get_nonexistent_report_id_returns_404(self):
        cookie, workspace_id, _ = self._seed_workspace_with_report("rg-2@example.com")
        status, _, _ = self.get("/workspaces/%s/reports/does-not-exist" % workspace_id, headers={"Cookie": cookie})
        self.assertEqual(status, 404)

    def test_get_cross_tenant_report_id_returns_404_never_leaks_existence(self):
        # workspace A's real report_id, requested through workspace B's
        # own (legitimate) URL - must be indistinguishable from a
        # report_id that never existed anywhere at all.
        cookie_a, workspace_a, report_id_a = self._seed_workspace_with_report("rg-3a@example.com")
        cookie_b = self.request_and_confirm_login("rg-3b@example.com")
        _, _, body_b_ws = self.post_json("/workspaces", {"name": "B WS"}, headers={"Cookie": cookie_b})
        workspace_b = json.loads(body_b_ws)["workspace_id"]

        status_cross, _, body_cross = self.get("/workspaces/%s/reports/%s" % (workspace_b, report_id_a), headers={"Cookie": cookie_b})
        status_fake, _, body_fake = self.get("/workspaces/%s/reports/does-not-exist" % workspace_b, headers={"Cookie": cookie_b})
        self.assertEqual(status_cross, 404)
        self.assertEqual(json.loads(body_cross), json.loads(body_fake))

    def test_get_requires_membership_in_the_url_workspace(self):
        _, workspace_id, report_id = self._seed_workspace_with_report("rg-4@example.com")
        cookie_stranger = self.request_and_confirm_login("rg-4-stranger@example.com")
        status, _, _ = self.get("/workspaces/%s/reports/%s" % (workspace_id, report_id), headers={"Cookie": cookie_stranger})
        self.assertEqual(status, 403)


class ReportGetWithoutStorageTests(_HttpAppTestCase):
    """_HttpAppTestCase (unlike _WorkspaceStorageTestCase above) never
    configures storage - proves GET .../reports/<id> degrades cleanly
    rather than 503ing when storage=None (see _handle_report_get()'s own
    "when applicable" framing for report_url)."""

    def test_get_without_storage_configured_omits_report_url_but_keeps_metadata(self):
        cookie = self.request_and_confirm_login("rg-nostorage@example.com")
        conn = repo.connect(self.db_path)
        user_id = repo.get_user_by_email(conn, "rg-nostorage@example.com")["id"]
        workspace_id = repo.create_workspace(conn, "No Storage WS", user_id)
        contract_id = repo.create_contract(conn, workspace_id, "sources/x/ns", "hash", "A.sol")
        job_id = repo.enqueue_job(conn, workspace_id, contract_id, user_id, "quick")
        report_id = repo.record_report(
            conn, job_id, workspace_id, "reports/%s/%s" % (workspace_id, job_id), score_status="computed", score=5, risk_band="LOW"
        )
        conn.close()

        status, _, body = self.get("/workspaces/%s/reports/%s" % (workspace_id, report_id), headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        report = json.loads(body)["report"]
        self.assertEqual(report["score"], 5)
        self.assertEqual(report["risk_band"], "LOW")
        self.assertNotIn("storage_ref", report)
        self.assertNotIn("report_url", report)


# ---------------------------------------------------------------------------
# Phase 6A (docs/decisiones.md D-077 follow-up): health/readiness, in-flight
# tracking, and alert emission at the HTTP layer.
# ---------------------------------------------------------------------------

class _CollectingAlertSender:
    def __init__(self):
        self.events = []

    def emit(self, event_type, severity, detail):
        self.events.append((event_type, severity, detail))


class HealthReadyTests(_HttpAppTestCase):
    """_HttpAppTestCase's base server never configures storage/billing -
    exactly the "some dependencies missing" case GET /ready needs to
    report accurately."""

    def test_health_is_always_200_and_unauthenticated(self):
        status, _, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_ready_is_503_when_storage_and_billing_are_not_configured(self):
        status, _, body = self.get("/ready")
        result = json.loads(body)
        self.assertEqual(status, 503)
        self.assertFalse(result["ok"])
        self.assertTrue(result["checks"]["database"])  # the one dependency this server DOES have - real SQLite.
        self.assertFalse(result["checks"]["storage"])
        self.assertFalse(result["checks"]["billing"])

    def test_ready_never_includes_a_dsn_or_the_word_password(self):
        _, _, body = self.get("/ready")
        lowered = body.lower()
        self.assertNotIn(b"sqlite", lowered)
        self.assertNotIn(b"password", lowered)
        self.assertNotIn(self.db_path.lower().encode(), lowered)


class HealthReadyFullyConfiguredTests(_HttpAppTestCase):
    """A server with storage AND billing both wired - proves GET /ready
    reports 200 once every dependency this deployment actually declared
    is genuinely usable, not just "some are missing"."""

    def setUp(self):
        super().setUp()
        self.storage_dir = tempfile.mkdtemp(prefix="ready-full-tests-")
        self.addCleanup(shutil.rmtree, self.storage_dir, True)
        storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="ready-full-secret")
        billing = billing_module.StripeBilling(secret_key="sk_test_fake", webhook_secret="whsec_fake", price_allowlist={"quick": "price_fake"})
        self.alert_sender = _CollectingAlertSender()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path),
            email_sender=self.email_sender,
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False,
            storage=storage, billing=billing, alert_sender=self.alert_sender,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def test_ready_is_200_when_database_storage_and_billing_are_all_usable(self):
        status, _, body = self.get("/ready")
        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(result["checks"], {"database": True, "storage": True, "billing": True})
        self.assertEqual(self.alert_sender.events, [])  # no failure -> no alert emitted.


class ReadyDependencyOutageTests(unittest.TestCase):
    """A server whose connect_fn always raises - simulates a real
    database outage (not merely "never configured"), the "dependency
    outage" adversarial case."""

    def setUp(self):
        self.alert_sender = _CollectingAlertSender()
        self.email_sender = _CapturingEmailSender()

        def _broken_connect():
            raise ConnectionError("simulated database outage")

        self.httpd = http_app.run_server(
            connect_fn=_broken_connect, email_sender=self.email_sender,
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False,
            alert_sender=self.alert_sender,
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_ready_returns_503_and_reports_database_false_on_a_real_outage(self):
        conn = http.client.HTTPConnection(HOST, self.port, timeout=5)
        conn.request("GET", "/ready", headers={"Host": "%s:%d" % (HOST, self.port)})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 503)
        result = json.loads(body)
        self.assertFalse(result["checks"]["database"])

    def test_readiness_failure_emits_an_alert(self):
        conn = http.client.HTTPConnection(HOST, self.port, timeout=5)
        conn.request("GET", "/ready", headers={"Host": "%s:%d" % (HOST, self.port)})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(len(self.alert_sender.events), 1)
        event_type, severity, detail = self.alert_sender.events[0]
        self.assertEqual(event_type, alerting.EVENT_READINESS_FAILURE)
        self.assertFalse(detail["checks"]["database"])

    def test_health_still_reports_ok_even_during_a_database_outage(self):
        # /health touches nothing - it must never be affected by a DB outage.
        conn = http.client.HTTPConnection(HOST, self.port, timeout=5)
        conn.request("GET", "/health", headers={"Host": "%s:%d" % (HOST, self.port)})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(body), {"ok": True})


class WebhookFailureAlertTests(_HttpAppTestCase):
    def setUp(self):
        super().setUp()
        self.alert_sender = _CollectingAlertSender()
        billing = billing_module.StripeBilling(secret_key="sk_test_fake", webhook_secret="whsec_fake", price_allowlist={"quick": "price_fake"})
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path),
            email_sender=self.email_sender,
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False,
            billing=billing, alert_sender=self.alert_sender,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def test_invalid_webhook_signature_never_emits_a_processing_failure_alert(self):
        # An invalid signature is rejected by billing.verify_and_parse_webhook()
        # itself, BEFORE _apply_webhook_event() ever runs - not the
        # "processing failed" case this alert exists for (that would
        # over-alert on routine, expected abuse/misconfiguration noise).
        conn = self._conn()
        body = b'{"id": "evt_1", "type": "checkout.session.completed"}'
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body)), "Host": self.host_header, "Stripe-Signature": "t=1,v1=deadbeef"}
        conn.request("POST", "/billing/webhook", body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 400)
        self.assertEqual(self.alert_sender.events, [])


class RateLimitAlertTests(_HttpAppTestCase):
    def test_rate_limit_exceeded_emits_an_alert(self):
        alert_sender = _CollectingAlertSender()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path), email_sender=self.email_sender,
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False, alert_sender=alert_sender,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

        import backend.auth as auth
        for i in range(auth.RATE_LIMIT_MAX_PER_IP):
            self.post_json("/auth/request-link", {"email": "flood-%d@example.com" % i})
        status, _, _ = self.post_json("/auth/request-link", {"email": "one-more@example.com"})
        self.assertEqual(status, 429)
        self.assertTrue(any(e[0] == alerting.EVENT_AUTH_RATE_LIMIT for e in alert_sender.events))


class _FailingEmailSender:
    """Same shape as _CapturingEmailSender (records what a real provider
    adapter would have tried to send, including a working last_token())
    but THEN raises - simulating a real SMTPEmailSender whose message was
    fully built before the network call itself failed (docs/decisiones.md
    D-083)."""

    def __init__(self, exc):
        self._exc = exc
        self.sent = []

    def send(self, to_email, subject, body):
        self.sent.append((to_email, subject, body))
        raise self._exc

    def last_token(self):
        _, _, body = self.sent[-1]
        match = re.search(r"token=([A-Za-z0-9_-]+)", body)
        return match.group(1) if match else None


class EmailDeliveryFailureTests(_HttpAppTestCase):
    """D-083: a delivery failure from email_sender.send() (e.g. a real
    SMTPEmailSender) must never crash the request, leak provider detail,
    or change the token/anti-enumeration guarantees request-link already
    provides - see backend/http_app.py's _handle_request_link()."""

    def _swap_server(self, email_sender, alert_sender=None):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path), email_sender=email_sender,
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False, alert_sender=alert_sender,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def test_smtp_style_failure_still_returns_a_clean_200(self):
        failing = _FailingEmailSender(OSError("connection refused"))
        self._swap_server(failing)
        status, _, body = self.post_json("/auth/request-link", {"email": "u@example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True, "message": "If that email is registered, a sign-in link has been sent."})
        self.assertEqual(len(failing.sent), 1)  # delivery WAS attempted, not skipped.

    def test_delivery_failure_response_is_identical_to_a_successful_send(self):
        success_status, _, success_body = self.post_json("/auth/request-link", {"email": "success@example.com"})
        failing = _FailingEmailSender(RuntimeError("boom"))
        self._swap_server(failing)
        fail_status, _, fail_body = self.post_json("/auth/request-link", {"email": "fails@example.com"})
        self.assertEqual((success_status, success_body), (fail_status, fail_body))

    def test_anti_enumeration_unchanged_for_known_and_unknown_email_on_failure(self):
        seed_conn = repo.connect(self.db_path)
        repo.create_user(seed_conn, "known-fail@example.com")
        seed_conn.close()
        failing = _FailingEmailSender(RuntimeError("boom"))
        self._swap_server(failing)
        s1, _, b1 = self.post_json("/auth/request-link", {"email": "unknown-fail@example.com"})
        s2, _, b2 = self.post_json("/auth/request-link", {"email": "known-fail@example.com"})
        self.assertEqual((s1, b1), (s2, b2))

    def test_provider_exception_message_never_reaches_the_client(self):
        secret_looking = "535 5.7.8 Authentication failed for user s3cr3t-password"
        failing = _FailingEmailSender(RuntimeError(secret_looking))
        self._swap_server(failing)
        _, _, body = self.post_json("/auth/request-link", {"email": "u@example.com"})
        self.assertNotIn(b"s3cr3t-password", body)
        self.assertNotIn(b"Authentication failed", body)
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn(b"RuntimeError", body)

    def test_provider_exception_message_never_reaches_the_alert_payload(self):
        secret_looking = "535 5.7.8 Authentication failed: bad-password-abc"
        failing = _FailingEmailSender(RuntimeError(secret_looking))
        alert_sender = _CollectingAlertSender()
        self._swap_server(failing, alert_sender=alert_sender)
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        self.assertEqual(len(alert_sender.events), 1)
        event_type, severity, detail = alert_sender.events[0]
        self.assertEqual(event_type, alerting.EVENT_EMAIL_DELIVERY_FAILURE)
        self.assertEqual(severity, "error")
        self.assertEqual(detail["error_type"], "RuntimeError")
        self.assertNotIn("bad-password-abc", repr(detail))

    def test_successful_delivery_emits_no_alert(self):
        alert_sender = _CollectingAlertSender()
        self._swap_server(_CapturingEmailSender(), alert_sender=alert_sender)
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        self.assertEqual(alert_sender.events, [])

    def test_token_survives_a_failed_delivery_and_still_logs_in_exactly_once(self):
        # The blocker this fix closes: without a try/except around
        # email_sender.send(), do_POST's uncaught exception used to abort
        # the request with no HTTP response at all - never a token-state
        # problem (request_magic_link() already committed before delivery
        # is ever attempted), but this proves the token really is
        # completely unaffected either way: still valid, still single-use.
        failing = _FailingEmailSender(RuntimeError("boom"))
        self._swap_server(failing)
        self.post_json("/auth/request-link", {"email": "u@example.com"})
        token = failing.last_token()
        self.assertIsNotNone(token)
        first_status, first_headers, _ = self.post_form("/auth/verify", {"token": token, "redirect": "/dashboard"})
        self.assertEqual(first_status, 303)
        self.assertIn("Set-Cookie", first_headers)
        second_status, _, second_body = self.post_form("/auth/verify", {"token": token, "redirect": "/dashboard"})
        self.assertEqual(second_status, 200)
        self.assertIn(b"invalid or has expired", second_body)


class InFlightTrackerTests(unittest.TestCase):
    """Direct tests of backend.http_app._InFlightTracker/get_in_flight_count
    - the primitive backend/main.py's graceful-shutdown drain loop polls.
    Real HTTP-level in-flight behavior is exercised end-to-end in
    tests/test_backend_main.py's own shutdown tests."""

    def test_starts_at_zero(self):
        tracker = http_app._InFlightTracker()
        self.assertEqual(tracker.count, 0)

    def test_increment_and_decrement(self):
        tracker = http_app._InFlightTracker()
        tracker.increment()
        tracker.increment()
        self.assertEqual(tracker.count, 2)
        tracker.decrement()
        self.assertEqual(tracker.count, 1)

    def test_get_in_flight_count_is_zero_for_a_server_with_no_tracker_attached(self):
        class _FakeServer:
            pass
        self.assertEqual(http_app.get_in_flight_count(_FakeServer()), 0)

    def test_a_real_request_is_actually_tracked(self):
        # Proves handle_one_request() really is the hook point: the
        # tracker's own count is 0 before any request and 0 again right
        # after a full request/response cycle completes - a real server,
        # a real request, through the actual override, not a unit test
        # of _InFlightTracker in isolation (see the two tests above).
        fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(db_path)
        seed_conn = repo.connect(db_path)
        repo.init_schema(seed_conn)
        seed_conn.close()
        self.addCleanup(lambda: os.remove(db_path) if os.path.exists(db_path) else None)

        httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(db_path), email_sender=_CapturingEmailSender(),
            host_allowlist=[HOST], host=HOST, port=0, secure_cookies=False,
        )
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        self.assertEqual(http_app.get_in_flight_count(httpd), 0)
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.request("GET", "/health", headers={"Host": "%s:%d" % (HOST, port)})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        # After a full request/response round-trip completes, the
        # tracker must be back to 0 - never left incremented (a leak
        # here would make backend/main.py's shutdown drain loop wait out
        # its full grace period on every shutdown for no reason). Polled
        # with a short bound rather than asserted instantly: the client
        # finishing its read() and the SERVER thread's own
        # handle_one_request() `finally` block (where decrement()
        # actually runs) are not the same instant - a real, if tiny,
        # race between "client saw the last byte" and "server thread
        # finished its own next line of Python", confirmed by this
        # exact assertion flaking under full-suite load (never in
        # isolation) before this poll was added.
        deadline = time.monotonic() + 2
        while http_app.get_in_flight_count(httpd) != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(http_app.get_in_flight_count(httpd), 0)


if __name__ == "__main__":
    unittest.main()
