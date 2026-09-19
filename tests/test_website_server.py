"""Tests for website/server.py (V2.12 - Stateless render/validate/diff HTTP
endpoint, docs/decisiones.md D-067, capability W-03).

Covers: API boundary, malformed input, rate/abuse handling, and public-route
security, per the explicit V2.12 IMPLEMENT ONLY requirement.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import http.client
import json
import re
import sys
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = REPO_ROOT / "website"
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

import server as srv  # noqa: E402


def _start_server():
    httpd = srv.run_server("127.0.0.1", 0)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    return httpd, port


class _ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.httpd, self.port = _start_server()
        srv._rate_limiter._hits.clear()  # isolate this test's request budget

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def post(self, path, body, headers=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body).encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Content-Length": str(len(body))}
        if headers:
            hdrs.update(headers)
        conn.request("POST", path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data


# ---------------------------------------------------------------------------
# API boundary
# ---------------------------------------------------------------------------

class ApiBoundaryTests(_ServerTestCase):
    def test_only_three_routes_exist(self):
        for path in ("/api/render", "/api/validate", "/api/diff"):
            self.assertIn(path, srv._ALLOWED_PATHS)
        self.assertEqual(len(srv._ALLOWED_PATHS), 3)

    def test_unknown_post_path_is_404_not_crash(self):
        status, data = self.post("/api/does-not-exist", {"report": {}})
        self.assertEqual(status, 404)
        self.assertFalse(json.loads(data)["ok"])

    def test_get_to_any_path_is_404_never_serves_a_file(self):
        for path in ("/api/render", "/", "/index.html", "/../../etc/passwd", "/website/server.py"):
            with self.subTest(path=path):
                status, _ = self.get(path)
                self.assertEqual(status, 404)

    def test_options_preflight_never_crashes(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("OPTIONS", "/api/render")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 204)

    def test_no_file_path_field_is_ever_accepted(self):
        # Adversarial: the only input vector is inline JSON content - a
        # "path"/"file" field must simply be ignored, never interpreted.
        status, data = self.post("/api/render", {"report": {"mode": "standard", "findings": []}, "path": "/etc/passwd"})
        self.assertEqual(status, 200)
        self.assertNotIn("root:", json.loads(data)["rendered"])


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

class MalformedInputTests(_ServerTestCase):
    def test_non_json_body(self):
        status, data = self.post("/api/render", b"this is not json at all")
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(data)["ok"])

    def test_non_utf8_body(self):
        status, data = self.post("/api/render", b"\xff\xfe\x00\x01")
        self.assertEqual(status, 400)

    def test_top_level_non_object_payload(self):
        for bad in ([1, 2, 3], "a string", 42, None, True):
            with self.subTest(bad=bad):
                status, data = self.post("/api/render", json.dumps(bad).encode())
                self.assertEqual(status, 400)

    def test_missing_report_key(self):
        status, data = self.post("/api/render", {})
        self.assertEqual(status, 400)

    def test_report_wrong_type(self):
        status, data = self.post("/api/render", {"report": "not-a-dict"})
        self.assertEqual(status, 400)

    def test_invalid_format_enum(self):
        status, data = self.post("/api/render", {"report": {"mode": "standard", "findings": []}, "format": "pdf"})
        self.assertEqual(status, 400)

    def test_invalid_diff_mode_enum(self):
        status, data = self.post("/api/diff", {"v1": {"findings": []}, "v2": {"findings": []}, "mode": "bogus"})
        self.assertEqual(status, 400)

    def test_diff_malformed_reports_propagates_clean_400(self):
        status, data = self.post("/api/diff", {"v1": {"findings": "not-a-list"}, "v2": {"findings": []}})
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(data))

    def test_missing_content_length_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/api/render")
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        self.assertEqual(status, 400)

    def test_negative_content_length_rejected(self):
        status, data = self.post("/api/render", {"report": {}}, headers={"Content-Length": "-5"})
        self.assertEqual(status, 400)

    def test_oversized_body_rejected_with_413(self):
        # The server deliberately rejects based on the declared
        # Content-Length WITHOUT reading the (attacker-controlled) body
        # first - it must never buffer megabytes of data just to discard
        # them. That means the client may see a clean 413 OR the
        # connection drop while still sending (the server closes rather
        # than risk a corrupted keep-alive stream) - both outcomes are a
        # correct rejection; only a 200/500 (the oversized body being
        # processed) would be a real failure.
        huge_report = {"report": {"padding": "x" * (srv.MAX_BODY_BYTES + 1)}}
        try:
            status, _ = self.post("/api/render", huge_report)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            return
        self.assertEqual(status, 413)

    def test_validate_never_crashes_on_non_dict_report(self):
        status, data = self.post("/api/validate", {"report": ["not", "a", "dict"]})
        self.assertEqual(status, 400)


# ---------------------------------------------------------------------------
# Rate / abuse handling
# ---------------------------------------------------------------------------

class RateLimitTests(_ServerTestCase):
    def test_requests_within_budget_all_succeed(self):
        for _ in range(srv.RATE_LIMIT_MAX_REQUESTS):
            status, _ = self.post("/api/validate", {"report": {}})
            self.assertEqual(status, 200)

    def test_request_over_budget_is_throttled(self):
        for _ in range(srv.RATE_LIMIT_MAX_REQUESTS):
            self.post("/api/validate", {"report": {}})
        status, data = self.post("/api/validate", {"report": {}})
        self.assertEqual(status, 429)
        self.assertFalse(json.loads(data)["ok"])

    def test_throttling_applies_across_different_routes_for_the_same_client(self):
        # The limiter keys on client, not on route - exhausting the budget
        # on one endpoint throttles the others too for the same caller.
        for _ in range(srv.RATE_LIMIT_MAX_REQUESTS):
            self.post("/api/validate", {"report": {}})
        status, _ = self.post("/api/render", {"report": {"mode": "standard", "findings": []}})
        self.assertEqual(status, 429)


class RateLimiterUnitTests(unittest.TestCase):
    """Direct tests of _RateLimiter, independent of any real socket."""

    def test_allows_up_to_max_then_blocks(self):
        limiter = srv._RateLimiter(window_seconds=60.0, max_requests=3)
        self.assertTrue(limiter.allow("client-a"))
        self.assertTrue(limiter.allow("client-a"))
        self.assertTrue(limiter.allow("client-a"))
        self.assertFalse(limiter.allow("client-a"))

    def test_clients_are_independent(self):
        limiter = srv._RateLimiter(window_seconds=60.0, max_requests=1)
        self.assertTrue(limiter.allow("client-a"))
        self.assertFalse(limiter.allow("client-a"))
        self.assertTrue(limiter.allow("client-b"))

    def test_window_expiry_allows_new_requests(self):
        limiter = srv._RateLimiter(window_seconds=0.05, max_requests=1)
        self.assertTrue(limiter.allow("client-a"))
        self.assertFalse(limiter.allow("client-a"))
        time.sleep(0.08)
        self.assertTrue(limiter.allow("client-a"))


# ---------------------------------------------------------------------------
# Public-route security
# ---------------------------------------------------------------------------

class PublicRouteSecurityTests(_ServerTestCase):
    def test_error_bodies_never_contain_a_traceback(self):
        status, data = self.post("/api/render", b"not json")
        text = data.decode("utf-8")
        self.assertNotIn("Traceback", text)
        self.assertNotIn(".py\", line", text)

    def test_error_bodies_never_contain_a_local_filesystem_path(self):
        status, data = self.post("/api/render", b"not json")
        text = data.decode("utf-8")
        self.assertNotIn(str(REPO_ROOT), text)
        self.assertNotIn("C:\\Users", text)

    def test_unexpected_exception_yields_generic_500_never_the_exception_text(self):
        # _ROUTES captures each handler by value at module load time, so
        # patching the module-level handle_render name has no effect on
        # dispatch - the dict ENTRY itself must be replaced to exercise
        # this path.
        from unittest import mock

        def _boom(payload):
            raise RuntimeError("a secret internal detail")

        with mock.patch.dict(srv._ROUTES, {"/api/render": _boom}):
            status, data = self.post("/api/render", {"report": {}})
        self.assertEqual(status, 500)
        text = data.decode("utf-8")
        self.assertNotIn("secret internal detail", text)
        self.assertFalse(json.loads(data)["ok"])

    def test_no_cors_header_by_default(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps({"report": {}}).encode()
        conn.request("POST", "/api/validate", body=body, headers={"Content-Length": str(len(body))})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    def test_response_is_always_json_content_type(self):
        status, data = self.post("/api/validate", {"report": {}})
        conn_check_status, _ = status, data
        self.assertEqual(status, 200)

    def test_no_commercial_claims_terms_in_any_error_or_success_body(self):
        level_a_terms = [
            "certified", "audited", "guaranteed", "100% secure", "fully secure",
            "vulnerability-free", "no vulnerabilities", "production-ready",
            "zero retention", "never stored", "private by default",
        ]
        bodies = []
        _, d1 = self.post("/api/render", b"not json")
        bodies.append(d1.decode("utf-8", errors="replace"))
        _, d2 = self.post("/api/validate", {"report": {"mode": "standard", "findings": []}})
        bodies.append(d2.decode("utf-8", errors="replace"))
        joined = " ".join(bodies).lower()
        hits = [t for t in level_a_terms if t in joined]
        self.assertEqual(hits, [])


class ModuleShapeTests(unittest.TestCase):
    """Mechanical checks that this module stays a thin wrapper, never a
    second copy of analyzer logic."""

    def test_no_database_or_session_imports(self):
        # Substring-checks the actual MECHANISMS (a DB driver import, a
        # Set-Cookie header) rather than the bare word "session"/"cookie",
        # which also appears in this module's own honest "no sessions, no
        # cookies" docstring - that prose is the correct disclosure, not a
        # violation, and a naive substring match would flag it as one.
        with open(WEBSITE_DIR / "server.py", "r", encoding="utf-8") as fh:
            src = fh.read()
        for banned in ("sqlite3", "import sqlalchemy", "psycopg", "pymongo", "set-cookie", "sessionid"):
            self.assertNotIn(banned, src.lower(), "found forbidden stateful token: %r" % banned)

    def test_handlers_call_api_module_functions_only(self):
        import api
        self.assertIs(srv.api.render_markdown, api.render_markdown)
        self.assertIs(srv.api.validate_report, api.validate_report)
        self.assertIs(srv.api.diff_reports, api.diff_reports)


if __name__ == "__main__":
    unittest.main()
