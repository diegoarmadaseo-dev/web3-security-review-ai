"""Tests for the Private API (docs/decisiones.md D-113): backend/api_keys.py,
the API-key parts of backend/repository.py and /api/v1 plus the API key
endpoints in backend/http_app.py. No network, no LLM, no Docker. SQLite
(real-Postgres checks live in tests/test_backend_postgres_integration.py).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.api_keys as api_keys  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import backend.retention as retention  # noqa: E402
from tests.test_backend_commercial import _sol  # noqa: E402
from tests.test_backend_commercial_guards import _GuardsHttpCase  # noqa: E402
from tests.test_backend_http_app import HOST, _capture_stderr  # noqa: E402
from tests.test_backend_projects_multifile import A_SOL, B_SOL, _zip  # noqa: E402


# ---------------------------------------------------------------------------
# Units: key format, hashing, header parsing
# ---------------------------------------------------------------------------

class ApiKeyUnitTests(unittest.TestCase):
    def test_generated_key_format_entropy_and_hash(self):
        key, prefix, key_hash = api_keys.generate()
        self.assertRegex(key, r"^vcx_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$")
        self.assertEqual(api_keys.parse_prefix(key), prefix)
        self.assertEqual(key_hash, hashlib.sha256(key.encode()).hexdigest())
        self.assertNotIn(key.split("_", 2)[2], key_hash)
        self.assertEqual(len({api_keys.generate()[0] for _ in range(200)}), 200)
        secret = key.split("_", 2)[2]
        self.assertGreaterEqual(len(base64.urlsafe_b64decode(secret + "=")), 32)   # 256 bits

    def test_matches_is_exact(self):
        key, _, key_hash = api_keys.generate()
        self.assertTrue(api_keys.matches(key, key_hash))
        self.assertFalse(api_keys.matches(key[:-1] + ("A" if key[-1] != "A" else "B"), key_hash))
        self.assertFalse(api_keys.matches(None, key_hash))

    def test_authorization_parsing(self):
        key = api_keys.generate()[0]
        self.assertEqual(api_keys.parse_authorization(["Bearer " + key]), (key, None))
        self.assertEqual(api_keys.parse_authorization(["bearer " + key]), (key, None))
        self.assertEqual(api_keys.parse_authorization([]), (None, api_keys.AUTH_MISSING))
        for bad in (["Basic " + key], ["Bearer"], ["Bearer  " + key], ["Bearer " + key + " x"], ["Bearer vcx_short_x"],
                    ["Bearer " + key, "Bearer " + key], ["Token " + key], [key], ["Bearer " + key + "\t"]):
            self.assertEqual(api_keys.parse_authorization(bad), (None, api_keys.AUTH_MALFORMED), bad)

    def test_name_validation(self):
        self.assertEqual(api_keys.validate_name("  CI key "), "CI key")
        for bad in (None, "", "   ", "x" * 101, "a\nb", 5, "a\x7fb"):
            self.assertIsNone(api_keys.validate_name(bad), bad)

    def test_plan_availability(self):
        self.assertFalse(plans.plan_has_feature("trial", plans.FEATURE_PRIVATE_API))
        for plan in ("quick", "standard", "pro"):
            self.assertTrue(plans.plan_has_feature(plan, plans.FEATURE_PRIVATE_API), plan)
        self.assertFalse(plans.plan_has_feature("quick", plans.FEATURE_PRIVATE_GITHUB))   # D-111 unchanged
        self.assertFalse(plans.plan_has_feature(None, plans.FEATURE_PRIVATE_API))


# ---------------------------------------------------------------------------
# HTTP fixture
# ---------------------------------------------------------------------------

class _ApiHttpCase(_GuardsHttpCase):
    MAX_PENDING = 5
    RATE = 200

    def db(self):
        conn = repo.connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def request(self, method, path, key=None, payload=None, headers=None, raw_body=None):
        """A plain API client: no Origin, no cookie unless given."""
        conn = http.client.HTTPConnection(HOST, self.port, timeout=10)
        hdrs = {"Host": self.host_header}
        body = raw_body
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        if body is not None:
            hdrs.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
        if key is not None:
            hdrs["Authorization"] = "Bearer " + key
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        result_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        try:
            parsed = json.loads(data) if data[:1] in (b"{", b"[") else data
        except ValueError:
            parsed = data
        return resp.status, result_headers, parsed

    def api(self, method, path, key, payload=None, headers=None):
        return self.request(method, "/api/v1" + path, key=key, payload=payload, headers=headers)

    def session_create_key(self, cookie, ws, name="CI"):
        status, headers, body = self.post_json("/workspaces/%s/api-keys" % ws, {"name": name}, headers={"Cookie": cookie})
        return status, headers, json.loads(body)

    def account(self, plan, email, credit=True):
        """(cookie, workspace id, API key) for a workspace on `plan`."""
        cookie, ws = self.workspace(plan, email)
        if plan == "quick" and credit:
            repo.grant_scan_credit(self.db(), "cs_test_%s" % email, ws)
        status, _, body = self.session_create_key(cookie, ws)
        self.assertEqual(status, 200, body)
        return cookie, ws, body["secret"]

    def assert_error(self, result, status, code):
        got_status, headers, body = result
        self.assertEqual((got_status, body["error"]["code"]), (status, code), body)
        self.assertEqual(set(body), {"error"})
        self.assertTrue(body["error"]["message"])
        self.assertEqual(body["error"]["request_id"], headers["x-request-id"])
        self.assertRegex(headers["x-request-id"], r"^[0-9a-f]{32}$")
        return body["error"]

    def finish(self, job_id):
        conn = self.db()
        claimed = repo.claim_next_job(conn, "w")
        self.assertEqual(claimed["id"], job_id)
        repo.finalize_job_attempt(conn, job_id, claimed["workspace_id"], claimed["attempt_count"], "w", "claimed", "running")
        key = object_storage.workspace_key(claimed["workspace_id"], "reports", job_id)
        self.storage.put_object(key, b"# Automated security review\n", content_type="text/markdown")
        self.storage.put_object(object_storage.report_json_key(key), json.dumps({"findings": []}).encode(), content_type="application/json")
        res = repo.finalize_job_attempt(conn, job_id, claimed["workspace_id"], claimed["attempt_count"], "w", "running", "succeeded",
                                        report_storage_ref=key, report_score_status="computed", report_score=90, report_risk_band="LOW")
        return res["report_id"]


# ---------------------------------------------------------------------------
# API keys: create / list / revoke / storage
# ---------------------------------------------------------------------------

class ApiKeyLifecycleTests(_ApiHttpCase):
    def test_create_shows_the_key_once_and_stores_only_its_hash(self):
        cookie, ws = self.workspace("standard", "keys@example.com")
        status, headers, body = self.session_create_key(cookie, ws, "Build server")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        key = body["secret"]
        self.assertRegex(key, r"^vcx_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$")
        self.assertEqual((body["key"]["name"], body["key"]["key_prefix"], body["key"]["revoked_at"]),
                         ("Build server", api_keys.parse_prefix(key), None))
        self.assertNotIn("key_hash", body["key"])
        row = dict(self.db().execute("SELECT * FROM api_keys WHERE id = ?", (body["key"]["id"],)).fetchone())
        self.assertEqual(row["key_hash"], hashlib.sha256(key.encode()).hexdigest())
        secret = key.split("_", 2)[2]
        self.assertFalse([c for c, v in row.items() if isinstance(v, str) and secret in v])   # never in plaintext
        # Listings: metadata only, never the key or its hash.
        status, _, listed = self.jget("/workspaces/%s/api-keys" % ws, cookie)
        self.assertEqual(status, 200)
        self.assertEqual([k["id"] for k in listed["keys"]], [body["key"]["id"]])
        dumped = json.dumps(listed)
        self.assertNotIn(secret, dumped)
        self.assertNotIn(row["key_hash"], dumped)
        self.assertEqual(set(listed["keys"][0]), set(repo.API_KEY_PUBLIC_FIELDS))
        status, _, via_api = self.api("GET", "/keys", key)
        self.assertEqual(status, 200)
        self.assertNotIn(secret, json.dumps(via_api))

    def jget(self, path, cookie):
        status, headers, body = self.get(path, headers={"Cookie": cookie})
        return status, headers, json.loads(body)

    def test_last_used_is_recorded(self):
        _, ws, key = self.account("standard", "lastused@example.com")
        self.assertIsNone(self.db().execute("SELECT last_used_at FROM api_keys").fetchone()[0])
        self.assertEqual(self.api("GET", "/usage", key)[0], 200)
        self.assertIsNotNone(self.db().execute("SELECT last_used_at FROM api_keys").fetchone()[0])

    def test_revoked_key_is_rejected_and_the_workspace_survives(self):
        cookie, ws, key = self.account("standard", "revoke@example.com")
        other = self.session_create_key(cookie, ws, "second")[2]["secret"]
        key_id = self.api("GET", "/keys", key)[2]["keys"][-1]["id"]
        self.assertEqual(self.api("GET", "/projects", key)[0], 200)
        status, _, body = self.delete("/workspaces/%s/api-keys/%s" % (ws, key_id), headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIsNotNone(json.loads(body)["key"]["revoked_at"])
        self.assert_error(self.api("GET", "/projects", key), 401, "invalid_api_key")
        self.assertEqual(self.api("GET", "/projects", other)[0], 200)            # other keys unaffected
        self.assertIsNotNone(repo.get_workspace(self.db(), ws))
        status, _, again = self.delete("/workspaces/%s/api-keys/%s" % (ws, key_id), headers={"Cookie": cookie})
        self.assertEqual(status, 200)                                              # idempotent

    def test_rotation_via_the_api(self):
        _, ws, old = self.account("pro", "rotate@example.com")
        status, _, created = self.api("POST", "/keys", old, {"name": "rotated"})
        self.assertEqual(status, 200)
        new = created["secret"]
        old_id = [k["id"] for k in self.api("GET", "/keys", new)[2]["keys"] if k["name"] == "CI"][0]
        self.assertEqual(self.api("DELETE", "/keys/%s" % old_id, new)[0], 200)
        self.assert_error(self.api("GET", "/usage", old), 401, "invalid_api_key")
        self.assertEqual(self.api("GET", "/usage", new)[0], 200)

    def test_members_see_and_revoke_only_their_own_keys(self):
        owner_cookie, ws, owner_key = self.account("standard", "owner-k@example.com")
        member_cookie = self.request_and_confirm_login("member-k@example.com")
        conn = self.db()
        repo.add_workspace_member(conn, ws, repo.get_user_by_email(conn, "member-k@example.com")["id"], "member")
        member_key = self.session_create_key(member_cookie, ws, "mine")[2]["secret"]
        member_view = self.api("GET", "/keys", member_key)[2]["keys"]
        self.assertEqual([k["name"] for k in member_view], ["mine"])
        self.assertEqual(len(self.api("GET", "/keys", owner_key)[2]["keys"]), 2)
        owner_key_id = [k["id"] for k in self.api("GET", "/keys", owner_key)[2]["keys"] if k["name"] == "CI"][0]
        self.assert_error(self.api("DELETE", "/keys/%s" % owner_key_id, member_key), 404, "key_not_found")
        member_key_id = member_view[0]["id"]
        self.assertEqual(self.api("DELETE", "/keys/%s" % member_key_id, owner_key)[0], 200)   # owner may revoke any key

    def test_removed_member_key_stops_working(self):
        _, ws, _ = self.account("standard", "owner-r@example.com")
        member_cookie = self.request_and_confirm_login("member-r@example.com")
        conn = self.db()
        member_id = repo.get_user_by_email(conn, "member-r@example.com")["id"]
        repo.add_workspace_member(conn, ws, member_id, "member")
        member_key = self.session_create_key(member_cookie, ws)[2]["secret"]
        self.assertEqual(self.api("GET", "/projects", member_key)[0], 200)
        repo.remove_workspace_member(conn, ws, member_id)
        self.assert_error(self.api("GET", "/projects", member_key), 401, "invalid_api_key")

    def test_key_names_are_validated(self):
        cookie, ws = self.workspace("standard", "names@example.com")
        for bad in ("", "x" * 101, "a\nb", None):
            status, _, body = self.session_create_key(cookie, ws, bad)
            self.assertEqual((status, body["error"]), (400, "invalid_key_name"))

    def test_active_key_ceiling_including_concurrency(self):
        cookie, ws = self.workspace("standard", "ceiling@example.com")
        results, barrier = [], threading.Barrier(30)

        def go(i):
            barrier.wait()
            results.append(self.session_create_key(cookie, ws, "k%d" % i)[0])

        threads = [threading.Thread(target=go, args=(i,)) for i in range(30)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        self.assertEqual(sorted(results), [200] * api_keys.MAX_ACTIVE_KEYS_PER_WORKSPACE + [409] * (30 - api_keys.MAX_ACTIVE_KEYS_PER_WORKSPACE))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM api_keys WHERE workspace_id = ? AND revoked_at IS NULL", (ws,)).fetchone()[0],
                         api_keys.MAX_ACTIVE_KEYS_PER_WORKSPACE)

    def test_session_key_endpoints_keep_the_csrf_defense(self):
        cookie, ws = self.workspace("standard", "csrf-k@example.com")
        status, _, _ = self.post_json("/workspaces/%s/api-keys" % ws, {"name": "x"}, headers={"Cookie": cookie, "Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM api_keys").fetchone()[0], 0)

    def test_non_member_cannot_manage_keys_of_a_workspace(self):
        _, ws, _ = self.account("standard", "victim-k@example.com")
        intruder = self.request_and_confirm_login("intruder-k@example.com")
        self.assertEqual(self.session_create_key(intruder, ws)[0], 403)
        self.assertEqual(self.get("/workspaces/%s/api-keys" % ws, headers={"Cookie": intruder})[0], 403)

    def test_workspace_deletion_revokes_its_keys(self):
        _, ws, key = self.account("standard", "deleted-k@example.com")
        result = retention.delete_workspace_data(self.db(), self.storage, ws, dry_run=False)
        self.assertEqual(result["api_keys_revoked"], 1)
        self.assert_error(self.api("GET", "/usage", key), 401, "invalid_api_key")


# ---------------------------------------------------------------------------
# Plan gating (backend, not UI)
# ---------------------------------------------------------------------------

class PlanGatingTests(_ApiHttpCase):
    def _trial_workspace_with_key(self, email):
        cookie, ws = self.workspace("trial", email)
        conn = self.db()
        key, prefix, key_hash = api_keys.generate()
        repo.create_api_key(conn, ws, repo.get_user_by_email(conn, email)["id"], "forced", prefix, key_hash, 25)
        return cookie, ws, key

    def test_trial_is_denied_everywhere(self):
        cookie, ws = self.workspace("trial", "trial-api@example.com")
        status, _, body = self.session_create_key(cookie, ws)
        self.assertEqual((status, body["error"], body["feature"]), (403, "feature_not_available", "private_api"))
        _, _, key = self._trial_workspace_with_key("trial-api2@example.com")   # even a key planted in the database
        for method, path, payload in (("GET", "/usage", None), ("GET", "/billing", None), ("GET", "/projects", None), ("POST", "/projects", {"name": "x"}),
                                      ("POST", "/scans", {"mode": "quick", "source": _sol(10)}), ("GET", "/scans", None), ("GET", "/keys", None),
                                      ("POST", "/keys", {"name": "x"}), ("GET", "/reports/%s" % repo.new_id(), None), ("GET", "/nope", None)):
            err = self.assert_error(self.api(method, path, key, payload), 403, "feature_not_available")
            self.assertEqual((err["details"]["feature"], err["details"]["plan"]), ("private_api", "trial"))

    def test_quick_standard_pro_are_allowed(self):
        for plan in ("quick", "standard", "pro"):
            _, ws, key = self.account(plan, "%s-allowed@example.com" % plan)
            status, _, body = self.api("GET", "/billing", key)
            self.assertEqual((status, body["entitlement"]["plan"], "private_api" in body["features"]), (200, plan, True))
            self.assertEqual(self.api("GET", "/usage", key)[0], 200)

    def test_inactive_subscription_is_402(self):
        _, ws, key = self.account("standard", "pastdue@example.com")
        conn = self.db()
        conn.execute("UPDATE entitlements SET status = 'past_due' WHERE workspace_id = ?", (ws,))
        conn.commit()
        self.assert_error(self.api("GET", "/usage", key), 402, "no_active_subscription")

    def test_billing_never_exposes_stripe_identifiers(self):
        _, ws, key = self.account("standard", "stripe-ids@example.com")
        conn = self.db()
        conn.execute("UPDATE entitlements SET stripe_customer_id = 'cus_secretish', stripe_subscription_id = 'sub_secretish' WHERE workspace_id = ?", (ws,))
        conn.commit()
        body = self.api("GET", "/billing", key)[2]
        self.assertNotIn("cus_secretish", json.dumps(body))
        self.assertNotIn("sub_secretish", json.dumps(body))
        self.assertEqual(set(body["entitlement"]), {"plan", "status", "billing_interval", "current_period_start", "current_period_end", "display_name"})


# ---------------------------------------------------------------------------
# Authentication, CORS, logs, error contract
# ---------------------------------------------------------------------------

class ApiSecurityTests(_ApiHttpCase):
    def test_missing_malformed_and_invalid_credentials(self):
        _, ws, key = self.account("standard", "auth@example.com")
        status, headers, _ = self.request("GET", "/api/v1/projects")
        self.assert_error((status, headers, _), 401, "authentication_required")
        self.assertIn("Bearer", headers["www-authenticate"])
        for value in ("Basic " + key, "Bearer", "Bearer  " + key, "Token " + key, key, "Bearer vcx_123_abc"):
            self.assert_error(self.request("GET", "/api/v1/projects", headers={"Authorization": value}), 401, "invalid_authorization_header")
        forged = api_keys.generate()[0]
        self.assert_error(self.api("GET", "/projects", forged), 401, "invalid_api_key")
        same_prefix = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
        self.assert_error(self.api("GET", "/projects", same_prefix), 401, "invalid_api_key")

    def test_duplicate_authorization_headers_are_rejected(self):
        _, ws, key = self.account("standard", "dup-auth@example.com")
        conn = http.client.HTTPConnection(HOST, self.port, timeout=10)
        conn.putrequest("GET", "/api/v1/projects", skip_host=True)
        conn.putheader("Host", self.host_header)
        conn.putheader("Authorization", "Bearer " + key)
        conn.putheader("Authorization", "Bearer " + key)
        conn.endheaders()
        resp = conn.getresponse()
        body = json.loads(resp.read())
        conn.close()
        self.assertEqual((resp.status, body["error"]["code"]), (401, "invalid_authorization_header"))

    def test_session_cookie_is_not_api_auth_and_key_is_not_session_auth(self):
        cookie, ws, key = self.account("standard", "separation@example.com")
        self.assert_error(self.request("GET", "/api/v1/projects", headers={"Cookie": cookie}), 401, "authentication_required")
        status, _, _ = self.request("GET", "/workspaces/%s/projects" % ws, key=key)
        self.assertEqual(status, 401)
        status, _, _ = self.request("GET", "/workspaces", key=key)
        self.assertEqual(status, 401)

    def test_no_cors_and_no_preflight(self):
        _, ws, key = self.account("standard", "cors@example.com")
        status, headers, _ = self.api("GET", "/projects", key, headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 200)
        self.assertFalse([h for h in headers if h.startswith("access-control-")])
        status, headers, _ = self.request("OPTIONS", "/api/v1/projects", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
                                                                               "Access-Control-Request-Headers": "authorization"})
        self.assertNotEqual(status, 200)
        self.assertFalse([h for h in headers if h.startswith("access-control-")])

    def test_key_source_and_authorization_never_logged(self):
        marker = "uint256 public logMarker8842;"
        with _capture_stderr() as captured:
            cookie, ws, key = self.account("standard", "logs@example.com")
            source = "pragma solidity ^0.8.20;\ncontract L {\n    %s\n}\n" % marker
            status, headers, body = self.api("POST", "/scans", key, {"mode": "standard", "source": source})
            self.assertEqual(status, 200, body)
            self.api("GET", "/scans/%s" % body["job_id"], key)
            self.request("GET", "/api/v1/vcx_%s_leaked" % ("a" * 12))
        log = captured.getvalue()
        secret = key.split("_", 2)[2]
        self.assertNotIn(secret, log)
        self.assertNotIn(key, log)
        self.assertNotIn(marker, log)
        self.assertNotIn("Bearer", log)
        self.assertNotIn("_leaked", log)
        records = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
        submit = [r for r in records if r["method"] == "POST" and r["path"] == "/api/v1/scans"][0]
        self.assertEqual((submit["status"], submit["workspace_id"], submit["event"]), (200, ws, "api_request"))
        self.assertEqual(submit["request_id"], headers["x-request-id"])
        self.assertTrue(submit["api_key_id"])

    def test_error_contract_unknown_route_wrong_method_and_status_codes(self):
        _, ws, key = self.account("standard", "contract@example.com")
        self.assert_error(self.api("GET", "/nope", key), 404, "not_found")
        status, headers, body = self.api("PUT", "/projects", key, {"name": "x"})
        self.assertIn(status, (405, 501))                                         # PUT itself is not implemented by the server
        status, headers, body = self.api("DELETE", "/scans", key)
        self.assertEqual((status, body["error"]["code"], headers["allow"]), (405, "method_not_allowed", "GET, POST"))
        self.assert_error(self.request("POST", "/api/v1/projects", key=key, raw_body=b"{not json"), 400, "invalid_json")
        err = self.assert_error(self.api("POST", "/scans", key, {"mode": "standard", "source": "// only a comment\n"}), 422, "no_source_code")
        self.assertEqual(err["details"]["effective_loc"], 0)
        self.assert_error(self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)}), 403, "mode_not_allowed")
        self.assert_error(self.api("POST", "/scans", key, {"mode": "quick"}), 400, "source_required")
        # Deterministic: the same request twice yields the same status and code.
        first = self.api("GET", "/scans/%s" % repo.new_id(), key)
        second = self.api("GET", "/scans/%s" % repo.new_id(), key)
        self.assertEqual((first[0], first[2]["error"]["code"]), (second[0], second[2]["error"]["code"]))
        self.assertNotEqual(first[2]["error"]["request_id"], second[2]["error"]["request_id"])

    def test_success_responses_carry_a_request_id_and_no_store(self):
        _, ws, key = self.account("standard", "rid@example.com")
        status, headers, _ = self.api("GET", "/projects", key)
        self.assertEqual(status, 200)
        self.assertRegex(headers["x-request-id"], r"^[0-9a-f]{32}$")
        self.assertEqual(headers["cache-control"], "no-store")

    def test_internal_details_never_leak(self):
        _, ws, key = self.account("standard", "leak@example.com")
        job = self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10)})[2]
        report_id = self.finish(job["job_id"])
        for path in ("/scans/%s" % job["job_id"], "/reports/%s" % report_id, "/scans", "/usage", "/billing", "/keys"):
            text = json.dumps(self.api("GET", path, key)[2])
            self.assertNotIn("storage_ref", text, path)
            self.assertNotIn(ws + "/reports", text, path)
            self.assertNotIn("key_hash", text, path)
            self.assertNotIn("Traceback", text, path)

    def test_oversized_body_is_refused_before_reading(self):
        _, ws, key = self.account("standard", "big@example.com")
        conn = http.client.HTTPConnection(HOST, self.port, timeout=10)
        conn.putrequest("POST", "/api/v1/scans", skip_host=True)
        for k, v in (("Host", self.host_header), ("Authorization", "Bearer " + key), ("Content-Type", "application/json"),
                     ("Content-Length", str(http_app.JOB_SUBMIT_MAX_BODY_BYTES + 1))):
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        body = json.loads(resp.read())
        conn.close()
        self.assertEqual((resp.status, body["error"]["code"]), (413, "request_too_large"))


# ---------------------------------------------------------------------------
# Projects and tenant isolation
# ---------------------------------------------------------------------------

class ProjectApiTests(_ApiHttpCase):
    def test_crud(self):
        _, ws, key = self.account("standard", "crud@example.com")
        status, _, created = self.api("POST", "/projects", key, {"name": "Vault"})
        self.assertEqual(status, 200)
        pid = created["project"]["id"]
        self.assertEqual(self.api("GET", "/projects/%s" % pid, key)[2]["project"]["name"], "Vault")
        self.assertEqual([p["id"] for p in self.api("GET", "/projects", key)[2]["projects"]], [pid])
        self.assertEqual(self.api("PATCH", "/projects/%s" % pid, key, {"name": "Vault v2"})[2]["project"]["name"], "Vault v2")
        self.assert_error(self.api("POST", "/projects", key, {"name": "Vault v2"}), 409, "project_name_taken")
        self.assertEqual(self.api("DELETE", "/projects/%s" % pid, key)[2], {"ok": True, "deleted": True})
        self.assert_error(self.api("GET", "/projects/%s" % pid, key), 404, "project_not_found")

    def test_cross_workspace_resources_are_invisible(self):
        _, ws_a, key_a = self.account("standard", "tenant-a@example.com")
        _, ws_b, key_b = self.account("standard", "tenant-b@example.com")
        pid_b = self.api("POST", "/projects", key_b, {"name": "B"})[2]["project"]["id"]
        job_b = self.api("POST", "/scans", key_b, {"mode": "standard", "source": _sol(10), "project_id": pid_b})[2]["job_id"]
        report_b = self.finish(job_b)
        self.assert_error(self.api("GET", "/projects/%s" % pid_b, key_a), 404, "project_not_found")
        self.assert_error(self.api("PATCH", "/projects/%s" % pid_b, key_a, {"name": "pwn"}), 404, "project_not_found")
        self.assert_error(self.api("DELETE", "/projects/%s" % pid_b, key_a), 404, "project_not_found")
        self.assert_error(self.api("GET", "/scans/%s" % job_b, key_a), 404, "not_found")
        self.assert_error(self.api("GET", "/reports/%s" % report_b, key_a), 404, "not_found")
        self.assert_error(self.api("GET", "/reports/%s/json" % report_b, key_a), 404, "not_found")
        self.assert_error(self.api("POST", "/scans", key_a, {"mode": "standard", "source": _sol(10), "project_id": pid_b}), 404, "project_not_found")
        self.assertEqual(self.api("GET", "/scans", key_a)[2]["jobs"], [])
        self.assertEqual(self.api("GET", "/projects", key_a)[2]["projects"], [])
        self.assertEqual(self.api("GET", "/usage", key_a)[2]["workspace_id"], ws_a)
        self.assertEqual(self.api("GET", "/billing", key_a)[2]["workspace_id"], ws_a)
        key_b_id = self.api("GET", "/keys", key_b)[2]["keys"][0]["id"]
        self.assert_error(self.api("DELETE", "/keys/%s" % key_b_id, key_a), 404, "key_not_found")
        self.assertEqual(self.api("GET", "/projects/%s" % pid_b, key_b)[0], 200)   # untouched


# ---------------------------------------------------------------------------
# Scans: inputs, admission, D-108 guards
# ---------------------------------------------------------------------------

class ScanApiTests(_ApiHttpCase):
    def test_single_multi_file_zip_and_project(self):
        _, ws, key = self.account("standard", "inputs@example.com")
        pid = self.api("POST", "/projects", key, {"name": "P"})[2]["project"]["id"]
        single = self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(40), "project_id": pid})
        self.assertEqual((single[0], single[2]["source_kind"], single[2]["effective_loc"], single[2]["project_id"]), (200, "single", 40, pid))
        multi = self.api("POST", "/scans", key, {"mode": "standard", "files": [{"path": "A.sol", "content": A_SOL}, {"path": "B.sol", "content": B_SOL}]})
        self.assertEqual((multi[0], multi[2]["source_kind"], sorted(f["path"] for f in multi[2]["files"])), (200, "files", ["A.sol", "B.sol"]))
        archive = base64.b64encode(_zip([("src/A.sol", A_SOL), ("src/B.sol", B_SOL)])).decode()
        zipped = self.api("POST", "/scans", key, {"mode": "standard", "archive": {"format": "zip", "content_base64": archive}})
        self.assertEqual((zipped[0], zipped[2]["source_kind"]), (200, "archive"))
        listed = self.api("GET", "/scans?project_id=%s" % pid, key)[2]["jobs"]
        self.assertEqual([j["id"] for j in listed], [single[2]["job_id"]])
        detail = self.api("GET", "/scans/%s" % multi[2]["job_id"], key)[2]
        self.assertEqual((detail["job"]["status"], detail["source"]["kind"]), ("queued", "files"))
        self.assert_error(self.api("POST", "/scans", key, {"mode": "standard", "files": [{"path": "../A.sol", "content": B_SOL}]}), 400, "invalid_path")

    def test_quick_flow_and_credit(self):
        _, ws, key = self.account("quick", "quick-api@example.com")
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["scans_available"], 1)
        self.assert_error(self.api("POST", "/scans", key, {"mode": "quick", "source": _sol(3001)}), 413, "loc_per_scan_limit_exceeded")
        status, _, body = self.api("POST", "/scans", key, {"mode": "quick", "source": _sol(2999)})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["scans_available"], 0)
        self.assert_error(self.api("POST", "/scans", key, {"mode": "quick", "source": _sol(10)}), 402, "no_scan_credit")

    def test_standard_quota(self):
        _, ws, key = self.account("standard", "quota-api@example.com")
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10000)})[0], 200)
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(9000)})[0], 200)
        err = self.assert_error(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(2000)}), 402, "loc_quota_exceeded")
        self.assertEqual(err["details"]["loc_remaining"], 1000)
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["loc_remaining"], 1000)

    def test_pending_jobs_cap(self):
        _, ws, key = self.account("pro", "pending-api@example.com")
        for _ in range(self.MAX_PENDING):
            self.assertEqual(self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)})[0], 200)
        err = self.assert_error(self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)}), 429, "too_many_pending_jobs")
        self.assertEqual(err["details"]["max_pending_jobs"], self.MAX_PENDING)

    def test_technical_budget(self):
        _, ws, key = self.account("standard", "budget-api@example.com")
        job = self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10)})[2]["job_id"]
        conn = self.db()
        repo.transition_job_status(conn, job, "queued", "canceled")
        conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        conn.commit()
        self.assert_error(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10)}), 429, "technical_budget_exhausted")

    def test_github_source_is_not_accepted_by_the_api(self):
        _, ws, key = self.account("pro", "gh-api@example.com")
        self.assert_error(self.api("POST", "/scans", key, {"mode": "pro", "github": {"repository_id": 1}}), 400, "source_not_supported")
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], 0)

    def test_dry_run_reserves_nothing(self):
        _, ws, key = self.account("quick", "dry-api@example.com")
        status, _, body = self.api("POST", "/scans", key, {"mode": "quick", "source": _sol(20), "dry_run": True})
        self.assertEqual((status, body["admissible"], body["effective_loc"]), (200, True, 20))
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["scans_available"], 1)


class RateLimitApiTests(_ApiHttpCase):
    RATE = 3

    def test_d108_submit_rate_limit_is_shared_with_the_web_app(self):
        cookie, ws, key = self.account("pro", "rate-api@example.com")
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)})[0], 200)
        self.assertEqual(self.submit(cookie, ws, mode="pro")[0], 200)               # the same user's web-app submission
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)})[0], 200)
        status, headers, body = self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)})
        err = self.assert_error((status, headers, body), 429, "submit_rate_limited")
        self.assertEqual(headers["retry-after"], str(err["details"]["retry_after_seconds"]))


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

class IdempotencyApiTests(_ApiHttpCase):
    def counts(self, ws):
        conn = self.db()
        jobs = conn.execute("SELECT COUNT(*) FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()[0]
        usage = conn.execute("SELECT COUNT(*) FROM job_usage WHERE workspace_id = ?", (ws,)).fetchone()[0]
        return jobs, usage

    def test_same_key_same_payload_returns_the_same_job(self):
        _, ws, key = self.account("quick", "idem-same@example.com")
        payload = {"mode": "quick", "source": _sol(30), "idempotency_key": "build-42"}
        first = self.api("POST", "/scans", key, payload)[2]
        second = self.api("POST", "/scans", key, payload)[2]
        self.assertEqual((second["job_id"], second["duplicate"]), (first["job_id"], True))
        self.assertEqual(self.counts(ws), (1, 1))
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["scans_available"], 0)   # one Quick credit used, not two

    def test_same_key_different_payload_is_409(self):
        _, ws, key = self.account("standard", "idem-diff@example.com")
        first = self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(30), "idempotency_key": "k1"})[2]
        for changed in ({"source": _sol(31)}, {"mode": "quick"}, {"filename": "other.sol"},
                        {"source": None, "files": [{"path": "A.sol", "content": A_SOL}, {"path": "B.sol", "content": B_SOL}]}):
            payload = dict({"mode": "standard", "source": _sol(30), "idempotency_key": "k1"}, **changed)
            payload = {k: v for k, v in payload.items() if v is not None}
            err = self.assert_error(self.api("POST", "/scans", key, payload), 409, "idempotency_key_reused")
            self.assertEqual(err["details"]["job_id"], first["job_id"])
        self.assertEqual(self.counts(ws), (1, 1))

    def test_header_alias_and_conflict(self):
        _, ws, key = self.account("standard", "idem-header@example.com")
        payload = {"mode": "standard", "source": _sol(30)}
        first = self.api("POST", "/scans", key, payload, headers={"Idempotency-Key": "hdr-1"})[2]
        again = self.api("POST", "/scans", key, dict(payload, idempotency_key="hdr-1"))[2]
        self.assertEqual((again["job_id"], again["duplicate"]), (first["job_id"], True))
        self.assert_error(self.api("POST", "/scans", key, dict(payload, idempotency_key="a"), headers={"Idempotency-Key": "b"}), 400, "idempotency_key_conflict")
        self.assertEqual(self.counts(ws), (1, 1))

    def test_concurrent_same_key(self):
        _, ws, key = self.account("standard", "idem-race@example.com")
        payload = {"mode": "standard", "source": _sol(50), "idempotency_key": "race"}
        results, barrier = [], threading.Barrier(8)

        def go():
            barrier.wait()
            results.append(self.api("POST", "/scans", key, payload))

        threads = [threading.Thread(target=go) for _ in range(8)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        self.assertEqual([r[0] for r in results], [200] * 8, [r[2] for r in results])
        self.assertEqual(len({r[2]["job_id"] for r in results}), 1)
        self.assertEqual(sum(1 for r in results if not r[2].get("duplicate")), 1)
        self.assertEqual(self.counts(ws), (1, 1))
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["loc_used"], 50)

    def test_keys_are_isolated_per_workspace(self):
        _, ws_a, key_a = self.account("standard", "idem-a@example.com")
        _, ws_b, key_b = self.account("standard", "idem-b@example.com")
        payload = {"mode": "standard", "source": _sol(30), "idempotency_key": "shared"}
        job_a = self.api("POST", "/scans", key_a, payload)[2]["job_id"]
        job_b = self.api("POST", "/scans", key_b, payload)[2]
        self.assertNotEqual(job_b["job_id"], job_a)
        self.assertNotIn("duplicate", job_b)

    def test_web_app_reuse_behavior_is_unchanged(self):
        cookie, ws, key = self.account("standard", "idem-ui@example.com")
        first = self.post_json("/workspaces/%s/jobs" % ws, {"mode": "standard", "source": _sol(30), "idempotency_key": "ui"}, headers={"Cookie": cookie})
        second = self.post_json("/workspaces/%s/jobs" % ws, {"mode": "standard", "source": _sol(31), "idempotency_key": "ui"}, headers={"Cookie": cookie})
        self.assertEqual((second[0], json.loads(second[2])["job_id"], json.loads(second[2])["duplicate"]), (200, json.loads(first[2])["job_id"], True))
        stored = self.db().execute("SELECT request_fingerprint FROM analysis_jobs").fetchone()[0]
        self.assertRegex(stored, r"^[0-9a-f]{64}$")
        self.assert_error(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(31), "idempotency_key": "ui"}), 409, "idempotency_key_reused")


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportApiTests(_ApiHttpCase):
    def test_own_report_document_json_and_markdown(self):
        _, ws, key = self.account("standard", "report-api@example.com")
        job = self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10)})[2]["job_id"]
        report_id = self.finish(job)
        detail = self.api("GET", "/scans/%s" % job, key)[2]
        self.assertEqual((detail["job"]["status"], detail["report"]["id"]), ("succeeded", report_id))
        doc = self.api("GET", "/reports/%s" % report_id, key)[2]
        self.assertEqual((doc["scored_report"], doc["markdown"], doc["trial"], doc["downloads"]),
                         ({"findings": []}, "# Automated security review\n", False, True))
        status, headers, body = self.api("GET", "/reports/%s/json" % report_id, key)
        self.assertEqual((status, headers["content-type"], body), (200, "application/json; charset=utf-8", {"findings": []}))
        self.assertRegex(headers["x-request-id"], r"^[0-9a-f]{32}$")
        status, headers, body = self.api("GET", "/reports/%s/markdown" % report_id, key)
        self.assertEqual((status, headers["content-type"], body), (200, "text/markdown; charset=utf-8", b"# Automated security review\n"))

    def test_trial_admitted_report_keeps_its_rules_after_an_upgrade(self):
        cookie, ws = self.workspace("trial", "upgraded@example.com")
        conn = self.db()
        user_id = repo.get_user_by_email(conn, "upgraded@example.com")["id"]
        conn.execute("INSERT INTO trial_grants (normalized_email, user_id, workspace_id, status, granted_at, updated_at) VALUES (?, ?, ?, 'available', ?, ?)",
                     ("upgraded@example.com", user_id, ws, repo.utcnow_iso(), repo.utcnow_iso()))
        conn.commit()
        status, _, body = self.submit(cookie, ws, loc=10)
        self.assertEqual(status, 200, body)
        report_id = self.finish(body["job_id"])
        conn.execute("UPDATE entitlements SET plan = 'standard' WHERE workspace_id = ?", (ws,))   # upgrade
        conn.commit()
        key = self.session_create_key(cookie, ws)[2]["secret"]
        self.assertEqual(self.api("GET", "/reports/%s" % report_id, key)[2]["advisory"], None)
        err = self.assert_error(self.api("GET", "/reports/%s/json" % report_id, key), 403, "feature_not_available")
        self.assertEqual(err["details"]["feature"], "report_download")


# ---------------------------------------------------------------------------
# Web app: API keys view
# ---------------------------------------------------------------------------

class WebAppApiKeysTests(unittest.TestCase):
    APP = (REPO_ROOT / "backend" / "webapp" / "app.js").read_text(encoding="utf-8")
    INDEX = (REPO_ROOT / "backend" / "webapp" / "index.html").read_text(encoding="utf-8")
    CORE = REPO_ROOT / "backend" / "webapp" / "app-core.js"

    def test_view_is_routed_and_gated_by_the_backend_feature_list(self):
        self.assertIn('<a href="#/api-keys" data-nav="api-keys">API keys</a>', self.INDEX)
        self.assertIn('"api-keys": apiKeysView', self.APP)
        self.assertIn('var allowed = (adm.features || []).indexOf("private_api") >= 0;', self.APP)
        self.assertIn('api("POST", wsPath("/api-keys"), { name: input.value })', self.APP)

    def test_the_key_is_shown_once_and_never_persisted_in_the_browser(self):
        self.assertNotRegex(self.APP, r"localStorage\.setItem\([^)]*secret|sessionStorage")
        self.assertEqual(self.APP.count("d.secret"), 1)                     # rendered once, as text, from the create response only
        self.assertIn('el("code", { text: d.secret })', self.APP)

    @unittest.skipUnless(__import__("shutil").which("node"), "node is not installed")
    def test_feature_aware_error_messages(self):
        import subprocess
        script = ("var C = require(%s);\nprocess.stdout.write(JSON.stringify(["
                  "C.describeError(403, {error: 'feature_not_available', feature: 'private_api'}).message,"
                  "C.describeError(403, {error: 'feature_not_available', feature: 'private_github'}).message,"
                  "C.describeError(403, {error: 'feature_not_available'}).message,"
                  "C.describeError(409, {error: 'key_limit_reached'}).message]));" % json.dumps(str(self.CORE)))
        out = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout)
        self.assertEqual(out[0], "The Private API is available on the Quick, Standard and Pro plans.")
        self.assertEqual(out[1], "Private GitHub is available on the Standard and Pro plans.")
        self.assertEqual(out[2], "Private GitHub is available on the Standard and Pro plans.")
        self.assertIn("Revoke an unused key", out[3])


if __name__ == "__main__":
    unittest.main()
