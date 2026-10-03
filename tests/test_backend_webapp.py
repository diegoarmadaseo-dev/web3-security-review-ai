"""Tests for the SaaS web app (docs/decisiones.md D-110): the /app shell and
static files served by backend/http_app.py, the JSON additions the app
uses (/auth/me, /billing/plans, job summaries, job report link, report
document/downloads, submit dry_run, workspace admission/usage display data),
the structured-report persistence in the worker, and the browser code's own
safety properties (backend/webapp/*.js: no HTML sinks, no third-party
origins, no prohibited claims) plus its pure helpers run under Node when
Node is installed. No LLM, no Docker, no Stripe network.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import backend.retention as retention  # noqa: E402
import backend.targeted_review as targeted_review  # noqa: E402
import backend.worker_entrypoint as worker_entrypoint  # noqa: E402
import backend.worker_supervisor as ws_mod  # noqa: E402
from tests.test_backend_commercial import _sol  # noqa: E402
from tests.test_backend_commercial_guards import _GuardsHttpCase  # noqa: E402
from tests.test_backend_projects_multifile import _zip  # noqa: E402
from tests.test_backend_worker_supervisor_no_docker import _FAKE_CONFIG, _CollectingAlertSender  # noqa: E402

WEBAPP = REPO_ROOT / "backend" / "webapp"
SCORED = json.loads((REPO_ROOT / "evals" / "results" / "actual" / "sc01_unprotected_withdraw.json").read_text(encoding="utf-8"))
B_SOL = "pragma solidity ^0.8.20;\ncontract B {\n    function g() internal {}\n}\n"


class _AppCase(_GuardsHttpCase):
    MAX_PENDING = 5
    RATE = 50

    def ws(self, plan, email, credits=0):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        ws = repo.create_workspace(conn, "App WS", repo.get_user_by_email(conn, email)["id"])
        if plan:
            repo.create_entitlement(conn, ws, plan, "active", billing_interval=None if plan == "quick" else "monthly")
        for i in range(credits):
            repo.grant_scan_credit(conn, "cs_%s_%d" % (ws, i), ws)
        conn.close()
        return cookie, ws

    def jget(self, path, cookie=None):
        status, headers, body = self.get(path, headers={"Cookie": cookie} if cookie else None)
        return status, headers, (json.loads(body) if body and headers.get("Content-Type", "").startswith("application/json") else body)

    def submit(self, cookie, ws, **payload):
        payload.setdefault("mode", "quick")
        status, _, body = self.post_json("/workspaces/%s/jobs" % ws, payload, headers={"Cookie": cookie})
        return status, json.loads(body)

    def complete(self, job_id, scored=SCORED, advisory=None, markdown="# Report\n"):
        """Simulates the worker's success path for one queued job."""
        conn = repo.connect(self.db_path)
        try:
            job = repo.claim_next_job(conn, "w")
            assert job["id"] == job_id, (job["id"], job_id)
            repo.finalize_job_attempt(conn, job_id, job["workspace_id"], job["attempt_count"], "w", "claimed", "running")
            key = object_storage.workspace_key(job["workspace_id"], "reports", job_id)
            self.storage.put_object(key, markdown.encode(), content_type="text/markdown")
            ri = (scored or {}).get("riskIndicator") or {"score": None, "band": None}
            res = repo.finalize_job_attempt(conn, job_id, job["workspace_id"], job["attempt_count"], "w", "running", "succeeded",
                                            report_storage_ref=key, report_score_status="computed" if ri.get("score") is not None else "not_computed",
                                            report_score=ri.get("score"), report_risk_band=ri.get("band"))
            if scored is not None:
                self.storage.put_object(object_storage.report_json_key(key), json.dumps(scored).encode(), content_type="application/json")
            if advisory is not None:
                self.storage.put_object(key + targeted_review.OBJECT_SUFFIX, json.dumps(advisory).encode(), content_type="application/json")
            return res["report_id"], key
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Shell and static files
# ---------------------------------------------------------------------------

class AppShellTests(_AppCase):
    def test_root_redirects_to_the_app_and_the_app_requires_a_session(self):
        status, headers, _ = self.get("/")
        self.assertEqual((status, headers["Location"]), (302, "/app"))
        for path in ("/app", "/app/", "/app/scans/123"):
            status, headers, _ = self.get(path)
            self.assertEqual((status, headers["Location"]), (302, "/auth/login"), path)

    def test_signed_in_shell_is_static_strict_and_deep_linkable(self):
        cookie, _ = self.ws("standard", "shell@example.com")
        for path in ("/app", "/app/dashboard", "/app/reports/x"):
            status, headers, body = self.get(path, headers={"Cookie": cookie})
            self.assertEqual(status, 200, path)
            html = body.decode()
            self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
            self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertEqual((headers["X-Content-Type-Options"], headers["X-Frame-Options"], headers["Cache-Control"]), ("nosniff", "DENY", "no-store"))
            self.assertEqual(re.findall(r"<script(?![^>]*\ssrc=)", html), [])            # no inline script
            self.assertNotRegex(html, r"\sstyle=|\son[a-z]+=")                           # no inline style/handlers
            self.assertIn('src="/app/static/app-core.js"', html)
            self.assertNotIn("shell@example.com", html)                                    # the shell carries no user data

    def test_static_allowlist(self):
        for name, ctype in (("app.js", "text/javascript"), ("app-core.js", "text/javascript"), ("app.css", "text/css")):
            status, headers, body = self.get("/app/static/" + name)
            self.assertEqual(status, 200)
            self.assertTrue(headers["Content-Type"].startswith(ctype))
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(body, (WEBAPP / name).read_bytes())
        for name in ("index.html", "..", "../http_app.py", "%2e%2e%2fhttp_app.py", "app.js.map", "missing.js"):
            self.assertEqual(self.get("/app/static/" + name)[0], 404, name)


class WebappSourceSafetyTests(unittest.TestCase):
    """Static checks over the browser code itself."""

    def sources(self):
        return {p.name: p.read_text(encoding="utf-8") for p in WEBAPP.iterdir() if p.suffix in (".js", ".html", ".css")}

    def test_no_html_sinks_or_dynamic_code(self):
        sink = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function|setTimeout\(\s*['\"]|javascript:")
        for name, text in self.sources().items():
            self.assertIsNone(sink.search(text), name)

    def test_no_third_party_origins_or_secrets(self):
        for name, text in self.sources().items():
            self.assertNotRegex(text, r"https?://(?!www\.w3\.org)", name)                # nothing loaded from anywhere else
            self.assertNotRegex(text, r"sk_(live|test)_|whsec_|price_1|api_key|PRIVATE_KEY", name)
            self.assertNotIn("storage_ref", text, name)
        app = (WEBAPP / "app.js").read_text(encoding="utf-8")
        self.assertNotRegex(app, r"\.budget\b|_units\b")                                  # technical units are never shown

    def test_no_prohibited_claims(self):
        level_a = re.compile(r"certified|audited|audit completed|complete audit|professional audit|official|safe to deploy|guaranteed|100% secure|fully secure|"
                             r"vulnerability-free|no vulnerabilities|no security issues|production-ready|zero retention|no logs|never stored|private by default|"
                             r"deploy with confidence|secure your contract|eliminate vulnerabilities|audit your contract|security score", re.I)
        for name, text in self.sources().items():
            self.assertIsNone(level_a.search(text), name)
        core = (WEBAPP / "app-core.js").read_text(encoding="utf-8")
        for name, text in self.sources().items():
            for m in re.finditer(r"\b(audit|certification|guarantee)\b", text, re.I):
                line = text[text.rfind("\n", 0, m.start()) + 1:text.find("\n", m.start())]
                self.assertTrue(name == "app-core.js" and ("It is NOT" in line or "NOT a formal" in line), (name, line))
        self.assertIn("It is NOT a formal security audit, a certification, or a guarantee", core)

    def test_every_backend_error_code_has_wording(self):
        codes = set(re.findall(r'_refuse\("([a-z_]+)"', (REPO_ROOT / "backend" / "submission_input.py").read_text(encoding="utf-8")))
        codes |= {"too_many_pending_jobs", "submit_rate_limited", "technical_budget_exhausted", "loc_quota_exceeded", "loc_per_scan_limit_exceeded",
                  "no_scan_credit", "no_source_code", "project_not_found", "project_name_taken", "billing_not_configured", "report_content_unavailable"}
        core = (WEBAPP / "app-core.js").read_text(encoding="utf-8")
        for code in sorted(codes):
            self.assertRegex(core, r"\b%s:" % code, code)


@unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
class WebappCoreNodeTests(unittest.TestCase):
    """Runs backend/webapp/app-core.js's pure helpers under Node."""

    def run_js(self, body):
        script = "const C = require(%s);\nconst out = (function(){ %s })();\nprocess.stdout.write(JSON.stringify(out));" % (json.dumps(str(WEBAPP / "app-core.js")), body)
        res = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def test_error_wording_and_details(self):
        out = self.run_js("""return [
          C.describeError(429, {error: 'submit_rate_limited', retry_after_seconds: 12}),
          C.describeError(413, {error: 'loc_per_scan_limit_exceeded', effective_loc: 3001, max_loc_per_scan: 3000}),
          C.describeError(402, {error: 'loc_quota_exceeded', loc_remaining: 500}),
          C.describeError(500, null), C.describeError(400, {error: 'something new'})];""")
        self.assertIn("Try again in 12 s", out[0]["details"])
        self.assertEqual(out[1]["details"], ["Effective LOC: 3,001", "Plan limit per scan: 3,000 effective LOC"])
        self.assertEqual(out[2]["details"], ["Remaining this service month: 500 effective LOC"])
        self.assertTrue(out[3]["message"].startswith("Something went wrong"))
        self.assertEqual(out[4]["message"], "something new")

    def test_plan_limit_lines_come_from_backend_data(self):
        catalog = [dict(name=n, **{k: plans.PLANS[n][k] for k in ("usage_model", "max_loc_per_scan", "monthly_loc_quota", "scans_per_purchase", "max_projects", "max_members")})
                   for n in plans.PLANS_ORDER]
        out = self.run_js("const cat = %s; return cat.map(function (p) { return C.planLimitLines(null, p); });" % json.dumps(catalog))
        self.assertEqual(out[0], ["1 scan per purchase (one-time payment, no subscription)", "Up to 3,000 effective LOC per scan", "Unlimited projects"])
        self.assertEqual(out[1], ["Up to 10,000 effective LOC per scan", "20,000 effective LOC per service month", "Unlimited projects", "Up to 2 members"])
        self.assertEqual(out[2], ["Up to 20,000 effective LOC per scan", "60,000 effective LOC per service month", "Unlimited projects", "Up to 5 members"])

    def test_misc_helpers(self):
        out = self.run_js("""return {
          urls: ['https://checkout.stripe.com/c/x', 'http://evil', 'javascript:alert(1)', '//x', 'https://a b'].map(C.safeExternalUrl),
          money: [C.formatMoney(2999, 'usd'), C.formatMoney(199990, 'usd')],
          hash: C.parseHash('#/scans/abc?project=p%201&status=failed'),
          sorted: C.sortFindings([{severity:'LOW'},{severity:'CRITICAL'},{severity:'weird'},{severity:'HIGH'}]).map(function(f){return f.severity;}),
          loc: C.locationText({file:'a.sol', lineStart: 3, lineEnd: 7, contract:'A', 'function':'f'}),
          b64: C.bytesToBase64(new Uint8Array([80, 75, 3, 4, 255])),
          status: ['queued','claimed','running','succeeded','failed','canceled','weird'].map(C.jobStatusLabel),
          pending: ['queued','claimed','running','succeeded'].map(C.isPending),
          pct: C.usagePercent({loc_used: 19500, loc_limit: 20000})};""")
        self.assertEqual(out["urls"], ["https://checkout.stripe.com/c/x", None, None, None, None])
        self.assertEqual(out["money"], ["$29.99", "$1,999.90"])
        self.assertEqual(out["hash"], {"parts": ["scans", "abc"], "query": {"project": "p 1", "status": "failed"}})
        self.assertEqual(out["sorted"], ["CRITICAL", "HIGH", "LOW", "weird"])
        self.assertEqual(out["loc"], "a.sol:3-7 (A.f)")
        self.assertEqual(out["b64"], base64.b64encode(bytes([80, 75, 3, 4, 255])).decode())
        self.assertEqual(out["status"], ["Queued", "Starting", "Running", "Completed", "Failed", "Cancelled", "weird"])
        self.assertEqual(out["pending"], [True, True, True, False])
        self.assertEqual(out["pct"], 98)


# ---------------------------------------------------------------------------
# JSON additions used by the app
# ---------------------------------------------------------------------------

class AppApiTests(_AppCase):
    def test_me_and_plans(self):
        cookie, _ = self.ws(None, "me@example.com")
        self.assertEqual(self.jget("/auth/me")[0], 401)
        status, _, body = self.jget("/auth/me", cookie)
        self.assertEqual((status, body["user"]["email"]), (200, "me@example.com"))
        status, _, body = self.jget("/billing/plans")
        self.assertEqual(status, 200)
        self.assertEqual([p["plan"] for p in body["plans"]], ["trial", "quick", "standard", "pro"])   # D-112: the free Trial is listed first, never sold
        self.assertEqual((body["plans"][0]["checkout"], [x["amount_cents"] for x in body["plans"][0]["prices"]]), (False, [0]))
        for p in body["plans"][1:]:
            spec = plans.PLANS[p["plan"]]
            self.assertEqual((p["max_loc_per_scan"], p["monthly_loc_quota"], p["max_projects"], p["max_members"]),
                             (spec["max_loc_per_scan"], spec["monthly_loc_quota"], spec["max_projects"], spec["max_members"]))
            self.assertEqual(sorted(x["amount_cents"] for x in p["prices"]), sorted(m["amount_cents"] for m in plans.PRICE_MODES.values() if m["plan"] == p["plan"]))
        self.assertNotIn("price_", json.dumps(body))                                       # never a Stripe Price ID

    def test_workspace_display_data(self):
        cookie, ws = self.ws("standard", "wsd@example.com")
        self.submit(cookie, ws, source=_sol(100))
        status, _, body = self.jget("/workspaces/%s" % ws, cookie)
        self.assertEqual(body["admission"], {"pending_jobs": 1, "max_pending_jobs": 5, "allowed_modes": ["quick", "standard"], "billing_configured": False,
                                             "features": ["private_api", "private_github"], "github_configured": False})   # D-113 adds private_api
        self.assertEqual((body["usage"]["scans_in_period"], body["usage"]["scans_completed_in_period"]), (1, 0))
        cookie2, ws2 = self.ws(None, "wsd2@example.com")
        self.assertEqual(self.jget("/workspaces/%s" % ws2, cookie2)[2]["admission"]["allowed_modes"], [])

    def test_job_summaries_detail_and_isolation(self):
        cookie, ws = self.ws("standard", "hist@example.com")
        pid = json.loads(self.post_json("/workspaces/%s/projects" % ws, {"name": "Vault"}, headers={"Cookie": cookie})[2])["project"]["id"]
        done = self.submit(cookie, ws, files=[{"path": "src/B.sol", "content": B_SOL}], project_id=pid)[1]["job_id"]
        report_id, _ = self.complete(done)
        pending = self.submit(cookie, ws, source=_sol(50))[1]["job_id"]
        jobs = {j["id"]: j for j in self.jget("/workspaces/%s/jobs" % ws, cookie)[2]["jobs"]}
        self.assertEqual({k: jobs[done][k] for k in ("status", "project_name", "source_kind", "effective_loc", "report_id", "score", "risk_band")},
                         {"status": "succeeded", "project_name": "Vault", "source_kind": "files", "effective_loc": 4, "report_id": report_id, "score": 40, "risk_band": "HIGH"})
        self.assertEqual((jobs[pending]["report_id"], jobs[pending]["project_name"], jobs[pending]["source_kind"]), (None, None, "single"))
        self.assertNotIn("storage_ref", json.dumps(jobs))
        self.assertEqual([j["id"] for j in self.jget("/workspaces/%s/jobs?project_id=%s" % (ws, pid), cookie)[2]["jobs"]], [done])
        detail = self.jget("/workspaces/%s/jobs/%s" % (ws, done), cookie)[2]
        self.assertEqual((detail["report"]["id"], detail["report"]["score"]), (report_id, 40))
        self.assertIsNone(self.jget("/workspaces/%s/jobs/%s" % (ws, pending), cookie)[2]["report"])
        other_cookie, other_ws = self.ws("pro", "hist-other@example.com")
        self.assertEqual(self.jget("/workspaces/%s/jobs" % other_ws, other_cookie)[2]["jobs"], [])
        self.assertEqual(self.jget("/workspaces/%s/jobs" % ws, other_cookie)[0], 403)

    def test_report_document_and_downloads(self):
        cookie, ws = self.ws("standard", "rep@example.com")
        job = self.submit(cookie, ws, source=_sol(30))[1]["job_id"]
        advisory = {"status": "completed", "advisoryOnly": True, "summary": {"targetsReviewed": 1}, "targets": []}
        report_id, key = self.complete(job, advisory=advisory, markdown="# Automated review\n<script>x</script>\n")
        status, _, doc = self.jget("/workspaces/%s/reports/%s/document" % (ws, report_id), cookie)
        self.assertEqual(status, 200)
        self.assertEqual(doc["scored_report"]["findings"][0]["stableKey"], SCORED["findings"][0]["stableKey"])
        self.assertEqual((doc["advisory"], doc["purged"], doc["job"]["id"], doc["source"]["kind"]), (advisory, False, job, "single"))
        self.assertIn("<script>x</script>", doc["markdown"])                             # data, rendered as text by the app
        self.assertNotIn(key, json.dumps(doc))
        self.assertNotIn("report_url", doc["report"])
        self.assertNotIn("storage_ref", doc["report"])
        for fmt, ctype, ext in (("json", "application/json", "json"), ("markdown", "text/markdown", "md")):
            status, headers, body = self.get("/workspaces/%s/reports/%s/download?format=%s" % (ws, report_id, fmt), headers={"Cookie": cookie})
            self.assertEqual(status, 200)
            self.assertTrue(headers["Content-Type"].startswith(ctype))
            self.assertEqual(headers["Content-Disposition"], 'attachment; filename="vericexa-report-%s.%s"' % (report_id, ext))
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(json.loads(self.get("/workspaces/%s/reports/%s/download?format=json" % (ws, report_id), headers={"Cookie": cookie})[2]), SCORED)
        self.assertEqual(self.get("/workspaces/%s/reports/%s/download?format=html" % (ws, report_id), headers={"Cookie": cookie})[0], 400)
        # isolation and authentication
        other_cookie, other_ws = self.ws("pro", "rep-other@example.com")
        self.assertEqual(self.jget("/workspaces/%s/reports/%s/document" % (ws, report_id), other_cookie)[0], 403)
        self.assertEqual(self.jget("/workspaces/%s/reports/%s/document" % (other_ws, report_id), other_cookie)[0], 404)
        self.assertEqual(self.get("/workspaces/%s/reports/%s/download?format=json" % (other_ws, report_id), headers={"Cookie": other_cookie})[0], 404)
        self.assertEqual(self.jget("/workspaces/%s/reports/%s/document" % (ws, report_id))[0], 401)
        self.assertEqual(self.jget("/workspaces/%s/reports/not-a-uuid/document" % ws, cookie)[0], 404)

    def test_report_without_json_and_purged_report(self):
        cookie, ws = self.ws("standard", "rep2@example.com")
        job = self.submit(cookie, ws, source=_sol(30))[1]["job_id"]
        report_id, _ = self.complete(job, scored=None)
        doc = self.jget("/workspaces/%s/reports/%s/document" % (ws, report_id), cookie)[2]
        self.assertEqual((doc["scored_report"], doc["markdown"], doc["report"]["score_status"]), (None, "# Report\n", "not_computed"))
        self.assertEqual(self.get("/workspaces/%s/reports/%s/download?format=json" % (ws, report_id), headers={"Cookie": cookie})[0], 404)
        conn = repo.connect(self.db_path)
        repo.mark_report_purged(conn, report_id)
        conn.close()
        doc = self.jget("/workspaces/%s/reports/%s/document" % (ws, report_id), cookie)[2]
        self.assertEqual((doc["purged"], doc["markdown"], doc["scored_report"]), (True, None, None))
        self.assertEqual(self.get("/workspaces/%s/reports/%s/download?format=markdown" % (ws, report_id), headers={"Cookie": cookie})[0], 404)


class DryRunTests(_AppCase):
    def counts(self):
        conn = repo.connect(self.db_path)
        try:
            return tuple(conn.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0] for t in ("analysis_jobs", "contracts", "job_usage", "submit_attempts"))
        finally:
            conn.close()

    def test_preview_runs_the_same_checks_and_creates_nothing(self):
        cookie, ws = self.ws("standard", "dry@example.com")
        objects_before = sum(len(f) for _, _, f in os.walk(self.storage_dir))
        before = self.counts()
        status, body = self.submit(cookie, ws, files=[{"path": "src/B.sol", "content": B_SOL}, {"path": "x.json", "content": "{}"}], dry_run=True)
        self.assertEqual((status, body["dry_run"], body["admissible"], body["effective_loc"], body["ignored"], body["max_loc_per_scan"]), (200, True, True, 4, ["x.json"], 10000))
        status, body = self.submit(cookie, ws, archive={"format": "zip", "content_base64": base64.b64encode(_zip([("B.sol", B_SOL)])).decode()}, dry_run=True)
        self.assertEqual((status, body["source_kind"], body["effective_loc"]), (200, "archive", 4))
        after = self.counts()
        self.assertEqual(after[:3], before[:3])                                           # no job, contract or reservation
        self.assertEqual(after[3], before[3] + 2)                                         # each preview is a submit request (D-108)
        self.assertEqual(sum(len(f) for _, _, f in os.walk(self.storage_dir)), objects_before)   # nothing stored

    def test_preview_refuses_exactly_like_a_submission(self):
        cookie, ws = self.ws("standard", "dry-err@example.com")
        self.assertEqual(self.submit(cookie, ws, source=_sol(10001), dry_run=True)[1]["error"], "loc_per_scan_limit_exceeded")
        for _ in range(2):
            self.submit(cookie, ws, source=_sol(10000))
        status, body = self.submit(cookie, ws, source=_sol(10), dry_run=True)
        self.assertEqual((status, body["error"]), (402, "loc_quota_exceeded"))
        self.assertEqual(self.submit(cookie, ws, source=_sol(10), dry_run="yes")[0], 400)
        qcookie, qws = self.ws("quick", "dry-quick@example.com")
        self.assertEqual(self.submit(qcookie, qws, source=_sol(10), dry_run=True)[1]["error"], "no_scan_credit")

    def test_preview_ignores_idempotency_and_pending_cap_still_applies(self):
        cookie, ws = self.ws("pro", "dry-idem@example.com")
        first = self.submit(cookie, ws, source=_sol(10), idempotency_key="k1")[1]
        status, body = self.submit(cookie, ws, source=_sol(10), idempotency_key="k1", dry_run=True)
        self.assertEqual((status, body.get("dry_run"), "duplicate" in body), (200, True, False))
        for i in range(4):
            self.submit(cookie, ws, source=_sol(10), idempotency_key="k%d" % (i + 2))
        self.assertEqual(self.submit(cookie, ws, source=_sol(10), dry_run=True)[1]["error"], "too_many_pending_jobs")
        self.assertTrue(first["job_id"])


# ---------------------------------------------------------------------------
# Structured report persistence (worker)
# ---------------------------------------------------------------------------

class _Storage:
    def __init__(self, fail_json=False):
        self.objects, self.fail_json = {}, fail_json

    def put_object(self, key, data, content_type="application/octet-stream"):
        if self.fail_json and key.endswith(object_storage.REPORT_JSON_SUFFIX):
            raise ConnectionError("simulated outage")
        self.objects[key] = data

    def get_object(self, key):
        return self.objects.get(key, b"source")

    def delete_object(self, key):
        self.objects.pop(key, None)


class ScoredReportPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)
        user = repo.create_user(self.conn, "worker@example.com")
        self.ws = repo.create_workspace(self.conn, "WS", user)
        contract = repo.create_contract(self.conn, self.ws, object_storage.workspace_key(self.ws, "sources", "s1"), "h", "A.sol")
        self.job = repo.enqueue_job(self.conn, self.ws, contract, user, "quick")

    def run_worker(self, result, storage):
        alerts = _CollectingAlertSender()
        with mock.patch.object(ws_mod, "run_job_in_container", return_value=result):
            ws_mod.claim_and_run_one_job(self.conn, "w", _FAKE_CONFIG, storage, alerts)
        return alerts

    def test_bounded_output_from_the_container(self):
        self.assertEqual(worker_entrypoint._bounded_scored_report(SCORED), {"scored_report": SCORED})
        huge = dict(SCORED, limitations=["x" * (worker_entrypoint.SCORED_REPORT_MAX_BYTES + 1)])
        self.assertEqual(worker_entrypoint._bounded_scored_report(huge), {"scored_report_omitted": "too_large"})
        self.assertEqual(worker_entrypoint._bounded_scored_report(None), {})

    def test_success_stores_the_json_next_to_the_report(self):
        storage = _Storage()
        self.run_worker({"status": "succeeded", "rendered": "# r", "risk_indicator": SCORED["riskIndicator"], "scored_report": SCORED}, storage)
        key = object_storage.workspace_key(self.ws, "reports", self.job)
        self.assertEqual(json.loads(storage.objects[object_storage.report_json_key(key)]), SCORED)
        self.assertEqual(repo.get_job(self.conn, self.job)["status"], "succeeded")

    def test_json_storage_failure_never_changes_the_job(self):
        alerts = self.run_worker({"status": "succeeded", "rendered": "# r", "risk_indicator": SCORED["riskIndicator"], "scored_report": SCORED}, _Storage(fail_json=True))
        self.assertEqual(repo.get_job(self.conn, self.job)["status"], "succeeded")
        self.assertEqual([e[2]["phase"] for e in alerts.events], ["store_report_json"])

    def test_failure_stores_nothing_and_retention_deletes_the_json(self):
        storage = _Storage()
        self.run_worker({"status": "failed", "error": "x"}, storage)
        self.assertEqual(storage.objects, {})
        key = "reports/%s/r1" % self.ws
        storage.objects = {key: b"md", object_storage.report_json_key(key): b"{}", key + targeted_review.OBJECT_SUFFIX: b"{}"}
        retention._delete_report_companions(storage, key)
        self.assertEqual(list(storage.objects), [key])


if __name__ == "__main__":
    unittest.main()
