"""Tests for the Vericexa GitHub Action (docs/decisiones.md D-114):
.github/actions/vericexa-scan/vericexa_scan.py, action.yml, the example
workflow .github/workflows/vericexa.yml and the backend's GitHub Actions
gating (the "ci" object of POST /api/v1/scans).

The action runs IN-PROCESS against the REAL Vericexa HTTP server (SQLite,
real Private API, real admission/queue) and a fake GitHub API server; the
worker is played by the test (each poll "sleep" completes queued jobs), and
the clock is fake, so no test waits. What still needs real GitHub (hosted
runner, real secrets, a real Check Run on github.com) is listed in
docs/github-actions.md.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.api_keys as api_keys  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.repository as repo  # noqa: E402
from tests.test_backend_commercial import _sol  # noqa: E402
from tests.test_backend_private_api import _ApiHttpCase  # noqa: E402

ACTION_DIR = REPO_ROOT / ".github" / "actions" / "vericexa-scan"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "vericexa.yml"
_spec = importlib.util.spec_from_file_location("vericexa_scan", str(ACTION_DIR / "vericexa_scan.py"))
action = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(action)

SCORED_FINDINGS = json.loads((REPO_ROOT / "evals" / "results" / "actual" / "sc01_unprotected_withdraw.json").read_text(encoding="utf-8"))   # CRITICAL + LOW
SCORED_CLEAN = {"findings": [], "riskIndicator": {"band": "LOW", "score": 96, "scoreStatus": "computed"}, "scoreStatus": "computed"}
SOURCE_MARKER = "uint256 public actionSourceMarker7731;"
GITHUB_TOKEN = "ghs_test_token_" + "x" * 20
HAS_GIT = shutil.which("git") is not None


# ---------------------------------------------------------------------------
# Fake GitHub API
# ---------------------------------------------------------------------------

class _FakeGitHub:
    def __init__(self):
        self.requests = []
        self.status = 201
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": json.loads(body) if body else None})
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                status = outer.status if self.command == "POST" else (200 if outer.status < 300 else outer.status)
                payload = json.dumps({"id": 4242}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_POST = do_PATCH = do_GET = _handle

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

class _ActionCase(_ApiHttpCase):
    REPORT = SCORED_FINDINGS

    def setUp(self):
        super().setUp()
        self.github = _FakeGitHub()
        self.addCleanup(self.github.close)
        self.tmp = tempfile.mkdtemp(prefix="vericexa-action-")
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.worker_mode = "succeed"
        self.calls = []
        self.clock = [0.0]
        self.checkout = self.make_checkout()

    # -- checkout ---------------------------------------------------------
    def make_checkout(self):
        root = os.path.join(self.tmp, "checkout")
        files = {
            "contracts/Vault.sol": "pragma solidity ^0.8.20;\ncontract Vault {\n    %s\n    function f() public {}\n}\n" % SOURCE_MARKER,
            "contracts/token/Token.sol": "pragma solidity ^0.8.20;\ncontract Token {\n    uint256 public supply;\n}\n",
            "lib/forge-std/Test.sol": _sol(400),                       # dependency: excluded by default
            "node_modules/pkg/Dep.sol": _sol(50),                      # always skipped
            ".hidden/Hidden.sol": _sol(20),                            # hidden directory: skipped
            "contracts/weird name$(id).sol": _sol(10),                 # unsafe path characters: skipped
            ".env": "SECRET_TOKEN=supersecret-value-123\n",            # never read
            "README.md": "# Vault\n",
        }
        for rel, text in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        self.sha = "ab" * 20
        if HAS_GIT:
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(git + ["add", "-A"], cwd=root, check=True)
            subprocess.run(git + ["commit", "-q", "-m", "init"], cwd=root, check=True)
            self.sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
        return root

    def event_file(self, name, payload):
        path = os.path.join(self.tmp, "event-%s.json" % name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return path

    def env(self, key, event="push", fork=False, **extra):
        payload = {"repository": {"full_name": "octo/vault"}}
        if event in ("pull_request", "pull_request_target"):
            head_repo = {"full_name": "mallory/vault" if fork else "octo/vault", "fork": fork}
            payload.update({"number": 7, "pull_request": {"number": 7, "head": {"sha": self.sha, "repo": head_repo}}})
        env = {
            "GITHUB_EVENT_NAME": event, "GITHUB_EVENT_PATH": self.event_file(event, payload), "GITHUB_REPOSITORY": "octo/vault",
            "GITHUB_SHA": self.sha, "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "1001", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKSPACE": self.checkout, "GITHUB_API_URL": self.github.url,
            "GITHUB_OUTPUT": os.path.join(self.tmp, "output.txt"), "GITHUB_STEP_SUMMARY": os.path.join(self.tmp, "summary.md"),
            "VERICEXA_API_URL": "http://127.0.0.1:%d" % self.port, "VERICEXA_API_KEY": key or "", "INPUT_GITHUB_TOKEN": GITHUB_TOKEN,
        }
        env.update(extra)
        return env

    # -- worker / clock ---------------------------------------------------
    def work(self):
        if self.worker_mode == "hold":
            return
        conn = repo.connect(self.db_path)
        try:
            while True:
                job = repo.claim_next_job(conn, "w")
                if job is None:
                    return
                repo.finalize_job_attempt(conn, job["id"], job["workspace_id"], job["attempt_count"], "w", "claimed", "running")
                if self.worker_mode == "fail":
                    repo.finalize_job_attempt(conn, job["id"], job["workspace_id"], job["attempt_count"], "w", "running", "failed", error="engine error")
                    continue
                key = object_storage.workspace_key(job["workspace_id"], "reports", job["id"])
                self.storage.put_object(key, b"# Automated security review\n", content_type="text/markdown")
                self.storage.put_object(object_storage.report_json_key(key), json.dumps(self.REPORT).encode(), content_type="application/json")
                ri = self.REPORT["riskIndicator"]
                repo.finalize_job_attempt(conn, job["id"], job["workspace_id"], job["attempt_count"], "w", "running", "succeeded", report_storage_ref=key,
                                          report_score_status="computed", report_score=ri["score"], report_risk_band=ri["band"])
        finally:
            conn.close()

    def sleep(self, seconds):
        self.clock[0] += seconds
        self.work()

    def recording_http(self, method, url, headers, body=None, timeout=60.0):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        return action.http_request(method, url, headers, body, timeout)

    def run_action(self, env):
        out = io.StringIO()
        code = action.main(env, out=out, http=self.recording_http, sleep=self.sleep, monotonic=lambda: self.clock[0])
        self.stdout = out.getvalue()
        return code

    def outputs(self):
        path = os.path.join(self.tmp, "output.txt")
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as handle:
            return dict(line.rstrip("\n").split("=", 1) for line in handle if "=" in line)

    def summary(self):
        path = os.path.join(self.tmp, "summary.md")
        return open(path, encoding="utf-8").read() if os.path.exists(path) else ""

    def job_count(self, ws=None):
        conn = self.db()
        if ws:
            return conn.execute("SELECT COUNT(*) FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0]

    def planted_key(self, plan, email):
        cookie, ws = self.workspace(plan, email)
        conn = self.db()
        key, prefix, key_hash = api_keys.generate()
        repo.create_api_key(conn, ws, repo.get_user_by_email(conn, email)["id"], "planted", prefix, key_hash, 25)
        return ws, key


# ---------------------------------------------------------------------------
# Plan gating (backend)
# ---------------------------------------------------------------------------

class ActionPlanTests(_ActionCase):
    def test_standard_push_runs_and_records_the_exact_commit(self):
        _, ws, key = self.account("standard", "gha-std@example.com")
        code = self.run_action(self.env(key))
        self.assertEqual(code, action.EXIT_GATE_FAILED, self.stdout)                 # sc01 has a CRITICAL finding
        out = self.outputs()
        self.assertEqual((out["result"], out["exit-code"], out["findings-critical"], out["findings-low"], out["blocking-findings"]),
                         ("gate_failed", "1", "1", "1", "1"))
        job_id = out["job-id"]
        detail = self.api("GET", "/scans/%s" % job_id, key)[2]
        ci = detail["source"]["ci"]
        self.assertEqual((ci["provider"], ci["repository"], ci["commit_sha"], ci["event"], ci["run_id"], ci["run_attempt"], ci["pull_request_number"], ci["ref"]),
                         ("github_actions", "octo/vault", self.sha, "push", 1001, 1, None, "refs/heads/main"))
        self.assertEqual(sorted(f["path"] for f in detail["source"]["files"]), ["contracts/Vault.sol", "contracts/token/Token.sol"])
        self.assertEqual(detail["source"]["name"], "octo/vault@%s" % self.sha[:12])
        self.assertTrue(out["job-url"].endswith("/app#/scans/%s" % job_id))
        self.assertTrue(out["report-url"].endswith("/app#/reports/%s" % out["report-id"]))

    def test_pro_pull_request_with_a_clean_report_passes(self):
        self.REPORT = SCORED_CLEAN
        _, ws, key = self.account("pro", "gha-pro@example.com")
        code = self.run_action(self.env(key, event="pull_request", INPUT_MODE="pro"))
        self.assertEqual(code, action.EXIT_OK, self.stdout)
        out = self.outputs()
        self.assertEqual((out["result"], out["risk-band"], out["findings-total"]), ("passed", "LOW", "0"))
        ci = self.api("GET", "/scans/%s" % out["job-id"], key)[2]["source"]["ci"]
        self.assertEqual((ci["event"], ci["pull_request_number"], ci["commit_sha"], ci["ref"]), ("pull_request", 7, self.sha, "refs/pull/7/head"))
        summary = self.summary()
        self.assertIn(action.NO_FINDINGS_TEXT, summary)
        self.assertIn(action.LOW_BAND_TEXT, summary)
        self.assertIn("NOT a formal security audit", summary)

    def test_quick_is_refused_without_using_its_credit(self):
        _, ws, key = self.account("quick", "gha-quick@example.com")
        code = self.run_action(self.env(key, INPUT_MODE="quick"))
        self.assertEqual(code, action.EXIT_ERROR)
        self.assertIn("feature_not_available", self.stdout)
        self.assertIn("GitHub Actions is available on the Standard and Pro plans", self.stdout)
        self.assertEqual(self.job_count(ws), 0)
        self.assertEqual(self.api("GET", "/usage", key)[2]["usage"]["scans_available"], 1)    # credit untouched
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "quick", "source": _sol(10)})[0], 200)   # the Private API itself stays available

    def test_trial_is_refused(self):
        ws, key = self.planted_key("trial", "gha-trial@example.com")
        code = self.run_action(self.env(key, INPUT_MODE="quick"))
        self.assertEqual(code, action.EXIT_ERROR)
        self.assertIn("feature_not_available", self.stdout)
        self.assertEqual(self.job_count(ws), 0)


class BackendCiGatingTests(_ActionCase):
    CI = {"provider": "github_actions", "repository": "octo/vault", "commit_sha": "a" * 40, "ref": "refs/heads/main", "event": "push", "run_id": 5, "run_attempt": 1}

    def test_ci_object_validation(self):
        ok, err = http_app._parse_ci_source(dict(self.CI))
        self.assertIsNone(err)
        self.assertEqual(ok["pull_request"], None)
        bad = [dict(self.CI, provider="gitlab"), dict(self.CI, repository="octo"), dict(self.CI, repository="o/../x;rm"), dict(self.CI, commit_sha="A" * 40),
               dict(self.CI, commit_sha="abc"), dict(self.CI, ref="refs/heads/a b"), dict(self.CI, event="pull_request_target"), dict(self.CI, run_id=True),
               dict(self.CI, run_id=0), dict(self.CI, run_attempt="x"), dict(self.CI, event="pull_request"), dict(self.CI, pull_request=3),
               dict(self.CI, extra=1), "ci", None]
        for value in bad:
            self.assertIsNone(http_app._parse_ci_source(value)[0], value)
        pr, err = http_app._parse_ci_source(dict(self.CI, event="pull_request", pull_request=12, run_id="77"))
        self.assertEqual((pr["pull_request"], pr["run_id"]), (12, 77))

    def test_api_gating_and_session_refusal(self):
        cookie, ws, key = self.account("standard", "ci-gate@example.com")
        body = {"mode": "standard", "source": _sol(20), "ci": dict(self.CI)}
        self.assert_error(self.api("POST", "/scans", key, dict(body, ci=dict(self.CI, commit_sha="nope"))), 400, "invalid_ci_source")
        status, _, created = self.api("POST", "/scans", key, body)
        self.assertEqual((status, created["ci"]["commit_sha"]), (200, "a" * 40))
        status, _, session = self.post_json("/workspaces/%s/jobs" % ws, body, headers={"Cookie": cookie})
        self.assertEqual((status, json.loads(session)["error"]), (400, "ci_not_supported"))
        _, qws, qkey = self.account("quick", "ci-quick@example.com")
        err = self.assert_error(self.api("POST", "/scans", qkey, dict(body, mode="quick")), 403, "feature_not_available")
        self.assertEqual(err["details"]["feature"], "github_actions")
        err = self.assert_error(self.api("POST", "/scans", qkey, dict(body, mode="quick", dry_run=True)), 403, "feature_not_available")
        self.assertEqual(self.job_count(qws), 0)
        self.assertEqual(sorted(self.api("GET", "/billing", key)[2]["features"]), ["github_actions", "private_api", "private_github"])
        self.assertEqual(self.api("GET", "/billing", qkey)[2]["features"], ["private_api"])


# ---------------------------------------------------------------------------
# Authentication / secrets
# ---------------------------------------------------------------------------

class ActionAuthTests(_ActionCase):
    def test_missing_secret_is_a_configuration_error(self):
        code = self.run_action(self.env(""))
        self.assertEqual(code, action.EXIT_ERROR)
        self.assertIn("missing_api_key", self.stdout)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.outputs(), {"result": "error", "exit-code": "2", "error-code": "missing_api_key"})

    def test_fork_pull_request_without_secret_skips_safely(self):
        code = self.run_action(self.env("", event="pull_request", fork=True))
        self.assertEqual(code, action.EXIT_OK)
        self.assertEqual(self.outputs()["result"], "skipped")
        self.assertIn("forks", self.stdout)
        self.assertEqual(self.calls, [])                                         # nothing sent anywhere

    def test_fork_pull_request_with_a_secret_never_publishes_with_the_token(self):
        self.REPORT = SCORED_CLEAN
        _, ws, key = self.account("standard", "gha-fork@example.com")
        code = self.run_action(self.env(key, event="pull_request", fork=True))
        self.assertEqual(code, action.EXIT_OK, self.stdout)
        self.assertEqual(self.github.requests, [])

    def test_invalid_and_revoked_keys(self):
        code = self.run_action(self.env(api_keys.generate()[0]))
        self.assertEqual(code, action.EXIT_ERROR)
        self.assertIn("invalid_api_key", self.stdout)
        cookie, ws, key = self.account("standard", "gha-revoked@example.com")
        key_id = self.api("GET", "/keys", key)[2]["keys"][0]["id"]
        self.assertEqual(self.api("DELETE", "/keys/%s" % key_id, key)[0], 200)
        code = self.run_action(self.env(key))
        self.assertEqual(code, action.EXIT_ERROR)
        self.assertIn("invalid_api_key", self.stdout)
        self.assertEqual(self.job_count(ws), 0)

    def test_base_url_must_be_https_without_credentials(self):
        for url in ("http://vericexa.example", "https://user:pw@vericexa.example", "https://vericexa.example/?x=1", "ftp://vericexa.example", "", "not a url"):
            with self.assertRaises(action.ActionError, msg=url):
                action.validate_base_url(url)
        self.assertEqual(action.validate_base_url("https://vericexa.example/base/"), "https://vericexa.example/base")
        self.assertEqual(action.validate_base_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080")

    def test_redirects_are_never_followed(self):
        with self.assertRaises(action.TransportError):
            action.http_request("GET", self.github.url + "/redirect", {"Authorization": "Bearer x"})
        self.assertEqual([r["path"] for r in self.github.requests], ["/redirect"])   # the target was never contacted


# ---------------------------------------------------------------------------
# Scan input and commercial admission (reused, not duplicated)
# ---------------------------------------------------------------------------

class ActionScanTests(_ActionCase):
    def test_only_selected_sources_are_sent_and_loc_is_the_servers(self):
        _, ws, key = self.account("standard", "gha-files@example.com")
        self.run_action(self.env(key))
        submit = [c for c in self.calls if c["method"] == "POST" and c["url"].endswith("/api/v1/scans")][0]
        body = json.loads(submit["body"])
        self.assertEqual(sorted(f["path"] for f in body["files"]), ["contracts/Vault.sol", "contracts/token/Token.sol"])
        raw = submit["body"].decode()
        self.assertNotIn("supersecret", raw)
        self.assertNotIn("forge-std", raw)
        self.assertNotIn("node_modules", raw)
        self.assertNotIn("Hidden", raw)
        self.assertEqual(body["idempotency_key"], "gha:octo/vault:1001:push:%s" % self.sha)
        usage = self.api("GET", "/usage", key)[2]["usage"]
        detail = self.api("GET", "/scans/%s" % self.outputs()["job-id"], key)[2]
        self.assertEqual(usage["loc_used"], detail["usage"]["effective_loc"])      # LOC counted by Vericexa only

    def test_path_and_exclude_inputs(self):
        _, ws, key = self.account("standard", "gha-path@example.com")
        self.run_action(self.env(key, INPUT_PATH="contracts", INPUT_EXCLUDE="token"))
        body = json.loads([c for c in self.calls if c["url"].endswith("/api/v1/scans")][0]["body"])
        self.assertEqual([f["path"] for f in body["files"]], ["Vault.sol"])
        self.assertEqual(self.run_action(self.env(key, INPUT_PATH="../..")), action.EXIT_ERROR)
        self.assertIn("inside the checkout", self.stdout)

    def test_quota_exceeded(self):
        _, ws, key = self.account("standard", "gha-quota@example.com")
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10000)})[0], 200)
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(9999)})[0], 200)
        self.assertEqual(self.run_action(self.env(key)), action.EXIT_ERROR)
        self.assertIn("loc_quota_exceeded", self.stdout)
        self.assertEqual(self.outputs()["error-code"], "loc_quota_exceeded")

    def test_technical_budget_exhausted(self):
        _, ws, key = self.account("standard", "gha-budget@example.com")
        job = self.api("POST", "/scans", key, {"mode": "standard", "source": _sol(10)})[2]["job_id"]
        conn = self.db()
        repo.transition_job_status(conn, job, "queued", "canceled")
        conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        conn.commit()
        self.assertEqual(self.run_action(self.env(key)), action.EXIT_ERROR)
        self.assertIn("technical_budget_exhausted", self.stdout)

    def test_no_source_files(self):
        _, ws, key = self.account("standard", "gha-empty@example.com")
        self.assertEqual(self.run_action(self.env(key, INPUT_PATH="lib", INPUT_EXCLUDE="forge-std")), action.EXIT_ERROR)
        self.assertIn("no_source_files", self.stdout)


class ActionPendingJobsTests(_ActionCase):
    MAX_PENDING = 1

    def test_pending_jobs_cap(self):
        _, ws, key = self.account("pro", "gha-pending@example.com")
        self.assertEqual(self.api("POST", "/scans", key, {"mode": "pro", "source": _sol(10)})[0], 200)
        self.worker_mode = "hold"
        self.assertEqual(self.run_action(self.env(key)), action.EXIT_ERROR)
        self.assertIn("too_many_pending_jobs", self.stdout)


# ---------------------------------------------------------------------------
# Results: gate semantics, failures, timeout, idempotency
# ---------------------------------------------------------------------------

class ActionResultTests(_ActionCase):
    def test_gate_disabled_reports_findings_without_failing(self):
        _, ws, key = self.account("standard", "gha-report-only@example.com")
        self.assertEqual(self.run_action(self.env(key, INPUT_BLOCKING_SEVERITIES="")), action.EXIT_OK)
        self.assertEqual((self.outputs()["result"], self.outputs()["findings-critical"]), ("passed", "1"))

    def test_min_confidence_and_custom_severities(self):
        _, ws, key = self.account("standard", "gha-policy@example.com")
        self.assertEqual(self.run_action(self.env(key, INPUT_BLOCKING_SEVERITIES="LOW")), action.EXIT_GATE_FAILED)
        self.assertEqual(self.outputs()["blocking-findings"], "1")
        self.assertEqual(self.run_action(self.env(key, INPUT_BLOCKING_SEVERITIES="BOGUS")), action.EXIT_ERROR)

    def test_failed_scan_is_an_execution_error_not_a_finding(self):
        _, ws, key = self.account("standard", "gha-failed@example.com")
        self.worker_mode = "fail"
        self.assertEqual(self.run_action(self.env(key)), action.EXIT_ERROR)
        self.assertIn("scan_failed", self.stdout)
        self.assertIn("NOT a security finding", self.stdout)
        self.assertEqual(self.outputs()["result"], "error")

    def test_timeout_then_rerun_resumes_the_same_scan(self):
        _, ws, key = self.account("standard", "gha-timeout@example.com")
        self.worker_mode = "hold"
        self.assertEqual(self.run_action(self.env(key, INPUT_TIMEOUT_MINUTES="1")), action.EXIT_ERROR)
        self.assertIn("timeout", self.stdout)
        first_job = self.outputs()["job-url"].rsplit("/", 1)[1]
        self.assertLessEqual(len([c for c in self.calls if c["method"] == "GET"]), 6)   # backoff, not a tight loop
        self.worker_mode = "succeed"
        os.remove(os.path.join(self.tmp, "output.txt"))
        code = self.run_action(self.env(key, GITHUB_RUN_ATTEMPT="2"))
        self.assertEqual(code, action.EXIT_GATE_FAILED, self.stdout)
        self.assertEqual(self.outputs()["job-id"], first_job)
        self.assertIn("reusing it", self.stdout)
        self.assertEqual(self.job_count(ws), 1)

    def test_vericexa_unreachable(self):
        _, ws, key = self.account("standard", "gha-down@example.com")
        code = self.run_action(self.env(key, VERICEXA_API_URL="http://127.0.0.1:1"))
        self.assertEqual(code, action.EXIT_ERROR)
        self.assertIn("api_unavailable", self.stdout)
        self.assertEqual(len([c for c in self.calls if c["url"].startswith("http://127.0.0.1:1/")]), action.SUBMIT_ATTEMPTS)

    def test_repeated_and_concurrent_runs_create_one_job(self):
        _, ws, key = self.account("standard", "gha-repeat@example.com")
        self.worker_mode = "hold"
        codes = []

        def go():
            out = io.StringIO()
            codes.append(action.main(self.env(key, INPUT_TIMEOUT_MINUTES="1"), out=out, http=action.http_request, sleep=lambda s: None,
                                     monotonic=iter(range(0, 10 ** 6, 30)).__next__))

        threads = [threading.Thread(target=go) for _ in range(4)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        self.assertEqual(codes, [action.EXIT_ERROR] * 4)                          # all time out (worker held) ...
        self.assertEqual(self.job_count(ws), 1)                                    # ... but exactly one scan exists
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM job_usage WHERE workspace_id = ?", (ws,)).fetchone()[0], 1)

    def test_check_run_is_created_and_completed_on_the_exact_sha(self):
        _, ws, key = self.account("standard", "gha-check@example.com")
        self.run_action(self.env(key))
        methods = [(r["method"], r["path"]) for r in self.github.requests]
        self.assertEqual(methods, [("POST", "/repos/octo/vault/check-runs"), ("PATCH", "/repos/octo/vault/check-runs/4242")])
        start, finish = self.github.requests[0]["body"], self.github.requests[1]["body"]
        self.assertEqual((start["head_sha"], start["status"]), (self.sha, "in_progress"))
        self.assertEqual((finish["status"], finish["conclusion"]), ("completed", "failure"))
        self.assertIn("security gate FAILED", finish["output"]["title"])
        self.assertIn("| CRITICAL | 1 |", finish["output"]["summary"])

    def test_check_run_permission_denied_falls_back_to_the_summary(self):
        self.REPORT = SCORED_CLEAN
        self.github.status = 403
        _, ws, key = self.account("standard", "gha-check403@example.com")
        self.assertEqual(self.run_action(self.env(key)), action.EXIT_OK, self.stdout)
        self.assertIn("checks: write", self.stdout)
        self.assertIn("security gate passed", self.summary())


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

class ActionSecurityTests(_ActionCase):
    def test_secrets_go_only_to_their_own_host_and_never_to_the_log(self):
        _, ws, key = self.account("standard", "gha-secrets@example.com")
        self.run_action(self.env(key))
        vericexa = "http://127.0.0.1:%d/" % self.port
        for call in self.calls:
            auth = call["headers"].get("Authorization", "")
            if call["url"].startswith(vericexa):
                self.assertEqual(auth, "Bearer " + key)
                self.assertNotIn(GITHUB_TOKEN, json.dumps(call["headers"]) + (call["body"] or b"").decode())
            else:
                self.assertTrue(call["url"].startswith(self.github.url), call["url"])
                self.assertNotIn(key, json.dumps(call["headers"]) + (call["body"] or b"").decode())
        for request in self.github.requests:
            self.assertEqual(request["headers"].get("Authorization"), "Bearer " + GITHUB_TOKEN)
        everything = self.stdout + self.summary() + json.dumps(self.outputs())
        self.assertNotIn(key, everything)
        self.assertNotIn(key.split("_", 2)[2], everything)
        self.assertNotIn(GITHUB_TOKEN, everything)
        self.assertNotIn(SOURCE_MARKER, everything)
        self.assertNotIn("supersecret", everything)

    def test_every_log_line_is_inert(self):
        _, ws, key = self.account("standard", "gha-lines@example.com")
        self.run_action(self.env(key))
        for line in self.stdout.splitlines():
            self.assertTrue(line.startswith("[vericexa] ") or line.startswith("::error title=Vericexa::"), line)

    def test_untrusted_text_cannot_inject_commands_or_markup(self):
        evil = "x.sol\n::add-mask::secret\r\n::set-output name=result::passed"
        self.assertNotIn("\n", action.clean(evil))
        self.assertNotIn("\r", action.clean(evil))
        value = action.command_value("50%\n::error::y")
        self.assertEqual(value, "50%25 ::error::y")
        self.assertNotIn("\n", value)
        rendered = action.md("<script>alert(1)</script> | [x](javascript:y)")
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("|", rendered.replace("\\|", ""))
        self.assertNotIn("](", rendered)
        out = io.StringIO()
        log = action.Logger(out, ["topsecret"])
        log.info("path " + evil + " topsecret")
        log.command("error", "finding at " + evil)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("[vericexa] "))
        self.assertNotIn("topsecret", out.getvalue())

    def test_malicious_finding_location_stays_on_one_annotation_line(self):
        finding = {"severity": "HIGH", "category": "SC01", "id": "F-1", "status": "confirmed", "confidence": "high",
                   "locations": [{"file": "a.sol\n::add-mask::x", "lineStart": 3}]}
        result = action.evaluate({"findings": [finding]}, ["HIGH"], None)
        out = io.StringIO()
        action.Logger(out, []).command("error", "%s %s" % (finding["id"], action.finding_location(result["blocking"][0])))
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        summary = action.render_summary({"headline": "h", "evaluation": result, "commit_sha": "a" * 40, "event": "push"})
        self.assertNotIn("\n::add-mask", summary)

    def test_symlinks_are_not_followed(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "Stolen.sol"), "w") as handle:
            handle.write(_sol(10))
        try:
            os.symlink(outside, os.path.join(self.checkout, "contracts", "linkdir"), target_is_directory=True)
            os.symlink(os.path.join(outside, "Stolen.sol"), os.path.join(self.checkout, "contracts", "Link.sol"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available here")
        files = action.collect_files(self.checkout, ".", action.DEFAULT_EXCLUDE.split(","), action.Logger(io.StringIO(), []))
        self.assertEqual(sorted(f["path"] for f in files), ["contracts/Vault.sol", "contracts/token/Token.sol"])

    def test_symlink_detection_without_os_privileges(self):
        from unittest import mock
        real = os.path.islink
        linked = {os.path.join(self.checkout, "contracts", "token"), os.path.join(self.checkout, "contracts", "Vault.sol")}
        with mock.patch.object(action.os.path, "islink", side_effect=lambda p: p in linked or real(p)):
            out = io.StringIO()
            with self.assertRaises(action.ActionError) as ctx:                    # both remaining sources were "links"
                action.collect_files(self.checkout, ".", action.DEFAULT_EXCLUDE.split(","), action.Logger(out, []))
        self.assertEqual(ctx.exception.code, "no_source_files")
        self.assertIn("skipped 1 symbolic link", out.getvalue())

    def test_pull_request_target_and_other_events_are_refused(self):
        for event in ("pull_request_target", "workflow_run", "issue_comment"):
            self.assertEqual(self.run_action(self.env("vcx_x", event=event)), action.EXIT_ERROR, event)
            self.assertIn("unsupported_event", self.stdout)
        self.assertEqual(self.calls, [])


# ---------------------------------------------------------------------------
# Workflow / action definitions (static)
# ---------------------------------------------------------------------------

class WorkflowDefinitionTests(unittest.TestCase):
    WF = WORKFLOW.read_text(encoding="utf-8")
    ACTION = (ACTION_DIR / "action.yml").read_text(encoding="utf-8")

    def code_lines(self, text):
        return [line for line in text.splitlines() if not line.lstrip().startswith("#")]

    def test_triggers_permissions_and_secrets(self):
        code = "\n".join(self.code_lines(self.WF))
        self.assertIn("\n  push:", code)
        self.assertIn("\n  pull_request:", code)
        self.assertNotIn("pull_request_target", code)
        self.assertIn("permissions:\n  contents: read\n  checks: write\n", code)
        self.assertNotRegex(code, r"write-all|contents: write|pull-requests: write|id-token")
        self.assertIn("api-key: ${{ secrets.VERICEXA_API_KEY }}", code)
        self.assertIn("api-url: ${{ vars.VERICEXA_API_URL }}", code)
        self.assertIn("if: ${{ vars.VERICEXA_API_URL != '' }}", code)
        self.assertIn("persist-credentials: false", code)
        self.assertIn("github.event.pull_request.head.sha", code)               # the PR commit itself, not the merge commit
        self.assertNotIn("run:", code)                                            # no shell step in the workflow at all
        self.assertNotRegex(code, r"vcx_[0-9a-f]{12}_|https?://[a-z0-9]")         # no key, no hardcoded URL

    def test_action_passes_every_input_through_env_only(self):
        code = self.code_lines(self.ACTION)
        run_lines = [line for line in code if line.strip().startswith("run:")]
        self.assertEqual([line.strip() for line in run_lines], ['run: python3 "$GITHUB_ACTION_PATH/vericexa_scan.py"'])
        self.assertNotIn("${{", run_lines[0])
        env_block = "\n".join(code)
        for name in ("VERICEXA_API_KEY: ${{ inputs.api-key }}", "INPUT_GITHUB_TOKEN: ${{ inputs.github-token }}", "INPUT_PATH: ${{ inputs.path }}"):
            self.assertIn(name, env_block)
        self.assertNotIn("github.event", env_block)

    def test_script_is_stdlib_only(self):
        source = (ACTION_DIR / "vericexa_scan.py").read_text(encoding="utf-8")
        imports = {line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith(("import ", "from ")) and "__future__" not in line}
        self.assertTrue(imports <= {"hashlib", "html", "json", "os", "re", "subprocess", "sys", "time", "urllib", "typing"}, imports)


if __name__ == "__main__":
    unittest.main()
