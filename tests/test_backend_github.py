"""Tests for Private GitHub (docs/decisiones.md D-111): backend/
github_integration.py, the GitHub functions of backend/repository.py, the
GitHub endpoints and the "github" job-submission shape in backend/
http_app.py, the GITHUB_* configuration in backend/main.py and the web app
gating. GitHub itself is a fake transport (FakeGitHub) - no network, no
real token, no LLM, no Docker, no Stripe. SQLite (real-Postgres checks live
in tests/test_backend_postgres_integration.py).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.github_integration as gi  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.loc_count as loc_count  # noqa: E402
import backend.main as main  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import backend.retention as retention  # noqa: E402
import backend.submission_input as si  # noqa: E402
from tests.test_backend_commercial import _sol  # noqa: E402
from tests.test_backend_commercial_guards import _GuardsHttpCase  # noqa: E402
from tests.test_backend_http_app import HOST, _CapturingEmailSender, _capture_stderr  # noqa: E402
from tests.test_backend_projects_multifile import A_SOL, B_SOL, _engine  # noqa: E402
from tests.test_backend_worker_supervisor_no_docker import _CollectingAlertSender  # noqa: E402

# Test-only fake values: nothing here is a real credential.
CLIENT_ID = "Iv1.testclientid"
CLIENT_SECRET = "test-client-secret-value"
REDIRECT = "http://127.0.0.1/github/callback"
TOKEN_KEY = b"k" * 32
MAX = http_app.MAX_RAW_SOURCE_BYTES


def _config(**overrides):
    values = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT, "token_key": TOKEN_KEY, "app_slug": "vericexa-test"}
    values.update(overrides)
    return gi.GitHubConfig(**values)


class FakeGitHub:
    """An in-memory GitHub: OAuth token endpoint, /user, installations,
    repositories by id and by full name, branches, refs, compare, commits,
    trees and blobs - with per-account repository access. Records every
    request it receives."""

    def __init__(self):
        self.calls = []
        self.repos = {}
        self.repo_objects = {}
        self.objects = {}
        self.grants = {}
        self.tokens = {}
        self.refresh_tokens = {}
        self.access = {}
        self.accounts = {"octo": 9001, "other": 9002}
        self.revoked = []
        self.expiring = False
        self.rate_limited = False
        self.redirect_everything = False
        self.truncate_trees = False
        self.tamper_blobs = set()
        self.weird_full_name = None
        self.counter = 0
        self.lock = threading.Lock()

    # -- fixtures ---------------------------------------------------------
    def add_repo(self, repo_id, full_name, owner_login="octo", private=True, default_branch="main"):
        self.repos[repo_id] = {"id": repo_id, "full_name": full_name, "private": private, "default_branch": default_branch, "branches": {}}
        self.repo_objects[repo_id] = set()
        self.access.setdefault(owner_login, set()).add(repo_id)

    def _store(self, repo_id, sha, obj):
        self.objects[sha] = obj
        self.repo_objects[repo_id].add(sha)

    def commit(self, repo_id, branch, files, parent="branch"):
        entries = []
        for path, value in sorted(files.items()):
            if isinstance(value, tuple) and value[0] == "symlink":
                data = value[1].encode()
                sha = gi.git_blob_sha(data)
                self._store(repo_id, sha, ("blob", data))
                entries.append({"path": path, "mode": "120000", "type": "blob", "sha": sha, "size": len(data)})
            elif isinstance(value, tuple) and value[0] == "submodule":
                entries.append({"path": path, "mode": "160000", "type": "commit", "sha": "c" * 40})
            else:
                data = value.encode("utf-8") if isinstance(value, str) else value
                sha = gi.git_blob_sha(data)
                self._store(repo_id, sha, ("blob", data))
                entries.append({"path": path, "mode": "100644", "type": "blob", "sha": sha, "size": len(data)})
        for d in sorted({"/".join(p.split("/")[:i]) for p in files for i in range(1, len(p.split("/")))}):
            entries.append({"path": d, "mode": "040000", "type": "tree", "sha": hashlib.sha1(d.encode()).hexdigest()})
        tree_sha = hashlib.sha1(json.dumps(entries, sort_keys=True).encode()).hexdigest()
        self._store(repo_id, tree_sha, ("tree", entries))
        parent_sha = self.repos[repo_id]["branches"].get(branch) if parent == "branch" else parent
        self.counter += 1
        commit_sha = hashlib.sha1(("%s:%s:%d" % (tree_sha, parent_sha, self.counter)).encode()).hexdigest()
        self._store(repo_id, commit_sha, ("commit", {"tree": tree_sha, "parents": [parent_sha] if parent_sha else []}))
        self.repos[repo_id]["branches"][branch] = commit_sha
        return commit_sha

    def blob_calls(self):
        return [c[1] for c in self.calls if "/git/blobs/" in c[1]]

    def _ancestors(self, sha):
        seen, stack = set(), [sha]
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in self.objects:
                continue
            seen.add(cur)
            stack.extend(self.objects[cur][1]["parents"])
        return seen

    def _repo_json(self, repo_id):
        r = self.repos[repo_id]
        owner, name = r["full_name"].split("/")
        return {"id": repo_id, "name": name, "full_name": self.weird_full_name or r["full_name"], "owner": {"login": owner},
                "private": r["private"], "default_branch": r["default_branch"], "html_url": "ignored"}

    # -- transport ----------------------------------------------------------
    def request(self, method, url, headers, body, max_bytes):
        with self.lock:
            self.calls.append((method, url, dict(headers)))
        parsed = urlparse(url)
        path = parsed.path
        if self.redirect_everything:
            return 302, {"location": "http://169.254.169.254/latest/meta-data/"}, b""
        if parsed.netloc == "github.com" and path == "/login/oauth/access_token" and method == "POST":
            return self._token_endpoint(body)
        if parsed.netloc != "api.github.com":
            return 404, {}, b"{}"
        if self.rate_limited:
            return 403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(time.time()) + 120)}, b'{"message": "rate limited"}'
        if path.startswith("/applications/") and method == "DELETE":
            self.revoked.append(json.loads(body.decode())["access_token"])
            return 204, {}, b""
        auth = headers.get("Authorization", "")
        info = self.tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
        if info is None:
            return 401, {}, b'{"message": "Bad credentials"}'
        login = info["login"]
        allowed = self.access.get(login, set())

        def ok(obj):
            return 200, {}, json.dumps(obj).encode()

        not_found = (404, {}, b'{"message": "Not Found"}')
        if path == "/user":
            return ok({"id": self.accounts[login], "login": login})
        if path == "/user/installations":
            return ok({"total_count": 1, "installations": [{"id": 77, "account": {"login": login}}]})
        if path == "/user/installations/77/repositories":
            ids = sorted(allowed)
            return ok({"total_count": len(ids), "repositories": [self._repo_json(i) for i in ids]})
        m = re.match(r"^/repositories/(\d+)$", path)
        if m:
            rid = int(m.group(1))
            return ok(self._repo_json(rid)) if rid in allowed else not_found
        m = re.match(r"^/repos/([^/]+)/([^/]+)(/.*)$", path)
        if not m:
            return not_found
        full = unquote(m.group(1)) + "/" + unquote(m.group(2))
        rest = m.group(3)
        r = next((x for x in self.repos.values() if x["full_name"] == full), None)
        if r is None or r["id"] not in allowed:
            return not_found
        objects = self.repo_objects[r["id"]]
        if rest == "/branches":
            return ok([{"name": b, "commit": {"sha": s}} for b, s in sorted(r["branches"].items())])
        if rest.startswith("/git/ref/heads/"):
            branch = unquote(rest[len("/git/ref/heads/"):])
            sha = r["branches"].get(branch)
            return ok({"ref": "refs/heads/" + branch, "object": {"type": "commit", "sha": sha}}) if sha else not_found
        m = re.match(r"^/compare/([0-9a-f]{40})\.\.\.([0-9a-f]{40})$", rest)
        if m:
            base_sha, head_sha = m.groups()
            if base_sha not in objects or head_sha not in objects:
                return not_found
            status = "identical" if base_sha == head_sha else ("ahead" if base_sha in self._ancestors(head_sha) else "diverged")
            return ok({"status": status, "files": []})
        m = re.match(r"^/git/commits/([0-9a-f]{40})$", rest)
        if m:
            sha = m.group(1)
            if sha not in objects or self.objects[sha][0] != "commit":
                return not_found
            return ok({"sha": sha, "tree": {"sha": self.objects[sha][1]["tree"]}})
        m = re.match(r"^/git/trees/([0-9a-f]{40})$", rest)
        if m:
            sha = m.group(1)
            if sha not in objects or self.objects[sha][0] != "tree":
                return not_found
            return ok({"sha": sha, "tree": self.objects[sha][1], "truncated": self.truncate_trees})
        m = re.match(r"^/git/blobs/([0-9a-f]{40})$", rest)
        if m:
            sha = m.group(1)
            if sha not in objects or self.objects[sha][0] != "blob":
                return not_found
            data = self.objects[sha][1] + (b"tampered" if sha in self.tamper_blobs else b"")
            encoded = base64.b64encode(data).decode()
            return ok({"sha": sha, "size": len(data), "encoding": "base64", "content": "\n".join(encoded[i:i + 60] for i in range(0, len(encoded), 60))})
        return not_found

    def _token_endpoint(self, body):
        form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        if form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET:
            return 200, {}, b'{"error": "incorrect_client_credentials"}'
        with self.lock:
            if form.get("grant_type") == "refresh_token":
                login = self.refresh_tokens.pop(form.get("refresh_token"), None)
                if login is None:
                    return 200, {}, b'{"error": "bad_refresh_token"}'
            else:
                login = self.grants.pop(form.get("code"), None)
                if login is None or form.get("redirect_uri") != REDIRECT:
                    return 200, {}, b'{"error": "bad_verification_code"}'
            self.counter += 1
            token = "ghu_fake%dx%s" % (self.counter, login)
            grant = {"access_token": token, "token_type": "bearer", "scope": ""}
            self.tokens[token] = {"login": login}
            if self.expiring:
                refresh = "ghr_fake%d" % self.counter
                self.refresh_tokens[refresh] = login
                grant.update({"expires_in": 28800, "refresh_token": refresh, "refresh_token_expires_in": 15897600})
        return 200, {}, json.dumps(grant).encode()


# ---------------------------------------------------------------------------
# Unit tests: validation, cipher, transport, client
# ---------------------------------------------------------------------------

class ValidationTests(unittest.TestCase):
    def test_repository_ids(self):
        self.assertEqual(gi.parse_repository_id(42), 42)
        self.assertEqual(gi.parse_repository_id("42"), 42)
        for bad in (0, -1, True, False, None, "x", "1e3", "-5", " 4", 1.5, 2 ** 53, "9" * 17, [], {}):
            with self.subTest(value=bad):
                with self.assertRaises(gi.GitHubError) as ctx:
                    gi.parse_repository_id(bad)
                self.assertEqual(ctx.exception.code, "invalid_repository_id")

    def test_branch_names_cannot_navigate_the_api(self):
        for ok in ("main", "feature/x", "release-1.2", "a_b", "dependabot/npm/x-1.0"):
            self.assertEqual(gi.validate_branch_name(ok), ok)
        for bad in ("", "../user", "a/../b", "a..b", "%2e%2e", "a?b", "a#b", "a b", "a\\b", "/main", "main/", "-x", "a//b", ".hidden", "a/.x",
                    "x.lock", "a@{1}", "@", "a~1", "a^", "a:b", "a*", "a[", "\x00", "x" * 256, None, 5):
            with self.subTest(ref=bad):
                with self.assertRaises(gi.GitHubError) as ctx:
                    gi.validate_branch_name(bad)
                self.assertEqual(ctx.exception.code, "invalid_ref")

    def test_commit_sha(self):
        self.assertEqual(gi.validate_commit_sha("A" * 40), "a" * 40)
        for bad in ("a" * 39, "a" * 41, "g" * 40, "", None, 1, "HEAD", "main"):
            with self.subTest(sha=bad):
                with self.assertRaises(gi.GitHubError):
                    gi.validate_commit_sha(bad)

    def test_repository_summary_only_trusts_githubs_shape(self):
        good = {"id": 5, "full_name": "acme/vault", "owner": {"login": "acme"}, "private": True, "default_branch": "main", "token": "x"}
        self.assertEqual(gi.repository_summary(good), {"id": 5, "owner": "acme", "name": "vault", "full_name": "acme/vault", "private": True, "default_branch": "main"})
        for name in ("acme/../x", "a/b/c", "../x", "acme/..", "acme", "", "acme/va lt", "-acme/x"):
            with self.subTest(full_name=name):
                self.assertIsNone(gi.repository_summary(dict(good, full_name=name)))
        self.assertIsNone(gi.repository_summary(dict(good, id=True)))


class TokenCipherTests(unittest.TestCase):
    def test_roundtrip_and_binding(self):
        cipher = gi.TokenCipher(TOKEN_KEY)
        aad = gi.token_associated_data("ws1", "u1", "access")
        enc = cipher.encrypt("ghu_secretvalue", aad)
        self.assertTrue(enc.startswith("v1."))
        self.assertNotIn("ghu_secretvalue", enc)
        self.assertEqual(cipher.decrypt(enc, aad), "ghu_secretvalue")
        self.assertNotEqual(cipher.encrypt("ghu_secretvalue", aad), enc)   # random nonce
        for other in (gi.token_associated_data("ws2", "u1", "access"), gi.token_associated_data("ws1", "u2", "access"),
                      gi.token_associated_data("ws1", "u1", "refresh")):
            with self.assertRaises(gi.GitHubError) as ctx:
                cipher.decrypt(enc, other)
            self.assertEqual(ctx.exception.code, "github_reconnect_required")
        with self.assertRaises(gi.GitHubError):
            gi.TokenCipher(b"z" * 32).decrypt(enc, aad)

    def test_tampering_and_garbage_fail_closed(self):
        cipher = gi.TokenCipher(TOKEN_KEY)
        aad = gi.token_associated_data("ws1", "u1", "access")
        enc = cipher.encrypt("ghu_secretvalue", aad)
        raw = bytearray(base64.urlsafe_b64decode(enc[3:]))
        raw[20] ^= 1
        for bad in ("v1." + base64.urlsafe_b64encode(bytes(raw)).decode(), "v2." + enc[3:], "v1.!!!", "nope", "v1." + base64.urlsafe_b64encode(b"short").decode()):
            with self.subTest(value=bad[:12]):
                with self.assertRaises(gi.GitHubError):
                    cipher.decrypt(bad, aad)

    def test_key_requirements(self):
        with self.assertRaises(ValueError):
            gi.TokenCipher(b"short")
        self.assertEqual(gi.decode_token_key(base64.b64encode(b"\xfb" * 32).decode()), b"\xfb" * 32)
        self.assertEqual(gi.decode_token_key(base64.urlsafe_b64encode(b"\xfb" * 40).decode().rstrip("=")), b"\xfb" * 40)
        for bad in (base64.b64encode(b"x" * 31).decode(), "@@@@", ""):
            with self.assertRaises(ValueError):
                gi.decode_token_key(bad)


class _RedirectingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class TransportAndClientTests(unittest.TestCase):
    def test_transport_never_follows_redirects(self):
        server = HTTPServer(("127.0.0.1", 0), _RedirectingHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        status, headers, data = gi.UrllibTransport(timeout=5).request("GET", "http://127.0.0.1:%d/x" % server.server_address[1], {}, None, 100)
        self.assertEqual(status, 302)
        self.assertEqual(data, b"")

    def test_unreachable_host_is_a_clean_error(self):
        with self.assertRaises(gi.GitHubError) as ctx:
            gi.UrllibTransport(timeout=1).request("GET", "http://127.0.0.1:1/x", {}, None, 100)
        self.assertEqual(ctx.exception.code, "github_unavailable")

    def test_client_only_talks_to_its_two_fixed_origins(self):
        fake = FakeGitHub()
        client = gi.GitHubClient(_config(), fake)
        with self.assertRaises(gi.GitHubError):
            client._call("GET", "http://169.254.169.254", "/latest")
        with self.assertRaises(gi.GitHubError):
            client._call("GET", gi.API_BASE, "relative")
        self.assertEqual(fake.calls, [])

    def test_redirects_rate_limits_and_oversized_responses(self):
        fake = FakeGitHub()
        client = gi.GitHubClient(_config(), fake)
        fake.tokens["t"] = {"login": "octo"}
        fake.redirect_everything = True
        with self.assertRaises(gi.GitHubError) as ctx:
            client.get_user("t")
        self.assertEqual(ctx.exception.code, "github_unavailable")
        fake.redirect_everything = False
        fake.rate_limited = True
        with self.assertRaises(gi.GitHubError) as ctx:
            client.get_user("t")
        self.assertEqual((ctx.exception.code, ctx.exception.http_status), ("github_rate_limited", 429))
        self.assertTrue(60 <= ctx.exception.retry_after <= 121)
        fake.rate_limited = False
        with self.assertRaises(gi.GitHubError) as ctx:
            client._api_get("/user", "t", max_bytes=5)
        self.assertEqual(ctx.exception.code, "github_response_too_large")
        with self.assertRaises(gi.GitHubError) as ctx:
            client.get_user("unknown-token")
        self.assertEqual(ctx.exception.code, "github_reconnect_required")

    def test_requests_carry_the_token_only_in_the_authorization_header(self):
        fake = FakeGitHub()
        client = gi.GitHubClient(_config(), fake)
        fake.tokens["ghu_tok"] = {"login": "octo"}
        client.get_user("ghu_tok")
        method, url, headers = fake.calls[-1]
        self.assertNotIn("ghu_tok", url)
        self.assertEqual(headers["Authorization"], "Bearer ghu_tok")
        self.assertEqual(headers["X-GitHub-Api-Version"], gi.API_VERSION)

    def test_authorize_url(self):
        url = gi.GitHubClient(_config()).authorize_url("STATE123")
        parsed = urlparse(url)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ("https", "github.com", "/login/oauth/authorize"))
        self.assertEqual({k: v[0] for k, v in parse_qs(parsed.query).items()},
                         {"client_id": CLIENT_ID, "redirect_uri": REDIRECT, "state": "STATE123", "allow_signup": "false"})
        self.assertNotIn(CLIENT_SECRET, url)
        self.assertEqual(gi.GitHubClient(_config()).install_url(), "https://github.com/apps/vericexa-test/installations/new")
        self.assertIsNone(gi.GitHubClient(_config(app_slug="Bad Slug!")).install_url())


class RepositoryFetchTests(unittest.TestCase):
    """fetch_repository_entries() + submission_input.from_repository_entries():
    exactly the D-109 policy, with nothing downloaded that it would ignore."""

    def setUp(self):
        self.fake = FakeGitHub()
        self.fake.add_repo(101, "octo/vault")
        self.fake.tokens["t"] = {"login": "octo"}
        self.client = gi.GitHubClient(_config(), self.fake)

    def build(self, files):
        sha = self.fake.commit(101, "main", files)
        return si.from_repository_entries(gi.fetch_repository_entries(self.client, "t", "octo/vault", sha, MAX), MAX), sha

    def test_multi_file_repository_imports_inheritance_and_same_bundle_as_files(self):
        files = {"src/A.sol": A_SOL, "src/B.sol": B_SOL, "README.md": "# Vault\n", "package.json": "{}", "node_modules/x/Lib.sol": B_SOL,
                 "img/logo.png": b"\x89PNG\r\n", "lib/link.sol": ("symlink", "../src/A.sol"), "lib/forge-std": ("submodule",)}
        built, _ = self.build(files)
        self.assertEqual([f["path"] for f in built["files"]], ["README.md", "src/A.sol", "src/B.sol"])
        self.assertEqual(built["ignored"], ["img/logo.png", "lib/forge-std", "lib/link.sol", "node_modules/x/Lib.sol", "package.json"])
        same = si.from_files([{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}, {"path": "README.md", "content": "# Vault\n"}], MAX)
        self.assertEqual(built["source"], same["source"])                         # byte-identical bundle -> identical LOC
        artifact = _engine(built["source"])
        self.assertEqual([(i["path"], i["resolved"], i["resolvedTo"]) for i in artifact["imports"]], [("./B.sol", True, "src/B.sol")])
        a = next(c for c in artifact["contracts"] if c["name"] == "A")
        self.assertEqual(a["basesResolved"], [{"name": "B", "source": "bundle", "kind": "contract"}])
        self.assertEqual(loc_count.submission_effective_loc(built["source"]), sum(f["effective_loc"] for f in built["files"]))

    def test_ignored_files_are_never_downloaded(self):
        files = {"src/A.sol": B_SOL, "node_modules/x/Lib.sol": "contract Huge {}", "big.bin": b"\x00" * 5000, "docs/notes é.md": "x",
                 "lib/link.sol": ("symlink", "../src/A.sol")}
        self.build(files)
        fetched = {url.rsplit("/", 1)[1] for url in self.fake.blob_calls()}
        self.assertEqual(fetched, {gi.git_blob_sha(B_SOL.encode())})

    def test_path_count_and_size_limits_before_any_download(self):
        cases = [
            ({"src/A.sol": B_SOL, "bad\\name.sol": B_SOL}, "invalid_path", 400),
            ({"src/A.sol": B_SOL, "../escape.sol": B_SOL}, "invalid_path", 400),
            ({"f%d.sol" % i: "contract C%d {}" % i for i in range(si.MAX_SUBMISSION_FILES + 1)}, "too_many_files", 413),
            ({"Big.sol": "contract Big {\n" + "    uint256 a;\n" * (MAX // 14) + "}\n"}, "submission_too_large", 413),
        ]
        for files, code, status in cases:
            with self.subTest(code=code):
                before = len(self.fake.blob_calls())
                sha = self.fake.commit(101, "main", files, parent=None)
                with self.assertRaises(si.SubmissionInputError) as ctx:
                    gi.fetch_repository_entries(self.client, "t", "octo/vault", sha, MAX)
                self.assertEqual((ctx.exception.code, ctx.exception.http_status), (code, status))
                self.assertEqual(len(self.fake.blob_calls()), before)

    def test_d109_rules_still_apply_after_fetch(self):
        for files, code in (({"A.sol": B_SOL, "a.sol": B_SOL}, "duplicate_path"), ({"README.md": "# only docs"}, "no_source_files"),
                            ({"A.sol": "contract A {}\n=== END FILE ===\n"}, "reserved_marker"), ({"A.sol": b"\xff\xfe"}, "file_not_utf8")):
            with self.subTest(code=code):
                with self.assertRaises(si.SubmissionInputError) as ctx:
                    self.build(files)
                self.assertEqual(ctx.exception.code, code)

    def test_truncated_or_huge_tree_and_tampered_blob(self):
        sha = self.fake.commit(101, "main", {"A.sol": B_SOL})
        self.fake.truncate_trees = True
        with self.assertRaises(gi.GitHubError) as ctx:
            gi.fetch_repository_entries(self.client, "t", "octo/vault", sha, MAX)
        self.assertEqual((ctx.exception.code, ctx.exception.http_status), ("repository_too_large", 413))
        self.fake.truncate_trees = False
        with mock.patch.object(gi, "MAX_TREE_ENTRIES", 0):
            with self.assertRaises(gi.GitHubError) as ctx:
                gi.fetch_repository_entries(self.client, "t", "octo/vault", sha, MAX)
            self.assertEqual(ctx.exception.code, "repository_too_large")
        self.fake.tamper_blobs.add(gi.git_blob_sha(B_SOL.encode()))
        with self.assertRaises(gi.GitHubError) as ctx:
            gi.fetch_repository_entries(self.client, "t", "octo/vault", sha, MAX)
        self.assertEqual(ctx.exception.code, "github_unavailable")

    def test_resolve_scan_commit_pins_an_exact_sha(self):
        first = self.fake.commit(101, "main", {"A.sol": B_SOL})
        second = self.fake.commit(101, "main", {"A.sol": A_SOL, "B.sol": B_SOL})
        self.fake.commit(101, "other", {"X.sol": B_SOL}, parent=None)
        target = gi.resolve_scan_commit(self.client, "t", 101, None, None)              # default branch head
        self.assertEqual((target["ref"], target["commit_sha"], target["repository"]["full_name"]), ("main", second, "octo/vault"))
        self.assertEqual(gi.resolve_scan_commit(self.client, "t", 101, "main", first)["commit_sha"], first)   # an older commit of the branch
        foreign = self.fake.repos[101]["branches"]["other"]
        with self.assertRaises(gi.GitHubError) as ctx:
            gi.resolve_scan_commit(self.client, "t", 101, "main", foreign)
        self.assertEqual(ctx.exception.code, "commit_not_on_ref")
        with self.assertRaises(gi.GitHubError) as ctx:
            gi.resolve_scan_commit(self.client, "t", 101, "nope", None)
        self.assertEqual(ctx.exception.code, "ref_not_found")
        self.fake.weird_full_name = "octo/../admin"
        with self.assertRaises(gi.GitHubError) as ctx:
            gi.resolve_scan_commit(self.client, "t", 101, None, None)
        self.assertEqual(ctx.exception.code, "repository_not_accessible")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _GitHubHttpCase(_GuardsHttpCase):
    MAX_PENDING = 5
    RATE = 200
    CONFIGURED = True

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        os.remove(self.db_path)
        seed = repo.connect(self.db_path)
        repo.init_schema(seed)
        seed.close()
        self.storage_dir = tempfile.mkdtemp(prefix="http-github-")
        self.storage = object_storage.LocalFilesystemStorage(self.storage_dir, sign_secret="test-only-secret")
        self.email_sender = _CapturingEmailSender()
        self.alerts = _CollectingAlertSender()
        self.fake = FakeGitHub()
        self.github = gi.GitHubIntegration(_config(), self.fake) if self.CONFIGURED else None
        self.httpd = http_app.run_server(
            connect_fn=lambda: repo.connect(self.db_path), email_sender=self.email_sender, host_allowlist=[HOST],
            host=HOST, port=0, secure_cookies=False, storage=self.storage, alert_sender=self.alerts,
            max_pending_jobs_per_workspace=self.MAX_PENDING, submit_rate_limit_per_window=self.RATE, github=self.github,
        )
        self.port = self.httpd.server_address[1]
        self.host_header = "%s:%d" % (HOST, self.port)
        self.same_origin = "http://%s" % self.host_header
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.05)
        self.addCleanup(lambda: shutil.rmtree(self.storage_dir, ignore_errors=True))
        self.addCleanup(lambda: os.remove(self.db_path) if os.path.exists(self.db_path) else None)
        self.addCleanup(self._shutdown)
        self.fake.add_repo(101, "octo/vault")
        self.fake.add_repo(202, "other/secret", owner_login="other")
        self.head = self.fake.commit(101, "main", {"src/A.sol": A_SOL, "src/B.sol": B_SOL, "README.md": "# Vault\n", "package.json": "{}"})

    def db(self):
        conn = repo.connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def jget(self, path, cookie):
        status, headers, body = self.get(path, headers={"Cookie": cookie})
        return status, headers, json.loads(body) if body else None

    def jpost(self, path, cookie, payload=None, **kw):
        status, headers, body = self.post_json(path, payload if payload is not None else {}, headers=dict({"Cookie": cookie}, **kw))
        return status, headers, json.loads(body) if body else None

    def start_connect(self, cookie, ws):
        status, _, body = self.jpost("/workspaces/%s/github/connect" % ws, cookie)
        self.assertEqual(status, 200, body)
        return {k: v[0] for k, v in parse_qs(urlparse(body["authorize_url"]).query).items()}["state"]

    def callback(self, cookie, state, code="code-1", login="octo", extra=""):
        if code:
            self.fake.grants[code] = login
        qs = "state=%s%s%s" % (state, "&code=%s" % code if code else "", extra)
        status, headers, _ = self.get("/github/callback?" + qs, headers={"Cookie": cookie} if cookie else None)
        return status, headers.get("Location")

    def connect(self, cookie, ws, login="octo", code=None):
        state = self.start_connect(cookie, ws)
        status, location = self.callback(cookie, state, code=code or "code-%s-%s" % (ws[:8], login), login=login)
        self.assertEqual((status, location), (302, "/app#/scan/new?github=connected&workspace=%s" % ws))

    def scan(self, cookie, ws, repository_id=101, ref="main", commit_sha=None, dry_run=False, mode="quick", key=None, project_id=None):
        spec = {"repository_id": repository_id}
        if ref is not None:
            spec["ref"] = ref
        if commit_sha is not None:
            spec["commit_sha"] = commit_sha
        payload = {"mode": mode, "github": spec, "dry_run": dry_run}
        if key:
            payload["idempotency_key"] = key
        if project_id:
            payload["project_id"] = project_id
        return self.jpost("/workspaces/%s/jobs" % ws, cookie, payload)


class GitHubPlanGatingTests(_GitHubHttpCase):
    def test_quick_is_refused_on_every_endpoint_without_touching_github(self):
        cookie, ws = self.workspace("quick", "quick-gh@example.com")
        expected = {"ok": False, "error": "feature_not_available", "feature": "private_github", "plan": "quick",
                    "detail": "Private GitHub is available on the Standard and Pro plans"}
        for status, _, body in (self.jget("/workspaces/%s/github" % ws, cookie),
                                self.jpost("/workspaces/%s/github/connect" % ws, cookie),
                                self.jget("/workspaces/%s/github/repositories" % ws, cookie),
                                self.jget("/workspaces/%s/github/repositories/101/branches" % ws, cookie),
                                self.scan(cookie, ws), self.scan(cookie, ws, dry_run=True)):
            self.assertEqual((status, body), (403, expected))
        self.assertEqual(self.fake.calls, [])
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM github_oauth_states").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], 0)
        ws_body = self.jget("/workspaces/%s" % ws, cookie)[2]
        self.assertEqual(ws_body["admission"]["features"], ["private_api"])   # D-113: Quick has the Private API, never GitHub
        self.assertEqual(self.scan_quick_single(cookie, ws), 200)   # Quick keeps single/multi-file/ZIP

    def scan_quick_single(self, cookie, ws):
        repo.grant_scan_credit(self.db(), "cs_test_quick_gh", ws)
        return self.jpost("/workspaces/%s/jobs" % ws, cookie, {"mode": "quick", "files": [{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}]})[0]

    def test_quick_cannot_complete_a_callback_either(self):
        cookie, ws = self.workspace("standard", "downgrade@example.com")
        state = self.start_connect(cookie, ws)
        conn = self.db()
        conn.execute("UPDATE entitlements SET plan = 'quick' WHERE workspace_id = ?", (ws,))
        conn.commit()
        self.assertEqual(self.callback(cookie, state), (302, "/app#/scan/new?github=not_available&workspace=%s" % ws))
        self.assertEqual([c for c in self.fake.calls if "access_token" in c[1]], [])
        self.assertIsNone(repo.get_active_github_connection(conn, ws, repo.get_user_by_email(conn, "downgrade@example.com")["id"]))

    def test_standard_and_pro_are_allowed(self):
        for plan in ("standard", "pro"):
            with self.subTest(plan=plan):
                cookie, ws = self.workspace(plan, "%s-gh@example.com" % plan)
                status, _, body = self.jget("/workspaces/%s/github" % ws, cookie)
                self.assertEqual((status, body["configured"], body["connection"]), (200, True, None))
                self.assertEqual(self.jget("/workspaces/%s" % ws, cookie)[2]["admission"]["features"], ["private_api", "private_github"])   # D-113 adds private_api
                self.connect(cookie, ws)
                status, _, body = self.scan(cookie, ws, mode=plan)
                self.assertEqual(status, 200, body)
                job = repo.get_job(self.db(), body["job_id"])
                self.assertEqual(job["priority"], 1 if plan == "pro" else 0)

    def test_inactive_plan_and_unconfigured_server(self):
        cookie, ws = self.workspace("standard", "inactive-gh@example.com")
        conn = self.db()
        conn.execute("UPDATE entitlements SET status = 'canceled' WHERE workspace_id = ?", (ws,))
        conn.commit()
        self.assertEqual(self.jget("/workspaces/%s/github/repositories" % ws, cookie)[0], 402)
        self.assertEqual(self.scan(cookie, ws)[0], 402)

    def test_catalog_lists_the_feature_per_plan(self):
        catalog = {p["plan"]: p["features"] for p in json.loads(self.get("/billing/plans")[2])["plans"]}
        self.assertEqual(catalog, {"trial": [], "quick": ["private_api"], "standard": ["private_api", "private_github"],
                                   "pro": ["private_api", "private_github"]})   # D-113 adds private_api
        self.assertFalse(plans.plan_has_feature("quick", plans.FEATURE_PRIVATE_GITHUB))
        self.assertTrue(plans.plan_has_feature("standard", plans.FEATURE_PRIVATE_GITHUB))
        self.assertTrue(plans.plan_has_feature("pro", plans.FEATURE_PRIVATE_GITHUB))
        self.assertFalse(plans.plan_has_feature("enterprise", plans.FEATURE_PRIVATE_GITHUB))
        self.assertFalse(plans.plan_has_feature(None, plans.FEATURE_PRIVATE_GITHUB))


class GitHubUnconfiguredTests(_GitHubHttpCase):
    CONFIGURED = False

    def test_standard_gets_a_clean_503(self):
        cookie, ws = self.workspace("standard", "noconf@example.com")
        status, _, body = self.jget("/workspaces/%s/github" % ws, cookie)
        self.assertEqual((status, body["configured"], body["connection"], body["install_url"]), (200, False, None, None))
        for status, _, body in (self.jpost("/workspaces/%s/github/connect" % ws, cookie), self.jget("/workspaces/%s/github/repositories" % ws, cookie),
                                self.scan(cookie, ws)):
            self.assertEqual((status, body["error"]), (503, "github_not_configured"))
        self.assertEqual(self.get("/github/callback?state=x&code=y")[1]["Location"], "/app#/scan/new?github=not_configured")
        self.assertFalse(self.jget("/workspaces/%s" % ws, cookie)[2]["admission"]["github_configured"])


class GitHubOAuthTests(_GitHubHttpCase):
    def test_valid_state_connects_and_stores_only_encrypted_tokens(self):
        cookie, ws = self.workspace("standard", "oauth@example.com")
        self.connect(cookie, ws)
        conn = self.db()
        user = repo.get_user_by_email(conn, "oauth@example.com")["id"]
        row = repo.get_active_github_connection(conn, ws, user)
        token = next(iter(self.fake.tokens))
        self.assertEqual((row["github_account_id"], row["github_login"], row["provider"], row["status"]), (9001, "octo", "github", "active"))
        self.assertTrue(row["access_token_enc"].startswith("v1."))
        self.assertNotIn(token, row["access_token_enc"])
        self.assertEqual(self.github.cipher.decrypt(row["access_token_enc"], gi.token_associated_data(ws, user, "access")), token)
        state_rows = conn.execute("SELECT state_hash, consumed_at FROM github_oauth_states").fetchall()
        self.assertEqual(len(state_rows), 1)
        self.assertIsNotNone(state_rows[0]["consumed_at"])
        status, _, body = self.jget("/workspaces/%s/github" % ws, cookie)
        self.assertEqual(set(body["connection"]), set(repo.GITHUB_CONNECTION_PUBLIC_FIELDS))
        self.assertEqual(body["connection"]["github_login"], "octo")
        self.assertEqual(body["install_url"], "https://github.com/apps/vericexa-test/installations/new")
        self.assertNotIn(token, json.dumps(body))
        self.assertNotIn("token", json.dumps(body["connection"]))

    def test_invalid_replayed_expired_and_foreign_states_are_refused(self):
        cookie, ws = self.workspace("standard", "state@example.com")
        self.assertEqual(self.callback(cookie, "not-a-real-state"), (302, "/app#/scan/new?github=invalid_state"))
        self.assertEqual(self.callback(cookie, ""), (302, "/app#/scan/new?github=invalid_state"))
        state = self.start_connect(cookie, ws)
        self.assertEqual(self.callback(cookie, state, code="c-ok")[1], "/app#/scan/new?github=connected&workspace=%s" % ws)
        self.assertEqual(self.callback(cookie, state, code="c-replay"), (302, "/app#/scan/new?github=invalid_state"))   # single use
        expired = self.start_connect(cookie, ws)
        conn = self.db()
        conn.execute("UPDATE github_oauth_states SET expires_at = ? WHERE state_hash = ?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), gi.state_hash(expired)))
        conn.commit()
        self.assertEqual(self.callback(cookie, expired, code="c-exp"), (302, "/app#/scan/new?github=invalid_state"))
        # A state started by another member, replayed in this member's browser
        # (login CSRF / account mix-up), is refused and left unconsumed.
        other_cookie, other_ws = self.workspace("standard", "attacker@example.com")
        foreign = self.start_connect(other_cookie, other_ws)
        self.assertEqual(self.callback(cookie, foreign, code="c-foreign", login="other"), (302, "/app#/scan/new?github=invalid_state"))
        self.assertIsNone(conn.execute("SELECT consumed_at FROM github_oauth_states WHERE state_hash = ?", (gi.state_hash(foreign),)).fetchone()[0])
        self.assertIsNone(repo.get_active_github_connection(conn, other_ws, repo.get_user_by_email(conn, "attacker@example.com")["id"]))

    def test_callback_validation(self):
        cookie, ws = self.workspace("standard", "cb@example.com")
        state = self.start_connect(cookie, ws)
        status, location = self.callback(None, state)
        self.assertEqual((status, location), (302, "/auth/login"))                      # no session: state not consumed
        self.assertEqual(self.callback(cookie, state, code=None, extra="&error=access_denied")[1], "/app#/scan/new?github=denied&workspace=%s" % ws)
        state = self.start_connect(cookie, ws)
        self.assertEqual(self.callback(cookie, state, code=None)[1], "/app#/scan/new?github=failed&workspace=%s" % ws)
        state = self.start_connect(cookie, ws)
        status, headers, _ = self.get("/github/callback?state=%s&code=never-granted" % state, headers={"Cookie": cookie})
        self.assertEqual(headers["Location"], "/app#/scan/new?github=failed&workspace=%s" % ws)
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM github_connections").fetchone()[0], 0)
        # Removed from the workspace between connect and callback.
        state = self.start_connect(cookie, ws)
        conn.execute("DELETE FROM workspace_members WHERE workspace_id = ?", (ws,))
        conn.commit()
        self.assertEqual(self.callback(cookie, state)[1], "/app#/scan/new?github=invalid_state")

    def test_csrf_on_connect_and_disconnect(self):
        cookie, ws = self.workspace("standard", "csrf@example.com")
        for origin in (None, "http://evil.example", "null"):
            with self.subTest(origin=origin):
                status, _, body = self.jpost("/workspaces/%s/github/connect" % ws, cookie, Origin=origin)
                self.assertEqual((status, body["error"]), (403, "cross-origin request rejected"))
        self.connect(cookie, ws)
        status, _, _ = self.delete("/workspaces/%s/github" % ws, headers={"Cookie": cookie, "Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertIsNotNone(repo.get_active_github_connection(self.db(), ws, repo.get_user_by_email(self.db(), "csrf@example.com")["id"]))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM github_oauth_states").fetchone()[0], 1)

    def test_disconnect_wipes_tokens_revokes_and_blocks_use(self):
        cookie, ws = self.workspace("standard", "disc@example.com")
        self.connect(cookie, ws)
        token = next(iter(self.fake.tokens))
        status, _, body = self.delete("/workspaces/%s/github" % ws, headers={"Cookie": cookie})
        self.assertEqual((status, json.loads(body)), (200, {"ok": True, "disconnected": True}))
        self.assertEqual(self.fake.revoked, [token])
        row = self.db().execute("SELECT status, access_token_enc, refresh_token_enc, revoked_at FROM github_connections").fetchone()
        self.assertEqual((row[0], row[1], row[2]), ("revoked", None, None))
        self.assertIsNotNone(row[3])
        for status, _, body in (self.jget("/workspaces/%s/github/repositories" % ws, cookie), self.scan(cookie, ws)):
            self.assertEqual((status, body["error"]), (409, "github_not_connected"))
        self.assertEqual(json.loads(self.delete("/workspaces/%s/github" % ws, headers={"Cookie": cookie})[2]), {"ok": True, "disconnected": False})
        # Reconnecting creates a new active connection; the old row stays revoked.
        self.connect(cookie, ws, code="again")
        self.assertEqual([r[0] for r in self.db().execute("SELECT status FROM github_connections ORDER BY created_at")], ["revoked", "active"])

    def test_reconnect_replaces_the_active_connection(self):
        cookie, ws = self.workspace("pro", "replace@example.com")
        self.connect(cookie, ws)
        self.connect(cookie, ws, login="other", code="second")
        rows = self.db().execute("SELECT github_login, status, access_token_enc FROM github_connections ORDER BY created_at").fetchall()
        self.assertEqual([(r[0], r[1], r[2] is None) for r in rows], [("octo", "revoked", True), ("other", "active", False)])

    def test_expiring_tokens_are_refreshed_and_a_dead_refresh_requires_reconnect(self):
        self.fake.expiring = True
        cookie, ws = self.workspace("standard", "refresh@example.com")
        self.connect(cookie, ws)
        conn = self.db()
        before = conn.execute("SELECT access_token_enc, refresh_token_enc, access_token_expires_at FROM github_connections").fetchone()
        self.assertIsNotNone(before[1])
        self.assertIsNotNone(before[2])
        conn.execute("UPDATE github_connections SET access_token_expires_at = ?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),))
        conn.commit()
        status, _, body = self.jget("/workspaces/%s/github/repositories" % ws, cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(len([c for c in self.fake.calls if c[1].endswith("/login/oauth/access_token")]), 2)
        after = conn.execute("SELECT access_token_enc, refresh_token_enc FROM github_connections WHERE status = 'active'").fetchone()
        self.assertNotEqual(after[0], before[0])
        self.assertNotEqual(after[1], before[1])
        conn.execute("UPDATE github_connections SET access_token_expires_at = ?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),))
        conn.commit()
        self.fake.refresh_tokens.clear()                                                   # GitHub no longer honours it
        status, _, body = self.jget("/workspaces/%s/github/repositories" % ws, cookie)
        self.assertEqual((status, body["error"]), (409, "github_reconnect_required"))
        row = conn.execute("SELECT status, access_token_enc, refresh_token_enc FROM github_connections ORDER BY updated_at DESC").fetchone()
        self.assertEqual(tuple(row), ("invalid", None, None))

    def test_a_token_revoked_at_github_marks_the_connection_invalid(self):
        cookie, ws = self.workspace("standard", "revoked@example.com")
        self.connect(cookie, ws)
        self.fake.tokens.clear()
        status, _, body = self.jget("/workspaces/%s/github/repositories" % ws, cookie)
        self.assertEqual((status, body["error"]), (409, "github_reconnect_required"))
        self.assertEqual(self.db().execute("SELECT status FROM github_connections").fetchone()[0], "invalid")


class GitHubRepositoryTests(_GitHubHttpCase):
    def test_lists_authorized_repositories_with_the_required_fields(self):
        cookie, ws = self.workspace("standard", "list@example.com")
        self.connect(cookie, ws)
        status, _, body = self.jget("/workspaces/%s/github/repositories" % ws, cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body["repositories"], [{"id": 101, "owner": "octo", "name": "vault", "full_name": "octo/vault", "private": True, "default_branch": "main"}])
        self.assertFalse(body["truncated"])
        status, _, body = self.jget("/workspaces/%s/github/repositories/101/branches" % ws, cookie)
        self.assertEqual((status, body["repository"]["full_name"], body["branches"]), (200, "octo/vault", [{"name": "main", "commit_sha": self.head}]))

    def test_inaccessible_and_invalid_repository_ids(self):
        cookie, ws = self.workspace("standard", "inacc@example.com")
        self.connect(cookie, ws)
        status, _, body = self.jget("/workspaces/%s/github/repositories/202/branches" % ws, cookie)     # exists, not granted to octo
        self.assertEqual((status, body["error"]), (404, "repository_not_accessible"))
        status, _, body = self.scan(cookie, ws, repository_id=202)
        self.assertEqual((status, body["error"]), (404, "repository_not_accessible"))
        for bad in ("abc", "0", "-1", "1e3", "%31"):
            with self.subTest(path_id=bad):
                self.assertEqual(self.jget("/workspaces/%s/github/repositories/%s/branches" % (ws, bad), cookie)[0], 404)
        for bad in ("x", 0, -5, True, None, 1.5):
            with self.subTest(repository_id=bad):
                status, _, body = self.scan(cookie, ws, repository_id=bad)
                self.assertEqual((status, body["error"]), (400, "invalid_repository_id"))
        for spec in ({"repository_id": 101, "url": "https://evil.example/x.zip"}, [101], "octo/vault", {"repository_id": 101, "owner": "octo", "name": "vault"}):
            with self.subTest(spec=spec):
                status, _, body = self.jpost("/workspaces/%s/jobs" % ws, cookie, {"mode": "quick", "github": spec})
                self.assertEqual((status, body["error"]), (400, "invalid_github_source"))
        status, _, body = self.jpost("/workspaces/%s/jobs" % ws, cookie, {"mode": "quick", "github": {"repository_id": 101}, "source": "contract X {}"})
        self.assertEqual((status, body["error"]), (400, "only one of source, files, archive or github may be given"))
        self.assertFalse(any("evil.example" in c[1] for c in self.fake.calls))

    def test_workspace_and_member_isolation(self):
        cookie, ws_a = self.workspace("standard", "iso-a@example.com")
        self.connect(cookie, ws_a)
        conn = self.db()
        user = repo.get_user_by_email(conn, "iso-a@example.com")["id"]
        ws_b = repo.create_workspace(conn, "B", user)                       # same user, another workspace: not connected there
        repo.create_entitlement(conn, ws_b, "standard", "active", billing_interval="monthly")
        self.assertEqual(self.jget("/workspaces/%s/github/repositories" % ws_b, cookie)[2]["error"], "github_not_connected")
        self.assertEqual(self.scan(cookie, ws_b)[2]["error"], "github_not_connected")
        member_cookie = self.request_and_confirm_login("iso-member@example.com")   # another member of A has no connection of their own
        repo.add_workspace_member(conn, ws_a, repo.get_user_by_email(conn, "iso-member@example.com")["id"], "member")
        self.assertEqual(self.jget("/workspaces/%s/github" % ws_a, member_cookie)[2]["connection"], None)
        self.assertEqual(self.jget("/workspaces/%s/github/repositories" % ws_a, member_cookie)[2]["error"], "github_not_connected")
        outsider, ws_c = self.workspace("standard", "iso-out@example.com")
        for status, _, _ in (self.jget("/workspaces/%s/github" % ws_a, outsider), self.jget("/workspaces/%s/github/repositories" % ws_a, outsider),
                             self.scan(outsider, ws_a), self.jpost("/workspaces/%s/github/connect" % ws_a, outsider)):
            self.assertEqual(status, 403)
        self.assertEqual(self.delete("/workspaces/%s/github" % ws_a, headers={"Cookie": outsider})[0], 403)
        self.assertEqual(self.jget("/workspaces/%s/github" % ws_a, "session=nope")[0], 401)
        # A ciphertext copied into another workspace's row cannot be decrypted there.
        enc = conn.execute("SELECT access_token_enc FROM github_connections WHERE workspace_id = ?", (ws_a,)).fetchone()[0]
        outsider_user = repo.get_user_by_email(conn, "iso-out@example.com")["id"]
        repo.save_github_connection(conn, ws_c, outsider_user, 1, "copy", "", enc, None, None, None)
        status, _, body = self.jget("/workspaces/%s/github/repositories" % ws_c, outsider)
        self.assertEqual((status, body["error"]), (409, "github_reconnect_required"))
        self.assertEqual(repo.get_active_github_connection(conn, ws_c, outsider_user), None)


class GitHubScanTests(_GitHubHttpCase):
    def test_check_pins_the_sha_and_start_records_it(self):
        cookie, ws = self.workspace("standard", "pin@example.com")
        self.connect(cookie, ws)
        conn = self.db()
        project = repo.create_project(conn, ws, "Vault")
        status, _, preview = self.scan(cookie, ws, dry_run=True, project_id=project)
        self.assertEqual(status, 200, preview)
        self.assertEqual(preview["github"], {"repository_id": 101, "full_name": "octo/vault", "ref": "main", "commit_sha": self.head})
        self.assertEqual(preview["effective_loc"], loc_count.submission_effective_loc(A_SOL) + loc_count.submission_effective_loc(B_SOL))
        self.assertEqual(preview["ignored"], ["package.json"])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0], 0)      # Check stores nothing
        moved = self.fake.commit(101, "main", {"src/A.sol": A_SOL, "src/B.sol": B_SOL, "src/C.sol": "contract C {}\n"})
        status, _, body = self.scan(cookie, ws, commit_sha=preview["github"]["commit_sha"], project_id=project, key="k1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["github"]["commit_sha"], self.head)                                # the Checked commit, not the new head
        self.assertNotEqual(moved, self.head)
        job = repo.get_job(conn, body["job_id"])
        contract = repo.get_contract(conn, job["contract_id"])
        self.assertEqual((contract["source_kind"], contract["project_id"], contract["name"]), ("files", project, "octo/vault@%s" % self.head[:12]))
        self.assertEqual({k: v for k, v in repo.get_contract_git_source(conn, ws, contract["id"]).items() if k != "created_at"},
                         {"provider": "github", "repository_id": 101, "repository_full_name": "octo/vault", "ref": "main", "commit_sha": self.head})
        stored = self.storage.get_object(contract["storage_ref"]).decode("utf-8")
        self.assertNotIn("contract C", stored)
        self.assertEqual([f["path"] for f in repo.list_contract_files(conn, ws, contract["id"])], ["README.md", "src/A.sol", "src/B.sol"])
        status, _, detail = self.jget("/workspaces/%s/jobs/%s" % (ws, body["job_id"]), cookie)
        self.assertEqual(detail["source"]["git"]["commit_sha"], self.head)
        rows = self.jget("/workspaces/%s/jobs" % ws, cookie)[2]["jobs"]
        self.assertEqual((rows[0]["git_repository"], rows[0]["git_ref"], rows[0]["git_commit_sha"]), ("octo/vault", "main", self.head))
        # Reproducible: the same commit again builds the byte-identical bundle.
        status, _, again = self.scan(cookie, ws, commit_sha=self.head)
        contract2 = repo.get_contract(conn, repo.get_job(conn, again["job_id"])["contract_id"])
        self.assertEqual(contract2["content_hash"], contract["content_hash"])

    def test_default_branch_other_branches_and_refusals(self):
        cookie, ws = self.workspace("standard", "branches@example.com")
        self.connect(cookie, ws)
        dev = self.fake.commit(101, "feature/x", {"src/A.sol": B_SOL}, parent=None)
        self.assertEqual(self.scan(cookie, ws, ref=None, dry_run=True)[2]["github"]["ref"], "main")
        status, _, body = self.scan(cookie, ws, ref="feature/x", dry_run=True)
        self.assertEqual((status, body["github"]["commit_sha"]), (200, dev))
        status, _, body = self.scan(cookie, ws, ref="main", commit_sha=dev)
        self.assertEqual((status, body["error"]), (409, "commit_not_on_ref"))
        status, _, body = self.scan(cookie, ws, ref="missing")
        self.assertEqual((status, body["error"]), (404, "ref_not_found"))
        for bad in ("../../user", "a..b", "x?y", "a b"):
            with self.subTest(ref=bad):
                status, _, body = self.scan(cookie, ws, ref=bad)
                self.assertEqual((status, body["error"]), (400, "invalid_ref"))
        status, _, body = self.scan(cookie, ws, commit_sha="HEAD")
        self.assertEqual((status, body["error"]), (400, "invalid_commit_sha"))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], 0)

    def test_github_errors_are_reported_cleanly(self):
        cookie, ws = self.workspace("standard", "gherr@example.com")
        self.connect(cookie, ws)
        self.fake.rate_limited = True
        status, headers, body = self.scan(cookie, ws)
        self.assertEqual((status, body["error"]), (429, "github_rate_limited"))
        self.assertEqual(headers["Retry-After"], str(body["retry_after_seconds"]))
        self.fake.rate_limited = False
        self.fake.tamper_blobs.add(gi.git_blob_sha(A_SOL.encode()))
        self.assertEqual(self.scan(cookie, ws)[2]["error"], "github_unavailable")
        self.fake.tamper_blobs.clear()
        self.fake.truncate_trees = True
        status, _, body = self.scan(cookie, ws)
        self.assertEqual((status, body["error"]), (413, "repository_too_large"))
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], 0)


class GitHubAdmissionTests(_GitHubHttpCase):
    def repo_with_loc(self, repo_id, loc):
        self.fake.add_repo(repo_id, "octo/r%d" % repo_id)
        return self.fake.commit(repo_id, "main", {"src/Big.sol": _sol(loc)})

    def test_standard_10k_per_scan_and_20k_per_service_month(self):
        cookie, ws = self.workspace("standard", "std-loc@example.com")
        self.connect(cookie, ws)
        self.repo_with_loc(301, 10001)
        self.repo_with_loc(302, 10000)
        status, _, body = self.scan(cookie, ws, repository_id=301)
        self.assertEqual((status, body["error"], body["effective_loc"], body["max_loc_per_scan"]), (413, "loc_per_scan_limit_exceeded", 10001, 10000))
        self.assertEqual(self.scan(cookie, ws, repository_id=302)[0], 200)
        self.assertEqual(self.scan(cookie, ws, repository_id=302)[0], 200)
        status, _, body = self.scan(cookie, ws, repository_id=302)
        self.assertEqual((status, body["error"], body["loc_remaining"]), (402, "loc_quota_exceeded", 0))
        self.assertEqual(self.jget("/workspaces/%s" % ws, cookie)[2]["usage"]["loc_remaining"], 0)

    def test_pro_20k_per_scan_and_60k_per_service_month_with_priority(self):
        cookie, ws = self.workspace("pro", "pro-loc@example.com")
        self.connect(cookie, ws)
        self.repo_with_loc(401, 20001)
        self.repo_with_loc(402, 20000)
        self.assertEqual(self.scan(cookie, ws, repository_id=401, mode="pro")[2]["error"], "loc_per_scan_limit_exceeded")
        jobs = [self.scan(cookie, ws, repository_id=402, mode="pro") for _ in range(3)]
        self.assertEqual([j[0] for j in jobs], [200, 200, 200])
        self.assertEqual({repo.get_job(self.db(), j[2]["job_id"])["priority"] for j in jobs}, {1})
        status, _, body = self.scan(cookie, ws, repository_id=402, mode="pro")
        self.assertEqual((status, body["error"]), (402, "loc_quota_exceeded"))

    def test_idempotency_returns_the_same_job_without_calling_github_again(self):
        cookie, ws = self.workspace("standard", "idem@example.com")
        self.connect(cookie, ws)
        first = self.scan(cookie, ws, key="same-key")
        calls = len(self.fake.calls)
        second = self.scan(cookie, ws, key="same-key")
        self.assertEqual((second[0], second[2]["job_id"], second[2]["duplicate"]), (200, first[2]["job_id"], True))
        self.assertEqual(len(self.fake.calls), calls)
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0], 1)

    def test_technical_budget_still_guards_github_scans(self):
        cookie, ws = self.workspace("standard", "tech-gh@example.com")
        self.connect(cookie, ws)
        status, _, body = self.scan(cookie, ws, mode="standard")
        self.assertEqual(status, 200)
        conn = self.db()
        self.assertTrue(repo.transition_job_status(conn, body["job_id"], "queued", "canceled"))
        conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        conn.commit()
        status, _, body = self.scan(cookie, ws, mode="standard")
        self.assertEqual((status, body["error"]), (429, "technical_budget_exhausted"))


class GitHubQueueGuardsTests(_GitHubHttpCase):
    MAX_PENDING = 1
    RATE = 3

    def test_pending_jobs_and_rate_limit_apply_to_github_submissions(self):
        cookie, ws = self.workspace("standard", "guards-gh@example.com")
        self.connect(cookie, ws)
        self.assertEqual(self.scan(cookie, ws)[0], 200)
        status, _, body = self.scan(cookie, ws)
        self.assertEqual((status, body["error"], body["max_pending_jobs"]), (429, "too_many_pending_jobs", 1))
        self.assertEqual(self.scan(cookie, ws, dry_run=True)[2]["error"], "too_many_pending_jobs")
        calls = len(self.fake.calls)
        status, headers, body = self.scan(cookie, ws)                                   # 4th request in the window
        self.assertEqual((status, body["error"]), (429, "submit_rate_limited"))
        self.assertIn("Retry-After", headers)
        self.assertEqual(len(self.fake.calls), calls)                                    # refused before GitHub is touched


class GitHubTokenSecrecyTests(_GitHubHttpCase):
    def test_tokens_never_reach_responses_logs_or_scan_records(self):
        self.fake.expiring = True
        cookie, ws = self.workspace("standard", "secret@example.com")
        with _capture_stderr() as log:
            state = self.start_connect(cookie, ws)
            self.callback(cookie, state, code="the-oauth-code")
            bodies = [json.dumps(self.jget("/workspaces/%s/github" % ws, cookie)[2]),
                      json.dumps(self.jget("/workspaces/%s/github/repositories" % ws, cookie)[2]),
                      json.dumps(self.jget("/workspaces/%s/github/repositories/101/branches" % ws, cookie)[2]),
                      json.dumps(self.scan(cookie, ws, dry_run=True)[2])]
            started = self.scan(cookie, ws)
            bodies.append(json.dumps(started[2]))
            bodies.append(json.dumps(self.jget("/workspaces/%s/jobs/%s" % (ws, started[2]["job_id"]), cookie)[2]))
            bodies.append(json.dumps(self.jget("/workspaces/%s/jobs" % ws, cookie)[2]))
            bodies.append(json.dumps(self.jget("/workspaces/%s" % ws, cookie)[2]))
        secrets = list(self.fake.tokens) + list(self.fake.refresh_tokens) + ["the-oauth-code", state, CLIENT_SECRET]
        logged = log.getvalue()
        self.assertIn("/github/callback?state=[REDACTED]&code=[REDACTED]", logged)
        for secret in secrets:
            self.assertNotIn(secret, logged)
            for body in bodies:
                self.assertNotIn(secret, body)
        self.assertNotIn("access_token", "".join(bodies))
        conn = self.db()
        dump = []
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
            for row in conn.execute("SELECT * FROM %s" % table).fetchall():
                dump.append("%s %r" % (table, tuple(row)))
        for secret in secrets:
            self.assertFalse([line for line in dump if secret in line], secret)
        stored = self.storage.get_object(repo.get_contract(conn, repo.get_job(conn, started[2]["job_id"])["contract_id"])["storage_ref"]).decode()
        for secret in secrets:
            self.assertNotIn(secret, stored)
        self.assertEqual(self.alerts.events, [])

    def test_github_error_bodies_never_echo_github_text(self):
        cookie, ws = self.workspace("standard", "echo@example.com")
        self.connect(cookie, ws)
        self.fake.rate_limited = True
        body = self.jget("/workspaces/%s/github/repositories" % ws, cookie)[2]
        self.assertEqual(set(body), {"ok", "error", "detail", "retry_after_seconds"})
        self.assertEqual(body["detail"], "GitHub's API rate limit was reached; try again later")


class RetentionAndConfigTests(unittest.TestCase):
    def test_workspace_deletion_revokes_github_connections(self):
        conn = repo.connect()
        repo.init_schema(conn)
        user = repo.create_user(conn, "ret@example.com")
        ws = repo.create_workspace(conn, "R", user)
        repo.save_github_connection(conn, ws, user, 1, "octo", "", "v1.x", None, "v1.y", None)
        storage_dir = tempfile.mkdtemp(prefix="ret-gh-")
        self.addCleanup(lambda: shutil.rmtree(storage_dir, ignore_errors=True))
        result = retention.delete_workspace_data(conn, object_storage.LocalFilesystemStorage(storage_dir, sign_secret="x"), ws)
        self.assertEqual(result["github_connections_revoked"], 1)
        self.assertEqual(tuple(conn.execute("SELECT status, access_token_enc, refresh_token_enc FROM github_connections").fetchone()), ("revoked", None, None))

    def test_state_consumption_is_single_use_and_bound(self):
        conn = repo.connect()
        repo.init_schema(conn)
        user = repo.create_user(conn, "st@example.com")
        other = repo.create_user(conn, "st2@example.com")
        ws = repo.create_workspace(conn, "S", user)
        repo.create_github_oauth_state(conn, "h1", ws, user, 600)
        self.assertIsNone(repo.consume_github_oauth_state(conn, "h1", other))
        self.assertEqual(repo.consume_github_oauth_state(conn, "h1", user)["workspace_id"], ws)
        self.assertIsNone(repo.consume_github_oauth_state(conn, "h1", user))
        repo.create_github_oauth_state(conn, "old", ws, user, 1, now=datetime.now(timezone.utc) - timedelta(days=2))
        repo.create_github_oauth_state(conn, "h2", ws, user, 600)                         # prunes the stale one
        self.assertEqual({r[0] for r in conn.execute("SELECT state_hash FROM github_oauth_states")}, {"h1", "h2"})
        with self.assertRaises(repo.RepositoryError):
            repo.set_github_connection_status(conn, ws, "x", "active")

    def _env(self, **values):
        base = {name: "" for name in main.GITHUB_REQUIRED_ENV_VARS}
        base["GITHUB_APP_SLUG"] = ""
        base.update(values)
        return mock.patch.dict(os.environ, base)

    def test_config_is_all_or_nothing_and_validated(self):
        key = base64.b64encode(os.urandom(32)).decode()
        full = {"GITHUB_APP_CLIENT_ID": CLIENT_ID, "GITHUB_APP_CLIENT_SECRET": CLIENT_SECRET,
                "GITHUB_OAUTH_REDIRECT_URI": "https://app.vericexa.test/github/callback", "GITHUB_TOKEN_ENCRYPTION_KEY": key}
        with self._env():
            self.assertEqual(main._load_github_config(), {"github": None})
            self.assertIsNone(main._build_github(None))
        with self._env(**dict(full, GITHUB_APP_SLUG="vericexa")):
            cfg = main._load_github_config()["github"]
            self.assertEqual((cfg["client_id"], cfg["app_slug"], len(cfg["token_key"])), (CLIENT_ID, "vericexa", 32))
            self.assertIsInstance(main._build_github(cfg), gi.GitHubIntegration)
        with self._env(GITHUB_APP_CLIENT_ID=CLIENT_ID):
            with self.assertRaises(main.ConfigError):
                main._load_github_config()
        for bad in ("http://app.vericexa.test/github/callback", "https://app.vericexa.test/other", "https://evil/x/github/callback?x=1", "javascript:x"):
            with self.subTest(redirect=bad):
                with self._env(**dict(full, GITHUB_OAUTH_REDIRECT_URI=bad)):
                    with self.assertRaises(main.ConfigError):
                        main._load_github_config()
        with self._env(**dict(full, GITHUB_OAUTH_REDIRECT_URI="http://localhost:8080/github/callback")):
            self.assertIsNotNone(main._load_github_config()["github"])
        with self._env(**dict(full, GITHUB_TOKEN_ENCRYPTION_KEY=base64.b64encode(b"x" * 16).decode())):
            with self.assertRaises(main.ConfigError):
                main._load_github_config()


class WebAppGitHubTests(unittest.TestCase):
    APP = (REPO_ROOT / "backend" / "webapp" / "app.js").read_text(encoding="utf-8")
    CORE = REPO_ROOT / "backend" / "webapp" / "app-core.js"

    def test_option_is_shown_only_when_the_backend_lists_the_feature(self):
        self.assertIn('var hasGitHub = (adm.features || []).indexOf("private_github") >= 0;', self.APP)
        self.assertIn('.concat(hasGitHub ? [["github", "Import from GitHub"]] : [])', self.APP)
        self.assertEqual(self.APP.count("Import from GitHub"), 1)
        self.assertIn("if (hasGitHub) { loadGitHub(", self.APP)
        self.assertNotRegex(self.APP, r"access_token|refresh_token|client_secret")      # the browser never handles a token
        self.assertIn("C.safeExternalUrl(url)", self.APP)                                  # only the backend's https URL is opened

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_core_helpers(self):
        script = ("var C = require(%s);\nprocess.stdout.write(JSON.stringify({"
                  "msg: ['connected', 'invalid_state', 'denied', 'x'].map(C.githubCallbackMessage),"
                  "label: [C.sourceKindLabel('files', 'octo/vault'), C.sourceKindLabel('files', null), C.sourceKindLabel('archive')],"
                  "sha: [C.shortSha('a'.repeat(40)), C.shortSha('nope')],"
                  "err: C.describeError(403, {error: 'feature_not_available'}).message}));" % json.dumps(str(self.CORE)))
        out = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout)
        self.assertEqual(out["msg"][0], {"kind": "ok", "text": "GitHub connected."})
        self.assertEqual(out["msg"][1]["kind"], "error")
        self.assertEqual(out["msg"][3], None)
        self.assertEqual(out["label"], ["GitHub", "Multiple files", "ZIP"])
        self.assertEqual(out["sha"], ["a" * 12, "-"])
        self.assertEqual(out["err"], "Private GitHub is available on the Standard and Pro plans.")


if __name__ == "__main__":
    unittest.main()
