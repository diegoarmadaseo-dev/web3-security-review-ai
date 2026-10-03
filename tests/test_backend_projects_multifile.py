"""Tests for projects, multi-file and ZIP submissions (docs/decisiones.md
D-109): backend/submission_input.py, the project/contract-file functions of
backend/repository.py, and the HTTP endpoints in backend/http_app.py. No
LLM call, no Docker, no Stripe: SQLite (real-Postgres checks live in
tests/test_backend_postgres_integration.py).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.http_app as http_app  # noqa: E402
import backend.loc_count as loc_count  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402
import backend.submission_input as si  # noqa: E402
import preprocess as pp  # noqa: E402
from tests.test_backend_commercial import _sol  # noqa: E402
from tests.test_backend_commercial_guards import _GuardsHttpCase  # noqa: E402

MAX = http_app.MAX_RAW_SOURCE_BYTES

A_SOL = 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A is B {\n    function f() public { g(); }\n}\n'
B_SOL = "pragma solidity ^0.8.20;\ncontract B {\n    function g() internal {}\n}\n"


def _zip(entries, compression=zipfile.ZIP_DEFLATED):
    """entries: list of (name, bytes|str) or (ZipInfo, bytes)."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # duplicate-name warnings are the point of some tests
        with zipfile.ZipFile(buf, "w", compression) as zf:
            for name, data in entries:
                zf.writestr(name, data)
    return buf.getvalue()


def _code(fn):
    try:
        fn()
    except si.SubmissionInputError as exc:
        return exc.code, exc.http_status
    raise AssertionError("expected SubmissionInputError")


def _engine(source):
    d = tempfile.mkdtemp(prefix="d109-")
    try:
        path = os.path.join(d, "contract.sol")
        with open(path, "w", encoding="utf-8", newline="") as h:
            h.write(source)
        return pp.run([path], mode="pro", max_loc=None, use_stdin=False, include_timestamp=False)
    finally:
        shutil.rmtree(d, True)


# ---------------------------------------------------------------------------
# Multi-file input (backend/submission_input.py)
# ---------------------------------------------------------------------------

class MultiFileInputTests(unittest.TestCase):
    def test_two_files_one_bundle_with_paths_imports_and_inheritance(self):
        built = si.from_files([{"path": "src/B.sol", "content": B_SOL}, {"path": "src/A.sol", "content": A_SOL}], MAX)
        self.assertEqual([f["path"] for f in built["files"]], ["src/A.sol", "src/B.sol"])
        artifact = _engine(built["source"])
        self.assertEqual([f["path"] for f in artifact["files"]], ["src/A.sol", "src/B.sol"])
        self.assertEqual([(i["path"], i["resolved"], i["resolvedTo"]) for i in artifact["imports"]], [("./B.sol", True, "src/B.sol")])
        a = next(c for c in artifact["contracts"] if c["name"] == "A")
        self.assertEqual(a["basesResolved"], [{"name": "B", "source": "bundle", "kind": "contract"}])
        self.assertEqual(artifact["completeness"]["status"], "complete")

    def test_effective_loc_is_the_sum_and_matches_the_engine(self):
        files = [{"path": "a/X.sol", "content": _sol(120, comment_lines=10)}, {"path": "b/Y.sol", "content": _sol(80, blank_lines=7)},
                 {"path": "README.md", "content": "# docs\npragma solidity in prose\n"}]
        built = si.from_files(files, MAX)
        total = loc_count.submission_effective_loc(built["source"])
        self.assertEqual(total, 200)
        self.assertEqual(total, sum(f["effective_loc"] for f in built["files"]))
        self.assertEqual(total, loc_count.submission_effective_loc(files[0]["content"]) + loc_count.submission_effective_loc(files[1]["content"]))
        self.assertEqual(total, _engine(built["source"])["totals"]["totalEffectiveLoc"])
        self.assertEqual({f["path"]: f["language"] for f in built["files"]}["README.md"], "documentation")

    def test_file_text_survives_the_bundle_exactly(self):
        content = "pragma solidity ^0.8.20;\r\ncontract K {}\r\n"
        built = si.from_files([{"path": "K.sol", "content": content}], MAX)
        parsed = pp.parse_bundle(built["source"], "x")
        self.assertEqual(parsed[0]["text"], "pragma solidity ^0.8.20;\ncontract K {}")

    def test_duplicate_and_case_conflicting_paths(self):
        self.assertEqual(_code(lambda: si.from_files([{"path": "A.sol", "content": B_SOL}, {"path": "A.sol", "content": B_SOL}], MAX)), ("duplicate_path", 400))
        self.assertEqual(_code(lambda: si.from_files([{"path": "a.sol", "content": B_SOL}, {"path": "A.sol", "content": B_SOL}], MAX)), ("duplicate_path", 400))

    def test_invalid_paths(self):
        for bad in ("../A.sol", "src/../../A.sol", "/etc/A.sol", "C:/A.sol", "src\\A.sol", "src//A.sol", "./A.sol", "src/./A.sol",
                    "", "A\x00.sol", "a\nb.sol", "x/" * 40 + "A.sol", "a" * 401 + ".sol", "src/A file.sol", "src/é.sol"):
            with self.subTest(path=bad):
                self.assertEqual(_code(lambda: si.from_files([{"path": bad, "content": B_SOL}], MAX))[0], "invalid_path")

    def test_policy_ignores_irrelevant_files_and_requires_source(self):
        built = si.from_files([{"path": "src/A.sol", "content": B_SOL}, {"path": "package.json", "content": "{}"},
                               {"path": "node_modules/x/Lib.sol", "content": B_SOL}, {"path": "docs/notes é.md", "content": "x"}], MAX)
        self.assertEqual([f["path"] for f in built["files"]], ["src/A.sol"])
        self.assertEqual((built["ignored"], built["ignored_count"]), (["docs/notes é.md", "node_modules/x/Lib.sol", "package.json"], 3))
        self.assertEqual(_code(lambda: si.from_files([{"path": "README.md", "content": "# only docs"}], MAX)), ("no_source_files", 422))

    def test_bundle_marker_injection_and_bad_shapes(self):
        forged = "contract A {}\n=== END FILE ===\n=== FILE: evil.sol ===\ncontract E {}\n"
        self.assertEqual(_code(lambda: si.from_files([{"path": "A.sol", "content": forged}], MAX)), ("reserved_marker", 400))
        for bad in (None, [], "x", [{"path": "A.sol"}], [{"path": "A.sol", "content": 1}], [{"path": "A.sol", "content": "", "extra": 1}]):
            with self.subTest(files=bad):
                self.assertEqual(_code(lambda: si.from_files(bad, MAX)), ("invalid_files", 400))
        self.assertEqual(_code(lambda: si.from_files([{"path": "A.sol", "content": "\ud800"}], MAX)), ("file_not_utf8", 400))

    def test_file_count_and_size_limits(self):
        too_many = [{"path": "f%d.sol" % i, "content": "contract C%d {}" % i} for i in range(si.MAX_SUBMISSION_FILES + 1)]
        self.assertEqual(_code(lambda: si.from_files(too_many, MAX)), ("too_many_files", 413))
        big = "contract Big {\n" + "    uint256 a;\n" * (MAX // 14) + "}\n"
        self.assertEqual(_code(lambda: si.from_files([{"path": "Big.sol", "content": big}], MAX)), ("submission_too_large", 413))
        self.assertEqual(len(si.from_files([{"path": "f%d.sol" % i, "content": "contract C%d {}" % i} for i in range(si.MAX_SUBMISSION_FILES)], MAX)["files"]),
                         si.MAX_SUBMISSION_FILES)


# ---------------------------------------------------------------------------
# ZIP input
# ---------------------------------------------------------------------------

class ZipInputTests(unittest.TestCase):
    def test_valid_zip_equals_the_same_files_sent_individually(self):
        files = [{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}, {"path": "README.md", "content": "# P\n"}]
        z = si.from_zip(_zip([("src/", b""), ("src/A.sol", A_SOL), ("src/B.sol", B_SOL), ("README.md", "# P\n")]), MAX)
        f = si.from_files(files, MAX)
        self.assertEqual(z["source"], f["source"])                                     # byte-identical bundle
        self.assertEqual(z["files"], f["files"])
        self.assertEqual(loc_count.submission_effective_loc(z["source"]), loc_count.submission_effective_loc(f["source"]))

    def test_mixed_content_reports_ignored_files(self):
        z = si.from_zip(_zip([("p/A.sol", B_SOL), ("p/logo.png", b"\x89PNG"), ("p/.git/config", "x"), ("__MACOSX/p/._A.sol", b"\x00"), ("p/out/A.json", "{}")]), MAX)
        self.assertEqual([f["path"] for f in z["files"]], ["p/A.sol"])
        self.assertEqual(z["ignored_count"], 4)

    def test_empty_and_no_solidity_archives(self):
        self.assertEqual(_code(lambda: si.from_zip(_zip([]), MAX)), ("no_source_files", 422))
        self.assertEqual(_code(lambda: si.from_zip(_zip([("README.md", "x"), ("a.js", "x")]), MAX)), ("no_source_files", 422))

    def test_malformed_archives(self):
        good = _zip([("A.sol", B_SOL * 50)])
        corrupt = bytearray(good)
        start = good.index(b"A.sol") + len("A.sol")                                    # inside the compressed data of the only entry
        for i in range(start + 5, start + 40):
            corrupt[i] ^= 0xFF
        for bad in (b"not a zip at all", good[: len(good) // 2], bytes(corrupt), b"PK\x05\x06" + b"\x00" * 10):
            with self.subTest(size=len(bad)):
                self.assertEqual(_code(lambda: si.from_zip(bad, MAX)), ("archive_malformed", 400))

    def test_traversal_absolute_and_ambiguous_entry_names(self):
        for name in ("../evil.sol", "a/../../evil.sol", "/abs/evil.sol", "C:/evil.sol", "../readme.txt", "a//b.sol"):
            with self.subTest(name=name):
                info = zipfile.ZipInfo(name)
                self.assertEqual(_code(lambda: si.from_zip(_zip([(info, B_SOL)]), MAX))[0], "invalid_path")
        # A STORED backslash: ZipInfo rewrites it on Windows, so patch the raw bytes (same length).
        for stored in (b"a\\evil.sol", b"..\\evil.sol"):
            placeholder = b"x" * (len(stored) - len(b"evil.sol")) + b"evil.sol"
            raw = _zip([(placeholder.decode(), B_SOL)]).replace(placeholder, stored)
            with self.subTest(stored=stored):
                self.assertEqual(_code(lambda: si.from_zip(raw, MAX))[0], "invalid_path")

    def test_duplicate_entries(self):
        self.assertEqual(_code(lambda: si.from_zip(_zip([("A.sol", B_SOL), ("A.sol", B_SOL)]), MAX)), ("duplicate_path", 400))
        self.assertEqual(_code(lambda: si.from_zip(_zip([("src/A.sol", B_SOL), ("SRC/a.sol", B_SOL)]), MAX)), ("duplicate_path", 400))

    def test_too_many_entries(self):
        entries = [("f%d.txt" % i, "x") for i in range(si.MAX_ARCHIVE_ENTRIES + 1)]
        self.assertEqual(_code(lambda: si.from_zip(_zip(entries, zipfile.ZIP_STORED), MAX)), ("too_many_files", 413))
        sources = [("f%d.sol" % i, "contract C%d {}" % i) for i in range(si.MAX_SUBMISSION_FILES + 1)]
        self.assertEqual(_code(lambda: si.from_zip(_zip(sources), MAX)), ("too_many_files", 413))

    def test_zip_bomb_is_stopped_by_what_is_actually_decompressed(self):
        bomb = _zip([("Bomb.sol", b"\n" * (64 * 1024 * 1024))])                      # 64 MiB of newlines, a few KB compressed
        self.assertLess(len(bomb), si.MAX_ARCHIVE_BYTES)
        reads = []
        real_open = zipfile.ZipFile.open

        def spy_open(self_zf, *a, **kw):
            handle = real_open(self_zf, *a, **kw)
            real_read = handle.read
            handle.read = lambda n=-1: reads.append(n) or real_read(n)
            return handle

        with mock.patch.object(zipfile.ZipFile, "open", spy_open):
            self.assertEqual(_code(lambda: si.from_zip(bomb, MAX)), ("archive_uncompressed_too_large", 413))
        self.assertEqual(reads, [MAX + 1])                                              # one bounded read, never the declared 64 MiB
        many = _zip([("f%d.sol" % i, b"\n" * (MAX // 3)) for i in range(4)])          # the budget is the TOTAL across files
        self.assertEqual(_code(lambda: si.from_zip(many, MAX)), ("archive_uncompressed_too_large", 413))

    def test_compressed_size_limit(self):
        self.assertEqual(_code(lambda: si.from_zip(b"\x00" * (si.MAX_ARCHIVE_BYTES + 1), MAX)), ("archive_too_large", 413))
        too_big_b64 = base64.b64encode(b"\x00" * (si.MAX_ARCHIVE_BYTES + 3)).decode()
        self.assertEqual(_code(lambda: si.decode_archive({"format": "zip", "content_base64": too_big_b64})), ("archive_too_large", 413))

    def test_symlink_and_encrypted_entries(self):
        link = zipfile.ZipInfo("src/A.sol")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assertEqual(_code(lambda: si.from_zip(_zip([(link, "/etc/passwd")]), MAX)), ("archive_symlink", 400))
        data = bytearray(_zip([("A.sol", B_SOL)], zipfile.ZIP_STORED))
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):                                     # set the encryption flag in both headers
            pos = data.index(sig)
            flag_at = pos + (6 if sig == b"PK\x03\x04" else 8)
            data[flag_at] |= 0x01
        self.assertEqual(_code(lambda: si.from_zip(bytes(data), MAX)), ("archive_encrypted", 400))

    def test_archive_envelope(self):
        payload = {"format": "zip", "content_base64": base64.b64encode(_zip([("A.sol", B_SOL)])).decode()}
        self.assertTrue(si.decode_archive(payload).startswith(b"PK"))
        self.assertEqual(_code(lambda: si.decode_archive({"format": "tar", "content_base64": "AA=="})), ("unsupported_archive_format", 400))
        for bad in (None, "x", {"format": "zip"}, {"format": "zip", "content_base64": "@@@"}, {"format": "zip", "content_base64": "AA==", "x": 1}):
            with self.subTest(archive=bad):
                self.assertEqual(_code(lambda: si.decode_archive(bad))[0], "invalid_archive")

    def test_nothing_is_ever_extracted_or_written_to_disk(self):
        def forbidden(*a, **kw):
            raise AssertionError("submission_input must not touch the filesystem")

        before = set(os.listdir(tempfile.gettempdir()))
        with mock.patch.object(zipfile.ZipFile, "extract", forbidden), mock.patch.object(zipfile.ZipFile, "extractall", forbidden), \
                mock.patch.object(tempfile, "mkdtemp", forbidden), mock.patch.object(tempfile, "mkstemp", forbidden), \
                mock.patch.object(tempfile, "NamedTemporaryFile", forbidden), mock.patch.object(tempfile, "TemporaryDirectory", forbidden):
            si.from_zip(_zip([("src/A.sol", A_SOL), ("src/B.sol", B_SOL)]), MAX)                # success
            _code(lambda: si.from_zip(_zip([("../x.sol", B_SOL)]), MAX))                        # failure
            _code(lambda: si.from_zip(b"garbage", MAX))                                         # malformed
        self.assertEqual(set(os.listdir(tempfile.gettempdir())) - before, set())


# ---------------------------------------------------------------------------
# Projects (repository)
# ---------------------------------------------------------------------------

class ProjectRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = repo.connect(":memory:")
        repo.init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.user = repo.create_user(self.conn, "proj@example.com")
        self.ws = repo.create_workspace(self.conn, "WS", self.user)
        self.other = repo.create_workspace(self.conn, "Other", self.user)

    def test_crud_and_soft_delete(self):
        pid = repo.create_project(self.conn, self.ws, "Vault")
        self.assertEqual(repo.get_project(self.conn, self.ws, pid)["name"], "Vault")
        self.assertTrue(repo.rename_project(self.conn, self.ws, pid, "Vault v2"))
        self.assertEqual([p["name"] for p in repo.list_projects(self.conn, self.ws)], ["Vault v2"])
        self.assertTrue(repo.delete_project(self.conn, self.ws, pid))
        self.assertFalse(repo.delete_project(self.conn, self.ws, pid))                     # idempotent
        self.assertIsNone(repo.get_project(self.conn, self.ws, pid))
        self.assertFalse(repo.rename_project(self.conn, self.ws, pid, "x"))
        repo.create_project(self.conn, self.ws, "Vault v2")                                 # name reusable after delete

    def test_names_and_isolation(self):
        pid = repo.create_project(self.conn, self.ws, "Vault")
        with self.assertRaises(repo.ProjectNameTakenError):
            repo.create_project(self.conn, self.ws, "Vault")
        other_pid = repo.create_project(self.conn, self.other, "Vault")                    # same name, other workspace
        with self.assertRaises(repo.ProjectNameTakenError):
            repo.rename_project(self.conn, self.ws, repo.create_project(self.conn, self.ws, "B"), "Vault")
        self.assertIsNone(repo.get_project(self.conn, self.ws, other_pid))                 # cross-workspace = not found
        self.assertFalse(repo.rename_project(self.conn, self.ws, other_pid, "Stolen"))
        self.assertFalse(repo.delete_project(self.conn, self.ws, other_pid))
        self.assertEqual(repo.get_project(self.conn, self.other, other_pid)["name"], "Vault")
        self.assertEqual({p["name"] for p in repo.list_projects(self.conn, self.ws)}, {"Vault", "B"})
        self.assertEqual([p["id"] for p in repo.list_projects(self.conn, self.other)], [other_pid])
        self.assertIn(pid, [p["id"] for p in repo.list_projects(self.conn, self.ws)])

    def test_contract_manifest_is_atomic_with_the_contract(self):
        built = si.from_files([{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}], MAX)
        cid = repo.create_contract(self.conn, self.ws, "ref", "h", "n", source_kind="files", files=built["files"])
        rows = repo.list_contract_files(self.conn, self.ws, cid)
        self.assertEqual([r["path"] for r in rows], ["src/A.sol", "src/B.sol"])
        self.assertEqual(repo.list_contract_files(self.conn, self.other, cid), [])         # workspace-scoped read
        before = self.conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
        broken = built["files"] + [dict(built["files"][0])]                                 # duplicate path -> PK violation
        with self.assertRaises(Exception):
            repo.create_contract(self.conn, self.ws, "ref2", "h", "n", source_kind="files", files=broken)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0], before)   # no half-written contract
        with self.assertRaises(repo.RepositoryError):
            repo.create_contract(self.conn, self.ws, "ref3", "h", "n", source_kind="tarball")

    def test_scoped_idempotency_key(self):
        self.assertNotEqual(repo.scoped_idempotency_key(self.ws, "k"), repo.scoped_idempotency_key(self.other, "k"))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _D109HttpCase(_GuardsHttpCase):
    MAX_PENDING = 50
    RATE = 100

    def ws(self, plan, email, credits=0):
        cookie = self.request_and_confirm_login(email)
        conn = repo.connect(self.db_path)
        ws = repo.create_workspace(conn, "D109 WS", repo.get_user_by_email(conn, email)["id"])
        if plan:
            repo.create_entitlement(conn, ws, plan, "active", billing_interval=None if plan == "quick" else "monthly")
        for i in range(credits):
            repo.grant_scan_credit(conn, "cs_%s_%d" % (ws, i), ws)
        conn.close()
        return cookie, ws

    def call(self, method, path, cookie=None, payload=None):
        headers = {"Cookie": cookie} if cookie else {}
        if method == "POST":
            status, h, body = self.post_json(path, payload or {}, headers=headers)
        elif method == "GET":
            status, h, body = self.get(path, headers=headers)
        elif method == "DELETE":
            status, h, body = self.delete(path, headers=headers)
        else:
            conn = self._conn()
            raw = json.dumps(payload or {}).encode()
            hdrs = {"Content-Type": "application/json", "Content-Length": str(len(raw)), "Host": self.host_header, "Origin": self.same_origin}
            hdrs.update(headers)
            conn.request(method, path, body=raw, headers=hdrs)
            resp = conn.getresponse()
            status, h, body = resp.status, dict(resp.getheaders()), resp.read()
            conn.close()
        return status, (json.loads(body) if body else None)

    def submit(self, cookie, ws, **payload):
        payload.setdefault("mode", "quick")
        return self.call("POST", "/workspaces/%s/jobs" % ws, cookie, payload)


class ProjectHttpTests(_D109HttpCase):
    def test_crud(self):
        cookie, ws = self.ws("standard", "p-crud@example.com")
        status, body = self.call("POST", "/workspaces/%s/projects" % ws, cookie, {"name": "  Vault  "})
        self.assertEqual((status, body["project"]["name"]), (200, "Vault"))
        pid = body["project"]["id"]
        self.assertEqual(self.call("GET", "/workspaces/%s/projects/%s" % (ws, pid), cookie)[1]["project"]["id"], pid)
        self.assertEqual([p["id"] for p in self.call("GET", "/workspaces/%s/projects" % ws, cookie)[1]["projects"]], [pid])
        status, body = self.call("PATCH", "/workspaces/%s/projects/%s" % (ws, pid), cookie, {"name": "Vault v2"})
        self.assertEqual((status, body["project"]["name"]), (200, "Vault v2"))
        self.assertEqual(self.call("POST", "/workspaces/%s/projects" % ws, cookie, {"name": "Vault v2"}), (409, {"ok": False, "error": "project_name_taken"}))
        self.assertEqual(self.call("DELETE", "/workspaces/%s/projects/%s" % (ws, pid), cookie)[0], 200)
        self.assertEqual(self.call("GET", "/workspaces/%s/projects/%s" % (ws, pid), cookie), (404, {"ok": False, "error": "project_not_found"}))
        self.assertEqual(self.call("DELETE", "/workspaces/%s/projects/%s" % (ws, pid), cookie)[0], 404)

    def test_validation_and_errors(self):
        cookie, ws = self.ws("standard", "p-val@example.com")
        for bad in ({}, {"name": ""}, {"name": "   "}, {"name": 5}, {"name": "x" * 201}, {"name": "a\x00b"}):
            with self.subTest(payload=bad):
                self.assertEqual(self.call("POST", "/workspaces/%s/projects" % ws, cookie, bad)[0], 400)
        for pid in ("nope", "00000000-0000-0000-0000-000000000000", "../x"):
            with self.subTest(project=pid):
                self.assertEqual(self.call("GET", "/workspaces/%s/projects/%s" % (ws, pid), cookie)[0], 404)
                self.assertEqual(self.call("PATCH", "/workspaces/%s/projects/%s" % (ws, pid), cookie, {"name": "n"})[0], 404)

    def test_authentication_permissions_and_tenant_isolation(self):
        owner, ws = self.ws("standard", "p-owner@example.com")
        outsider, other_ws = self.ws("pro", "p-outsider@example.com")
        pid = self.call("POST", "/workspaces/%s/projects" % ws, owner, {"name": "Secret"})[1]["project"]["id"]
        foreign_pid = self.call("POST", "/workspaces/%s/projects" % other_ws, outsider, {"name": "Theirs"})[1]["project"]["id"]
        self.assertEqual(self.call("GET", "/workspaces/%s/projects" % ws)[0], 401)                              # no session
        self.assertEqual(self.call("GET", "/workspaces/%s/projects" % ws, outsider)[0], 403)                    # not a member
        self.assertEqual(self.call("GET", "/workspaces/%s/projects/%s" % (ws, pid), outsider)[0], 403)
        self.assertEqual(self.call("POST", "/workspaces/%s/projects" % repo.new_id(), owner, {"name": "x"})[0], 403)   # nonexistent workspace
        self.assertEqual(self.call("GET", "/workspaces/%s/projects/%s" % (ws, foreign_pid), owner)[0], 404)     # other workspace's project
        self.assertEqual(self.call("DELETE", "/workspaces/%s/projects/%s" % (ws, foreign_pid), owner)[0], 404)
        self.assertEqual(self.call("GET", "/workspaces/%s/projects/%s" % (other_ws, foreign_pid), outsider)[1]["project"]["name"], "Theirs")
        # a member may create/rename but not delete; the owner may delete
        member_cookie = self.request_and_confirm_login("p-member@example.com")
        self.assertEqual(self.post_json("/workspaces/%s/members" % ws, {"email": "p-member@example.com", "role": "member"}, headers={"Cookie": owner})[0], 200)
        self.assertEqual(self.call("PATCH", "/workspaces/%s/projects/%s" % (ws, pid), member_cookie, {"name": "Renamed"})[0], 200)
        self.assertEqual(self.call("DELETE", "/workspaces/%s/projects/%s" % (ws, pid), member_cookie)[0], 403)
        self.assertEqual(self.call("DELETE", "/workspaces/%s/projects/%s" % (ws, pid), owner)[0], 200)

    def test_projects_are_unlimited_for_every_plan_and_need_no_entitlement(self):
        self.assertTrue(all(plans.PLANS[p]["max_projects"] is None for p in plans.PLANS_ORDER))
        for plan in ("quick", "standard", "pro", None):
            cookie, ws = self.ws(plan, "p-unl-%s@example.com" % (plan or "none"))
            for i in range(25):
                self.assertEqual(self.call("POST", "/workspaces/%s/projects" % ws, cookie, {"name": "P%d" % i})[0], 200)
            self.assertEqual(len(self.call("GET", "/workspaces/%s/projects?limit=100" % ws, cookie)[1]["projects"]), 25)


class MultiFileSubmitHttpTests(_D109HttpCase):
    def b64zip(self, entries):
        return {"format": "zip", "content_base64": base64.b64encode(_zip(entries)).decode()}

    def test_files_and_zip_scans_with_project_and_traceability(self):
        cookie, ws = self.ws("standard", "mf-flow@example.com")
        pid = self.call("POST", "/workspaces/%s/projects" % ws, cookie, {"name": "DeFi"})[1]["project"]["id"]
        files = [{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}, {"path": "foundry.toml", "content": "x"}]
        status, body = self.submit(cookie, ws, files=files, project_id=pid)
        self.assertEqual((status, body["source_kind"], body["project_id"], body["ignored"]), (200, "files", pid, ["foundry.toml"]))
        self.assertEqual(body["effective_loc"], sum(f["effective_loc"] for f in body["files"]))
        status, zbody = self.submit(cookie, ws, archive=self.b64zip([("src/A.sol", A_SOL), ("src/B.sol", B_SOL), ("foundry.toml", "x")]), project_id=pid)
        self.assertEqual((status, zbody["source_kind"], zbody["effective_loc"]), (200, "archive", body["effective_loc"]))
        status, detail = self.call("GET", "/workspaces/%s/jobs/%s" % (ws, zbody["job_id"]), cookie)
        self.assertEqual((detail["source"]["kind"], detail["source"]["project_id"]), ("archive", pid))
        self.assertEqual([f["path"] for f in detail["source"]["files"]], ["src/A.sol", "src/B.sol"])
        self.assertNotIn("storage_ref", json.dumps(detail))
        self.assertEqual(detail["usage"]["effective_loc"], body["effective_loc"])
        listed = self.call("GET", "/workspaces/%s/jobs?project_id=%s" % (ws, pid), cookie)[1]["jobs"]
        self.assertEqual(sorted(j["id"] for j in listed), sorted([body["job_id"], zbody["job_id"]]))
        conn = repo.connect(self.db_path)
        stored = self.storage.get_object(repo.get_contract(conn, repo.get_job(conn, zbody["job_id"])["contract_id"])["storage_ref"]).decode()
        conn.close()
        self.assertTrue(stored.startswith("=== FILE: src/A.sol ==="))                    # the worker gets the engine bundle
        self.assertEqual(loc_count.submission_effective_loc(stored), body["effective_loc"])

    def test_input_errors_are_deterministic(self):
        cookie, ws = self.ws("standard", "mf-err@example.com")
        cases = [
            ({"files": [{"path": "A.sol", "content": B_SOL}], "source": B_SOL}, 400, "only one of source, files or archive may be given"),
            ({"files": [{"path": "../A.sol", "content": B_SOL}]}, 400, "invalid_path"),
            ({"files": [{"path": "A.sol", "content": B_SOL}, {"path": "A.sol", "content": B_SOL}]}, 400, "duplicate_path"),
            ({"files": [{"path": "README.md", "content": "x"}]}, 422, "no_source_files"),
            ({"files": [{"path": "A.sol", "content": "// nothing\n"}]}, 422, "no_source_code"),
            ({"archive": {"format": "zip", "content_base64": base64.b64encode(b"garbage").decode()}}, 400, "archive_malformed"),
            ({"archive": self.b64zip([("/abs/A.sol", B_SOL)])}, 400, "invalid_path"),
            ({"archive": self.b64zip([])}, 422, "no_source_files"),
            ({"files": [{"path": "A.sol", "content": B_SOL}], "project_id": "not-a-uuid"}, 404, "project_not_found"),
            ({"files": [{"path": "A.sol", "content": B_SOL}], "project_id": repo.new_id()}, 404, "project_not_found"),
        ]
        for payload, status, error in cases:
            with self.subTest(error=error):
                got_status, body = self.submit(cookie, ws, **payload)
                self.assertEqual((got_status, body["error"]), (status, error))
        conn = repo.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()[0], 0)
        conn.close()

    def test_cross_workspace_and_deleted_projects_are_refused(self):
        cookie, ws = self.ws("standard", "mf-x1@example.com")
        cookie2, ws2 = self.ws("standard", "mf-x2@example.com")
        foreign = self.call("POST", "/workspaces/%s/projects" % ws2, cookie2, {"name": "Other"})[1]["project"]["id"]
        self.assertEqual(self.submit(cookie, ws, source=B_SOL, project_id=foreign)[0], 404)
        own = self.call("POST", "/workspaces/%s/projects" % ws, cookie, {"name": "Gone"})[1]["project"]["id"]
        self.call("DELETE", "/workspaces/%s/projects/%s" % (ws, own), cookie)
        self.assertEqual(self.submit(cookie, ws, source=B_SOL, project_id=own)[0], 404)
        job = self.submit(cookie2, ws2, source=B_SOL)[1]["job_id"]
        self.assertEqual(self.call("GET", "/workspaces/%s/jobs/%s" % (ws, job), cookie)[0], 404)                # other workspace's job
        self.assertEqual(self.call("GET", "/workspaces/%s/jobs/%s" % (ws2, job), cookie)[0], 403)              # not a member there

    def test_idempotency_with_files_and_across_workspaces(self):
        cookie, ws = self.ws("standard", "mf-idem@example.com")
        files = [{"path": "src/A.sol", "content": A_SOL}, {"path": "src/B.sol", "content": B_SOL}]
        first = self.submit(cookie, ws, files=files, idempotency_key="deploy-1")[1]
        again = self.submit(cookie, ws, files=files, idempotency_key="deploy-1")[1]
        self.assertEqual((again["job_id"], again["duplicate"]), (first["job_id"], True))
        cookie2, ws2 = self.ws("standard", "mf-idem2@example.com")
        theirs = self.submit(cookie2, ws2, files=files, idempotency_key="deploy-1")[1]          # same client key, other tenant
        self.assertNotEqual(theirs["job_id"], first["job_id"])
        self.assertNotIn("duplicate", theirs)
        conn = repo.connect(self.db_path)
        s = repo.usage_summary(conn, ws, repo.get_entitlement_by_workspace(conn, ws))
        conn.close()
        self.assertEqual(s["loc_reserved"], first["effective_loc"])                              # reserved once


class MultiFileAdmissionHttpTests(_D109HttpCase):
    def split(self, total, parts=2):
        each = total // parts
        sizes = [each] * (parts - 1) + [total - each * (parts - 1)]
        return [{"path": "src/F%d.sol" % i, "content": _sol(n).replace("contract C", "contract C%d" % i)} for i, n in enumerate(sizes)]

    def test_per_scan_limits_apply_to_the_total_of_the_scan(self):
        for plan, limit, mode in (("quick", 3000, "quick"), ("standard", 10000, "standard"), ("pro", 20000, "pro")):
            with self.subTest(plan=plan):
                cookie, ws = self.ws(plan, "adm-%s@example.com" % plan, credits=2)
                status, body = self.submit(cookie, ws, mode=mode, files=self.split(limit + 1))
                self.assertEqual((status, body["error"], body["effective_loc"]), (413, "loc_per_scan_limit_exceeded", limit + 1))
                status, body = self.submit(cookie, ws, mode=mode, archive={"format": "zip", "content_base64": base64.b64encode(
                    _zip([(f["path"], f["content"]) for f in self.split(limit + 1, 3)])).decode()})
                self.assertEqual((status, body["error"]), (413, "loc_per_scan_limit_exceeded"))
                status, body = self.submit(cookie, ws, mode=mode, files=self.split(limit, 3))
                self.assertEqual((status, body["effective_loc"]), (200, limit))

    def test_monthly_quotas_count_the_whole_scan_once(self):
        cookie, ws = self.ws("standard", "adm-q-std@example.com")
        self.assertEqual(self.submit(cookie, ws, files=self.split(10000, 4))[0], 200)
        self.assertEqual(self.submit(cookie, ws, files=self.split(9500, 3))[0], 200)
        status, body = self.submit(cookie, ws, files=self.split(1000, 2))
        self.assertEqual((status, body["error"], body["loc_remaining"]), (402, "loc_quota_exceeded", 500))
        cookie, ws = self.ws("pro", "adm-q-pro@example.com")
        for _ in range(3):
            self.assertEqual(self.submit(cookie, ws, mode="pro", files=self.split(20000, 2))[0], 200)
        self.assertEqual(self.submit(cookie, ws, mode="pro", files=self.split(2, 2))[1]["error"], "loc_quota_exceeded")

    def test_quick_one_scan_and_not_partial_by_commercial_overflow(self):
        cookie, ws = self.ws("quick", "adm-quick@example.com", credits=1)
        self.assertEqual(self.submit(cookie, ws, files=self.split(3001))[1]["error"], "loc_per_scan_limit_exceeded")   # refused, never queued as partial
        self.assertEqual(self.submit(cookie, ws, files=self.split(3000))[0], 200)
        self.assertEqual(self.submit(cookie, ws, files=self.split(10))[1]["error"], "no_scan_credit")
        conn = repo.connect(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM analysis_jobs WHERE workspace_id = ?", (ws,)).fetchone()[0], 1)
        conn.close()

    def test_technical_budget_and_pending_guards_still_apply(self):
        cookie, ws = self.ws("standard", "adm-tech@example.com")
        job = self.submit(cookie, ws, mode="standard", files=self.split(100))[1]["job_id"]
        conn = repo.connect(self.db_path)
        repo.transition_job_status(conn, job, "queued", "canceled")
        conn.execute("UPDATE technical_budget_periods SET consumed_units = limit_units WHERE workspace_id = ?", (ws,))
        conn.commit()
        conn.close()
        self.assertEqual(self.submit(cookie, ws, mode="standard", files=self.split(100))[1]["error"], "technical_budget_exhausted")

    def test_concurrent_multi_file_submissions_never_overshoot_the_quota(self):
        cookie, ws = self.ws("standard", "adm-race@example.com")
        results, lock = [], threading.Lock()

        def worker(i):
            status, body = self.submit(cookie, ws, files=self.split(3000, 2), idempotency_key="race-%d" % i)
            with lock:
                results.append(body.get("error", "ok") if status != 200 else "ok")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ["loc_quota_exceeded"] * 2 + ["ok"] * 6)            # 6 x 3,000 = 18,000 <= 20,000
        conn = repo.connect(self.db_path)
        self.assertEqual(repo.usage_summary(conn, ws, repo.get_entitlement_by_workspace(conn, ws))["loc_reserved"], 18000)
        conn.close()


class PendingCapWithMultiFileHttpTests(_D109HttpCase):
    MAX_PENDING = 2

    def test_pending_cap(self):
        cookie, ws = self.ws("standard", "adm-pend@example.com")
        files = [{"path": "A.sol", "content": B_SOL}]
        self.assertEqual(self.submit(cookie, ws, files=files)[0], 200)
        self.assertEqual(self.submit(cookie, ws, archive={"format": "zip", "content_base64": base64.b64encode(_zip([("A.sol", B_SOL)])).decode()})[0], 200)
        self.assertEqual(self.submit(cookie, ws, files=files)[1]["error"], "too_many_pending_jobs")


if __name__ == "__main__":
    unittest.main()
