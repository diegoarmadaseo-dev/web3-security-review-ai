#!/usr/bin/env python3
"""Private GitHub as a scan source for Standard/Pro (docs/decisiones.md D-111).

GITHUB IS ONLY ANOTHER INPUT: this module turns "repository + branch +
commit" into the list of (path, bytes) entries that backend/
submission_input.from_repository_entries() validates with the exact D-109
file policy and turns into the engine's own multi-file bundle. Everything
after that - effective LOC, commercial admission, technical guard, pending
jobs, rate limit, idempotency, object storage, queue, worker, report - is the
existing POST /workspaces/<id>/jobs path, unchanged.

AUTHORIZATION MODEL - a GitHub App, user-to-server: the member signs in to
GitHub through the standard web flow (github.com/login/oauth/authorize with
a single-use `state`), and the App only sees the repositories its
installation was granted, intersected with what that member can read. The
App needs read-only permissions (Contents: read, Metadata: read) - no write
access, no `repo` scope over every private repository. Vericexa never asks
for a GitHub password; the browser only ever goes to github.com itself.

TOKENS: the user access token (and refresh token, when the App issues
expiring tokens) are encrypted by TokenCipher before they reach the
database, bound to the workspace+user+field they belong to, and decrypted
only in memory right before a GitHub API call. They are never returned to the
browser, never written to a log line, an alert, a job, a contract, a report
or an exception message: every GitHubError carries a stable code and a fixed
sentence, never GitHub's own response text.

NO SSRF BY CONSTRUCTION: every request goes to one of two fixed origins
(api.github.com, github.com - overridable only in code, for tests) and
every variable path segment is validated first: a repository is addressed by
GitHub's numeric id, then by the full_name GitHub itself returned for that id
(never a client-supplied owner/name), branches and SHAs are checked against
strict patterns, and redirects are never followed. No user-supplied URL is
ever fetched.

BOUNDED: per-request timeout, response-size ceilings (read at most limit + 1
bytes), tree-entry ceiling, file-count and byte budgets checked against the
tree's declared sizes BEFORE any file is downloaded, and every downloaded
blob verified against its git SHA-1 (so the bytes analysed are exactly the
pinned commit's). GitHub rate limiting is reported as github_rate_limited
with GitHub's own reset time.

Standard library only.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import quote, urlencode

import backend.repository as repo
import backend.submission_input as submission_input

API_BASE = "https://api.github.com"
OAUTH_BASE = "https://github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "Vericexa-Private-GitHub"

HTTP_TIMEOUT_SECONDS = 10
MAX_JSON_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TREE_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_COMPARE_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TREE_ENTRIES = 20000          # every path in the commit, kept or ignored (ignored ones are never downloaded)
MAX_INSTALLATIONS = 100
MAX_LISTED_REPOSITORIES = 300
MAX_LISTED_BRANCHES = 100
FETCH_CONCURRENCY = 8
OAUTH_STATE_TTL_SECONDS = 600
TOKEN_REFRESH_SKEW_SECONDS = 120

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_BRANCH_FORBIDDEN_RE = re.compile(r"[\x00-\x20\x7f~^:?*\[\\%#]")
_MAX_REPOSITORY_ID = 2 ** 53


class GitHubError(Exception):
    """A refused or failed GitHub operation. `code` is stable and
    machine-readable, `detail` a fixed sentence (never GitHub's own text,
    never a token), `http_status` what the HTTP layer answers."""

    def __init__(self, code: str, detail: str, http_status: int, retry_after: Optional[int] = None) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.http_status = http_status
        self.retry_after = retry_after


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def parse_repository_id(value: Any) -> int:
    if isinstance(value, bool):
        value = None
    if isinstance(value, str) and value.isdigit() and len(value) <= 16:
        value = int(value)
    if not isinstance(value, int) or not (1 <= value < _MAX_REPOSITORY_ID):
        raise GitHubError("invalid_repository_id", "repository_id must be a GitHub repository id", 400)
    return value


def validate_branch_name(ref: Any) -> str:
    """A branch name safe to place in a GitHub API path: git's own
    check-ref-format rules plus no URL-significant character, so a name can
    never navigate to another API path ('..' segments, '?', '#', '%')."""
    if not isinstance(ref, str) or not (1 <= len(ref) <= 255):
        raise GitHubError("invalid_ref", "ref must be a branch name", 400)
    if (_BRANCH_FORBIDDEN_RE.search(ref) or ".." in ref or "@{" in ref or ref.startswith(("/", "-")) or ref.endswith(("/", ".", ".lock"))
            or "//" in ref or any(segment.startswith(".") for segment in ref.split("/")) or ref == "@"):
        raise GitHubError("invalid_ref", "ref must be a branch name", 400)
    return ref


def validate_commit_sha(sha: Any) -> str:
    if not isinstance(sha, str) or not _COMMIT_SHA_RE.match(sha.lower()):
        raise GitHubError("invalid_commit_sha", "commit_sha must be a full 40-character commit SHA", 400)
    return sha.lower()


def _validated_full_name(full_name: Any) -> str:
    if not isinstance(full_name, str) or not _FULL_NAME_RE.match(full_name) or full_name.split("/")[1] in (".", ".."):
        raise GitHubError("github_unavailable", "GitHub returned an unexpected repository name", 502)
    return full_name


def _repo_path(full_name: str) -> str:
    owner, name = _validated_full_name(full_name).split("/")
    return "/repos/%s/%s" % (quote(owner, safe=""), quote(name, safe=""))


# ---------------------------------------------------------------------------
# Token encryption (stdlib only)
# ---------------------------------------------------------------------------

class TokenCipher:
    """Authenticated encryption of OAuth tokens with standard-library
    primitives only (no third-party crypto package is approved for this
    backend): encrypt-then-MAC with independent sub-keys derived from the
    configured key - HMAC-SHA256 in counter mode as the keystream (a PRF
    stream cipher) under a random 128-bit nonce, and an HMAC-SHA256 tag over
    version, nonce, ciphertext and the caller's associated data. The
    associated data binds a ciphertext to its workspace, user and field, so
    a value copied into another row or swapped between the access and
    refresh columns fails authentication instead of decrypting."""

    VERSION = "v1"

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("the token encryption key must be at least 32 bytes")
        self._enc_key = hmac.new(key, b"vericexa/github-token/enc", hashlib.sha256).digest()
        self._mac_key = hmac.new(key, b"vericexa/github-token/mac", hashlib.sha256).digest()

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        blocks = []
        for counter in range((length + 31) // 32):
            blocks.append(hmac.new(self._enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        return b"".join(blocks)[:length]

    def _tag(self, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        message = self.VERSION.encode() + b"\x00" + nonce + len(associated_data).to_bytes(4, "big") + associated_data + ciphertext
        return hmac.new(self._mac_key, message, hashlib.sha256).digest()

    def encrypt(self, plaintext: str, associated_data: str) -> str:
        data = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(16)
        ciphertext = bytes(a ^ b for a, b in zip(data, self._keystream(nonce, len(data))))
        tag = self._tag(nonce, ciphertext, associated_data.encode("utf-8"))
        return "%s.%s" % (self.VERSION, base64.urlsafe_b64encode(nonce + ciphertext + tag).decode("ascii"))

    def decrypt(self, token: str, associated_data: str) -> str:
        try:
            version, encoded = token.split(".", 1)
            blob = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, AttributeError, binascii.Error):
            raise GitHubError("github_reconnect_required", "the GitHub connection must be renewed", 409)
        if version != self.VERSION or len(blob) < 16 + 32:
            raise GitHubError("github_reconnect_required", "the GitHub connection must be renewed", 409)
        nonce, ciphertext, tag = blob[:16], blob[16:-32], blob[-32:]
        if not hmac.compare_digest(tag, self._tag(nonce, ciphertext, associated_data.encode("utf-8"))):
            raise GitHubError("github_reconnect_required", "the GitHub connection must be renewed", 409)
        return bytes(a ^ b for a, b in zip(ciphertext, self._keystream(nonce, len(ciphertext)))).decode("utf-8")


def token_associated_data(workspace_id: str, user_id: str, field: str) -> str:
    return "github-connection:%s:%s:%s" % (workspace_id, user_id, field)


# ---------------------------------------------------------------------------
# HTTP transport (no redirects, bounded reads, fixed origins)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib signature
        return None   # a 3xx surfaces as an HTTPError with its own status; nothing is ever followed


class UrllibTransport:
    """request(method, url, headers, body, max_bytes) -> (status, headers
    with lower-case names, body bytes). Reads at most max_bytes + 1 bytes."""

    def __init__(self, timeout: int = HTTP_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout
        self._opener = urllib_request.build_opener(_NoRedirect())

    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes], max_bytes: int) -> Tuple[int, Dict[str, str], bytes]:
        req = urllib_request.Request(url, data=body, headers=headers, method=method)
        try:
            response = self._opener.open(req, timeout=self._timeout)
        except urllib_error.HTTPError as exc:
            response = exc
        except (urllib_error.URLError, OSError, ValueError):
            raise GitHubError("github_unavailable", "GitHub could not be reached", 502)
        try:
            data = response.read(max_bytes + 1)
            status = response.getcode() or 0
            response_headers = {k.lower(): v for k, v in (response.headers.items() if response.headers else [])}
        except (OSError, ValueError):
            raise GitHubError("github_unavailable", "GitHub could not be reached", 502)
        finally:
            try:
                response.close()
            except Exception:
                pass
        return status, response_headers, data


# ---------------------------------------------------------------------------
# Configuration and client
# ---------------------------------------------------------------------------

class GitHubConfig:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, token_key: bytes,
                 app_slug: Optional[str] = None, api_base: str = API_BASE, oauth_base: str = OAUTH_BASE) -> None:
        for name, value in (("client_id", client_id), ("client_secret", client_secret), ("redirect_uri", redirect_uri)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("%s is required" % name)
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.token_key = token_key
        self.app_slug = app_slug if app_slug and re.match(r"^[a-z0-9-]{1,100}$", app_slug) else None
        self.api_base = api_base.rstrip("/")
        self.oauth_base = oauth_base.rstrip("/")


def decode_token_key(value: str) -> bytes:
    """GITHUB_TOKEN_ENCRYPTION_KEY: base64 (standard or URL-safe) of at
    least 32 random bytes."""
    try:
        key = base64.urlsafe_b64decode(value.strip().replace("+", "-").replace("/", "_") + "=" * (-len(value.strip()) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("GITHUB_TOKEN_ENCRYPTION_KEY must be base64")
    if len(key) < 32:
        raise ValueError("GITHUB_TOKEN_ENCRYPTION_KEY must decode to at least 32 bytes")
    return key


class GitHubClient:
    def __init__(self, config: GitHubConfig, transport: Optional[Any] = None) -> None:
        self.config = config
        self.transport = transport or UrllibTransport()

    # -- low level ---------------------------------------------------------
    def _call(self, method: str, base: str, path: str, token: Optional[str] = None, query: Optional[Dict[str, Any]] = None,
              form: Optional[Dict[str, str]] = None, json_body: Optional[Dict[str, Any]] = None, basic_auth: bool = False,
              max_bytes: int = MAX_JSON_RESPONSE_BYTES, accept: str = "application/vnd.github+json") -> Tuple[int, Dict[str, str], Any]:
        if base not in (self.config.api_base, self.config.oauth_base) or not path.startswith("/"):
            raise GitHubError("github_unavailable", "GitHub could not be reached", 502)   # fixed origins only
        url = base + path + ("?" + urlencode(query) if query else "")
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if base == self.config.api_base:
            headers["X-GitHub-Api-Version"] = API_VERSION
        body = None
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if basic_auth:
            headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (self.config.client_id, self.config.client_secret)).encode()).decode()
        if form is not None:
            body = urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, response_headers, data = self.transport.request(method, url, headers, body, max_bytes)
        if len(data) > max_bytes:
            raise GitHubError("github_response_too_large", "GitHub returned more data than allowed", 502)
        if status in (401,):
            raise GitHubError("github_reconnect_required", "the GitHub connection must be renewed", 409)
        if status == 429 or (status == 403 and response_headers.get("x-ratelimit-remaining") == "0"):
            raise GitHubError("github_rate_limited", "GitHub's API rate limit was reached; try again later", 429, _retry_after(response_headers))
        if status >= 500 or status == 0 or 300 <= status < 400:
            raise GitHubError("github_unavailable", "GitHub could not be reached", 502)
        parsed: Any = None
        if data:
            try:
                parsed = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        return status, response_headers, parsed

    def _api_get(self, path: str, token: str, query: Optional[Dict[str, Any]] = None, max_bytes: int = MAX_JSON_RESPONSE_BYTES,
                 not_found: Tuple[str, str] = ("repository_not_accessible", "the repository is not accessible with this GitHub connection")) -> Any:
        status, _, data = self._call("GET", self.config.api_base, path, token=token, query=query, max_bytes=max_bytes)
        if status in (403, 404, 409, 422):
            raise GitHubError(not_found[0], not_found[1], 404)
        if status != 200 or data is None:
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        return data

    # -- OAuth (GitHub App user authorization) -----------------------------
    def authorize_url(self, state: str) -> str:
        return "%s/login/oauth/authorize?%s" % (self.config.oauth_base, urlencode(
            {"client_id": self.config.client_id, "redirect_uri": self.config.redirect_uri, "state": state, "allow_signup": "false"}))

    def install_url(self) -> Optional[str]:
        return "%s/apps/%s/installations/new" % (self.config.oauth_base, self.config.app_slug) if self.config.app_slug else None

    def _token_request(self, form: Dict[str, str]) -> Dict[str, Any]:
        status, _, data = self._call("POST", self.config.oauth_base, "/login/oauth/access_token", form=form, accept="application/json")
        if status != 200 or not isinstance(data, dict) or data.get("error") or not isinstance(data.get("access_token"), str) or not data["access_token"]:
            raise GitHubError("github_authorization_failed", "GitHub did not grant access", 400)
        return data

    def exchange_code(self, code: str) -> Dict[str, Any]:
        return self._token_request({"client_id": self.config.client_id, "client_secret": self.config.client_secret,
                                    "code": code, "redirect_uri": self.config.redirect_uri})

    def refresh(self, refresh_token: str) -> Dict[str, Any]:
        return self._token_request({"client_id": self.config.client_id, "client_secret": self.config.client_secret,
                                    "grant_type": "refresh_token", "refresh_token": refresh_token})

    def revoke(self, access_token: str) -> None:
        """Best effort: GitHub's 'delete an app token' endpoint."""
        try:
            self._call("DELETE", self.config.api_base, "/applications/%s/token" % quote(self.config.client_id, safe=""),
                       json_body={"access_token": access_token}, basic_auth=True)
        except GitHubError:
            pass

    # -- reads ---------------------------------------------------------------
    def get_user(self, token: str) -> Dict[str, Any]:
        data = self._api_get("/user", token, not_found=("github_authorization_failed", "GitHub did not grant access"))
        if not isinstance(data, dict) or not isinstance(data.get("id"), int) or not isinstance(data.get("login"), str):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        return {"id": data["id"], "login": data["login"][:100]}

    def list_repositories(self, token: str) -> Tuple[List[Dict[str, Any]], bool]:
        """Repositories this GitHub App user token can read: every
        installation the member can access, then each installation's
        granted repositories. Bounded; `truncated` says more exist."""
        installations = self._api_get("/user/installations", token, query={"per_page": MAX_INSTALLATIONS})
        items = installations.get("installations") if isinstance(installations, dict) else None
        if not isinstance(items, list):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        truncated = isinstance(installations.get("total_count"), int) and installations["total_count"] > len(items)
        seen, repositories = set(), []
        for installation in items:
            if truncated and len(repositories) >= MAX_LISTED_REPOSITORIES:
                break
            if not isinstance(installation, dict) or not isinstance(installation.get("id"), int):
                continue
            page = 1
            while not (truncated and len(repositories) >= MAX_LISTED_REPOSITORIES):
                data = self._api_get("/user/installations/%d/repositories" % installation["id"], token, query={"per_page": 100, "page": page})
                batch = data.get("repositories") if isinstance(data, dict) else None
                if not isinstance(batch, list):
                    raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
                for item in batch:
                    summary = repository_summary(item)
                    if summary is not None and summary["id"] not in seen:
                        if len(repositories) >= MAX_LISTED_REPOSITORIES:
                            truncated = True
                            break
                        seen.add(summary["id"])
                        repositories.append(summary)
                total = data.get("total_count")
                if len(batch) < 100 or not isinstance(total, int) or page * 100 >= total:
                    break
                page += 1
        repositories.sort(key=lambda r: r["full_name"].lower())
        return repositories, truncated

    def get_repository(self, token: str, repository_id: int) -> Dict[str, Any]:
        summary = repository_summary(self._api_get("/repositories/%d" % repository_id, token))
        if summary is None or summary["id"] != repository_id:
            raise GitHubError("repository_not_accessible", "the repository is not accessible with this GitHub connection", 404)
        return summary

    def list_branches(self, token: str, full_name: str) -> Tuple[List[Dict[str, str]], bool]:
        data = self._api_get(_repo_path(full_name) + "/branches", token, query={"per_page": MAX_LISTED_BRANCHES})
        if not isinstance(data, list):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        branches = []
        for item in data:
            name = item.get("name") if isinstance(item, dict) else None
            sha = (item.get("commit") or {}).get("sha") if isinstance(item, dict) and isinstance(item.get("commit"), dict) else None
            try:
                branches.append({"name": validate_branch_name(name), "commit_sha": validate_commit_sha(sha)})
            except GitHubError:
                continue   # a branch name this backend cannot address safely is simply not offered
        return branches, len(data) >= MAX_LISTED_BRANCHES

    def branch_head(self, token: str, full_name: str, branch: str) -> str:
        """The commit a branch points to right now, by exact ref."""
        path = _repo_path(full_name) + "/git/ref/heads/" + quote(validate_branch_name(branch), safe="/")
        data = self._api_get(path, token, not_found=("ref_not_found", "the branch does not exist in this repository"))
        obj = data.get("object") if isinstance(data, dict) else None
        if not isinstance(obj, dict) or data.get("ref") != "refs/heads/" + branch or obj.get("type") != "commit":
            raise GitHubError("ref_not_found", "the branch does not exist in this repository", 404)
        return validate_commit_sha(obj.get("sha"))

    def commit_is_on_branch(self, token: str, full_name: str, commit_sha: str, branch_head_sha: str) -> bool:
        if commit_sha == branch_head_sha:
            return True
        data = self._api_get(_repo_path(full_name) + "/compare/%s...%s" % (commit_sha, branch_head_sha), token, query={"per_page": 1},
                             max_bytes=MAX_COMPARE_RESPONSE_BYTES, not_found=("commit_not_found", "the commit does not exist in this repository"))
        return isinstance(data, dict) and data.get("status") in ("identical", "ahead")

    def commit_tree_sha(self, token: str, full_name: str, commit_sha: str) -> str:
        data = self._api_get(_repo_path(full_name) + "/git/commits/" + commit_sha, token,
                             not_found=("commit_not_found", "the commit does not exist in this repository"))
        tree = data.get("tree") if isinstance(data, dict) else None
        if not isinstance(tree, dict) or data.get("sha") != commit_sha:
            raise GitHubError("commit_not_found", "the commit does not exist in this repository", 404)
        return validate_commit_sha(tree.get("sha"))

    def tree(self, token: str, full_name: str, tree_sha: str) -> List[Dict[str, Any]]:
        try:
            data = self._api_get(_repo_path(full_name) + "/git/trees/" + tree_sha, token, query={"recursive": "1"}, max_bytes=MAX_TREE_RESPONSE_BYTES,
                                 not_found=("commit_not_found", "the commit does not exist in this repository"))
        except GitHubError as exc:
            if exc.code == "github_response_too_large":
                raise GitHubError("repository_too_large", "the repository has too many files to scan from GitHub", 413)
            raise
        entries = data.get("tree") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        if data.get("truncated") or len(entries) > MAX_TREE_ENTRIES:
            raise GitHubError("repository_too_large", "the repository has more than %d paths; scan a smaller repository or upload a ZIP" % MAX_TREE_ENTRIES, 413)
        return entries

    def blob(self, token: str, full_name: str, blob_sha: str, declared_size: int) -> bytes:
        data = self._api_get(_repo_path(full_name) + "/git/blobs/" + blob_sha, token, max_bytes=declared_size * 3 // 2 + 8192,   # base64 (4/3) + JSON-escaped newline every 60 chars + envelope
                             not_found=("commit_not_found", "a file of the commit could not be read"))
        if not isinstance(data, dict) or data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        try:
            content = base64.b64decode(data["content"].replace("\n", ""), validate=True)
        except (binascii.Error, ValueError):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        if git_blob_sha(content) != blob_sha:
            raise GitHubError("github_unavailable", "a file did not match its commit (integrity check failed)", 502)
        return content


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(content) + content).hexdigest()


def _retry_after(headers: Dict[str, str]) -> int:
    try:
        if headers.get("retry-after"):
            return max(1, min(3600, int(headers["retry-after"])))
        if headers.get("x-ratelimit-reset"):
            reset = int(headers["x-ratelimit-reset"]) - int(datetime.now(timezone.utc).timestamp())
            return max(1, min(3600, reset))
    except ValueError:
        pass
    return 60


def repository_summary(item: Any) -> Optional[Dict[str, Any]]:
    """The fields the product shows for one repository, from GitHub's own
    response (never from the client)."""
    if not isinstance(item, dict) or not isinstance(item.get("id"), int) or isinstance(item.get("id"), bool):
        return None
    try:
        full_name = _validated_full_name(item.get("full_name"))
    except GitHubError:
        return None
    owner = item.get("owner") if isinstance(item.get("owner"), dict) else {}
    default_branch = item.get("default_branch")
    try:
        default_branch = validate_branch_name(default_branch)
    except GitHubError:
        default_branch = None
    return {"id": item["id"], "owner": owner.get("login") if isinstance(owner.get("login"), str) else full_name.split("/")[0],
            "name": full_name.split("/")[1], "full_name": full_name, "private": bool(item.get("private")), "default_branch": default_branch}


# ---------------------------------------------------------------------------
# Repository -> D-109 entries
# ---------------------------------------------------------------------------

def _wanted(path: str) -> bool:
    """Whether D-109's policy would read this file's bytes (a kept source or
    document with a safe path); everything else is passed as None and never
    downloaded. submission_input re-applies the full policy either way."""
    if submission_input.classify(path) == submission_input.KIND_IGNORED:
        return False
    return all(submission_input._SAFE_SEGMENT_RE.match(segment) for segment in path.split("/"))


def fetch_repository_entries(client: GitHubClient, token: str, full_name: str, commit_sha: str, max_source_bytes: int) -> List[Tuple[str, Optional[bytes]]]:
    """Every path of the commit's tree for submission_input.
    from_repository_entries(): kept files with their bytes (verified against
    their git blob SHA), everything else None. Symlinks and submodules are
    never resolved or followed - they are listed as ignored paths. Path,
    count and size limits are checked on the tree BEFORE any download."""
    entries = client.tree(token, full_name, client.commit_tree_sha(token, full_name, commit_sha))
    plan: List[Tuple[str, Optional[Tuple[str, int]]]] = []
    budget = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
        if entry.get("type") == "tree":
            continue
        path = entry["path"]
        submission_input.check_path(path)   # D-109 path safety for every entry, before anything is downloaded
        regular = entry.get("type") == "blob" and entry.get("mode") in ("100644", "100755")
        if regular and _wanted(path):
            size, sha = entry.get("size"), entry.get("sha")
            if not isinstance(size, int) or size < 0 or not isinstance(sha, str) or not _COMMIT_SHA_RE.match(sha):
                raise GitHubError("github_unavailable", "GitHub returned an unexpected response", 502)
            budget += size
            plan.append((path, (sha, size)))
        else:
            plan.append((path, None))
    wanted = [item for item in plan if item[1] is not None]
    if len(wanted) > submission_input.MAX_SUBMISSION_FILES:
        raise submission_input.SubmissionInputError("too_many_files", "%d files would be analysed; at most %d per scan" % (len(wanted), submission_input.MAX_SUBMISSION_FILES), 413)
    if budget > max_source_bytes:
        raise submission_input.SubmissionInputError("submission_too_large", "the files exceed the maximum submission size (%d bytes)" % max_source_bytes, 413)
    contents: Dict[str, bytes] = {}
    if wanted:
        with ThreadPoolExecutor(max_workers=min(FETCH_CONCURRENCY, len(wanted))) as pool:
            futures = {path: pool.submit(client.blob, token, full_name, spec[0], spec[1]) for path, spec in wanted}
            try:
                for path, future in futures.items():
                    contents[path] = future.result()
            except Exception:
                for future in futures.values():
                    future.cancel()
                raise
    return [(path, contents.get(path) if spec is not None else None) for path, spec in plan]


# ---------------------------------------------------------------------------
# Connection tokens (database <-> GitHub)
# ---------------------------------------------------------------------------

class GitHubIntegration:
    """What backend/http_app.py is given when Private GitHub is configured:
    the client plus the token cipher. Built by backend/main.py from the
    GITHUB_* environment variables; tests build it with a fake transport."""

    def __init__(self, config: GitHubConfig, transport: Optional[Any] = None) -> None:
        self.config = config
        self.client = GitHubClient(config, transport)
        self.cipher = TokenCipher(config.token_key)

    def new_state(self) -> Tuple[str, str]:
        """(state for the authorize URL, its SHA-256 for the database)."""
        state = secrets.token_urlsafe(32)
        return state, state_hash(state)

    def encrypted_token_fields(self, workspace_id: str, user_id: str, grant: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        def expiry(key: str) -> Optional[str]:
            value = grant.get(key)
            return (now + timedelta(seconds=value)).isoformat() if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
        refresh = grant.get("refresh_token") if isinstance(grant.get("refresh_token"), str) and grant.get("refresh_token") else None
        return {
            "access_token_enc": self.cipher.encrypt(grant["access_token"], token_associated_data(workspace_id, user_id, "access")),
            "access_token_expires_at": expiry("expires_in"),
            "refresh_token_enc": self.cipher.encrypt(refresh, token_associated_data(workspace_id, user_id, "refresh")) if refresh else None,
            "refresh_token_expires_at": expiry("refresh_token_expires_in") if refresh else None,
        }

    def access_token(self, conn: Any, connection: Dict[str, Any], now: Optional[datetime] = None) -> str:
        """A usable access token for this connection, refreshing it first
        when it is about to expire. An unusable connection is marked invalid
        (tokens wiped) and github_reconnect_required is raised."""
        now = now or datetime.now(timezone.utc)
        ws, user = connection["workspace_id"], connection["user_id"]
        expires_at = repo._parse_iso(connection.get("access_token_expires_at"))
        if expires_at is None or expires_at - timedelta(seconds=TOKEN_REFRESH_SKEW_SECONDS) > now:
            return self.cipher.decrypt(connection["access_token_enc"], token_associated_data(ws, user, "access"))
        refresh_expires = repo._parse_iso(connection.get("refresh_token_expires_at"))
        if not connection.get("refresh_token_enc") or (refresh_expires is not None and refresh_expires <= now):
            repo.set_github_connection_status(conn, ws, connection["id"], "invalid")
            raise GitHubError("github_reconnect_required", "the GitHub connection expired; connect GitHub again", 409)
        try:
            grant = self.client.refresh(self.cipher.decrypt(connection["refresh_token_enc"], token_associated_data(ws, user, "refresh")))
        except GitHubError as exc:
            if exc.code not in ("github_authorization_failed", "github_reconnect_required"):
                raise
            # Refresh tokens are single-use: a concurrent request may already
            # have rotated this one. Use its result when it did.
            latest = repo.get_github_connection(conn, ws, connection["id"])
            if latest and latest["status"] == "active" and latest["access_token_enc"] != connection["access_token_enc"]:
                latest_exp = repo._parse_iso(latest.get("access_token_expires_at"))
                if latest_exp is None or latest_exp > now:
                    return self.cipher.decrypt(latest["access_token_enc"], token_associated_data(ws, user, "access"))
            repo.set_github_connection_status(conn, ws, connection["id"], "invalid")
            raise GitHubError("github_reconnect_required", "the GitHub connection expired; connect GitHub again", 409)
        fields = self.encrypted_token_fields(ws, user, grant, now)
        if fields["refresh_token_enc"] is None:   # GitHub kept the old refresh token
            fields["refresh_token_enc"] = connection["refresh_token_enc"]
            fields["refresh_token_expires_at"] = connection.get("refresh_token_expires_at")
        repo.update_github_connection_tokens(conn, ws, connection["id"], **fields)
        return grant["access_token"]


def state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def resolve_scan_commit(client: GitHubClient, token: str, repository_id: int, ref: Optional[str], commit_sha: Optional[str]) -> Dict[str, Any]:
    """Repository (validated by id against GitHub and this connection), the
    branch (the repository's default branch when none is given) and the
    exact commit to analyse: the branch head, or a given commit_sha only if
    it is on that branch. Never 'latest' at analysis time - the returned SHA
    is what is fetched and recorded."""
    repository = client.get_repository(token, repository_id)
    branch = validate_branch_name(ref) if ref is not None else repository["default_branch"]
    if not branch:
        raise GitHubError("ref_not_found", "the repository has no default branch", 404)
    head = client.branch_head(token, repository["full_name"], branch)
    if commit_sha is None:
        sha = head
    else:
        sha = validate_commit_sha(commit_sha)
        if not client.commit_is_on_branch(token, repository["full_name"], sha, head):
            raise GitHubError("commit_not_on_ref", "the commit is not part of the selected branch", 409)
    return {"repository": repository, "ref": branch, "commit_sha": sha}
