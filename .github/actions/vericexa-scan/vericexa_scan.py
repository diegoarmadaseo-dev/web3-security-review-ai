#!/usr/bin/env python3
"""Vericexa GitHub Action client (docs/decisiones.md D-114).

A thin client of the Vericexa Private API (D-113): it collects the Solidity /
Vyper files of the workflow's checkout, submits them to POST /api/v1/scans
(the same endpoint, admission, queue, worker and report pipeline as every
other scan), polls the job, reads the scored report and publishes the result
to GitHub (job summary, annotations, outputs and, when a token with
checks:write is given, a Check Run). It never analyses anything itself: no LOC
counting, admission, detectors or report generation happen here.

Exit codes (stable, documented in docs/github-actions.md):
  0  scan completed and the security gate passed (or the gate is disabled),
     or the run was skipped (fork pull request without the secret);
  1  scan completed and the security gate FAILED (blocking findings);
  2  execution / API / configuration error (invalid or revoked key, plan
     without GitHub Actions, quota, pending jobs, technical budget, invalid
     input, scan failed, timeout, Vericexa unreachable).
Findings are never reported as an API failure, and an API failure is never
reported as findings.

Security:
- The Vericexa key (VERICEXA_API_KEY, a GitHub Actions secret) is sent ONLY
  to VERICEXA_API_URL (https; plain http only for a localhost test server),
  with redirects disabled. The GitHub token is sent ONLY to GITHUB_API_URL.
  Neither is ever printed: every output line is passed through a redactor.
- Repository content is data: file names, finding text and server messages
  are sanitized before reaching the log (no line can start a workflow
  command), the job summary (Markdown/HTML escaped) or annotations
  (workflow-command escaped). Nothing from the repository or the event is
  ever executed; the only subprocess is `git rev-parse HEAD` with fixed
  arguments.
- Symlinks are never followed; only regular .sol/.vy files under the
  scanned path are read; .git, node_modules, hidden directories and the
  configured dependency/output directories are skipped. Source code is never
  printed.

Standard library only (Python 3.8+), so it runs on any GitHub-hosted runner.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "1.0.0"
EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2

SOURCE_EXTENSIONS = (".sol", ".vy")
ALWAYS_SKIPPED_DIRECTORIES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "__MACOSX"})   # D-109's ignored set
DEFAULT_EXCLUDE = "lib,out,cache,artifacts,build,coverage"
SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._@+\-]{1,128}$")     # D-109: other segments are ignored by the server anyway
MAX_FILES = 500                                                  # D-109 MAX_SUBMISSION_FILES
MAX_TOTAL_BYTES = 2 * 1024 * 1024                                # D-109/D-113 MAX_RAW_SOURCE_BYTES
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
POLL_INITIAL_SECONDS = 5.0
POLL_MAX_SECONDS = 30.0
POLL_FACTOR = 1.5
SUBMIT_ATTEMPTS = 4
MAX_RETRY_AFTER_SECONDS = 120
MAX_TRANSIENT_POLL_ERRORS = 6
CHECK_RUN_NAME = "Vericexa automated review"
NO_FINDINGS_TEXT = "No findings matching the configured detection criteria were identified within the analyzed scope."
INDICATOR_TEXT = "This indicator reflects findings detected within the analyzed scope. It is not a measure of overall protocol security."
LOW_BAND_TEXT = "A LOW automated risk indicator does not mean that deployment is safe."
NOT_AN_AUDIT_TEXT = "Automated AI-assisted smart contract security review. This is NOT a formal security audit."


class ActionError(Exception):
    """An execution/API/configuration error (exit code 2)."""

    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


class TransportError(Exception):
    """The HTTP request could not be completed (network, TLS, timeout, redirect)."""


# ---------------------------------------------------------------------------
# Sanitizing untrusted text
# ---------------------------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f  ]")


def clean(text: Any, limit: int = 300) -> str:
    """One safe line: control characters (CR/LF included) removed and
    length bounded, so untrusted text can never start a new log line - and
    therefore never a GitHub workflow command."""
    value = _CONTROL_RE.sub(" ", str(text if text is not None else ""))
    return value if len(value) <= limit else value[:limit] + "..."


def md(text: Any, limit: int = 300) -> str:
    """Untrusted text for the Markdown job summary / Check Run body: HTML
    escaped and Markdown control characters backslash-escaped."""
    value = html.escape(clean(text, limit), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+!|~>-])", r"\\\1", value)


def command_value(text: Any) -> str:
    """Escaping for the data part of a workflow command (::error::...)."""
    return clean(text, 500).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class Logger:
    def __init__(self, out: Any, secrets: List[str]):
        self.out = out
        self.secrets = [s for s in secrets if s]
        self.outputs_written = False

    def add_secret(self, value: str) -> None:
        if value and len(value) >= 4:
            self.secrets.append(value)

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "***")
        return text

    def info(self, message: str) -> None:
        self.out.write(self.redact("[vericexa] " + clean(message, 2000)) + "\n")

    def command(self, name: str, message: str) -> None:
        """A workflow annotation built by this script (name is a constant)."""
        self.out.write(self.redact("::%s title=Vericexa::%s" % (name, command_value(message))) + "\n")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib signature
        raise TransportError("redirects are not followed (HTTP %s)" % code)


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_request(method: str, url: str, headers: Dict[str, str], body: Optional[bytes] = None, timeout: float = 60.0,
                 max_bytes: int = 32 * 1024 * 1024) -> Tuple[int, Dict[str, str], bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        response = _OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except TransportError:
        raise
    except Exception as exc:
        raise TransportError(type(exc).__name__) from None
    try:
        data = response.read(max_bytes + 1)
    except Exception as exc:
        raise TransportError(type(exc).__name__) from None
    if len(data) > max_bytes:
        raise TransportError("response too large")
    return response.status if hasattr(response, "status") else response.code, {k.lower(): v for k, v in response.headers.items()}, data


def validate_base_url(raw: str) -> str:
    """The Vericexa base URL: https, no credentials/query/fragment. Plain
    http is accepted only for a localhost test server."""
    raw = (raw or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        raise ActionError("VERICEXA_API_URL is not a valid URL", "invalid_configuration")
    if not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ActionError("VERICEXA_API_URL must be a plain https://host[/path] URL", "invalid_configuration")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in LOCAL_HOSTS):
        raise ActionError("VERICEXA_API_URL must use https", "invalid_configuration")
    return raw.rstrip("/")


class VericexaClient:
    def __init__(self, base_url: str, api_key: str, http: Callable[..., Tuple[int, Dict[str, str], bytes]]):
        self.base_url = base_url
        self.api_key = api_key
        self.http = http

    def call(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None, extra_headers: Optional[Dict[str, str]] = None,
             timeout: float = 60.0) -> Tuple[int, Dict[str, str], Any]:
        headers = {"Authorization": "Bearer " + self.api_key, "Accept": "application/json", "User-Agent": "vericexa-github-action/" + VERSION}
        headers.update(extra_headers or {})
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, response_headers, data = self.http(method, self.base_url + path, headers, body, timeout)
        try:
            parsed = json.loads(data.decode("utf-8")) if data else None
        except (UnicodeDecodeError, ValueError):
            parsed = None
        return status, response_headers, parsed


def api_error(status: int, body: Any) -> Tuple[str, str, str]:
    """(code, message, request_id) of a D-113 error envelope."""
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        return clean(error.get("code") or "error", 80), clean(error.get("message") or "", 300), clean(error.get("request_id") or "", 64)
    return "http_%d" % status, "unexpected response from Vericexa", ""


# ---------------------------------------------------------------------------
# GitHub context
# ---------------------------------------------------------------------------

def load_event(env: Dict[str, str]) -> Dict[str, Any]:
    path = env.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def is_fork_pull_request(event: Dict[str, Any]) -> bool:
    pr = event.get("pull_request") or {}
    head_repo = ((pr.get("head") or {}).get("repo") or {})
    base_repo = event.get("repository") or {}
    return bool(head_repo.get("fork")) or (bool(head_repo.get("full_name")) and head_repo.get("full_name") != base_repo.get("full_name"))


def checked_out_sha(workspace: str, fallback: str) -> str:
    """The exact commit of the checkout (git rev-parse HEAD, fixed
    arguments), else GITHUB_SHA."""
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=workspace, capture_output=True, text=True, timeout=15, check=False)
        sha = result.stdout.strip().lower()
        if result.returncode == 0 and SHA_RE.match(sha):
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    fallback = (fallback or "").strip().lower()
    if SHA_RE.match(fallback):
        return fallback
    raise ActionError("could not determine the commit SHA of the checkout", "invalid_configuration")


def idempotency_key(repository: str, run_id: str, event_name: str, sha: str) -> str:
    """Stable per workflow run: a re-run (new run_attempt) of the same run
    reuses the same scan instead of creating (and paying for) another."""
    key = "gha:%s:%s:%s:%s" % (repository, run_id, event_name, sha)
    return key if len(key) <= 200 else "gha:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def collect_files(workspace: str, scan_path: str, exclude: List[str], log: Logger) -> List[Dict[str, str]]:
    root_real = os.path.realpath(workspace)
    target = os.path.realpath(os.path.join(workspace, scan_path or "."))
    if os.path.commonpath([root_real, target]) != root_real or not os.path.isdir(target):
        raise ActionError("the path input must be a directory inside the checkout", "invalid_configuration")
    excluded = {e.strip().strip("/") for e in exclude if e.strip()}
    files: List[Dict[str, str]] = []
    skipped_unsafe = skipped_links = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        rel_dir = os.path.relpath(dirpath, target).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for name in sorted(dirnames):
            rel = (rel_dir + "/" + name) if rel_dir else name
            full = os.path.join(dirpath, name)
            if name in ALWAYS_SKIPPED_DIRECTORIES or name.startswith(".") or name in excluded or rel in excluded or os.path.islink(full):
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            if not name.lower().endswith(SOURCE_EXTENSIONS):
                continue
            full = os.path.join(dirpath, name)
            rel = (rel_dir + "/" + name) if rel_dir else name
            if os.path.islink(full) or not os.path.isfile(full):
                skipped_links += 1
                continue
            if not all(SAFE_SEGMENT_RE.match(segment) for segment in rel.split("/")):
                skipped_unsafe += 1
                continue
            with open(full, "rb") as handle:
                data = handle.read(MAX_TOTAL_BYTES + 1)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ActionError("the source files exceed the %d-byte submission limit; narrow the path or exclude inputs" % MAX_TOTAL_BYTES, "submission_too_large")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                raise ActionError("a source file is not valid UTF-8 text: %s" % clean(rel, 200), "file_not_utf8")
            files.append({"path": rel, "content": text})
            if len(files) > MAX_FILES:
                raise ActionError("more than %d source files; narrow the path or exclude inputs" % MAX_FILES, "too_many_files")
    if skipped_links:
        log.info("skipped %d symbolic link(s) or non-regular file(s)" % skipped_links)
    if skipped_unsafe:
        log.info("skipped %d file(s) whose path has characters outside A-Z a-z 0-9 . _ @ + -" % skipped_unsafe)
    if not files:
        raise ActionError("no Solidity (.sol) or Vyper (.vy) source file was found in the scanned path", "no_source_files")
    return files


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def parse_policy(blocking: str, min_confidence: str) -> Tuple[List[str], Optional[str]]:
    severities = [s.strip().upper() for s in (blocking or "").split(",") if s.strip()]
    unknown = [s for s in severities if s not in SEVERITIES]
    if unknown:
        raise ActionError("blocking-severities may only contain %s" % ", ".join(SEVERITIES), "invalid_configuration")
    confidence = (min_confidence or "").strip().lower() or None
    if confidence is not None and confidence not in CONFIDENCE_RANK:
        raise ActionError("min-confidence must be low, medium or high", "invalid_configuration")
    return severities, confidence


def evaluate(report: Dict[str, Any], blocking: List[str], min_confidence: Optional[str]) -> Dict[str, Any]:
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    counts = {s: 0 for s in SEVERITIES}
    blocking_findings = []
    for finding in findings:
        severity = str(finding.get("severity") or "").upper()
        if severity in counts:
            counts[severity] += 1
        if finding.get("status") == "informational" or severity not in blocking:
            continue
        if min_confidence and CONFIDENCE_RANK.get(str(finding.get("confidence") or "").lower(), 0) < CONFIDENCE_RANK[min_confidence]:
            continue
        blocking_findings.append(finding)
    risk = report.get("riskIndicator") if isinstance(report.get("riskIndicator"), dict) else {}
    return {"counts": counts, "total": len(findings), "blocking": blocking_findings, "band": risk.get("band"), "score": risk.get("score"),
            "score_status": risk.get("scoreStatus") or report.get("scoreStatus"), "passed": not blocking_findings}


def finding_location(finding: Dict[str, Any]) -> str:
    locations = finding.get("locations") if isinstance(finding.get("locations"), list) else []
    first = locations[0] if locations and isinstance(locations[0], dict) else {}
    if first.get("file"):
        return "%s:%s" % (first.get("file"), first.get("lineStart") or first.get("line") or "?")
    return ""


# ---------------------------------------------------------------------------
# GitHub outputs
# ---------------------------------------------------------------------------

class GitHubPublisher:
    """Job summary, step outputs and (optionally) a Check Run."""

    def __init__(self, env: Dict[str, str], log: Logger, http: Callable[..., Tuple[int, Dict[str, str], bytes]], token: str,
                 repository: str, sha: str, can_write: bool):
        self.env, self.log, self.http, self.token = env, log, http, token
        self.repository, self.sha = repository, sha
        self.api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.check_run_id: Optional[int] = None
        self.enabled = bool(token) and can_write

    def _github(self, method: str, path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "Content-Type": "application/json", "User-Agent": "vericexa-github-action/" + VERSION}
        try:
            status, _, data = self.http(method, self.api + path, headers, json.dumps(payload).encode("utf-8"), 30.0)
        except TransportError as exc:
            self.log.info("GitHub Check Run not published (%s)" % exc)
            return None
        if status >= 300:
            self.log.info("GitHub Check Run not published (HTTP %d - the token needs checks: write; fork pull requests get a read-only token)" % status)
            self.enabled = False
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def start_check(self, details_url: Optional[str]) -> None:
        if not self.enabled:
            return
        payload = {"name": CHECK_RUN_NAME, "head_sha": self.sha, "status": "in_progress"}
        if details_url:
            payload["details_url"] = details_url
        created = self._github("POST", "/repos/%s/check-runs" % self.repository, payload)
        if isinstance(created, dict) and isinstance(created.get("id"), int):
            self.check_run_id = created["id"]

    def finish_check(self, conclusion: str, title: str, summary: str, details_url: Optional[str]) -> None:
        if not self.enabled:
            return
        payload: Dict[str, Any] = {"name": CHECK_RUN_NAME, "head_sha": self.sha, "status": "completed", "conclusion": conclusion,
                                   "output": {"title": title[:250], "summary": summary[:60000]}}
        if details_url:
            payload["details_url"] = details_url
        if self.check_run_id is not None:
            self._github("PATCH", "/repos/%s/check-runs/%d" % (self.repository, self.check_run_id), payload)
        else:
            self._github("POST", "/repos/%s/check-runs" % self.repository, payload)

    def write_summary(self, text: str) -> None:
        path = self.env.get("GITHUB_STEP_SUMMARY")
        if path:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(self.log.redact(text) + "\n")

    def write_outputs(self, outputs: Dict[str, Any]) -> None:
        path = self.env.get("GITHUB_OUTPUT")
        if not path:
            return
        self.log.outputs_written = True
        with open(path, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write("%s=%s\n" % (key, self.log.redact(clean("" if value is None else value, 500))))


def render_summary(result: Dict[str, Any]) -> str:
    lines = ["## Vericexa automated review", "", "_%s_" % NOT_AN_AUDIT_TEXT, ""]
    lines.append("**Result:** %s" % md(result["headline"]))
    lines.append("")
    if result.get("commit_sha"):
        lines.append("- Commit: `%s` (%s)" % (result["commit_sha"], md(result.get("event") or "")))
    if result.get("job_url"):
        lines.append("- Vericexa scan: %s" % md(result["job_url"], 500))
    if result.get("report_url"):
        lines.append("- Report: %s" % md(result["report_url"], 500))
    evaluation = result.get("evaluation")
    if evaluation:
        lines.append("- Automated Risk Indicator: %s%s" % (md(evaluation.get("band") or "not computed"),
                                                           " (score %s)" % md(evaluation["score"]) if evaluation.get("score") is not None else ""))
        lines += ["", "| Severity | Findings |", "|---|---|"]
        lines += ["| %s | %d |" % (s, evaluation["counts"][s]) for s in SEVERITIES]
        lines.append("")
        if evaluation["total"] == 0:
            lines.append(NO_FINDINGS_TEXT)
        if evaluation["blocking"]:
            lines += ["", "**Blocking findings (%d):**" % len(evaluation["blocking"]), ""]
            for finding in evaluation["blocking"][:20]:
                lines.append("- %s %s %s %s" % (md(finding.get("severity")), md(finding.get("category")), md(finding.get("id")), md(finding_location(finding))))
        lines += ["", INDICATOR_TEXT]
        if evaluation.get("band") == "LOW":
            lines.append(LOW_BAND_TEXT)
    if result.get("policy"):
        lines += ["", "Security gate: %s" % md(result["policy"])]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def run(env: Dict[str, str], log: Logger, http: Callable[..., Tuple[int, Dict[str, str], bytes]], sleep: Callable[[float], None],
        monotonic: Callable[[], float]) -> int:
    event_name = env.get("GITHUB_EVENT_NAME", "")
    if event_name == "pull_request_target":
        raise ActionError("pull_request_target is not supported: it would run with secrets on untrusted pull request code. Use pull_request.", "unsupported_event")
    if event_name not in ("push", "pull_request"):
        raise ActionError("unsupported event %s: use push or pull_request" % clean(event_name, 60), "unsupported_event")
    event = load_event(env)
    fork = event_name == "pull_request" and is_fork_pull_request(event)
    api_key = env.get("VERICEXA_API_KEY", "").strip()
    github_token = env.get("INPUT_GITHUB_TOKEN", "").strip()
    log.add_secret(api_key)
    log.add_secret(github_token)
    publisher_outputs: Dict[str, Any] = {"result": "error", "exit-code": EXIT_ERROR}
    if not api_key:
        if fork:
            log.info("skipped: GitHub does not give repository secrets to workflows triggered by pull requests from forks, so no scan was submitted.")
            out_publisher = GitHubPublisher(env, log, http, "", "", "", False)
            out_publisher.write_summary("## Vericexa automated review\n\nSkipped: pull request from a fork (no secrets are available to this workflow).")
            out_publisher.write_outputs({"result": "skipped", "exit-code": EXIT_OK})
            return EXIT_OK
        raise ActionError("the VERICEXA_API_KEY secret is not set (store a Vericexa Private API key as a repository secret)", "missing_api_key")
    base_url = validate_base_url(env.get("VERICEXA_API_URL", ""))
    repository = env.get("GITHUB_REPOSITORY", "")
    if not REPOSITORY_RE.match(repository):
        raise ActionError("GITHUB_REPOSITORY is not a valid owner/name", "invalid_configuration")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "1") or "1"
    if not run_id.isdigit() or not run_attempt.isdigit():
        raise ActionError("GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT are missing", "invalid_configuration")
    workspace = env.get("GITHUB_WORKSPACE") or os.getcwd()
    sha = checked_out_sha(workspace, env.get("GITHUB_SHA", ""))
    pr_number = None
    ref = env.get("GITHUB_REF") or None
    if event_name == "pull_request":
        pr_number = (event.get("pull_request") or {}).get("number") or event.get("number")
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            raise ActionError("the pull_request event payload has no pull request number", "invalid_configuration")
        ref = "refs/pull/%d/head" % pr_number
        head_sha = str(((event.get("pull_request") or {}).get("head") or {}).get("sha") or "").lower()
        if head_sha and head_sha != sha:
            log.info("note: the checkout (%s) is not the pull request head (%s); scanning the checkout. Check out the head SHA to scan the PR commit itself." % (sha, clean(head_sha, 40)))
    if ref is not None and not re.match(r"^[A-Za-z0-9._/+@#=,-]{1,255}$", ref):
        ref = None
    blocking, min_confidence = parse_policy(env.get("INPUT_BLOCKING_SEVERITIES", "CRITICAL,HIGH"), env.get("INPUT_MIN_CONFIDENCE", ""))
    mode = (env.get("INPUT_MODE") or "standard").strip().lower()
    if mode not in ("standard", "pro", "quick"):
        raise ActionError("mode must be quick, standard or pro", "invalid_configuration")
    try:
        timeout_minutes = float(env.get("INPUT_TIMEOUT_MINUTES") or "30")
    except ValueError:
        raise ActionError("timeout-minutes must be a number", "invalid_configuration")
    if not 1 <= timeout_minutes <= 360:
        raise ActionError("timeout-minutes must be between 1 and 360", "invalid_configuration")
    project_id = (env.get("INPUT_PROJECT_ID") or "").strip() or None
    exclude = (env.get("INPUT_EXCLUDE") if env.get("INPUT_EXCLUDE") is not None else DEFAULT_EXCLUDE).split(",")

    files = collect_files(workspace, env.get("INPUT_PATH") or ".", exclude, log)
    log.info("event %s, commit %s, %d source file(s) selected" % (event_name, sha, len(files)))
    client = VericexaClient(base_url, api_key, http)
    publisher = GitHubPublisher(env, log, http, github_token, repository, sha, can_write=not fork)
    policy_text = ("fails on %s findings%s" % ("/".join(blocking), " with confidence >= %s" % min_confidence if min_confidence else "")) if blocking else "disabled (report only)"
    result: Dict[str, Any] = {"commit_sha": sha, "event": event_name + (" #%d" % pr_number if pr_number else ""), "policy": policy_text}
    publisher.start_check(None)

    try:
        payload: Dict[str, Any] = {
            "mode": mode, "files": files, "idempotency_key": idempotency_key(repository, run_id, event_name, sha),
            "ci": {"provider": "github_actions", "repository": repository, "commit_sha": sha, "ref": ref, "event": event_name,
                   "run_id": int(run_id), "run_attempt": int(run_attempt), "pull_request": pr_number},
        }
        if project_id:
            payload["project_id"] = project_id
        job_id = submit(client, payload, log, sleep)
        result["job_url"] = "%s/app#/scans/%s" % (base_url, job_id)
        log.info("scan %s submitted: %s" % (job_id, result["job_url"]))
        job = poll(client, job_id, log, sleep, monotonic, timeout_minutes * 60)
        report_id = (job.get("report") or {}).get("id")
        if not report_id:
            raise ActionError("the scan completed without a report", "report_unavailable")
        result["report_url"] = "%s/app#/reports/%s" % (base_url, report_id)
        status, _, body = client.call("GET", "/api/v1/reports/%s" % urllib.parse.quote(str(report_id), safe=""))
        if status != 200 or not isinstance(body, dict) or not isinstance(body.get("scored_report"), dict):
            code, message, request_id = api_error(status, body)
            raise ActionError("the structured report is not available (%s %s)" % (code, request_id), "report_unavailable")
        evaluation = evaluate(body["scored_report"], blocking, min_confidence)
        result["evaluation"] = evaluation
        counts = ", ".join("%s %d" % (s.lower(), evaluation["counts"][s]) for s in SEVERITIES)
        if evaluation["passed"]:
            result["headline"] = "scan completed - security gate passed" if blocking else "scan completed - security gate disabled"
            code, conclusion = EXIT_OK, "success"
        else:
            result["headline"] = "scan completed - security gate FAILED (%d blocking finding(s))" % len(evaluation["blocking"])
            code, conclusion = EXIT_GATE_FAILED, "failure"
        log.info("%s; findings: %s; automated risk indicator: %s" % (result["headline"], counts, evaluation.get("band") or "not computed"))
        for finding in evaluation["blocking"][:20]:
            log.command("error", "%s %s finding %s %s" % (finding.get("severity"), finding.get("category"), finding.get("id"), finding_location(finding)))
        summary = render_summary(result)
        publisher.write_summary(summary)
        publisher.finish_check(conclusion, result["headline"], summary, result.get("report_url"))
        publisher.write_outputs({"result": "passed" if code == EXIT_OK else "gate_failed", "exit-code": code, "job-id": job_id, "report-id": report_id,
                                 "job-url": result["job_url"], "report-url": result["report_url"], "risk-band": evaluation.get("band"),
                                 "score": evaluation.get("score"), "findings-total": evaluation["total"], "blocking-findings": len(evaluation["blocking"]),
                                 **{"findings-%s" % s.lower(): evaluation["counts"][s] for s in SEVERITIES}})
        return code
    except ActionError as exc:
        result["headline"] = "scan could not be completed - %s (%s)" % (exc, exc.code)
        summary = render_summary(result)
        publisher.write_summary(summary)
        publisher.finish_check("failure", "Vericexa scan could not be completed (%s)" % exc.code, summary, result.get("job_url"))
        publisher_outputs.update({"error-code": exc.code, "job-url": result.get("job_url")})
        publisher.write_outputs(publisher_outputs)
        raise


def submit(client: VericexaClient, payload: Dict[str, Any], log: Logger, sleep: Callable[[float], None]) -> str:
    """POST /api/v1/scans. Retries only what is safe to retry - transport
    errors, 5xx and the D-108 submit rate limit - always with the SAME
    idempotency key, so a retry can never create a second scan."""
    delay = 5.0
    for attempt in range(1, SUBMIT_ATTEMPTS + 1):
        try:
            status, headers, body = client.call("POST", "/api/v1/scans", payload, timeout=120.0)
        except TransportError as exc:
            if attempt == SUBMIT_ATTEMPTS:
                raise ActionError("Vericexa is unreachable (%s)" % clean(exc, 120), "api_unavailable")
            log.info("Vericexa unreachable (%s); retrying in %ds with the same idempotency key" % (clean(exc, 120), delay))
            sleep(delay)
            delay *= 3
            continue
        if status == 200 and isinstance(body, dict) and body.get("job_id"):
            if body.get("duplicate"):
                log.info("this workflow run already submitted scan %s; reusing it (no new scan)" % clean(body["job_id"], 40))
            return str(body["job_id"])
        code, message, request_id = api_error(status, body)
        if (status >= 500 or code == "submit_rate_limited") and attempt < SUBMIT_ATTEMPTS:
            wait = delay
            if code == "submit_rate_limited":
                try:
                    wait = min(MAX_RETRY_AFTER_SECONDS, max(1, int(headers.get("retry-after") or delay)))
                except ValueError:
                    wait = delay
            log.info("Vericexa answered %d %s; retrying in %ds with the same idempotency key" % (status, code, wait))
            sleep(wait)
            delay *= 3
            continue
        raise ActionError("Vericexa refused the scan: %s - %s (HTTP %d%s)" % (code, message, status, ", request %s" % request_id if request_id else ""), code)
    raise ActionError("Vericexa did not accept the scan", "api_unavailable")


def poll(client: VericexaClient, job_id: str, log: Logger, sleep: Callable[[float], None], monotonic: Callable[[], float],
         timeout_seconds: float) -> Dict[str, Any]:
    """GET /api/v1/scans/<id> with backoff (5 s x1.5, capped at 30 s) until
    the job finishes or the timeout expires. A timeout never re-submits:
    re-running the same workflow run resumes the same scan."""
    deadline = monotonic() + timeout_seconds
    interval = POLL_INITIAL_SECONDS
    transient = 0
    last_status = None
    while True:
        try:
            status, _, body = client.call("GET", "/api/v1/scans/%s" % urllib.parse.quote(job_id, safe=""))
        except TransportError as exc:
            status, body = 0, None
            log.info("poll failed (%s)" % clean(exc, 120))
        if status == 200 and isinstance(body, dict) and isinstance(body.get("job"), dict):
            transient = 0
            job_status = body["job"].get("status")
            if job_status != last_status:
                log.info("scan status: %s" % clean(job_status, 30))
                last_status = job_status
            if job_status == "succeeded":
                return body
            if job_status in ("failed", "canceled"):
                raise ActionError("the scan %s on the Vericexa side (no usage is charged for a failed scan)" % job_status, "scan_failed")
        elif status in (401, 402, 403, 404):
            code, message, request_id = api_error(status, body)
            raise ActionError("Vericexa refused the status request: %s - %s" % (code, message), code)
        else:
            transient += 1
            if transient > MAX_TRANSIENT_POLL_ERRORS:
                raise ActionError("Vericexa did not answer the status request %d times in a row" % transient, "api_unavailable")
        if monotonic() + interval > deadline:
            raise ActionError("the scan did not finish within the timeout; re-run this workflow run to keep waiting for the SAME scan", "timeout")
        sleep(interval)
        interval = min(POLL_MAX_SECONDS, interval * POLL_FACTOR)


def main(env: Optional[Dict[str, str]] = None, out: Any = None, http: Optional[Callable[..., Tuple[int, Dict[str, str], bytes]]] = None,
         sleep: Callable[[float], None] = time.sleep, monotonic: Callable[[], float] = time.monotonic) -> int:
    env = dict(os.environ if env is None else env)
    log = Logger(out or sys.stdout, [])
    try:
        return run(env, log, http or http_request, sleep, monotonic)
    except ActionError as exc:
        if not log.outputs_written:   # an error before anything was published (e.g. configuration)
            GitHubPublisher(env, log, http or http_request, "", "", "", False).write_outputs({"result": "error", "exit-code": EXIT_ERROR, "error-code": exc.code})
        log.command("error", "%s (%s)" % (exc, exc.code))
        log.info("exit code %d: execution/API/configuration error - this is NOT a security finding" % EXIT_ERROR)
        return EXIT_ERROR
    except Exception as exc:   # never a traceback with local values in the log
        log.command("error", "unexpected error in the Vericexa action (%s)" % type(exc).__name__)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
