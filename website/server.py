#!/usr/bin/env python3
"""Stateless HTTP endpoint connecting the website to the existing analyzer
API (V2.12, docs/decisiones.md D-067, capability W-03).

STATELESS ONLY: no database, no sessions, no accounts, no stored project/
report history. Every request is fully self-contained - report content
arrives in the request body and the result leaves in the response body;
nothing about either is retained once the response is sent. The ONE piece
of in-process state this module holds is the rate limiter's short-lived hit
counters (see _RateLimiter) - never persisted to disk, reset on restart,
and required by V2.12's own explicit rule that this endpoint enforce its
own rate/abuse limits.

Wraps api.py (V2.11) UNCHANGED - render_markdown/render_html/validate_report/
diff_reports/diff_preprocess are called exactly as they already exist; this
module contains no preprocessing, scoring, validation, diffing or rendering
logic of its own, and adds no detector.

Capafy owns auth, billing, tiers and execution. This endpoint implements
NONE of that: there is no login, no payment, no per-user quota - only a
flat, anonymous, per-IP rate limit against abuse of a public endpoint.

Resource governance is this wrapper's job (api.py's own docstring already
anticipates this): a request body over MAX_BODY_BYTES is rejected before
being read into memory, and a per-connection socket timeout bounds a slow/
stalled client. Behind a reverse proxy, forwarding the true client IP for
rate-limiting (vs. the proxy's own address) is that deployment's
responsibility, not something this module guesses at from a client-supplied
header - trusting a client-supplied X-Forwarded-For value would let an
attacker defeat the rate limit simply by varying it per request.

Standard library only (http.server). No database, no LLM calls, no
credentials. Python 3.8+.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SCRIPTS_DIR = os.path.join(REPO_ROOT, ".claude", "skills", "web3-auditor", "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import api  # noqa: E402 - the V2.11 facade, UNCHANGED

SERVER_VERSION = "2026.1"

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB - generous for a JSON report, bounds per-request memory use.
REQUEST_TIMEOUT_SECONDS = 10  # bounds how long a single slow/stalled client can hold a connection.

RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_MAX_REQUESTS = 30  # per client IP, per window.

# Empty (default) = no Access-Control-Allow-Origin header is sent, so only
# same-origin requests succeed in a browser. Set to the website's own
# origin if the frontend is served from a different origin than this API.
ALLOWED_ORIGIN = os.environ.get("WEBSITE_ALLOWED_ORIGIN", "")

_ALLOWED_PATHS = ("/api/render", "/api/validate", "/api/diff")


class _RateLimiter:
    """In-memory, per-process, per-client-IP sliding window counter. NEVER
    persisted to disk, NEVER a database - resets on process restart. This is
    the one piece of short-lived state this stateless endpoint is explicitly
    required to hold."""

    def __init__(self, window_seconds: float, max_requests: int) -> None:
        self._window = window_seconds
        self._max = max_requests
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._hits.get(client_id, []) if now - t < self._window]
            if len(recent) >= self._max:
                self._hits[client_id] = recent
                return False
            recent.append(now)
            self._hits[client_id] = recent
            return True


_rate_limiter = _RateLimiter(RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_REQUESTS)


def _require_dict(value: Any, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("%s must be a JSON object" % name)
    return value


def handle_render(payload: Any) -> Dict[str, Any]:
    payload = _require_dict(payload, "request body")
    report = _require_dict(payload.get("report"), "report")
    fmt = payload.get("format", "markdown")
    if fmt not in ("markdown", "html"):
        raise ValueError("format must be 'markdown' or 'html'")
    rendered = api.render_html(report) if fmt == "html" else api.render_markdown(report)
    return {"ok": True, "format": fmt, "rendered": rendered}


def handle_validate(payload: Any) -> Dict[str, Any]:
    payload = _require_dict(payload, "request body")
    errors = api.validate_report(payload.get("report"))
    return {"ok": True, "reportStatus": "valid" if not errors else "invalid", "errors": errors}


def handle_diff(payload: Any) -> Dict[str, Any]:
    payload = _require_dict(payload, "request body")
    v1 = payload.get("v1")
    v2 = payload.get("v2")
    mode = payload.get("mode", "reports")
    if mode == "preprocess":
        result = api.diff_preprocess(v1, v2)
    elif mode == "reports":
        result = api.diff_reports(v1, v2)
    else:
        raise ValueError("mode must be 'reports' or 'preprocess'")
    return {"ok": True, "diff": result}


_ROUTES = {
    "/api/render": handle_render,
    "/api/validate": handle_validate,
    "/api/diff": handle_diff,
}

# Every exception a route handler above can actually raise, either directly
# (ValueError from this module's own validation) or from the underlying
# api.py call it reuses unmodified. A truly unexpected exception is NOT in
# this tuple and falls through to the generic 500 handler below, which
# never echoes the exception text back to the client.
_KNOWN_EXCEPTIONS = (
    ValueError,
    api.DiffError,
    api.ReportRenderError,
    api.ReportValidationError,
    api.ModesConfigError,
)


def _error_body(message: str) -> bytes:
    return json.dumps({"ok": False, "error": message}, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "web3-auditor-website/%s" % SERVER_VERSION
    timeout = REQUEST_TIMEOUT_SECONDS

    def _client_id(self) -> str:
        return self.client_address[0]

    def _send_json_bytes(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        # No GET route exists anywhere on this server - it never serves a
        # file from disk and never reflects a query parameter.
        self._send_json_bytes(404, _error_body("not found"))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        if ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in _ALLOWED_PATHS:
            self._send_json_bytes(404, _error_body("not found"))
            return
        if not _rate_limiter.allow(self._client_id()):
            self._send_json_bytes(429, _error_body("rate limit exceeded - try again later"))
            return

        length_header = self.headers.get("Content-Length")
        try:
            content_length = int(length_header) if length_header is not None else -1
        except ValueError:
            content_length = -1
        if content_length < 0:
            # Bailing out here means the client's body (if any) is never
            # read - force-close rather than keep-alive, or its unread
            # bytes would be misread as the start of the next request on
            # a reused connection.
            self.close_connection = True
            self._send_json_bytes(400, _error_body("a valid Content-Length header is required"))
            return
        if content_length > MAX_BODY_BYTES:
            # Same reasoning: rejecting before reading an oversized body is
            # the whole point (never buffer an attacker-controlled body
            # just to discard it), so this connection can never be reused
            # safely either.
            self.close_connection = True
            self._send_json_bytes(413, _error_body("request body too large"))
            return

        raw = self.rfile.read(content_length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json_bytes(400, _error_body("request body is not valid UTF-8 JSON"))
            return

        try:
            result = _ROUTES[path](payload)
        except _KNOWN_EXCEPTIONS as exc:
            self._send_json_bytes(400, _error_body(str(exc)))
            return
        except Exception:
            # Defense in depth: a genuinely unexpected bug never reaches the
            # client as raw exception text (which could leak an internal
            # path or detail) - see D-056-style narrow-exception discipline
            # applied to a public HTTP boundary instead of a caught import.
            self._send_json_bytes(500, _error_body("internal error"))
            return

        self._send_json_bytes(200, json.dumps(result, ensure_ascii=False).encode("utf-8"))


def run_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    return server


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="server.py", description="Stateless render/validate/diff HTTP endpoint over api.py (V2.12, W-03).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    server = run_server(args.host, args.port)
    print("web3-auditor website API listening on http://%s:%d" % (args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
