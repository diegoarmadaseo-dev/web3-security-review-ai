#!/usr/bin/env python3
"""Phase 2 identity/access HTTP layer (docs/decisiones.md D-077/D-078
follow-up). Stdlib http.server only, same pattern as website/server.py:
BaseHTTPRequestHandler + a route table, per-client IP taken ONLY from
the socket peer address (self.client_address[0]), never a client-
supplied X-Forwarded-For header (same rule website/server.py documents).

Endpoints: POST /auth/request-link, GET+POST /auth/verify,
POST /auth/logout, POST /workspaces/<id>/members,
DELETE /workspaces/<id>/members/<user_id>. Nothing else - no resource
(project/contract/job/report) endpoints exist yet; that is a later
phase's job, wired against the SAME session/tenant-scope machinery this
module establishes. No workspace-creation endpoint exists yet either
(not in this phase's requested endpoint list) - tests create workspaces
directly via backend.repository.

SCANNER/PREFETCH SAFETY: GET /auth/verify is read-only (backend.auth.
peek_token, never consumes) and renders a confirmation page requiring an
explicit human click; only the resulting POST actually consumes the
token and creates a session. See backend/auth.py's module docstring for
the full reasoning.

HOST HEADER SAFETY: request-link builds the emailed verify URL from the
incoming Host header, so that header's HOSTNAME (the port, if any, is
ignored for the comparison - only the hostname needs to be trusted) is
checked against an explicit, caller-supplied allowlist before use -
trusting an unvalidated Host header here would let an attacker redirect
the emailed link's domain to one they control (host header injection),
silently defeating the whole magic-link security model. There is no
default allowlist; a caller must decide one explicitly (see
make_handler()).

CSRF / LOGIN-CSRF SAFETY (docs/decisiones.md D-078 follow-up, hardened
after a closure audit found two real gaps): every state-changing
handler (_handle_request_link, _handle_verify_post, _handle_logout,
_handle_member_add, _handle_member_remove) calls _check_same_origin()
FIRST and returns a clean 403 if it fails. That check reflects full
browser same-origin semantics, not hostname alone: the Origin header
must be PRESENT; its SCHEME must match this server's own expected
scheme (http/https, derived from secure_cookies); its HOSTNAME must be
exactly in host_allowlist - the same allowlist Host-header safety
already uses, reused rather than duplicated; and if Origin specifies an
explicit PORT, it must match this server's actual bound port (a bare
Origin with no port is never rejected on port grounds alone - see
_check_same_origin()'s own docstring on why). Confirmed by direct probing
that userinfo tricks, subdomain prefix/suffix tricks, `null`, empty,
and malformed Origins (including one that makes urlparse itself raise,
e.g. an invalid IPv6 bracket or a non-numeric port) all fail closed.
Referer, Host and any X-Forwarded-*/Forwarded header are NEVER consulted
for this decision (Origin is the one header a script running on another
origin cannot forge and modern browsers attach truthfully to every
state-changing request). Without this, an attacker could request their
OWN valid magic-link token, then have a victim's browser auto-submit a
hidden cross-site form POSTing that token to /auth/verify - the
victim's browser would receive a Set-Cookie for the ATTACKER's session
with no CSRF token or pre-existing cookie ever required (a "login
CSRF"). Legitimate same-origin browser requests are unaffected: browsers
send Origin on state-changing requests by default, so a normal
same-origin form submission or fetch() call already satisfies this
check.

TOKEN-LEAKAGE-IN-LOGS SAFETY (same follow-up, also hardened): the
original fix redacted a literal, case-sensitive "token=" substring,
which a closure audit found two real bypasses for - a differently-cased
name ("Token=") or a percent-encoded one ("%74oken=") both still resolve
to a live, functional token via the SAME urllib.parse.parse_qs the real
handlers use, while never matching that literal substring.
log_message() below now redacts via _redact_query_string(), which
decodes each query parameter's NAME (never its value) the same way
parse_qs does before deciding whether it is sensitive - see that
function's own docstring for the full reasoning and its fail-safe
(never fail-open) behavior on a malformed query string. The default
BaseHTTPRequestHandler.log_message never logs headers at all (only the
request line and status/size), so cookies, session tokens and
Authorization values were never included in the first place and still
are not - this override only ever touches the query string.

Connection-per-request, via a caller-supplied zero-argument connect_fn -
never a shared connection across requests/threads (sqlite3 connections
are not safe to share across threads under ThreadingHTTPServer; this
also matches how a real PostgreSQL connection pool would be used later,
so no code here changes shape when that swap happens).

Cookie flags (httpOnly, SameSite=Lax, Secure) are always set except
Secure, which is controlled by the secure_cookies flag make_handler()
takes - defaulting to True; a caller running local/plain-HTTP tests
passes False explicitly (a Secure cookie is never sent by a browser over
plain http://, so this is a real, documented, unavoidable local-testing
accommodation, never a production default).

Standard library only.
"""
from __future__ import annotations

import html
import json
import re
import sys
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, unquote_plus, urlparse

import backend.auth as auth
import backend.db as db
import backend.repository as repo
import backend.tenant_scope as tenant_scope

SESSION_COOKIE_NAME = "session"
MAX_BODY_BYTES = 64 * 1024  # generous for a JSON/form body this small; bounds per-request memory use.
REQUEST_TIMEOUT_SECONDS = 10

_MEMBER_COLLECTION_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/members$")
_MEMBER_ITEM_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/members/(?P<user_id>[^/]+)$")

# Query parameter names (decoded, lower-cased) this module never lets
# reach an access log - see module docstring and _redact_query_string().
_SENSITIVE_QUERY_PARAM_NAMES = frozenset({"token"})


def _redact_query_string(path: str) -> str:
    """Parser-aware redaction of any sensitive query parameter in `path`
    (e.g. "/auth/verify?token=xyz") - see module docstring on token-
    leakage safety. A literal regex on "token=" (this module's first
    attempt, since replaced) missed two real bypasses, confirmed
    empirically: a differently-cased name ("Token=") and a percent-
    encoded name ("%74oken=") both still resolve to a live, functional
    token via urllib.parse.parse_qs (what the real request handlers use
    to read it) while never matching a literal, case-sensitive "token="
    substring. This decodes each segment's NAME the same way
    (unquote_plus, confirmed to match parse_qs's own decoding exactly)
    before deciding whether it is sensitive - so it can only be bypassed
    by something the application's OWN handlers would also fail to
    recognize as a real "token" parameter, never separately from it.

    Every segment's raw text is otherwise preserved untouched (never
    re-encoded) - "preserve non-sensitive query parameters as normally
    as practical" - only a matched segment's VALUE is replaced with the
    literal marker [REDACTED]; its (possibly percent-encoded) NAME is
    left as originally written, which is itself never sensitive.

    Fails safe, never fails open: if anything about the query string
    can't be decoded/split as expected, the ENTIRE query string is
    replaced with a generic marker rather than passed through
    unredacted - a malformed/adversarial query string must never be the
    reason a real secret leaks, and must never crash logging either."""
    try:
        query_start = path.index("?")
    except ValueError:
        return path  # no query string at all.
    base, query = path[:query_start], path[query_start + 1:]
    if not query:
        return path
    try:
        changed = False
        redacted_segments = []
        for segment in query.split("&"):
            raw_name = segment.split("=", 1)[0]
            decoded_name = unquote_plus(raw_name).strip().lower()
            if decoded_name in _SENSITIVE_QUERY_PARAM_NAMES:
                redacted_segments.append("%s=[REDACTED]" % raw_name)
                changed = True
            else:
                redacted_segments.append(segment)
        return path if not changed else "%s?%s" % (base, "&".join(redacted_segments))
    except Exception:
        return "%s?[REDACTED-MALFORMED-QUERY]" % base


def _get_cookie(headers: Any, name: str) -> Optional[str]:
    raw = headers.get("Cookie")
    if not raw:
        return None
    jar = http_cookies.SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


def _build_cookie_header(name: str, value: str, max_age: int, secure: bool) -> str:
    parts = ["%s=%s" % (name, value), "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=%d" % max_age]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def _render_confirm_page(token: str, redirect_path: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Confirm sign-in</title></head>"
        "<body><h1>Confirm sign-in</h1>"
        "<p>Click the button below to finish signing in. This extra click confirms it was really "
        "you, not an automated scan of this email.</p>"
        "<form method=\"POST\" action=\"/auth/verify\">"
        "<input type=\"hidden\" name=\"token\" value=\"%s\">"
        "<input type=\"hidden\" name=\"redirect\" value=\"%s\">"
        "<button type=\"submit\">Confirm sign-in</button>"
        "</form></body></html>"
        % (html.escape(token, quote=True), html.escape(redirect_path, quote=True))
    ).encode("utf-8")


_INVALID_PAGE = (
    b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Link expired</title></head>"
    b"<body><h1>This link is invalid or has expired</h1>"
    b"<p>Request a new sign-in link and try again.</p></body></html>"
)


def make_handler(
    connect_fn: Callable[[], Any],
    email_sender: Any,
    host_allowlist: Sequence[str],
    secure_cookies: bool = True,
) -> type:
    """Returns a fresh Handler class closed over this specific server
    instance's config - never module-level globals, so multiple servers
    (e.g. one per test) never share state. host_allowlist is required
    (no default) - see module docstring on host header safety."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "backend-auth/2026.1"
        timeout = REQUEST_TIMEOUT_SECONDS

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _check_same_origin(self) -> bool:
            """The shared CSRF defense every state-changing handler calls
            first - see module docstring. Reflects full browser same-
            origin semantics, not hostname alone: scheme must match this
            server's own expected scheme (derived from secure_cookies -
            the same http/https choice already used to build the emailed
            verify URL); hostname must be exactly allowlisted; and if the
            Origin specifies an explicit port, it must match this
            server's actual bound port - but a bare Origin with NO port
            (the normal case for a real deployment's default 80/443,
            which is very likely served through a reverse proxy on a
            DIFFERENT internal port than this process binds) is never
            rejected on port grounds alone, since this process's own
            socket port is not necessarily what a real browser's Origin
            would ever show."""
            origin = self.headers.get("Origin")
            if not origin:
                return False
            try:
                parsed = urlparse(origin)
                origin_port = parsed.port
            except ValueError:
                return False  # unparseable Origin, or a port that isn't a valid 0-65535 integer.
            hostname = parsed.hostname
            if hostname is None or hostname not in host_allowlist:
                return False
            expected_scheme = "https" if secure_cookies else "http"
            if parsed.scheme != expected_scheme:
                return False
            if origin_port is not None and origin_port != self.server.server_address[1]:
                return False
            return True

        def _reject_if_cross_origin(self) -> bool:
            """Returns True (having already sent the 403) if this
            request fails _check_same_origin() - every state-changing
            handler calls this FIRST, before reading any body. Sets
            close_connection: this rejection always fires before the
            request body (if any) is read, so keep-alive must not be
            attempted on this connection - the same defensive pattern
            _read_body()'s own error paths already use, for the same
            reason (an unread body left in the socket can otherwise
            surface as a client-side connection reset - confirmed via
            repeated local runs, never a security issue by itself, but
            real avoidable flakiness worth closing here since this
            handler is the one introducing the unread body)."""
            if self._check_same_origin():
                return False
            self.close_connection = True
            self._send_json(403, {"ok": False, "error": "cross-origin request rejected"})
            return True

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - matches base class signature.
            """Same behavior as BaseHTTPRequestHandler.log_message, except
            any sensitive query parameter is redacted first - see
            _redact_query_string() and the module docstring on token-
            leakage safety. Substitutes self.path's own (already-parsed,
            authoritative) value for its redacted form directly in the
            composed message, rather than re-deriving anything from the
            opaque formatted string itself."""
            message = format % args
            raw_path = getattr(self, "path", None)
            if raw_path:
                redacted_path = _redact_query_string(raw_path)
                if redacted_path != raw_path:
                    message = message.replace(raw_path, redacted_path)
            sys.stderr.write(
                "%s - - [%s] %s\n" % (self._client_ip(), self.log_date_time_string(), message.translate(self._control_char_table))
            )

        def _send_json(self, status: int, body: Dict[str, Any], extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_html(self, status: int, body: bytes, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _read_body(self) -> Tuple[Optional[bytes], Optional[int], Optional[str]]:
            length_header = self.headers.get("Content-Length")
            try:
                content_length = int(length_header) if length_header is not None else -1
            except ValueError:
                content_length = -1
            if content_length < 0:
                self.close_connection = True
                return None, 400, "a valid Content-Length header is required"
            if content_length > MAX_BODY_BYTES:
                self.close_connection = True
                return None, 413, "request body too large"
            return self.rfile.read(content_length), None, None

        def _current_user_id(self, conn: Any) -> Optional[str]:
            session_token = _get_cookie(self.headers, SESSION_COOKIE_NAME)
            if not session_token:
                return None
            result = auth.validate_session(conn, session_token)
            return result["user_id"] if result else None

        # -------------------------------------------------------------
        # GET
        # -------------------------------------------------------------
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/auth/verify":
                self._handle_verify_get(parsed)
                return
            self._send_json(404, {"ok": False, "error": "not found"})

        def _handle_verify_get(self, parsed) -> None:
            qs = parse_qs(parsed.query)
            token = (qs.get("token") or [""])[0]
            redirect_path = auth.validate_redirect_path((qs.get("redirect") or [None])[0])
            conn = connect_fn()
            try:
                status = auth.peek_token(conn, token)
            finally:
                conn.close()
            if status != auth.TOKEN_VALID:
                self._send_html(200, _INVALID_PAGE)
                return
            self._send_html(200, _render_confirm_page(token, redirect_path))

        # -------------------------------------------------------------
        # POST
        # -------------------------------------------------------------
        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path == "/auth/request-link":
                self._handle_request_link()
            elif path == "/auth/verify":
                self._handle_verify_post()
            elif path == "/auth/logout":
                self._handle_logout()
            else:
                match = _MEMBER_COLLECTION_RE.match(path)
                if match:
                    self._handle_member_add(match.group("workspace_id"))
                else:
                    self._send_json(404, {"ok": False, "error": "not found"})

        def _handle_request_link(self) -> None:
            if self._reject_if_cross_origin():
                return
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"ok": False, "error": "request body is not valid UTF-8 JSON"})
                return
            host = self.headers.get("Host", "")
            hostname_only = host.split(":")[0]
            if hostname_only not in host_allowlist:
                self._send_json(400, {"ok": False, "error": "unrecognized host"})
                return
            email = payload.get("email") if isinstance(payload, dict) else None
            conn = connect_fn()
            try:
                token = auth.request_magic_link(conn, email, self._client_ip())
            except auth.RateLimitExceeded as exc:
                self._send_json(429, {"ok": False, "error": str(exc)})
                return
            except auth.AuthError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
                return
            finally:
                conn.close()
            scheme = "https" if secure_cookies else "http"
            verify_url = "%s://%s/auth/verify?token=%s" % (scheme, host, quote(token))
            email_sender.send(
                auth.normalize_email(email),
                "Your sign-in link",
                "Click to sign in (expires in 15 minutes): %s" % verify_url,
            )
            self._send_json(200, {"ok": True, "message": "If that email is registered, a sign-in link has been sent."})

        def _handle_verify_post(self) -> None:
            # The blocker this fix closes: without this check, an
            # attacker's own valid token could be relayed through a
            # victim's browser via a cross-site auto-submitting form -
            # see module docstring on CSRF/login-CSRF safety.
            if self._reject_if_cross_origin():
                return
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            try:
                fields = parse_qs(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_html(400, _INVALID_PAGE)
                return
            token = (fields.get("token") or [""])[0]
            redirect_path = auth.validate_redirect_path((fields.get("redirect") or [None])[0])
            conn = connect_fn()
            try:
                session = auth.consume_token_and_create_session(conn, token)
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
                return
            finally:
                conn.close()
            if session is None:
                self._send_html(200, _INVALID_PAGE)
                return
            cookie_header = _build_cookie_header(
                SESSION_COOKIE_NAME, session["session_token"], auth.SESSION_TTL_SECONDS, secure_cookies
            )
            self.send_response(303)
            self.send_header("Location", redirect_path)
            self.send_header("Set-Cookie", cookie_header)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _handle_logout(self) -> None:
            if self._reject_if_cross_origin():
                return
            session_token = _get_cookie(self.headers, SESSION_COOKIE_NAME)
            conn = connect_fn()
            try:
                if session_token:
                    auth.revoke_session(conn, session_token)
            finally:
                conn.close()
            clear_cookie = _build_cookie_header(SESSION_COOKIE_NAME, "", 0, secure_cookies)
            self._send_json(200, {"ok": True}, extra_headers=[("Set-Cookie", clear_cookie)])

        def _handle_member_add(self, workspace_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"ok": False, "error": "request body is not valid UTF-8 JSON"})
                return
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id, allowed_roles=("owner", "admin"))
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                email = payload.get("email") if isinstance(payload, dict) else None
                role = payload.get("role") if isinstance(payload, dict) else None
                try:
                    normalized = auth.normalize_email(email)
                except auth.AuthError as exc:
                    self._send_json(400, {"ok": False, "error": str(exc)})
                    return
                if role not in ("owner", "admin", "member"):
                    self._send_json(400, {"ok": False, "error": "role must be one of owner/admin/member"})
                    return
                existing = repo.get_user_by_email(conn, normalized)
                target_user_id = existing["id"] if existing is not None else repo.create_user(conn, normalized)
                try:
                    repo.add_workspace_member(conn, workspace_id, target_user_id, role)
                except db.integrity_error_class(conn):
                    self._send_json(409, {"ok": False, "error": "user is already a member of this workspace"})
                    return
                self._send_json(200, {"ok": True, "user_id": target_user_id})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        # -------------------------------------------------------------
        # DELETE
        # -------------------------------------------------------------
        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            match = _MEMBER_ITEM_RE.match(path)
            if not match:
                self._send_json(404, {"ok": False, "error": "not found"})
                return
            self._handle_member_remove(match.group("workspace_id"), match.group("user_id"))

        def _handle_member_remove(self, workspace_id: str, user_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id, allowed_roles=("owner", "admin"))
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                removed = repo.remove_workspace_member(conn, workspace_id, user_id)
                self._send_json(200, {"ok": True, "removed": removed})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

    return Handler


def run_server(
    connect_fn: Callable[[], Any],
    email_sender: Any,
    host_allowlist: Sequence[str],
    host: str = "127.0.0.1",
    port: int = 0,
    secure_cookies: bool = True,
) -> ThreadingHTTPServer:
    handler_cls = make_handler(connect_fn, email_sender, host_allowlist, secure_cookies)
    return ThreadingHTTPServer((host, port), handler_cls)
