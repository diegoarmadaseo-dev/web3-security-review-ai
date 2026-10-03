#!/usr/bin/env python3
"""Phase 2 identity/access HTTP layer (docs/decisiones.md D-077/D-078
follow-up). Stdlib http.server only, same pattern as website/server.py:
BaseHTTPRequestHandler + a route table, per-client IP taken ONLY from
the socket peer address (self.client_address[0]), never a client-
supplied X-Forwarded-For header (same rule website/server.py documents).

Endpoints: GET /health, GET /ready, GET /auth/login, POST
/auth/request-link, GET+POST /auth/verify, POST /auth/logout,
GET+POST /workspaces, GET /workspaces/<id>, POST
/workspaces/<id>/members, DELETE /workspaces/<id>/members/<user_id>,
POST /billing/checkout, POST /billing/portal, POST /billing/webhook,
GET+POST /workspaces/<id>/jobs, GET /workspaces/<id>/reports,
GET /workspaces/<id>/reports/<report_id>.

HEALTH/READINESS (Phase 6A, docs/decisiones.md D-077 follow-up):
GET /health is a bare liveness probe - always 200, touches nothing
(no DB, no Stripe, no S3), exists only to answer "is this process
still running at all". GET /ready is the stronger claim - it actually
queries the database (SELECT 1, not merely "connect_fn() didn't
raise at startup") and reports whether storage/billing are configured,
returning 503 if any required dependency is not currently usable. Ready
never returns a DSN, credential or any detail beyond three booleans -
see _handle_ready()'s own docstring. Neither route is authenticated or
CSRF-checked (same reasoning as GET /auth/verify: read-only, no side
effect, meant for infrastructure polling that sends no Origin/cookie
at all).

WORKSPACE CREATION/READ (Phase 5, docs/decisiones.md D-077 follow-up):
POST /workspaces is the ONLY place a workspace comes into existence
through this HTTP layer - the owner is always _current_user_id(), never
a client-supplied field in the request body (repository.create_workspace
already inserts the owner's workspace_members row atomically - see that
function's own docstring). There is deliberately NO auto-provision-on-
first-login: /auth/verify's POST handler only ever creates a session,
never a workspace, regardless of how many times a token or link is
verified - see docs/decisiones.md's Phase 5 entry for why an explicit,
separately-rate-limited endpoint is safer than trying to make workspace
auto-creation race-safe inside the login path itself. The three GET
reads (workspace list/detail, job list, report list/detail) are ordinary
tenant-scoped queries: every workspace_id in a URL is re-resolved against
the caller's real membership via tenant_scope, exactly like every
state-changing handler already does - a GET is never exempt from that
check just because it has no body. A report's storage_ref is never
returned to the client (see backend/object_storage.py's module
docstring) - GET .../reports/<id> instead mints a short-lived signed URL
per request.

BILLING (Phase 3, docs/decisiones.md D-077 follow-up): /billing/checkout
and /billing/portal are ordinary session-authed, CSRF-checked,
state-changing endpoints like the member-management ones above - the
workspace_id they act on comes from the JSON request body (there is no
per-workspace URL prefix for these two routes), but it is NEVER trusted
blindly: _current_user_id() resolves the caller from their session
cookie exactly as every other handler does, then
tenant_scope.require_workspace_role() re-derives that user's REAL role
in the claimed workspace_id from the database before anything else
happens - the same "authorization is a database fact, never a client
claim" pattern _handle_member_add()/_handle_member_remove() already use.
A tampered workspace_id in the body simply resolves to "you have no
role here" and gets a 403, never a bypass. The Stripe Price ID actually
charged is likewise never client-supplied - the client sends an internal
plan name, and billing.StripeBilling.resolve_price_id() is the only
place that becomes a Price ID (see backend/billing.py).

/billing/webhook is the one endpoint in this module that is NOT
session-authed and does NOT call _reject_if_cross_origin(): it has no
browser Origin at all (Stripe's servers call it directly), and its
"authentication" is the Stripe-Signature header verified against the
UNTOUCHED raw request body by billing.StripeBilling.
verify_and_parse_webhook() - see that function's own docstring for why
the body must never be JSON-parsed before that call.

RETRY AND ORDERING SAFETY (Phase 3 webhook hardening, docs/decisiones.md
D-077 follow-up - hardened after a final security audit found two real
gaps): a webhook event.id is deduplicated by repository.
record_webhook_event() - but "duplicate" now means "already SUCCEEDED",
never merely "already seen once": an event whose processing previously
failed remains retryable, and record_webhook_event() atomically reclaims
it for exactly one concurrent retrier (see that function's own
docstring). A failure never poisons the connection for the recovery
write that records it either - see the conn.rollback() call in
_handle_billing_webhook() below and repository.mark_webhook_event_
processed()'s docstring for the real, empirically-confirmed Postgres bug
this closes. Separately, every entitlement update carries the triggering
Stripe Event's own `created` timestamp through to repository.
update_entitlement_status()/create_entitlement(), which reject a stale
or tied update rather than blindly applying it - Stripe explicitly
documents webhook delivery as at-least-once and NOT guaranteed in order,
so without this an old, out-of-order event could both wrongly revoke an
active subscriber's access and, worse, wrongly RESTORE access after a
real cancellation (both confirmed reproducible before this fix - see
that same audit).

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

import hashlib
import html
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, unquote_plus, urlparse

import backend.alerting as alerting
import backend.auth as auth
import backend.billing as billing_module
import backend.black_friday as black_friday
import backend.db as db
import backend.email_policy as email_policy
import backend.github_integration as github_integration
import backend.loc_count as loc_count
import backend.object_storage as object_storage
import backend.plans as plans
import backend.repository as repo
import backend.submission_input as submission_input
import backend.targeted_review as targeted_review
import backend.tenant_scope as tenant_scope
import backend.trial as trial

SESSION_COOKIE_NAME = "session"
MAX_BODY_BYTES = 64 * 1024  # generous for a JSON/form body this small; bounds per-request memory use.
REQUEST_TIMEOUT_SECONDS = 10

_MEMBER_COLLECTION_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/members$")
_MEMBER_ITEM_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/members/(?P<user_id>[^/]+)$")
_JOBS_COLLECTION_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/jobs$")
# Phase 5: anchored with a trailing "$" right after the id group, exactly
# like every regex above - this cannot ever match a longer path like
# ".../reports" or ".../jobs", so route-check ORDER against those never
# matters (same reasoning already applies to _MEMBER_COLLECTION_RE vs.
# _MEMBER_ITEM_RE).
_WORKSPACE_ITEM_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)$")
_REPORTS_COLLECTION_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/reports$")
_REPORT_ITEM_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/reports/(?P<report_id>[^/]+)$")
# D-109: projects and single-job reads. Anchored like every regex above.
_PROJECTS_COLLECTION_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/projects$")
_PROJECT_ITEM_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/projects/(?P<project_id>[^/]+)$")
_JOB_ITEM_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/jobs/(?P<job_id>[^/]+)$")
_REPORT_DOCUMENT_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/reports/(?P<report_id>[^/]+)/document$")
_REPORT_DOWNLOAD_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/reports/(?P<report_id>[^/]+)/download$")
_APP_STATIC_RE = re.compile(r"^/app/static/(?P<name>[A-Za-z0-9._-]+)$")
# D-111 Private GitHub (Standard/Pro). Anchored like every regex above.
_GITHUB_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/github$")
_GITHUB_CONNECT_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/github/connect$")
_GITHUB_REPOSITORIES_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/github/repositories$")
_GITHUB_BRANCHES_RE = re.compile(r"^/workspaces/(?P<workspace_id>[^/]+)/github/repositories/(?P<repository_id>[^/]+)/branches$")

# D-110 web app: the ONLY files /app/static/ serves (a fixed allowlist, so no
# request path is ever joined onto the filesystem), and the headers every
# /app response carries - a strict CSP (no inline script/style, no third
# party, no framing), no MIME sniffing, no referrer leakage.
_WEBAPP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webapp")
_WEBAPP_STATIC = {
    "app.js": "text/javascript; charset=utf-8",
    "app-core.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
}
_APP_SECURITY_HEADERS = (
    ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "same-origin"),
)


def _public_git_source(git_source: Dict[str, Any]) -> Dict[str, Any]:
    """What a client sees of a GitHub scan's origin (D-111) - never the
    connection id, never a token."""
    return {"repository_id": git_source["repository_id"], "full_name": git_source["repository_full_name"],
            "ref": git_source["ref"], "commit_sha": git_source["commit_sha"]}


def _read_webapp_file(name: str) -> Optional[bytes]:
    if name != "index.html" and name not in _WEBAPP_STATIC:
        return None
    try:
        with open(os.path.join(_WEBAPP_DIR, name), "rb") as handle:
            return handle.read()
    except OSError:
        return None


# Every id this backend generates is repository.new_id(), a canonical UUID
# string. A malformed project/job id is answered 404 up front - never sent
# to Postgres, where a non-UUID literal would raise instead of matching
# nothing.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_MAX_WORKSPACE_NAME_LENGTH = 200
_MAX_WORKSPACES_PER_USER = 50  # abuse-safety cap on POST /workspaces - generous for any legitimate account.
_REPORT_SIGNED_URL_TTL_SECONDS = 300  # short-lived by design, matches this codebase's other signed-URL/token TTL philosophy (auth.py's own TOKEN_TTL_SECONDS).


class _InFlightTracker:
    """Phase 6A graceful shutdown: counts requests currently being
    processed by ONE server instance, right now - never module-level
    (a fresh tracker per run_server() call, same "never module-level
    globals" discipline make_handler() itself already documents, so
    multiple servers - e.g. one per test - never share a counter).
    Incremented/decremented around Handler.handle_one_request() (see
    make_handler() below), the one method BaseHTTPRequestHandler already
    calls exactly once per request regardless of which HTTP method it
    is - so this needs no separate hook in do_GET/do_POST/do_DELETE.
    backend/main.py's shutdown sequence polls .count via
    get_in_flight_count() to decide when every in-flight request has
    finished, bounded by its own configurable grace period."""

    def __init__(self) -> None:
        self._count = 0
        self._lock = threading.Lock()

    def increment(self) -> None:
        with self._lock:
            self._count += 1

    def decrement(self) -> None:
        with self._lock:
            self._count -= 1

    @property
    def count(self) -> int:
        with self._lock:
            return self._count


def get_in_flight_count(server: ThreadingHTTPServer) -> int:
    """0 for a server with no tracker attached (e.g. one constructed
    some other way than run_server() below) - never raises."""
    tracker = getattr(server, "in_flight_tracker", None)
    return tracker.count if tracker is not None else 0

# Phase 4: a raw-byte cap enforced HERE, synchronously, before anything is
# queued - "no execution during HTTP request" means this handler never
# runs preprocess.py's own (correct, authoritative) maxEffectiveLoc/
# maxSourceFiles check itself; that happens inside the worker, which
# already fails a job cleanly if exceeded (see backend/worker_entrypoint.py).
# This is only a cheap, fast rejection of the obviously-oversized case
# before it ever reaches the queue.
#
# 2 MiB since phase 15K-A (docs/decisiones.md D-096; was 512 KiB): real
# Solidity measures ~53-94 source bytes per effective LOC, so 512 KiB
# already rejected a real ~10K effLOC submission (~0.78 MB), and a real
# ~15K/~20K one measures ~1.31-1.36 MB/~1.73 MB. This bounds only what may
# be SUBMITTED; what reaches the LLM stays bounded separately by
# backend/context_selection.py's application prompt budget and the final
# pre-provider check in backend/llm_client.py.
MAX_RAW_SOURCE_BYTES = 2 * 1024 * 1024

# _handle_job_submit()'s request body is not raw source alone - it is a
# JSON envelope ({"mode","source","idempotency_key"}) around it, and JSON
# string escaping can expand the encoded "source" field beyond its own
# decoded UTF-8 byte length. This is a PROVEN bound, not a heuristic tuned
# to normal Solidity - it must hold for any valid-UTF-8 "source" a client
# sends, including adversarial content, and for any RFC-8259-conformant
# encoder (this module's own tests build request bodies with
# json.dumps(payload) - no ensure_ascii=False - so they use Python's
# default ensure_ascii=True, which \uXXXX-escapes every non-ASCII
# character; a prior version of this constant used 2x, which was verified
# insufficient: a source made entirely of JSON control characters (e.g.
# U+0001, which RFC 8259 requires every conformant encoder to escape as
# `\u0001` - 6 bytes for 1 decoded byte - regardless of ensure_ascii)
# expands to exactly 6x its own decoded UTF-8 byte length, confirmed by
# direct construction at MAX_RAW_SOURCE_BYTES scale; no valid UTF-8
# character can expand past 6x under any conformant JSON encoder, since
# the worst per-decoded-byte case (a 1-byte control character needing
# `\uXXXX`) is also the global worst case. 6x MAX_RAW_SOURCE_BYTES is
# therefore the smallest bound that holds for ALL valid UTF-8 source, not
# just realistic Solidity.
#
# +3072 covers the envelope's own JSON punctuation/keys plus
# idempotency_key: that field is validated below to have length 1-200
# (Python len(), i.e. Unicode code points, not bytes) but is otherwise
# unconstrained content, so its own worst case is 200 astral characters,
# each 1 code point but needing a UTF-16 surrogate PAIR (`\uXXXX\uXXXX`,
# 12 bytes) under ensure_ascii=True - confirmed by direct construction
# (mode="standard", the longest of the 3 allowed mode values, plus that
# idempotency_key, plus JSON structure) to need exactly 2457 bytes of
# overhead beyond the source field's own escaped content; 3072 (3 * 1024,
# the next clean multiple of 1024 above that measured exact worst case)
# leaves headroom without being an open-ended allowance for unrelated
# fields - an oversized/garbage "mode" value is not specially budgeted for
# here since mode is validated against exactly 3 known literal strings,
# never treated as free-form content the way idempotency_key is.
#
# MAX_RAW_SOURCE_BYTES itself remains the sole authority on how much
# actual source content is allowed; this constant only has to be large
# enough for _read_body() to hand that check a body to inspect in the
# first place - see that check, below, and _read_body()'s own docstring
# on why the generic MAX_BODY_BYTES (64 KiB, sized for login/membership-
# style payloads, shared by every OTHER POST endpoint in this module)
# would otherwise reject any job submission whose body exceeds 64 KiB
# before MAX_RAW_SOURCE_BYTES is ever reached.
JOB_SUBMIT_MAX_BODY_BYTES = 6 * MAX_RAW_SOURCE_BYTES + 3072

# Query parameter names (decoded, lower-cased) this module never lets
# reach an access log - see module docstring and _redact_query_string().
_SENSITIVE_QUERY_PARAM_NAMES = frozenset({"token", "code", "state"})   # D-111: the GitHub OAuth callback's code and state never reach a log either


def _is_utf8_encodable(text: str) -> bool:
    """False for text holding an unpaired surrogate (json.loads() produces
    one from an escape such as "\\ud800"), which cannot be encoded as
    UTF-8, stored or hashed."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


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

# Phase 5: the "app/auth entry" step of the product flow - a plain,
# JS-free HTML form (same no-JS philosophy as _render_confirm_page above)
# posting to /auth/request-link. Static content, so a module-level
# constant rather than a render function, same choice _INVALID_PAGE
# already made for the same reason.
_LOGIN_PAGE = (
    b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Sign in</title></head>"
    b"<body><h1>Sign in</h1>"
    b"<p>Enter your email to receive a one-time sign-in link.</p>"
    b"<form method=\"POST\" action=\"/auth/request-link\">"
    b"<input type=\"email\" name=\"email\" required placeholder=\"you@example.com\">"
    b"<button type=\"submit\">Send sign-in link</button>"
    b"</form><p>New here? <a href=\"/auth/signup\">Create an account and start a free Trial</a></p></body></html>"
)

# D-112: public sign-up - the same JS-free form style, posting to
# /auth/signup. Sign-up only sends a verification link; the free Trial is
# granted when that link is verified (backend/trial.py).
_SIGNUP_PAGE = (
    b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Create your account</title></head>"
    b"<body><h1>Create your Vericexa account</h1>"
    b"<p>Enter your email. We will send a link to verify it; once verified, your free Trial starts: "
    b"one automated security review of up to 500 effective lines of code. No card required.</p>"
    b"<form method=\"POST\" action=\"/auth/signup\">"
    b"<input type=\"email\" name=\"email\" required maxlength=\"254\" placeholder=\"you@example.com\">"
    b"<button type=\"submit\">Send verification link</button>"
    b"</form><p>Already have an account? <a href=\"/auth/login\">Sign in</a></p></body></html>"
)


def _render_signup_page(title: str, message: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head>"
        "<body><h1>%s</h1><p>%s</p><p><a href=\"/auth/signup\">Back to sign-up</a></p></body></html>"
        % (html.escape(title, quote=True), html.escape(title, quote=True), html.escape(message, quote=True))
    ).encode("utf-8")


SIGNUP_SENT_MESSAGE = ("If this address can receive email, a verification link has been sent. "
                       "Open it within 15 minutes to verify your email and start your free Trial.")


def _render_request_link_sent_page(message: str) -> bytes:
    """The HTML counterpart of /auth/request-link's JSON success/error
    body - rendered only when the request itself arrived form-encoded
    (i.e. a real browser submitted _LOGIN_PAGE's form, not an API/test
    caller) - see _handle_request_link()'s own is_form branch. Reuses the
    same anti-enumeration generic message the JSON path already sends;
    this function never learns or reveals anything the JSON path
    wouldn't."""
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Check your email</title></head>"
        "<body><h1>Check your email</h1><p>%s</p>"
        "<p><a href=\"/auth/login\">Back to sign in</a></p></body></html>"
        % html.escape(message, quote=True)
    ).encode("utf-8")


_MODES_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".claude", "skills", "web3-auditor", "config", "modes.json",
)
_modes_config_cache: Optional[Dict[str, Any]] = None
_modes_config_load_attempted = False


def _load_modes_config() -> Optional[Dict[str, Any]]:
    """Best-effort read of config/modes.json - the same single source of
    truth scripts/preprocess.py and website/build_site.py already treat
    as authoritative (see that file's own "description" field) - used
    only for GET /workspaces/<id>'s "limits" field. Cached after the
    first attempt (this file changes only at deploy time, never
    mid-process). A missing or malformed file degrades that ONE response
    field to None rather than failing the request - every other field
    (workspace/entitlement/budget) comes from this backend's own
    database and is unaffected. Reads the JSON directly rather than
    importing scripts/preprocess.py's own loader, deliberately: this
    keeps the web process's only coupling to .claude/skills/web3-auditor/
    to a single static data file, never its Python code (worker_
    entrypoint.py, which actually runs inside a container with that
    whole tree copied in, is the one place importing that code is
    appropriate - see that module and backend/docker/Dockerfile.worker)."""
    global _modes_config_cache, _modes_config_load_attempted
    if _modes_config_load_attempted:
        return _modes_config_cache
    _modes_config_load_attempted = True
    try:
        with open(_MODES_CONFIG_PATH, "r", encoding="utf-8") as handle:
            _modes_config_cache = json.load(handle)
    except (OSError, json.JSONDecodeError):
        _modes_config_cache = None
    return _modes_config_cache


def _parse_limit_offset(qs: Dict[str, List[str]]) -> Tuple[int, int, Optional[str]]:
    """Parses and bounds-checks a list endpoint's ?limit=&offset=
    parameters - see repo.MAX_LIST_LIMIT/DEFAULT_LIST_LIMIT. Returns
    (limit, offset, error_message); error_message is None on success, in
    which case limit/offset are always valid, ready to pass straight to
    repository.py - which re-validates its own bounds as the final
    authority (this is only about turning a query string into a clean
    400, never the source of truth for what is actually allowed, the
    same division of labor _handle_job_submit() already applies to
    mode/source)."""
    limit_raw = (qs.get("limit") or [None])[0]
    offset_raw = (qs.get("offset") or [None])[0]
    try:
        limit = int(limit_raw) if limit_raw is not None else repo.DEFAULT_LIST_LIMIT
        offset = int(offset_raw) if offset_raw is not None else 0
    except ValueError:
        return 0, 0, "limit and offset must be integers"
    if not (1 <= limit <= repo.MAX_LIST_LIMIT):
        return 0, 0, "limit must be between 1 and %d" % repo.MAX_LIST_LIMIT
    if offset < 0:
        return 0, 0, "offset must be >= 0"
    return limit, offset, None

_SUBSCRIPTION_EVENT_TYPES = ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted")
_SUBSCRIPTION_PLANS = tuple(name for name, spec in plans.PLANS.items() if spec["billing_type"] == plans.BILLING_SUBSCRIPTION)


def _upsert_entitlement(
    conn: Any,
    workspace_id: Optional[str],
    plan: Optional[str],
    status: str,
    stripe_customer_id: Optional[str],
    stripe_subscription_id: Optional[str],
    current_period_end: Optional[str],
    event_created_at: Optional[str],
    interval: Optional[str] = None,
    current_period_start: Optional[str] = None,
) -> None:
    """Shared by every branch of _apply_webhook_event() below that carries
    an authoritative subscription status. Checks existence FIRST (rather
    than branching on update_entitlement_status()'s return value, as a
    pre-Phase-3-hardening version of this function did) because that
    return value is now ambiguous between "no row exists yet" (must
    create) and "a row exists but this event is stale/tied and was
    correctly ignored" (must do nothing) - see that function's own
    docstring on the ordering rule. Creating one on whichever event
    happens to arrive FIRST for a given workspace also establishes this
    row's OWN ordering baseline (event_created_at is stamped on create
    too, not left NULL) - see module docstring on billing's "never
    assume webhook delivery order". A plan-less event with no existing
    row to update (should never happen for a session/subscription this
    backend itself created, since billing.StripeBilling.
    create_checkout_session() always stamps workspace_id/plan into
    metadata) is silently skipped rather than guessed at.

    interval (D-086) is validated here - not just plan - before ever
    reaching repository.py: an unrecognized/missing value is passed
    through as None (repository.py's own CHECK constraint would reject
    anything else at the CREATE path anyway; validating here keeps a
    malformed metadata value from ever reaching that far).

    D-107: a subscription event now also UPDATES plan (resolved from the
    subscription's own Price ID by the caller), the subscription/customer
    ids and current_period_start (service-month anchor) on an existing
    row, so a portal upgrade/downgrade or monthly<->annual switch is
    reflected; only subscription plans are accepted here."""
    if not workspace_id:
        return
    if interval not in ("monthly", "annual"):
        interval = None
    if plan not in _SUBSCRIPTION_PLANS:
        plan = None
    if repo.get_entitlement_by_workspace(conn, workspace_id) is None:
        if plan is not None:
            repo.create_entitlement(conn, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, event_created_at,
                                    billing_interval=interval, current_period_start=current_period_start)
        return
    repo.update_entitlement_status(conn, workspace_id, status, current_period_end, event_created_at, billing_interval=interval, plan=plan,
                                   current_period_start=current_period_start, stripe_customer_id=stripe_customer_id,
                                   stripe_subscription_id=stripe_subscription_id)


def _apply_quick_payment(conn: Any, obj: Dict[str, Any], event_created_at: Optional[str]) -> None:
    """A PAID Quick Checkout Session (D-107): grants exactly one scan credit
    (keyed by the session id - a redelivered event never grants twice) and
    makes the workspace's entitlement quick/active. Never touches a
    workspace whose current entitlement is a live subscription (checkout
    refuses to sell Quick to one; this is defense in depth)."""
    metadata = obj.get("metadata") or {}
    workspace_id = obj.get("client_reference_id") or metadata.get("workspace_id")
    session_id = obj.get("id")
    if not workspace_id or not isinstance(session_id, str) or not session_id or metadata.get("plan") != plans.PLAN_QUICK:
        return
    existing = repo.get_entitlement_by_workspace(conn, workspace_id)
    if existing is not None and existing["plan"] in _SUBSCRIPTION_PLANS and existing["status"] in ("active", "trialing", "past_due"):
        return
    repo.grant_scan_credit(conn, session_id, workspace_id)
    if existing is None:
        repo.create_entitlement(conn, workspace_id, plans.PLAN_QUICK, "active", stripe_customer_id=obj.get("customer"), stripe_event_created_at=event_created_at)
    else:
        repo.update_entitlement_status(conn, workspace_id, "active", stripe_event_created_at=event_created_at, plan=plans.PLAN_QUICK,
                                       stripe_customer_id=obj.get("customer"))


def _apply_webhook_event(conn: Any, event_type: str, obj: Dict[str, Any], event_created_at: Optional[str],
                         billing: Optional["billing_module.StripeBilling"] = None) -> None:
    """Dispatches one of the 5 handled Stripe event types
    (backend/billing.py's module docstring lists them) to an
    entitlements update. event_created_at is the ENCLOSING Stripe
    Event's own `created` timestamp (already converted to an ISO string
    by the caller, _handle_billing_webhook) - the ordering signal every
    branch below threads through to repository.py's update_entitlement_
    status()/create_entitlement(), per docs/decisiones.md D-077's Phase 3
    webhook-hardening follow-up: Stripe explicitly documents webhook
    delivery as at-least-once and NOT guaranteed in order, so a stale
    event must never regress (or, after a cancellation, incorrectly
    restore) a newer entitlement state - see update_entitlement_status()'s
    own docstring for the exact deterministic rule, including its tie-
    break. Any OTHER event type Stripe might deliver (there are dozens)
    is a deliberate silent no-op here, never an error -
    _handle_billing_webhook() still records via record_webhook_event()/
    mark_webhook_event_processed() that it was received, so nothing is
    lost, but this backend only ACTS on the 5 types this phase is scoped
    to."""
    if event_type in ("checkout.session.completed", "checkout.session.async_payment_succeeded") and obj.get("mode") == "payment":
        # D-107 Quick: one-time payment. Only a PAID session grants the
        # scan; an asynchronous payment method completes later with
        # checkout.session.async_payment_succeeded (handled here too).
        if obj.get("payment_status") == "paid":
            _apply_quick_payment(conn, obj, event_created_at)
        return
    if event_type == "checkout.session.async_payment_succeeded":
        return
    if event_type == "checkout.session.completed":
        # Deliberately NOT _upsert_entitlement(): this event's own object
        # carries no real subscription status (a Checkout Session's
        # status is about the CHECKOUT, not the subscription it created),
        # so this handler only ever CREATES a row that does not exist yet
        # - using 'incomplete' as an honest placeholder pending the
        # authoritative status a customer.subscription.* event carries -
        # and never touches status OR event_created_at on a row that
        # already exists, at any timestamp: an existing row, by
        # definition, was already established by a MORE authoritative
        # event (a subscription event carries a real status; this one
        # never does), so this event is never "newer" in the sense that
        # matters here, regardless of what its own `created` says.
        # Without this asymmetry, a customer.subscription.updated event
        # that happens to arrive FIRST (setting a real status like
        # 'active') would be silently regressed back to 'incomplete' by
        # this event arriving second - exactly the delivery-order
        # assumption this phase was explicitly scoped to never make.
        metadata = obj.get("metadata") or {}
        workspace_id = obj.get("client_reference_id")
        plan = metadata.get("plan")
        interval = metadata.get("interval")
        if interval not in ("monthly", "annual"):
            interval = None
        if workspace_id and plan in _SUBSCRIPTION_PLANS and repo.get_entitlement_by_workspace(conn, workspace_id) is None:
            repo.create_entitlement(
                conn,
                workspace_id,
                plan,
                status="incomplete",
                stripe_customer_id=obj.get("customer"),
                stripe_subscription_id=obj.get("subscription"),
                stripe_event_created_at=event_created_at,
                billing_interval=interval,
            )
    elif event_type in _SUBSCRIPTION_EVENT_TYPES:
        # A canceled subscription's own status is already 'canceled' on
        # the object customer.subscription.deleted carries - confirmed
        # Stripe behavior, so both event types share this one branch.
        metadata = obj.get("metadata") or {}
        status = obj.get("status")
        if not isinstance(status, str):
            return
        # D-107: the subscription's own Price ID decides plan/interval.
        # A Price ID outside the configured catalog (a retired D-086
        # price, a foreign price) is ignored entirely - never mapped to a
        # plan. Only an object carrying no price at all falls back to the
        # server-stamped metadata.
        plan, interval = metadata.get("plan"), metadata.get("interval")
        price_id = billing_module.subscription_price_id(obj)
        if price_id is not None:
            resolved = billing.plan_for_price_id(price_id) if billing is not None else None
            if resolved is None or resolved["plan"] not in _SUBSCRIPTION_PLANS:
                return
            plan, interval = resolved["plan"], resolved["interval"]
        _upsert_entitlement(
            conn,
            workspace_id=metadata.get("workspace_id"),
            plan=plan,
            status=status,
            stripe_customer_id=obj.get("customer"),
            stripe_subscription_id=obj.get("id"),
            current_period_end=billing_module.subscription_period_end(obj),
            event_created_at=event_created_at,
            interval=interval,
            current_period_start=billing_module.subscription_period_start(obj),
        )
    elif event_type == "invoice.paid":
        workspace_id = billing_module.invoice_workspace_id(obj)
        if workspace_id:
            repo.update_entitlement_status(conn, workspace_id, "active", stripe_event_created_at=event_created_at)
    elif event_type == "invoice.payment_failed":
        workspace_id = billing_module.invoice_workspace_id(obj)
        if workspace_id:
            repo.update_entitlement_status(conn, workspace_id, "past_due", stripe_event_created_at=event_created_at)


def make_handler(
    connect_fn: Callable[[], Any],
    email_sender: Any,
    host_allowlist: Sequence[str],
    secure_cookies: bool = True,
    billing: Optional["billing_module.StripeBilling"] = None,
    storage: Optional["object_storage.ObjectStorage"] = None,
    alert_sender: Optional["alerting.AlertSender"] = None,
    in_flight: Optional[_InFlightTracker] = None,
    black_friday_enabled: bool = False,
    black_friday_start: Optional[datetime] = None,
    black_friday_end: Optional[datetime] = None,
    black_friday_promotion_code_id: Optional[str] = None,
    max_pending_jobs_per_workspace: int = repo.DEFAULT_MAX_PENDING_JOBS_PER_WORKSPACE,
    submit_rate_limit_per_window: int = repo.DEFAULT_SUBMIT_RATE_LIMIT_PER_WINDOW,
    github: Optional["github_integration.GitHubIntegration"] = None,
    disposable_policy: Optional["email_policy.DisposableDomainPolicy"] = None,
) -> type:
    """Returns a fresh Handler class closed over this specific server
    instance's config - never module-level globals, so multiple servers
    (e.g. one per test) never share state. host_allowlist is required
    (no default) - see module docstring on host header safety. billing is
    OPTIONAL (None by default) - a deployment/test that never configures
    Stripe still gets every other endpoint working normally; the three
    /billing/* routes return a clean 503 rather than raising when it is
    None (see _handle_billing_checkout() etc.) - see module docstring on
    billing for the security model those routes follow. storage is
    likewise OPTIONAL (Phase 4) - POST /workspaces/<id>/jobs returns a
    clean 503 when it is None, the same degrade-cleanly convention.
    alert_sender is OPTIONAL (Phase 6A) - see backend/alerting.py's own
    module docstring; every call site here uses alerting.emit_safe(),
    which is already a no-op when it is None. in_flight is OPTIONAL,
    normally supplied by run_server() below (never constructed directly
    by a caller of make_handler() itself - see _InFlightTracker's own
    docstring).

    black_friday_* (Phase 7, D-086) are ALL optional, defaulting to fully
    disabled (enabled=False, everything else None) - a deployment/test
    that never configures the campaign gets ordinary Checkout behavior,
    unchanged. Passed straight through to backend.black_friday.
    resolve_promotion_code() on every /billing/checkout call - see that
    module's own docstring on why this is re-evaluated per-request,
    never cached or trusted from the client.

    max_pending_jobs_per_workspace / submit_rate_limit_per_window (D-108)
    bound POST /workspaces/<id>/jobs: queued+claimed+running jobs per
    workspace, and submissions per user per
    repo.SUBMIT_RATE_LIMIT_WINDOW_SECONDS. Both default to the repository's
    own defaults; backend/main.py reads them from the environment.

    github (D-111) is OPTIONAL: None leaves Private GitHub unconfigured (its
    endpoints answer 503 github_not_configured after the plan check); see
    backend/github_integration.py.

    disposable_policy (D-112) is the denylist of disposable email domains
    refused for the free Trial; None loads the bundled list
    (backend/email_policy.py)."""
    trial_policy = disposable_policy if disposable_policy is not None else email_policy.load_policy()

    class Handler(BaseHTTPRequestHandler):
        server_version = "backend-auth/2026.1"
        timeout = REQUEST_TIMEOUT_SECONDS

        def handle_one_request(self) -> None:
            """Overridden ONLY to bracket the in-flight counter (Phase
            6A graceful shutdown) around the base class's own request
            handling - never changes what a request actually does. This
            is the one method BaseHTTPRequestHandler already calls
            exactly once per request on a keep-alive connection
            (regardless of GET/POST/DELETE), so every request is counted
            without a separate hook in each do_* method - see
            _InFlightTracker's own docstring."""
            if in_flight is not None:
                in_flight.increment()
            try:
                super().handle_one_request()
            finally:
                if in_flight is not None:
                    in_flight.decrement()

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

        def _read_body(self, max_body_bytes: int = MAX_BODY_BYTES) -> Tuple[Optional[bytes], Optional[int], Optional[str]]:
            """max_body_bytes defaults to the generic MAX_BODY_BYTES (64 KiB) -
            every caller except _handle_job_submit() relies on that default
            and is unaffected by this parameter. _handle_job_submit() passes
            JOB_SUBMIT_MAX_BODY_BYTES explicitly (see that constant's own
            comment) so its body can actually reach MAX_RAW_SOURCE_BYTES's
            source-specific check instead of being rejected here first."""
            content_length, err_status, err_msg = self._check_content_length(max_body_bytes)
            if err_status:
                return None, err_status, err_msg
            return self.rfile.read(content_length), None, None

        def _check_content_length(self, max_body_bytes: int) -> Tuple[int, Optional[int], Optional[str]]:
            """The Content-Length checks of _read_body(), from the header
            alone - nothing is read from the socket. A request without a
            valid Content-Length (e.g. a chunked body) or declaring more
            than max_body_bytes is rejected and its connection closed, so
            the unread body is never parsed as a next request."""
            length_header = self.headers.get("Content-Length")
            try:
                content_length = int(length_header) if length_header is not None else -1
            except ValueError:
                content_length = -1
            if content_length < 0:
                self.close_connection = True
                return -1, 400, "a valid Content-Length header is required"
            if content_length > max_body_bytes:
                self.close_connection = True
                return -1, 413, "request body too large"
            return content_length, None, None

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
            path = parsed.path
            if path == "/health":
                self._send_json(200, {"ok": True})
                return
            if path == "/ready":
                self._handle_ready()
                return
            if path == "/auth/verify":
                self._handle_verify_get(parsed)
                return
            if path == "/auth/login":
                self._send_html(200, _LOGIN_PAGE)
                return
            if path == "/auth/me":
                self._handle_me()
                return
            if path == "/auth/signup":
                self._send_html(200, _SIGNUP_PAGE)
                return
            if path == "/trial":
                self._handle_trial_status()
                return
            if path == "/billing/plans":
                self._handle_billing_plans()
                return
            if path == "/github/callback":
                self._handle_github_callback(parsed)
                return
            if path == "/":
                # D-110: the signed-in product lives at /app (auth's default
                # post-login redirect is "/").
                self.send_response(302)
                self.send_header("Location", "/app")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/app" or (path.startswith("/app/") and not path.startswith("/app/static/")):
                self._handle_app_shell()
                return
            match = _APP_STATIC_RE.match(path)
            if match:
                self._handle_app_static(match.group("name"))
                return
            match = _REPORT_DOCUMENT_RE.match(path)
            if match:
                self._handle_report_document(match.group("workspace_id"), match.group("report_id"))
                return
            match = _REPORT_DOWNLOAD_RE.match(path)
            if match:
                self._handle_report_download(match.group("workspace_id"), match.group("report_id"), parsed)
                return
            match = _GITHUB_RE.match(path)
            if match:
                self._handle_github_status(match.group("workspace_id"))
                return
            match = _GITHUB_REPOSITORIES_RE.match(path)
            if match:
                self._handle_github_repositories(match.group("workspace_id"))
                return
            match = _GITHUB_BRANCHES_RE.match(path)
            if match:
                self._handle_github_branches(match.group("workspace_id"), match.group("repository_id"))
                return
            if path == "/workspaces":
                self._handle_workspace_list()
                return
            match = _JOBS_COLLECTION_RE.match(path)
            if match:
                self._handle_job_list(match.group("workspace_id"), parsed)
                return
            match = _JOB_ITEM_RE.match(path)
            if match:
                self._handle_job_get(match.group("workspace_id"), match.group("job_id"))
                return
            match = _PROJECTS_COLLECTION_RE.match(path)
            if match:
                self._handle_project_list(match.group("workspace_id"), parsed)
                return
            match = _PROJECT_ITEM_RE.match(path)
            if match:
                self._handle_project_get(match.group("workspace_id"), match.group("project_id"))
                return
            match = _REPORT_ITEM_RE.match(path)
            if match:
                self._handle_report_get(match.group("workspace_id"), match.group("report_id"))
                return
            match = _REPORTS_COLLECTION_RE.match(path)
            if match:
                self._handle_report_list(match.group("workspace_id"), parsed)
                return
            match = _WORKSPACE_ITEM_RE.match(path)
            if match:
                self._handle_workspace_get(match.group("workspace_id"))
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

        def _handle_ready(self) -> None:
            """Phase 6A: verifies the dependencies this process actually
            needs to serve PRODUCTION traffic are usable RIGHT NOW - a
            weaker "config was present at startup" check (see backend/
            main.py's own fail-fast validation) is not the same claim as
            "still reachable this instant" (a database can fail well
            after a healthy start). database is unconditionally checked
            (connect_fn is a required argument to make_handler(), never
            optional) via a trivial SELECT 1 - the cheapest real
            liveness probe, not merely "did connect_fn() not raise".
            storage/billing are reported as configured/not (both are
            legitimately optional per this module's own degrade-cleanly
            design for a dev/test deployment - see make_handler()'s own
            docstring) - never independently mutated into a 503 reason
            by themselves alone changing that existing contract, but
            production (backend/main.py's run_web(), which always
            constructs both) is never ready without them either, so both
            ARE required for an overall 200 here. Never returns a DSN,
            credential, or any value beyond these three booleans - see
            module docstring on host/CSRF safety's own "never leak
            internal detail" philosophy, applied here to config secrets
            instead of a workspace's existence."""
            database_ok = False
            conn = None
            try:
                conn = connect_fn()
                db.execute(conn, "SELECT 1")
                database_ok = True
            except Exception:
                database_ok = False
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
            checks = {"database": database_ok, "storage": storage is not None, "billing": billing is not None}
            ready = all(checks.values())
            if not ready:
                alerting.emit_safe(alert_sender, alerting.EVENT_READINESS_FAILURE, "error", {"checks": checks})
            self._send_json(200 if ready else 503, {"ok": ready, "checks": checks})

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
            elif path == "/auth/signup":
                self._handle_signup()
            elif path == "/trial/activate":
                self._handle_trial_activate()
            elif path == "/workspaces":
                self._handle_workspace_create()
            elif path == "/billing/checkout":
                self._handle_billing_checkout()
            elif path == "/billing/portal":
                self._handle_billing_portal()
            elif path == "/billing/webhook":
                self._handle_billing_webhook()
            else:
                match = _MEMBER_COLLECTION_RE.match(path)
                if match:
                    self._handle_member_add(match.group("workspace_id"))
                    return
                match = _JOBS_COLLECTION_RE.match(path)
                if match:
                    self._handle_job_submit(match.group("workspace_id"))
                    return
                match = _PROJECTS_COLLECTION_RE.match(path)
                if match:
                    self._handle_project_create(match.group("workspace_id"))
                    return
                match = _GITHUB_CONNECT_RE.match(path)
                if match:
                    self._handle_github_connect(match.group("workspace_id"))
                    return
                self._send_json(404, {"ok": False, "error": "not found"})

        def _handle_request_link(self) -> None:
            if self._reject_if_cross_origin():
                return
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            # Phase 5: _LOGIN_PAGE posts here as a plain, JS-free HTML
            # form (application/x-www-form-urlencoded), the same way
            # _render_confirm_page's form already posts to /auth/verify -
            # every existing API/test caller keeps sending JSON
            # unchanged, so this branches on Content-Type rather than
            # replacing the JSON path.
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            is_form = content_type == "application/x-www-form-urlencoded"
            if is_form:
                try:
                    fields = parse_qs(raw.decode("utf-8"))
                except UnicodeDecodeError:
                    self._send_html(400, _INVALID_PAGE)
                    return
                payload: Any = {"email": (fields.get("email") or [None])[0]}
            else:
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(400, {"ok": False, "error": "request body is not valid UTF-8 JSON"})
                    return
            host = self.headers.get("Host", "")
            hostname_only = host.split(":")[0]
            if hostname_only not in host_allowlist:
                if is_form:
                    self._send_html(400, _INVALID_PAGE)
                else:
                    self._send_json(400, {"ok": False, "error": "unrecognized host"})
                return
            email = payload.get("email") if isinstance(payload, dict) else None
            conn = connect_fn()
            try:
                token = auth.request_magic_link(conn, email, self._client_ip())
            except auth.RateLimitExceeded as exc:
                alerting.emit_safe(alert_sender, alerting.EVENT_AUTH_RATE_LIMIT, "warning", {"ip": self._client_ip()})
                if is_form:
                    self._send_html(429, _render_request_link_sent_page(str(exc)))
                else:
                    self._send_json(429, {"ok": False, "error": str(exc)})
                return
            except auth.AuthError as exc:
                if is_form:
                    self._send_html(400, _render_request_link_sent_page(str(exc)))
                else:
                    self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception:
                if is_form:
                    self._send_html(500, _render_request_link_sent_page("internal error"))
                else:
                    self._send_json(500, {"ok": False, "error": "internal error"})
                return
            finally:
                conn.close()
            # The token row above is already committed regardless of what
            # happens next (identical work for a real or fake address -
            # see request_magic_link()'s own anti-enumeration docstring),
            # so delivery is attempted unconditionally and a failure below
            # must never change the response shape - that would both crash
            # the request (do_POST has no wrapping handler, so an uncaught
            # SMTPEmailSender exception used to propagate as a raw
            # traceback with no HTTP response at all) and turn delivery
            # success/failure into a new enumeration signal. The token
            # itself needs no special handling on failure: it simply sits
            # unconsumed until its normal TOKEN_TTL_SECONDS expiry, exactly
            # like any link a user never clicked - see docs/decisiones.md
            # D-083.
            scheme = "https" if secure_cookies else "http"
            verify_url = "%s://%s/auth/verify?token=%s" % (scheme, host, quote(token))
            try:
                email_sender.send(
                    auth.normalize_email(email),
                    "Your sign-in link",
                    "Click to sign in (expires in 15 minutes): %s" % verify_url,
                )
            except Exception as exc:
                # TYPE NAME only, never str(exc)/the message body - same
                # discipline backend/email_sender.SMTPEmailSender and
                # backend/alerting.WebhookAlertSender already apply, for
                # the same reason (a provider's own error text can echo
                # back credentials or the message content).
                alerting.emit_safe(
                    alert_sender, alerting.EVENT_EMAIL_DELIVERY_FAILURE, "error",
                    {"ip": self._client_ip(), "error_type": type(exc).__name__},
                )
            if is_form:
                self._send_html(200, _render_request_link_sent_page("If that email is registered, a sign-in link has been sent."))
            else:
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
                if session is not None and session.get("purpose") == "signup":
                    self._grant_trial_after_signup(conn, session["user_id"])
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

        # -------------------------------------------------------------
        # Workspaces (Phase 5) - see module docstring on workspace
        # creation/read.
        # -------------------------------------------------------------
        def _handle_workspace_create(self) -> None:
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
            name = payload.get("name") if isinstance(payload, dict) else None
            if not isinstance(name, str) or not name.strip() or len(name.strip()) > _MAX_WORKSPACE_NAME_LENGTH:
                self._send_json(400, {"ok": False, "error": "name must be a non-empty string of at most %d characters" % _MAX_WORKSPACE_NAME_LENGTH})
                return
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                # Abuse-safety cap, never a uniqueness/idempotency check -
                # workspace names are NOT required to be unique per owner
                # (no such constraint on the workspaces table, unlike
                # projects' own uq_projects_workspace_name_live), so a
                # double-submitted form in the worst case creates two
                # similarly-named workspaces the owner can trivially see
                # and delete/rename later - never a security or data-
                # integrity issue, so this endpoint deliberately does not
                # add idempotency_key machinery for it (unlike job
                # submission, where a duplicate has a real cost - spend,
                # compute - this has none).
                if len(repo.list_workspaces_by_user(conn, current_user_id)) >= _MAX_WORKSPACES_PER_USER:
                    self._send_json(429, {"ok": False, "error": "workspace limit reached for this account"})
                    return
                workspace_id = repo.create_workspace(conn, name.strip(), current_user_id)
                self._send_json(200, {"ok": True, "workspace_id": workspace_id})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_workspace_list(self) -> None:
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                workspaces = repo.list_workspaces_by_user(conn, current_user_id)
                self._send_json(200, {"ok": True, "workspaces": workspaces})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_workspace_get(self, workspace_id: str) -> None:
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    role = tenant_scope.require_workspace_role(conn, current_user_id, workspace_id)
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                workspace = repo.get_workspace(conn, workspace_id)
                if workspace is None:
                    self._send_json(404, {"ok": False, "error": "not found"})
                    return
                workspace["membership_role"] = role
                entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
                budget = repo.technical_budget_summary(conn, workspace_id, entitlement)   # D-108: per-service-month safety guard, None for Quick
                limits = None
                if entitlement is not None:
                    modes_config = _load_modes_config()
                    if modes_config is not None:
                        limits = (modes_config.get("modes") or {}).get(entitlement["plan"])
                usage = repo.usage_summary(conn, workspace_id, entitlement)
                # D-110 (display only, every value server-derived): queue
                # occupancy against the D-108 cap, the analysis modes the
                # plan may request, and whether checkout is available.
                admission = {"pending_jobs": repo.count_pending_jobs(conn, workspace_id), "max_pending_jobs": max_pending_jobs_per_workspace,
                             "allowed_modes": sorted(repo.PLAN_ALLOWED_MODES.get(entitlement["plan"], frozenset())) if entitlement else [],
                             "billing_configured": billing is not None,
                             # D-111: plan features (backend/plans.py) and whether Private GitHub is configured - display only.
                             "features": sorted(plans.PLAN_FEATURES.get(entitlement["plan"], frozenset())) if entitlement and entitlement["status"] in ("active", "trialing") else [],
                             "github_configured": github is not None}
                self._send_json(200, {"ok": True, "workspace": workspace, "entitlement": entitlement, "budget": budget, "limits": limits, "usage": usage,
                                      "admission": admission})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_job_list(self, workspace_id: str, parsed: Any) -> None:
            qs = parse_qs(parsed.query)
            limit, offset, err = _parse_limit_offset(qs)
            if err:
                self._send_json(400, {"ok": False, "error": err})
                return
            status_filter = (qs.get("status") or [None])[0]
            if status_filter is not None and status_filter not in repo.JOB_STATUSES:
                self._send_json(400, {"ok": False, "error": "status must be one of %r" % (repo.JOB_STATUSES,)})
                return
            project_filter = (qs.get("project_id") or [None])[0]
            if project_filter is not None and not _UUID_RE.match(project_filter):
                self._send_json(400, {"ok": False, "error": "project_id must be a project id"})
                return
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id)
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                jobs = repo.list_job_summaries(conn, workspace_id, limit=limit, offset=offset, status=status_filter, project_id=project_filter,
                                               trial_history_cutoff=trial.history_cutoff())   # D-112: 7-day Trial history
                self._send_json(200, {"ok": True, "jobs": jobs, "limit": limit, "offset": offset})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_report_list(self, workspace_id: str, parsed: Any) -> None:
            qs = parse_qs(parsed.query)
            limit, offset, err = _parse_limit_offset(qs)
            if err:
                self._send_json(400, {"ok": False, "error": err})
                return
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id)
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                reports = repo.list_reports_by_workspace(conn, workspace_id, limit=limit, offset=offset)
                reports = [r for r in reports if not self._is_expired_trial_result(conn, r.get("job_id"))]   # D-112: 7-day Trial history
                for report in reports:
                    report.pop("storage_ref", None)  # never a raw storage path - see module docstring.
                self._send_json(200, {"ok": True, "reports": reports, "limit": limit, "offset": offset})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_report_get(self, workspace_id: str, report_id: str) -> None:
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id)
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                report = repo.get_report_by_id(conn, report_id)
                if report is None or report["workspace_id"] != workspace_id:
                    # Collapses "does not exist" and "belongs to a
                    # different workspace" into the same 404 - the same
                    # anti-enumeration property tenant_scope.py's own
                    # docstring establishes for workspace_id itself; a
                    # cross-tenant report_id guess must be
                    # indistinguishable from a nonexistent one.
                    self._send_json(404, {"ok": False, "error": "not found"})
                    return
                gate = self._trial_result_gate(conn, report.get("job_id"))
                if gate is None:
                    return
                storage_ref = report.pop("storage_ref", None)
                if storage is not None and storage_ref and not gate["trial"]:   # D-112: no download URL for a Trial report
                    report["report_url"] = storage.generate_signed_url(storage_ref, expires_in_seconds=_REPORT_SIGNED_URL_TTL_SECONDS)
                self._send_json(200, {"ok": True, "report": report})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

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
                # D-107: the plan's member ceiling (Standard 2, Pro 5,
                # owner included) - checked only for an active entitlement
                # whose plan defines one; existing members are never removed.
                entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
                if entitlement is not None and entitlement["status"] in ("active", "trialing") and entitlement["plan"] in plans.PLANS:
                    max_members = plans.PLANS[entitlement["plan"]]["max_members"]
                    if max_members is not None and len(repo.list_workspace_members(conn, workspace_id)) >= max_members:
                        self._send_json(409, {"ok": False, "error": "member_limit_reached", "detail": "the %s plan allows %d members" % (plans.PLANS[entitlement["plan"]]["display_name"], max_members)})
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
        # Jobs (Phase 4) - execution infrastructure. Submission only;
        # this endpoint never executes/compiles the submitted source -
        # see module docstring and backend/worker_supervisor.py.
        # -------------------------------------------------------------
        def _authorize_job_submit_before_body(self, workspace_id: str) -> bool:
            """Session and workspace-role checks of _handle_job_submit(),
            run before its body is read (see the call site). Same checks,
            statuses and messages as the ones after the body; on refusal the
            connection is closed because the body was never read. Returns
            True when the request may proceed to reading its body."""
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self.close_connection = True
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return False
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id, allowed_roles=("owner", "admin", "member"))
                except tenant_scope.TenantScopeError:
                    self.close_connection = True
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return False
                # D-108 submit rate limit: per user, before the body (up to
                # JOB_SUBMIT_MAX_BODY_BYTES) is read or any LOC is counted -
                # so every request from here on is one attempt whatever its
                # outcome (402/413, a duplicate idempotency_key...); only a
                # request refused right here records nothing. See
                # repository.check_submit_rate_limit(). Abuse protection
                # only - the LOC allowance is unaffected.
                retry_after = repo.check_submit_rate_limit(conn, current_user_id, workspace_id, submit_rate_limit_per_window)
                if retry_after:
                    self.close_connection = True
                    self._send_json(
                        429,
                        {"ok": False, "error": "submit_rate_limited", "retry_after_seconds": retry_after,
                         "detail": "too many scan submissions; at most %d per %d seconds" % (submit_rate_limit_per_window, repo.SUBMIT_RATE_LIMIT_WINDOW_SECONDS)},
                        extra_headers=[("Retry-After", str(retry_after))],
                    )
                    return False
                return True
            except Exception:
                self.close_connection = True
                self._send_json(500, {"ok": False, "error": "internal error"})
                return False
            finally:
                conn.close()

        def _handle_job_submit(self, workspace_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            if storage is None:
                self._send_json(503, {"ok": False, "error": "job execution is not configured"})
                return
            # Pre-15K-B hardening (docs/decisiones.md D-096): everything
            # decidable from the request line and headers runs BEFORE the
            # body (up to JOB_SUBMIT_MAX_BODY_BYTES) is read - the declared
            # size, then the session cookie and the caller's workspace role.
            # An unauthenticated or unauthorized caller is refused without
            # its body ever being read. The full checks below still run
            # unchanged after the body, in their original order.
            _, err_status, err_msg = self._check_content_length(JOB_SUBMIT_MAX_BODY_BYTES)
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            if not self._authorize_job_submit_before_body(workspace_id):
                return
            raw, err_status, err_msg = self._read_body(max_body_bytes=JOB_SUBMIT_MAX_BODY_BYTES)
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"ok": False, "error": "request body is not valid UTF-8 JSON"})
                return
            if not isinstance(payload, dict):
                self._send_json(400, {"ok": False, "error": "request body must be a JSON object"})
                return
            mode = payload.get("mode")
            source = payload.get("source")
            client_idempotency_key = payload.get("idempotency_key")
            if mode not in ("quick", "standard", "pro"):
                self._send_json(400, {"ok": False, "error": "mode must be one of quick/standard/pro"})
                return
            # D-109: exactly one input shape - "source" (one file, or a
            # bundle the client built itself, unchanged), "files" (a JSON
            # array) or "archive" (a ZIP). The last two are validated by
            # backend/submission_input.py and turned into the engine's own
            # bundle text, so EVERYTHING below (size ceiling, effective LOC,
            # admission, storage, worker) is the single-source path,
            # unchanged - one LOC count, one reservation.
            # D-111: "github" is a fourth shape - {repository_id, ref?,
            # commit_sha?} - validated here, gated by plan below, and fetched
            # by the backend itself (backend/github_integration.py) into the
            # SAME D-109 bundle; never a URL, never file content from the client.
            given = [key for key in ("source", "files", "archive", "github") if payload.get(key) is not None]
            if len(given) > 1:
                self._send_json(400, {"ok": False, "error": "only one of source, files, archive or github may be given" if "github" in given else "only one of source, files or archive may be given"})
                return
            source_kind, manifest, built, github_spec, git_source = "single", None, None, None, None
            if given and given[0] == "github":
                github_spec = self._parse_github_spec(payload["github"])
                if github_spec is None:
                    return
            if given and given[0] in ("files", "archive"):
                try:
                    if given[0] == "files":
                        built = submission_input.from_files(payload["files"], MAX_RAW_SOURCE_BYTES)
                    else:
                        built = submission_input.from_zip(submission_input.decode_archive(payload["archive"]), MAX_RAW_SOURCE_BYTES)
                except submission_input.SubmissionInputError as exc:
                    self._send_json(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.detail})
                    return
                source, source_kind, manifest = built["source"], given[0], built["files"]
            dry_run = payload.get("dry_run", False)
            if not isinstance(dry_run, bool):
                self._send_json(400, {"ok": False, "error": "dry_run must be true or false"})
                return
            project_id = payload.get("project_id")
            if project_id is not None and (not isinstance(project_id, str) or not _UUID_RE.match(project_id)):
                self._send_json(404, {"ok": False, "error": "project_not_found"})
                return
            if github_spec is None and (not isinstance(source, str) or not source.strip()):
                self._send_json(400, {"ok": False, "error": "source is required"})
                return
            # json.loads() turns a "\\ud800"-style escape into an unpaired
            # surrogate, which has no UTF-8 encoding: refuse it here instead
            # of letting .encode("utf-8") raise below (which closed the
            # connection with no response).
            if github_spec is None and not _is_utf8_encodable(source):
                self._send_json(400, {"ok": False, "error": "source must be valid Unicode text (unpaired surrogates are not allowed)"})
                return
            # Cheap, fast rejection only - see MAX_RAW_SOURCE_BYTES's own
            # comment on why the authoritative maxEffectiveLoc/
            # maxSourceFiles check happens inside the worker, not here.
            if github_spec is None and len(source.encode("utf-8")) > MAX_RAW_SOURCE_BYTES:
                self._send_json(413, {"ok": False, "error": "source exceeds the maximum submission size"})
                return
            if client_idempotency_key is not None and (not isinstance(client_idempotency_key, str) or not (1 <= len(client_idempotency_key) <= 200)):
                self._send_json(400, {"ok": False, "error": "idempotency_key must be a string of 1-200 characters"})
                return
            if client_idempotency_key is not None and not _is_utf8_encodable(client_idempotency_key):
                self._send_json(400, {"ok": False, "error": "idempotency_key must be valid Unicode text (unpaired surrogates are not allowed)"})
                return
            filename = payload.get("filename")
            if isinstance(filename, str) and not _is_utf8_encodable(filename):
                self._send_json(400, {"ok": False, "error": "filename must be valid Unicode text (unpaired surrogates are not allowed)"})
                return
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    tenant_scope.require_workspace_role(conn, current_user_id, workspace_id, allowed_roles=("owner", "admin", "member"))
                except tenant_scope.TenantScopeError:
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                if project_id is not None and repo.get_project(conn, workspace_id, project_id) is None:
                    self._send_json(404, {"ok": False, "error": "project_not_found"})
                    return
                entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
                if entitlement is None or entitlement["status"] not in ("active", "trialing"):
                    self._send_json(402, {"ok": False, "error": "this workspace has no active subscription"})
                    return
                if github_spec is not None and not plans.plan_has_feature(entitlement["plan"], plans.FEATURE_PRIVATE_GITHUB):
                    self._send_feature_not_available(entitlement["plan"])   # D-111: Quick never reaches GitHub
                    return
                # P0 plan authorization (D-086): the ONLY place that
                # decides whether an entitlement's plan may run a given
                # mode - repo.PLAN_ALLOWED_MODES is the single source of
                # truth (see that mapping's own docstring). An unknown
                # plan (should never happen - entitlements.plan has its
                # own CHECK constraint - defensive only) fails closed via
                # .get(plan, frozenset()), never an unbounded/implicit
                # allow. Never trusts the client's own request in any way
                # beyond the mode value itself, already validated above.
                if mode not in repo.PLAN_ALLOWED_MODES.get(entitlement["plan"], frozenset()):
                    self._send_json(403, {"ok": False, "error": "mode not included in the current plan"})
                    return
                idempotency_key = repo.scoped_idempotency_key(workspace_id, client_idempotency_key) if client_idempotency_key else repo.new_id()
                existing = None if dry_run else repo.get_job_by_idempotency_key(conn, idempotency_key)
                if existing is not None:
                    self._send_json(200, {"ok": True, "job_id": existing["id"], "status": existing["status"], "duplicate": True})
                    return
                if github_spec is not None:
                    fetched = self._github_submission(conn, workspace_id, current_user_id, github_spec)
                    if fetched is None:
                        return
                    built, git_source = fetched
                    source, source_kind, manifest = built["source"], "files", built["files"]
                # D-107 admission: the engine's own effective LOC (backend/
                # loc_count.py), checked against the plan before anything
                # is stored or queued.
                effective_loc = loc_count.submission_effective_loc(source)
                spec = plans.plan_spec(entitlement["plan"])   # D-112: includes the Trial (500 effective LOC per scan)
                if effective_loc <= 0:
                    self._send_json(422, {"ok": False, "error": "no_source_code", "detail": "no Solidity/Vyper source code found", "effective_loc": 0})
                    return
                if spec is not None and effective_loc > spec["max_loc_per_scan"]:
                    self._send_json(413, {"ok": False, "error": "loc_per_scan_limit_exceeded", "effective_loc": effective_loc,
                                          "max_loc_per_scan": spec["max_loc_per_scan"]})
                    return
                usage = repo.usage_summary(conn, workspace_id, entitlement) or {}
                if usage.get("usage_model") == plans.USAGE_TRIAL and usage.get("scans_available", 0) <= 0:
                    self._send_json(402, {"ok": False, "error": "trial_already_used", "effective_loc": effective_loc,
                                          "detail": "the free Trial includes exactly one scan and it has already been used"})
                    return
                if usage.get("usage_model") == plans.USAGE_SCAN_CREDIT and usage.get("scans_available", 0) <= 0:
                    self._send_json(402, {"ok": False, "error": "no_scan_credit", "detail": "no unused Quick scan is available", "effective_loc": effective_loc})
                    return
                if usage.get("usage_model") == plans.USAGE_SERVICE_MONTH and effective_loc > usage.get("loc_remaining", 0):
                    self._send_json(402, {"ok": False, "error": "loc_quota_exceeded", "effective_loc": effective_loc,
                                          "loc_remaining": usage.get("loc_remaining", 0), "period_end": usage.get("period_end")})
                    return
                if repo.count_pending_jobs(conn, workspace_id) >= max_pending_jobs_per_workspace:
                    self._send_json(429, {"ok": False, "error": "too_many_pending_jobs", "max_pending_jobs": max_pending_jobs_per_workspace})
                    return
                if dry_run:
                    # D-110 preview: the SAME checks as a real submission up
                    # to this point (same request, same rate-limit attempt,
                    # same LOC count, same per-scan/quota/pending
                    # pre-checks), then stop - nothing stored, no contract,
                    # no job, no reservation. Non-binding: the real
                    # submission re-runs every check atomically.
                    preview = {"ok": True, "dry_run": True, "admissible": True, "effective_loc": effective_loc, "source_kind": source_kind,
                               "plan": entitlement["plan"], "max_loc_per_scan": spec["max_loc_per_scan"] if spec else None, "usage": usage}
                    if built is not None:
                        preview.update({"files": built["files"], "ignored": built["ignored"], "ignored_count": built["ignored_count"]})
                    if git_source is not None:
                        preview["github"] = _public_git_source(git_source)
                    self._send_json(200, preview)
                    return
                content_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
                # A fresh id for the storage OBJECT only - decoupled from
                # the contract row's own id (create_contract() generates
                # that itself and needs storage_ref as an input, so the
                # two cannot be the same value chosen up front).
                storage_ref = object_storage.workspace_key(workspace_id, "sources", repo.new_id())
                storage.put_object(storage_ref, source.encode("utf-8"), content_type="text/plain")
                display_name = payload.get("filename") if isinstance(payload.get("filename"), str) and payload.get("filename") else (
                    "contract.sol" if source_kind == "single" else "%s submission" % source_kind)   # display only, never a path
                if git_source is not None:
                    display_name = "%s@%s" % (git_source["repository_full_name"], git_source["commit_sha"][:12])
                contract_id = repo.create_contract(conn, workspace_id, storage_ref, content_hash, display_name,
                                                   project_id=project_id, source_kind=source_kind, files=manifest, git_source=git_source)
                try:
                    job_id = repo.enqueue_job_with_usage(conn, workspace_id, contract_id, current_user_id, mode, idempotency_key, entitlement, effective_loc,
                                                         max_pending_jobs=max_pending_jobs_per_workspace)
                except repo.UsageLimitError as exc:
                    # Nothing was queued or reserved (rolled back). Only a
                    # submission that lost a concurrent race to the last of
                    # the allowance gets here (the pre-check above refuses
                    # the ordinary case before anything is stored); its
                    # contract row/object are left to retention like any
                    # other unreferenced upload.
                    status_code = {"loc_per_scan_limit_exceeded": 413, "no_source_code": 422,
                                   "too_many_pending_jobs": 429, "technical_budget_exhausted": 429}.get(exc.code, 402)
                    if exc.code == "technical_budget_exhausted":
                        alerting.emit_safe(alert_sender, alerting.EVENT_TECHNICAL_BUDGET_EXHAUSTED, "warning", {"workspace_id": workspace_id, "plan": entitlement["plan"]})
                    body = {"ok": False, "error": exc.code, "detail": exc.detail, "effective_loc": effective_loc}
                    if exc.code == "too_many_pending_jobs":
                        body["max_pending_jobs"] = max_pending_jobs_per_workspace
                    self._send_json(status_code, body)
                    return
                except db.integrity_error_class(conn):
                    # A concurrent identical submission won the idempotency_key race - same job, not an error.
                    # On Postgres, the IntegrityError above already aborted
                    # the whole transaction (unlike SQLite) - rollback()
                    # ends that aborted transaction and returns this SAME
                    # connection to a clean, usable state before the
                    # recovery lookup below, exactly the same fix already
                    # applied once in this codebase for the same bug class
                    # (repository.mark_webhook_event_processed()'s own
                    # docstring, backend/http_app.py's _handle_billing_
                    # webhook()). Without this, the SELECT below itself
                    # raises InFailedSqlTransaction on real Postgres
                    # (confirmed empirically - a real concurrent duplicate
                    # submission was turning into a spurious 500 for every
                    # losing request instead of the intended clean 200
                    # duplicate:true response) - a harmless no-op on
                    # SQLite, which never aborts a transaction on error in
                    # the first place.
                    conn.rollback()
                    winner = repo.get_job_by_idempotency_key(conn, idempotency_key)
                    self._send_json(200, {"ok": True, "job_id": winner["id"], "status": winner["status"], "duplicate": True})
                    return
                response = {"ok": True, "job_id": job_id, "status": "queued", "effective_loc": effective_loc, "source_kind": source_kind, "project_id": project_id}
                if built is not None:
                    response.update({"files": built["files"], "ignored": built["ignored"], "ignored_count": built["ignored_count"]})
                if git_source is not None:
                    response["github"] = _public_git_source(git_source)
                self._send_json(200, response)
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()



        # -------------------------------------------------------------
        # Sign-up and free Trial (D-112) - see backend/trial.py. Sign-up
        # only sends a verification link; verifying it (the existing
        # single-use magic-link token) grants the Trial. Every rule is
        # decided here, in the backend.
        # -------------------------------------------------------------
        def _handle_signup(self) -> None:
            if self._reject_if_cross_origin():
                return
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            is_form = content_type == "application/x-www-form-urlencoded"
            try:
                if is_form:
                    email_value = (parse_qs(raw.decode("utf-8")).get("email") or [None])[0]
                else:
                    payload = json.loads(raw.decode("utf-8"))
                    email_value = payload.get("email") if isinstance(payload, dict) else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"ok": False, "error": "request body is not valid UTF-8 JSON"})
                return

            def refuse(status: int, code: str, title: str, detail: str) -> None:
                if is_form:
                    self._send_html(status, _render_signup_page(title, detail))
                else:
                    self._send_json(status, {"ok": False, "error": code, "detail": detail})

            host = self.headers.get("Host", "")
            if host.split(":")[0] not in host_allowlist:
                refuse(400, "unrecognized host", "Sign-up failed", "Unrecognized host.")
                return
            try:
                normalized = email_policy.normalize_email(email_value)
            except auth.AuthError:
                refuse(400, "invalid_email", "Check your email address", "Enter a valid email address.")
                return
            if trial_policy.is_disposable(normalized):
                # Deterministic and checked BEFORE any token or email exists:
                # no account, no link, no Trial for this address.
                refuse(422, "disposable_email_not_allowed", "Use another email address", trial.NOT_ELIGIBLE_DETAIL)
                return
            conn = connect_fn()
            try:
                token = auth.request_magic_link(conn, normalized, self._client_ip(), purpose="signup")
            except auth.RateLimitExceeded:
                alerting.emit_safe(alert_sender, alerting.EVENT_AUTH_RATE_LIMIT, "warning", {"ip": self._client_ip()})
                refuse(429, "signup_rate_limited", "Please wait", "Too many requests. Please wait a few minutes and try again.")
                return
            except auth.AuthError:
                refuse(400, "invalid_email", "Check your email address", "Enter a valid email address.")
                return
            except Exception:
                refuse(500, "internal error", "Sign-up failed", "Something went wrong. Please try again.")
                return
            finally:
                conn.close()
            scheme = "https" if secure_cookies else "http"
            verify_url = "%s://%s/auth/verify?token=%s&redirect=%s" % (scheme, host, quote(token), quote("/app#/dashboard", safe=""))
            try:
                email_sender.send(normalized, "Verify your email for Vericexa",
                                  "Confirm your email address to start your free Vericexa Trial (link expires in 15 minutes): %s" % verify_url)
            except Exception as exc:
                alerting.emit_safe(alert_sender, alerting.EVENT_EMAIL_DELIVERY_FAILURE, "error", {"ip": self._client_ip(), "error_type": type(exc).__name__})
            # Same answer whether or not an account already exists for this
            # address (anti-enumeration, like /auth/request-link).
            if is_form:
                self._send_html(200, _render_signup_page("Check your email", SIGNUP_SENT_MESSAGE))
            else:
                self._send_json(200, {"ok": True, "message": SIGNUP_SENT_MESSAGE})

        def _grant_trial_after_signup(self, conn: Any, user_id: str) -> None:
            """A verified sign-up link: grant the Trial when eligible. A
            refusal (already used, not eligible) never blocks the sign-in;
            the app shows the Trial state from GET /trial."""
            try:
                user = repo.get_user(conn, user_id)
                if user is not None:
                    trial.grant_for_user(conn, user, trial_policy)
            except trial.TrialError:
                pass
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass

        def _handle_trial_status(self) -> None:
            conn = connect_fn()
            try:
                user_id = self._current_user_id(conn)
                if user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                user = repo.get_user(conn, user_id)
                self._send_json(200, {"ok": True, "trial": trial.status_for_user(conn, user, trial_policy)})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_trial_activate(self) -> None:
            if self._reject_if_cross_origin():
                return
            _, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            conn = connect_fn()
            try:
                user_id = self._current_user_id(conn)
                if user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                try:
                    workspace_id = trial.grant_for_user(conn, repo.get_user(conn, user_id), trial_policy)
                except trial.TrialError as exc:
                    self._send_json(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.detail})
                    return
                self._send_json(200, {"ok": True, "workspace_id": workspace_id})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _is_expired_trial_result(self, conn: Any, job_id: Optional[str]) -> bool:
            usage = repo.get_job_usage(conn, job_id) if job_id else None
            if not usage or usage.get("plan") != plans.PLAN_TRIAL:
                return False
            job = repo.get_job(conn, job_id) or {}
            created = repo._parse_iso(job.get("created_at"))
            return created is not None and created < repo._parse_iso(trial.history_cutoff())

        def _trial_result_gate(self, conn: Any, job_id: Optional[str], refuse_download: bool = False) -> Optional[Dict[str, bool]]:
            """{"trial": bool} for a job/report the caller may already see,
            or None after a refusal: a Trial scan older than the Trial's
            7-day history (410), or a download of a Trial report (403).
            Decided by the plan the scan was ADMITTED under (job_usage), so
            a later upgrade never re-opens a Trial result's limits."""
            usage = repo.get_job_usage(conn, job_id) if job_id else None
            if not usage or usage.get("plan") != plans.PLAN_TRIAL:
                return {"trial": False}
            if self._is_expired_trial_result(conn, job_id):
                self._send_json(410, {"ok": False, "error": "trial_history_expired", "detail": "Trial results are kept for %d days" % plans.TRIAL["history_days"]})
                return None
            if refuse_download:
                self._send_json(403, {"ok": False, "error": "feature_not_available", "feature": "report_download", "plan": plans.PLAN_TRIAL,
                                      "detail": "Report downloads are not included in the free Trial"})
                return None
            return {"trial": True}

        # -------------------------------------------------------------
        # Private GitHub (D-111) - Standard/Pro only, enforced HERE (the
        # web app merely hides the option). See backend/github_integration.py
        # for the authorization model, token protection and SSRF/size
        # bounds. Every endpoint resolves the caller's membership first,
        # then the workspace's active plan, then the member's OWN
        # connection in that workspace - a connection is never shared with
        # other members or usable from another workspace.
        # -------------------------------------------------------------
        def _send_feature_not_available(self, plan_name: Optional[str]) -> None:
            self._send_json(403, {"ok": False, "error": "feature_not_available", "feature": plans.FEATURE_PRIVATE_GITHUB, "plan": plan_name,
                                  "detail": "Private GitHub is available on the Standard and Pro plans"})

        def _send_github_error(self, conn: Any, workspace_id: str, connection: Optional[Dict[str, Any]], exc: "github_integration.GitHubError") -> None:
            if exc.code == "github_reconnect_required" and connection is not None:
                try:
                    repo.set_github_connection_status(conn, workspace_id, connection["id"], "invalid")
                except Exception:
                    pass
            body: Dict[str, Any] = {"ok": False, "error": exc.code, "detail": exc.detail}
            headers = None
            if exc.retry_after:
                body["retry_after_seconds"] = exc.retry_after
                headers = [("Retry-After", str(exc.retry_after))]
            self._send_json(exc.http_status, body, extra_headers=headers)

        def _github_scope(self, conn: Any, workspace_id: str, require_configured: bool = True) -> Optional[str]:
            """The current user id after the membership, active-plan and
            Private GitHub feature checks (and, by default, the configured
            check), or None after sending 401/402/403/503."""
            current_user_id = self._project_scope(conn, workspace_id)
            if current_user_id is None:
                return None
            entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
            if entitlement is None or entitlement["status"] not in ("active", "trialing"):
                self._send_json(402, {"ok": False, "error": "this workspace has no active subscription"})
                return None
            if not plans.plan_has_feature(entitlement["plan"], plans.FEATURE_PRIVATE_GITHUB):
                self._send_feature_not_available(entitlement["plan"])
                return None
            if require_configured and github is None:
                self._send_json(503, {"ok": False, "error": "github_not_configured", "detail": "Private GitHub is not configured on this server"})
                return None
            return current_user_id

        def _github_connection_or_refuse(self, conn: Any, workspace_id: str, user_id: str) -> Optional[Dict[str, Any]]:
            connection = repo.get_active_github_connection(conn, workspace_id, user_id)
            if connection is None:
                self._send_json(409, {"ok": False, "error": "github_not_connected", "detail": "connect GitHub first"})
            return connection

        def _handle_github_status(self, workspace_id: str) -> None:
            conn = connect_fn()
            try:
                user_id = self._github_scope(conn, workspace_id, require_configured=False)
                if user_id is None:
                    return
                connection = repo.get_active_github_connection(conn, workspace_id, user_id) if github is not None else None
                public = {k: connection.get(k) for k in repo.GITHUB_CONNECTION_PUBLIC_FIELDS} if connection else None
                self._send_json(200, {"ok": True, "configured": github is not None, "connection": public,
                                      "install_url": github.client.install_url() if github is not None else None})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_github_connect(self, workspace_id: str) -> None:
            """Starts the GitHub App authorization: a fresh single-use state
            (only its hash is stored), bound to this member and workspace.
            Returns the github.com URL for the browser to open - a POST, so
            the Origin check applies and no third-party page can start it."""
            if self._reject_if_cross_origin():
                return
            _, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            conn = connect_fn()
            try:
                user_id = self._github_scope(conn, workspace_id)
                if user_id is None:
                    return
                state, digest = github.new_state()
                repo.create_github_oauth_state(conn, digest, workspace_id, user_id, github_integration.OAUTH_STATE_TTL_SECONDS)
                self._send_json(200, {"ok": True, "authorize_url": github.client.authorize_url(state)})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _github_callback_redirect(self, outcome: str, workspace_id: Optional[str] = None) -> None:
            location = "/app#/scan/new?github=" + outcome + ("&workspace=" + workspace_id if workspace_id and _UUID_RE.match(workspace_id) else "")
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _handle_github_callback(self, parsed: Any) -> None:
            """GitHub redirects the member's browser here (a top-level GET,
            so there is no Origin to check): the state must exist, be
            unexpired, unused and belong to the member whose session cookie
            arrives with the request - it is consumed atomically, so a
            replay or a state started by someone else is refused. Membership
            and plan are checked again before the code is exchanged. The
            outcome goes back to the app as a fixed word, never GitHub's
            own error text; code and state are redacted from the access log."""
            if github is None:
                self._github_callback_redirect("not_configured")
                return
            qs = parse_qs(parsed.query)
            state = (qs.get("state") or [""])[0]
            code = (qs.get("code") or [""])[0]
            conn = connect_fn()
            try:
                user_id = self._current_user_id(conn)
                if user_id is None:
                    self.send_response(302)
                    self.send_header("Location", "/auth/login")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                row = repo.consume_github_oauth_state(conn, github_integration.state_hash(state), user_id) if 1 <= len(state) <= 200 else None
                if row is None:
                    self._github_callback_redirect("invalid_state")
                    return
                workspace_id = row["workspace_id"]
                try:
                    tenant_scope.require_workspace_role(conn, user_id, workspace_id, allowed_roles=("owner", "admin", "member"))
                except tenant_scope.TenantScopeError:
                    self._github_callback_redirect("invalid_state")
                    return
                entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
                if entitlement is None or entitlement["status"] not in ("active", "trialing") or not plans.plan_has_feature(entitlement["plan"], plans.FEATURE_PRIVATE_GITHUB):
                    self._github_callback_redirect("not_available", workspace_id)
                    return
                if (qs.get("error") or [None])[0] is not None:
                    self._github_callback_redirect("denied", workspace_id)
                    return
                if not (1 <= len(code) <= 200):
                    self._github_callback_redirect("failed", workspace_id)
                    return
                try:
                    grant = github.client.exchange_code(code)
                    account = github.client.get_user(grant["access_token"])
                except github_integration.GitHubError:
                    self._github_callback_redirect("failed", workspace_id)
                    return
                now = datetime.now(timezone.utc)
                fields = github.encrypted_token_fields(workspace_id, user_id, grant, now)
                scopes = grant.get("scope") if isinstance(grant.get("scope"), str) else ""
                repo.save_github_connection(conn, workspace_id, user_id, account["id"], account["login"], scopes[:200], **fields)
                self._github_callback_redirect("connected", workspace_id)
            except Exception:
                self._github_callback_redirect("failed")
            finally:
                conn.close()

        def _handle_github_disconnect(self, workspace_id: str) -> None:
            """Removes the member's own connection: tokens wiped from the
            database (the row is kept, revoked, for history) and, best
            effort, the token revoked at GitHub. Allowed on any plan, so a
            workspace that moved to Quick can still remove its credential."""
            if self._reject_if_cross_origin():
                return
            conn = connect_fn()
            try:
                user_id = self._project_scope(conn, workspace_id)
                if user_id is None:
                    return
                connection = repo.get_active_github_connection(conn, workspace_id, user_id)
                if connection is not None and github is not None:
                    try:
                        token = github.cipher.decrypt(connection["access_token_enc"], github_integration.token_associated_data(workspace_id, user_id, "access"))
                        github.client.revoke(token)
                    except github_integration.GitHubError:
                        pass
                disconnected = repo.set_github_connection_status(conn, workspace_id, connection["id"], "revoked") if connection else False
                self._send_json(200, {"ok": True, "disconnected": disconnected})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_github_repositories(self, workspace_id: str) -> None:
            conn = connect_fn()
            try:
                user_id = self._github_scope(conn, workspace_id)
                if user_id is None:
                    return
                connection = self._github_connection_or_refuse(conn, workspace_id, user_id)
                if connection is None:
                    return
                try:
                    token = github.access_token(conn, connection)
                    conn.commit()
                    repositories, truncated = github.client.list_repositories(token)
                except github_integration.GitHubError as exc:
                    self._send_github_error(conn, workspace_id, connection, exc)
                    return
                self._send_json(200, {"ok": True, "repositories": repositories, "truncated": truncated, "install_url": github.client.install_url()})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_github_branches(self, workspace_id: str, raw_repository_id: str) -> None:
            conn = connect_fn()
            try:
                user_id = self._github_scope(conn, workspace_id)
                if user_id is None:
                    return
                try:
                    repository_id = github_integration.parse_repository_id(raw_repository_id)
                except github_integration.GitHubError:
                    self._send_json(404, {"ok": False, "error": "not found"})
                    return
                connection = self._github_connection_or_refuse(conn, workspace_id, user_id)
                if connection is None:
                    return
                try:
                    token = github.access_token(conn, connection)
                    conn.commit()
                    repository = github.client.get_repository(token, repository_id)
                    branches, truncated = github.client.list_branches(token, repository["full_name"])
                except github_integration.GitHubError as exc:
                    self._send_github_error(conn, workspace_id, connection, exc)
                    return
                self._send_json(200, {"ok": True, "repository": repository, "branches": branches, "truncated": truncated})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _parse_github_spec(self, spec: Any) -> Optional[Dict[str, Any]]:
            """The "github" field of a job submission, or None after a 400."""
            try:
                if not isinstance(spec, dict) or set(spec) - {"repository_id", "ref", "commit_sha"}:
                    raise github_integration.GitHubError("invalid_github_source", "github must be an object {repository_id, ref, commit_sha}", 400)
                return {"repository_id": github_integration.parse_repository_id(spec.get("repository_id")),
                        "ref": github_integration.validate_branch_name(spec["ref"]) if spec.get("ref") is not None else None,
                        "commit_sha": github_integration.validate_commit_sha(spec["commit_sha"]) if spec.get("commit_sha") is not None else None}
            except github_integration.GitHubError as exc:
                self._send_json(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.detail})
                return None

        def _github_submission(self, conn: Any, workspace_id: str, user_id: str, spec: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
            """Fetches the pinned commit through the member's own connection
            and builds the D-109 bundle - (built, git_source) or None after
            an error response. The plan was already checked by the caller."""
            if github is None:
                self._send_json(503, {"ok": False, "error": "github_not_configured", "detail": "Private GitHub is not configured on this server"})
                return None
            connection = self._github_connection_or_refuse(conn, workspace_id, user_id)
            if connection is None:
                return None
            try:
                token = github.access_token(conn, connection)
                conn.commit()   # no database transaction stays open while GitHub is called
                target = github_integration.resolve_scan_commit(github.client, token, spec["repository_id"], spec["ref"], spec["commit_sha"])
                entries = github_integration.fetch_repository_entries(github.client, token, target["repository"]["full_name"], target["commit_sha"], MAX_RAW_SOURCE_BYTES)
                built = submission_input.from_repository_entries(entries, MAX_RAW_SOURCE_BYTES)
            except github_integration.GitHubError as exc:
                self._send_github_error(conn, workspace_id, connection, exc)
                return None
            except submission_input.SubmissionInputError as exc:
                self._send_json(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.detail})
                return None
            return built, {"connection_id": connection["id"], "repository_id": target["repository"]["id"],
                           "repository_full_name": target["repository"]["full_name"], "ref": target["ref"], "commit_sha": target["commit_sha"]}

        # -------------------------------------------------------------
        # SaaS web app (D-110) - ONE vanilla-JS app served by this same
        # backend under /app (same origin as the JSON API, so the HttpOnly
        # session cookie and the Origin-header CSRF check apply unchanged).
        # The shell carries no data at all: every number on screen comes
        # from the JSON endpoints below, which stay the only authority
        # (admission, usage, billing). The public marketing site
        # (website/) is a separate, static product and is not involved.
        # -------------------------------------------------------------
        def _send_app_bytes(self, status: int, body: bytes, content_type: str, cache_control: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache_control)
            for key, value in _APP_SECURITY_HEADERS:
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _handle_app_shell(self) -> None:
            conn = connect_fn()
            try:
                signed_in = self._current_user_id(conn) is not None
            finally:
                conn.close()
            if not signed_in:
                self.send_response(302)
                self.send_header("Location", "/auth/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = _read_webapp_file("index.html")
            if body is None:
                self._send_json(503, {"ok": False, "error": "web app is not available"})
                return
            self._send_app_bytes(200, body, "text/html; charset=utf-8", "no-store")

        def _handle_app_static(self, name: str) -> None:
            entry = _WEBAPP_STATIC.get(name)
            body = _read_webapp_file(name) if entry else None
            if body is None:
                self._send_json(404, {"ok": False, "error": "not found"})
                return
            self._send_app_bytes(200, body, entry, "no-cache")

        def _handle_me(self) -> None:
            conn = connect_fn()
            try:
                current_user_id = self._current_user_id(conn)
                if current_user_id is None:
                    self._send_json(401, {"ok": False, "error": "authentication required"})
                    return
                user = repo.get_user(conn, current_user_id) or {}
                self._send_json(200, {"ok": True, "user": {"id": user.get("id"), "email": user.get("email")}})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_billing_plans(self) -> None:
            """Display data for the plan catalog (D-110): backend/plans.py
            only - never a Stripe Price ID, never a rule the browser
            enforces (checkout and admission stay server-side)."""
            spec = plans.TRIAL   # D-112: shown, never sold - no checkout, no portal, no Stripe price
            catalog = [{"plan": plans.PLAN_TRIAL, "display_name": spec["display_name"], "billing_type": spec["billing_type"], "usage_model": spec["usage_model"],
                        "max_loc_per_scan": spec["max_loc_per_scan"], "monthly_loc_quota": None, "scans_per_purchase": None,
                        "scans_per_email": spec["scans_per_email"], "max_projects": spec["max_projects"], "max_members": spec["max_members"],
                        "queue_priority": spec["queue_priority"], "priority_support": spec["priority_support"], "history_days": spec["history_days"],
                        "report_downloads": spec["report_downloads"], "allowed_modes": sorted(plans.PLAN_ALLOWED_MODES[plans.PLAN_TRIAL]),
                        "features": sorted(plans.PLAN_FEATURES[plans.PLAN_TRIAL]), "checkout": False,
                        "prices": [{"interval": "free", "amount_cents": 0, "currency": "usd", "service_months": None}]}]
            for name in plans.PLANS_ORDER:
                spec = plans.PLANS[name]
                prices = [{"interval": mode["interval"], "amount_cents": mode["amount_cents"], "currency": mode["currency"], "service_months": mode["service_months"]}
                          for mode in plans.PRICE_MODES.values() if mode["plan"] == name]
                catalog.append({"plan": name, "display_name": spec["display_name"], "billing_type": spec["billing_type"], "usage_model": spec["usage_model"],
                                "max_loc_per_scan": spec["max_loc_per_scan"], "monthly_loc_quota": spec["monthly_loc_quota"],
                                "scans_per_purchase": spec["scans_per_purchase"], "max_projects": spec["max_projects"], "max_members": spec["max_members"],
                                "queue_priority": spec["queue_priority"], "priority_support": spec["priority_support"],
                                "allowed_modes": sorted(plans.PLAN_ALLOWED_MODES[name]), "features": sorted(plans.PLAN_FEATURES[name]), "prices": prices})
            self._send_json(200, {"ok": True, "plans": catalog})

        def _load_report_for(self, conn: Any, workspace_id: str, report_id: str) -> Optional[Dict[str, Any]]:
            """The report row (storage_ref still inside) after the session,
            membership and same-workspace checks, or None after a 401/403/404."""
            if self._project_scope(conn, workspace_id) is None:
                return None
            report = repo.get_report_by_id(conn, report_id) if _UUID_RE.match(report_id) else None
            if report is None or report["workspace_id"] != workspace_id:
                self._send_json(404, {"ok": False, "error": "not found"})
                return None
            return report

        def _storage_bytes(self, key: str) -> Optional[bytes]:
            if storage is None:
                return None
            try:
                return storage.get_object(key)
            except Exception:
                return None

        def _storage_json(self, key: str) -> Optional[Any]:
            data = self._storage_bytes(key)
            if data is None:
                return None
            try:
                return json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return None

        def _handle_report_document(self, workspace_id: str, report_id: str) -> None:
            """Everything the report viewer shows, read through this backend
            (never a storage key or signed URL): the structured report JSON
            when the worker stored one (D-110), the rendered Markdown, the
            Layer 2 advisory section when present, and the job/project
            context. A purged report keeps its metadata, not its content."""
            conn = connect_fn()
            try:
                report = self._load_report_for(conn, workspace_id, report_id)
                if report is None:
                    return
                gate = self._trial_result_gate(conn, report.get("job_id"))
                if gate is None:
                    return
                ref = report.pop("storage_ref", None)
                purged = report.get("purged_at") is not None
                job = repo.get_job(conn, report["job_id"]) or {}
                contract = repo.get_contract(conn, job.get("contract_id")) if job.get("contract_id") else None
                contract = contract if contract and contract.get("workspace_id") == workspace_id else {}
                project = repo.get_project(conn, workspace_id, contract["project_id"]) if contract.get("project_id") else None
                content = {"scored_report": None, "markdown": None, "advisory": None}
                if ref and not purged:
                    markdown = self._storage_bytes(ref)
                    content = {
                        "scored_report": self._storage_json(object_storage.report_json_key(ref)),
                        "markdown": markdown.decode("utf-8", "replace") if markdown is not None else None,
                        "advisory": None if gate["trial"] else self._storage_json(ref + targeted_review.OBJECT_SUFFIX),   # D-112: no Layer 2 in the Trial
                    }
                self._send_json(200, dict({
                    "ok": True, "report": report, "purged": purged, "trial": gate["trial"], "downloads": not gate["trial"],
                    "job": {k: job.get(k) for k in ("id", "status", "mode", "created_at", "started_at", "completed_at")},
                    "source": {"kind": contract.get("source_kind"), "name": contract.get("name"), "project_id": contract.get("project_id"),
                               "project_name": project.get("name") if project else None,
                               "git": repo.get_contract_git_source(conn, workspace_id, contract["id"]) if contract.get("id") else None},   # D-111
                }, **content))
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_report_download(self, workspace_id: str, report_id: str, parsed: Any) -> None:
            fmt = (parse_qs(parsed.query).get("format") or [None])[0]
            if fmt not in ("json", "markdown"):
                self._send_json(400, {"ok": False, "error": "format must be json or markdown"})
                return
            conn = connect_fn()
            try:
                report = self._load_report_for(conn, workspace_id, report_id)
                if report is None:
                    return
                if self._trial_result_gate(conn, report.get("job_id"), refuse_download=True) is None:
                    return
                ref = report.get("storage_ref")
                if report.get("purged_at") is not None or not ref:
                    self._send_json(404, {"ok": False, "error": "report_content_unavailable"})
                    return
                if fmt == "json":
                    body = self._storage_bytes(object_storage.report_json_key(ref))
                    content_type, ext = "application/json; charset=utf-8", "json"
                else:
                    body = self._storage_bytes(ref)
                    content_type, ext = "text/markdown; charset=utf-8", "md"
                if body is None:
                    self._send_json(404, {"ok": False, "error": "report_content_unavailable"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", 'attachment; filename="vericexa-report-%s.%s"' % (report_id, ext))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        # -------------------------------------------------------------
        # Projects (D-109) - CRUD inside one workspace. Every handler
        # resolves the caller's workspace role first (403 for a non-member
        # or a nonexistent workspace, the existing convention), then looks
        # the project up by (workspace_id, project_id) - a project of any
        # other workspace is indistinguishable from a missing one (404).
        # No entitlement/plan input: no plan limits projects.
        # -------------------------------------------------------------
        def _project_scope(self, conn: Any, workspace_id: str, allowed_roles: Tuple[str, ...] = ("owner", "admin", "member")) -> Optional[str]:
            """Returns the current user id, or None after sending 401/403."""
            current_user_id = self._current_user_id(conn)
            if current_user_id is None:
                self._send_json(401, {"ok": False, "error": "authentication required"})
                return None
            try:
                tenant_scope.require_workspace_role(conn, current_user_id, workspace_id, allowed_roles=allowed_roles)
            except tenant_scope.TenantScopeError:
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return None
            return current_user_id

        def _read_project_name(self) -> Optional[str]:
            """The validated "name" of a JSON body, or None after sending 400."""
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return None
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"ok": False, "error": "request body is not valid UTF-8 JSON"})
                return None
            name = payload.get("name") if isinstance(payload, dict) else None
            name = name.strip() if isinstance(name, str) else None
            if (not name or len(name) > repo.MAX_PROJECT_NAME_LENGTH or not _is_utf8_encodable(name)
                    or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)):
                self._send_json(400, {"ok": False, "error": "name must be a non-empty string of at most %d characters without control characters" % repo.MAX_PROJECT_NAME_LENGTH})
                return None
            return name

        def _handle_project_create(self, workspace_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            name = self._read_project_name()
            if name is None:
                return
            conn = connect_fn()
            try:
                if self._project_scope(conn, workspace_id) is None:
                    return
                # D-112: a plan that defines a project ceiling (only the
                # Trial: 1) creates under the per-workspace lock, so the
                # ceiling holds under concurrency; Quick/Standard/Pro define
                # none and keep the unchanged create_project() path.
                entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
                spec = plans.plan_spec(entitlement["plan"]) if entitlement is not None and entitlement["status"] in ("active", "trialing") else None
                try:
                    if spec is not None and spec["max_projects"] is not None:
                        project_id = repo.create_project_capped(conn, workspace_id, name, spec["max_projects"])
                    else:
                        project_id = repo.create_project(conn, workspace_id, name)
                except repo.ProjectLimitError:
                    self._send_json(409, {"ok": False, "error": "project_limit_reached", "max_projects": spec["max_projects"],
                                          "detail": "the %s plan includes %d project" % (spec["display_name"], spec["max_projects"])})
                    return
                except repo.ProjectNameTakenError:
                    self._send_json(409, {"ok": False, "error": "project_name_taken"})
                    return
                self._send_json(200, {"ok": True, "project": repo.get_project(conn, workspace_id, project_id)})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_project_list(self, workspace_id: str, parsed: Any) -> None:
            limit, offset, err = _parse_limit_offset(parse_qs(parsed.query))
            if err:
                self._send_json(400, {"ok": False, "error": err})
                return
            conn = connect_fn()
            try:
                if self._project_scope(conn, workspace_id, ("owner", "admin", "member")) is None:
                    return
                projects = repo.list_projects(conn, workspace_id, limit=limit, offset=offset)
                self._send_json(200, {"ok": True, "projects": projects, "limit": limit, "offset": offset})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_project_get(self, workspace_id: str, project_id: str) -> None:
            conn = connect_fn()
            try:
                if self._project_scope(conn, workspace_id, ("owner", "admin", "member")) is None:
                    return
                project = repo.get_project(conn, workspace_id, project_id) if _UUID_RE.match(project_id) else None
                if project is None:
                    self._send_json(404, {"ok": False, "error": "project_not_found"})
                    return
                self._send_json(200, {"ok": True, "project": project})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_project_rename(self, workspace_id: str, project_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            name = self._read_project_name()
            if name is None:
                return
            conn = connect_fn()
            try:
                if self._project_scope(conn, workspace_id) is None:
                    return
                try:
                    renamed = _UUID_RE.match(project_id) is not None and repo.rename_project(conn, workspace_id, project_id, name)
                except repo.ProjectNameTakenError:
                    self._send_json(409, {"ok": False, "error": "project_name_taken"})
                    return
                if not renamed:
                    self._send_json(404, {"ok": False, "error": "project_not_found"})
                    return
                self._send_json(200, {"ok": True, "project": repo.get_project(conn, workspace_id, project_id)})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_project_delete(self, workspace_id: str, project_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            conn = connect_fn()
            try:
                if self._project_scope(conn, workspace_id, ("owner", "admin")) is None:
                    return
                if not (_UUID_RE.match(project_id) and repo.delete_project(conn, workspace_id, project_id)):
                    self._send_json(404, {"ok": False, "error": "project_not_found"})
                    return
                self._send_json(200, {"ok": True, "deleted": True})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_job_get(self, workspace_id: str, job_id: str) -> None:
            """D-109: one job with its source metadata - submission kind,
            project, display name and, for a multi-file/ZIP scan, the
            per-file manifest. Never the storage key or any file content."""
            conn = connect_fn()
            try:
                if self._project_scope(conn, workspace_id, ("owner", "admin", "member")) is None:
                    return
                job = repo.get_job(conn, job_id) if _UUID_RE.match(job_id) else None
                if job is None or job["workspace_id"] != workspace_id:
                    self._send_json(404, {"ok": False, "error": "not found"})
                    return
                if self._trial_result_gate(conn, job_id) is None:
                    return
                contract = repo.get_contract(conn, job["contract_id"]) or {}
                source = {"kind": contract.get("source_kind", "single"), "project_id": contract.get("project_id"), "name": contract.get("name"),
                          "files": repo.list_contract_files(conn, workspace_id, job["contract_id"]),
                          "git": repo.get_contract_git_source(conn, workspace_id, job["contract_id"])}   # D-111: repository/ref/commit of a GitHub scan
                report = repo.get_report_by_job(conn, workspace_id, job_id)
                report_summary = {k: report.get(k) for k in ("id", "score_status", "score", "risk_band", "created_at", "purged_at")} if report else None
                self._send_json(200, {"ok": True, "job": job, "source": source, "usage": repo.get_job_usage(conn, job_id), "report": report_summary})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        # -------------------------------------------------------------
        # Billing (Phase 3) - see module docstring on billing.
        # -------------------------------------------------------------
        def _handle_billing_checkout(self) -> None:
            if self._reject_if_cross_origin():
                return
            if billing is None:
                self._send_json(503, {"ok": False, "error": "billing is not configured"})
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
            workspace_id = payload.get("workspace_id") if isinstance(payload, dict) else None
            plan = payload.get("plan") if isinstance(payload, dict) else None
            interval = payload.get("interval") if isinstance(payload, dict) else None
            if not isinstance(workspace_id, str) or not workspace_id:
                self._send_json(400, {"ok": False, "error": "workspace_id is required"})
                return
            if plan == plans.PLAN_QUICK and interval is None:
                interval = plans.INTERVAL_ONE_TIME
            if not isinstance(plan, str) or not isinstance(interval, str) or billing_module.price_key(plan, interval) is None:
                self._send_json(400, {"ok": False, "error": "unknown plan or billing interval"})
                return
            host = self.headers.get("Host", "")
            if host.split(":")[0] not in host_allowlist:
                self._send_json(400, {"ok": False, "error": "unrecognized host"})
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
                existing = repo.get_entitlement_by_workspace(conn, workspace_id)
                if existing is not None and existing["plan"] in _SUBSCRIPTION_PLANS and existing["status"] in ("active", "trialing"):
                    self._send_json(409, {"ok": False, "error": "this workspace already has an active subscription"})
                    return
                if plan == plans.PLAN_QUICK and existing is not None and existing["plan"] == plans.PLAN_QUICK and (repo.usage_summary(conn, workspace_id, existing) or {}).get("scans_available", 0) > 0:
                    self._send_json(409, {"ok": False, "error": "this workspace already has an unused Quick scan"})
                    return
                scheme = "https" if secure_cookies else "http"
                success_path = auth.validate_redirect_path(payload.get("success_path") if isinstance(payload, dict) else None)
                cancel_path = auth.validate_redirect_path(payload.get("cancel_path") if isinstance(payload, dict) else None)
                # Black Friday (D-086): re-evaluated fresh on EVERY
                # request, from server-side config/clock only - payload
                # carries no discount/coupon/campaign-flag field of any
                # kind, and none is ever read here. See backend/
                # black_friday.py's own docstring on why this is safe
                # regardless of what the website currently shows/showed.
                promotion_code_id = black_friday.resolve_promotion_code(
                    interval, datetime.now(timezone.utc),
                    black_friday_enabled, black_friday_start, black_friday_end, black_friday_promotion_code_id,
                )
                try:
                    session = billing.create_checkout_session(
                        plan=plan,
                        interval=interval,
                        workspace_id=workspace_id,
                        success_url="%s://%s%s" % (scheme, host, success_path),
                        cancel_url="%s://%s%s" % (scheme, host, cancel_path),
                        customer_id=existing["stripe_customer_id"] if existing is not None else None,
                        black_friday_promotion_code_id=promotion_code_id,
                    )
                except billing_module.PriceNotAllowedError:
                    self._send_json(400, {"ok": False, "error": "unknown plan or billing interval"})
                    return
                except billing_module.BillingNotConfiguredError:
                    # D-107: fail closed if a price mode has no Price ID
                    # (defensive - startup validation requires all five).
                    self._send_json(503, {"ok": False, "error": "billing_not_configured", "detail": "this plan cannot be purchased yet"})
                    return
                self._send_json(200, {"ok": True, "checkout_url": session.get("url")})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_billing_portal(self) -> None:
            if self._reject_if_cross_origin():
                return
            if billing is None:
                self._send_json(503, {"ok": False, "error": "billing is not configured"})
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
            workspace_id = payload.get("workspace_id") if isinstance(payload, dict) else None
            if not isinstance(workspace_id, str) or not workspace_id:
                self._send_json(400, {"ok": False, "error": "workspace_id is required"})
                return
            host = self.headers.get("Host", "")
            if host.split(":")[0] not in host_allowlist:
                self._send_json(400, {"ok": False, "error": "unrecognized host"})
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
                existing = repo.get_entitlement_by_workspace(conn, workspace_id)
                if existing is None or not existing.get("stripe_customer_id"):
                    self._send_json(400, {"ok": False, "error": "this workspace has no billing account yet"})
                    return
                if existing["plan"] not in _SUBSCRIPTION_PLANS or not existing.get("stripe_subscription_id"):
                    # D-107: Quick is a one-time purchase, not a subscription to manage.
                    self._send_json(409, {"ok": False, "error": "this workspace has no subscription to manage"})
                    return
                scheme = "https" if secure_cookies else "http"
                return_path = auth.validate_redirect_path(payload.get("return_path") if isinstance(payload, dict) else None)
                session = billing.create_portal_session(
                    customer_id=existing["stripe_customer_id"],
                    return_url="%s://%s%s" % (scheme, host, return_path),
                )
                self._send_json(200, {"ok": True, "portal_url": session.get("url")})
            except Exception:
                self._send_json(500, {"ok": False, "error": "internal error"})
            finally:
                conn.close()

        def _handle_billing_webhook(self) -> None:
            # No _reject_if_cross_origin() here - see module docstring on
            # billing: Stripe's servers call this directly and send no
            # Origin header at all; the Stripe-Signature check below,
            # verified over the untouched raw body, IS this endpoint's
            # authentication.
            if billing is None:
                self._send_json(503, {"ok": False, "error": "billing is not configured"})
                return
            raw, err_status, err_msg = self._read_body()
            if err_status:
                self._send_json(err_status, {"ok": False, "error": err_msg})
                return
            sig_header = self.headers.get("Stripe-Signature", "")
            try:
                event = billing.verify_and_parse_webhook(raw, sig_header)
            except billing_module.WebhookVerificationError:
                # The body was already fully read above (unlike
                # _reject_if_cross_origin()'s rejections), so there is no
                # unread-body reason to force close_connection here.
                self._send_json(400, {"ok": False, "error": "invalid signature"})
                return
            event_id = event.get("id")
            event_type = event.get("type")
            if not isinstance(event_id, str) or not event_id or not isinstance(event_type, str) or not event_type:
                self._send_json(400, {"ok": False, "error": "malformed event"})
                return
            event_created_at = billing_module.stripe_timestamp_to_iso(event.get("created"))
            conn = connect_fn()
            try:
                # True here means "(re)process it now" - a fresh event.id,
                # OR a previously FAILED one being retried; only an event
                # that previously SUCCEEDED is ever treated as a duplicate
                # - see record_webhook_event()'s own docstring (Phase 3
                # webhook hardening, docs/decisiones.md D-077 follow-up).
                should_process = repo.record_webhook_event(conn, event_id, event_type)
                if not should_process:
                    self._send_json(200, {"ok": True, "duplicate": True})
                    return
                obj = ((event.get("data") or {}).get("object")) or {}
                try:
                    _apply_webhook_event(conn, event_type, obj, event_created_at, billing)
                    repo.mark_webhook_event_processed(conn, event_id)
                    self._send_json(200, {"ok": True})
                except Exception as exc:
                    # On Postgres, the exception above already aborted the
                    # whole transaction (unlike SQLite) - rollback() ends
                    # that aborted transaction and returns this SAME
                    # connection to a clean, usable state, exactly the fix
                    # already applied once in this codebase for the same
                    # bug class (backend/migrate.py's _already_applied).
                    # Without this, the recovery write below would itself
                    # raise (InFailedSqlTransaction), losing the failure
                    # it exists to record - confirmed empirically against
                    # a real Postgres container (docs/decisiones.md D-077
                    # Phase 3 webhook-hardening follow-up). A harmless
                    # no-op on SQLite, which never aborts a transaction on
                    # error in the first place.
                    conn.rollback()
                    repo.mark_webhook_event_processed(conn, event_id, error=str(exc))
                    alerting.emit_safe(alert_sender, alerting.EVENT_STRIPE_WEBHOOK_FAILURE, "error", {"event_type": event_type, "error_type": type(exc).__name__})
                    self._send_json(500, {"ok": False, "error": "internal error processing webhook"})
            finally:
                conn.close()

        # -------------------------------------------------------------
        # DELETE
        # -------------------------------------------------------------
        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            match = _PROJECT_ITEM_RE.match(path)
            if match:
                self._handle_project_delete(match.group("workspace_id"), match.group("project_id"))
                return
            match = _GITHUB_RE.match(path)
            if match:
                self._handle_github_disconnect(match.group("workspace_id"))
                return
            match = _MEMBER_ITEM_RE.match(path)
            if not match:
                self._send_json(404, {"ok": False, "error": "not found"})
                return
            self._handle_member_remove(match.group("workspace_id"), match.group("user_id"))

        def do_PATCH(self) -> None:
            path = urlparse(self.path).path
            match = _PROJECT_ITEM_RE.match(path)
            if not match:
                self._send_json(404, {"ok": False, "error": "not found"})
                return
            self._handle_project_rename(match.group("workspace_id"), match.group("project_id"))

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
    billing: Optional["billing_module.StripeBilling"] = None,
    storage: Optional["object_storage.ObjectStorage"] = None,
    alert_sender: Optional["alerting.AlertSender"] = None,
    black_friday_enabled: bool = False,
    black_friday_start: Optional[datetime] = None,
    black_friday_end: Optional[datetime] = None,
    black_friday_promotion_code_id: Optional[str] = None,
    max_pending_jobs_per_workspace: int = repo.DEFAULT_MAX_PENDING_JOBS_PER_WORKSPACE,
    submit_rate_limit_per_window: int = repo.DEFAULT_SUBMIT_RATE_LIMIT_PER_WINDOW,
    github: Optional["github_integration.GitHubIntegration"] = None,
    disposable_policy: Optional["email_policy.DisposableDomainPolicy"] = None,
) -> ThreadingHTTPServer:
    in_flight = _InFlightTracker()
    handler_cls = make_handler(
        connect_fn, email_sender, host_allowlist, secure_cookies, billing, storage, alert_sender, in_flight,
        black_friday_enabled, black_friday_start, black_friday_end, black_friday_promotion_code_id,
        max_pending_jobs_per_workspace, submit_rate_limit_per_window, github, disposable_policy,
    )
    server = ThreadingHTTPServer((host, port), handler_cls)
    server.in_flight_tracker = in_flight  # see get_in_flight_count() and _InFlightTracker's own docstring.
    return server
