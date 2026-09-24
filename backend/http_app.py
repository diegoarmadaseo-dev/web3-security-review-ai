#!/usr/bin/env python3
"""Phase 2 identity/access HTTP layer (docs/decisiones.md D-077/D-078
follow-up). Stdlib http.server only, same pattern as website/server.py:
BaseHTTPRequestHandler + a route table, per-client IP taken ONLY from
the socket peer address (self.client_address[0]), never a client-
supplied X-Forwarded-For header (same rule website/server.py documents).

Endpoints: GET /auth/login, POST /auth/request-link, GET+POST
/auth/verify, POST /auth/logout, GET+POST /workspaces,
GET /workspaces/<id>, POST /workspaces/<id>/members,
DELETE /workspaces/<id>/members/<user_id>, POST /billing/checkout,
POST /billing/portal, POST /billing/webhook,
GET+POST /workspaces/<id>/jobs, GET /workspaces/<id>/reports,
GET /workspaces/<id>/reports/<report_id>.

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
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, unquote_plus, urlparse

import backend.auth as auth
import backend.billing as billing_module
import backend.db as db
import backend.object_storage as object_storage
import backend.repository as repo
import backend.tenant_scope as tenant_scope

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

_MAX_WORKSPACE_NAME_LENGTH = 200
_MAX_WORKSPACES_PER_USER = 50  # abuse-safety cap on POST /workspaces - generous for any legitimate account.
_REPORT_SIGNED_URL_TTL_SECONDS = 300  # short-lived by design, matches this codebase's other signed-URL/token TTL philosophy (auth.py's own TOKEN_TTL_SECONDS).

# Phase 4: a raw-byte cap enforced HERE, synchronously, before anything is
# queued - "no execution during HTTP request" means this handler never
# runs preprocess.py's own (correct, authoritative) maxEffectiveLoc/
# maxSourceFiles check itself; that happens inside the worker, which
# already fails a job cleanly if exceeded (see backend/worker_entrypoint.py).
# This is only a cheap, fast rejection of the obviously-oversized case
# before it ever reaches the queue.
MAX_RAW_SOURCE_BYTES = 512 * 1024

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
    b"</form></body></html>"
)


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

_SUBSCRIPTION_EVENT_TYPES = ("customer.subscription.updated", "customer.subscription.deleted")


def _upsert_entitlement(
    conn: Any,
    workspace_id: Optional[str],
    plan: Optional[str],
    status: str,
    stripe_customer_id: Optional[str],
    stripe_subscription_id: Optional[str],
    current_period_end: Optional[str],
    event_created_at: Optional[str],
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
    metadata) is silently skipped rather than guessed at."""
    if not workspace_id:
        return
    if repo.get_entitlement_by_workspace(conn, workspace_id) is None:
        if plan in ("quick", "standard", "pro"):
            repo.create_entitlement(conn, workspace_id, plan, status, stripe_customer_id, stripe_subscription_id, current_period_end, event_created_at)
        return
    repo.update_entitlement_status(conn, workspace_id, status, current_period_end, event_created_at)


def _apply_webhook_event(conn: Any, event_type: str, obj: Dict[str, Any], event_created_at: Optional[str]) -> None:
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
        if workspace_id and plan in ("quick", "standard", "pro") and repo.get_entitlement_by_workspace(conn, workspace_id) is None:
            repo.create_entitlement(
                conn,
                workspace_id,
                plan,
                status="incomplete",
                stripe_customer_id=obj.get("customer"),
                stripe_subscription_id=obj.get("subscription"),
                stripe_event_created_at=event_created_at,
            )
    elif event_type in _SUBSCRIPTION_EVENT_TYPES:
        # A canceled subscription's own status is already 'canceled' on
        # the object customer.subscription.deleted carries - confirmed
        # Stripe behavior, so both event types share this one branch.
        metadata = obj.get("metadata") or {}
        status = obj.get("status")
        if not isinstance(status, str):
            return
        _upsert_entitlement(
            conn,
            workspace_id=metadata.get("workspace_id"),
            plan=metadata.get("plan"),
            status=status,
            stripe_customer_id=obj.get("customer"),
            stripe_subscription_id=obj.get("id"),
            current_period_end=billing_module.subscription_period_end(obj),
            event_created_at=event_created_at,
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
    clean 503 when it is None, the same degrade-cleanly convention."""

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
            path = parsed.path
            if path == "/auth/verify":
                self._handle_verify_get(parsed)
                return
            if path == "/auth/login":
                self._send_html(200, _LOGIN_PAGE)
                return
            if path == "/workspaces":
                self._handle_workspace_list()
                return
            match = _JOBS_COLLECTION_RE.match(path)
            if match:
                self._handle_job_list(match.group("workspace_id"), parsed)
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
            scheme = "https" if secure_cookies else "http"
            verify_url = "%s://%s/auth/verify?token=%s" % (scheme, host, quote(token))
            email_sender.send(
                auth.normalize_email(email),
                "Your sign-in link",
                "Click to sign in (expires in 15 minutes): %s" % verify_url,
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
                budget = repo.get_workspace_budget(conn, workspace_id)
                limits = None
                if entitlement is not None:
                    modes_config = _load_modes_config()
                    if modes_config is not None:
                        limits = (modes_config.get("modes") or {}).get(entitlement["plan"])
                self._send_json(200, {"ok": True, "workspace": workspace, "entitlement": entitlement, "budget": budget, "limits": limits})
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
                jobs = repo.list_jobs_by_workspace(conn, workspace_id, limit=limit, offset=offset, status=status_filter)
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
                storage_ref = report.pop("storage_ref", None)
                if storage is not None and storage_ref:
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
        def _handle_job_submit(self, workspace_id: str) -> None:
            if self._reject_if_cross_origin():
                return
            if storage is None:
                self._send_json(503, {"ok": False, "error": "job execution is not configured"})
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
            if not isinstance(payload, dict):
                self._send_json(400, {"ok": False, "error": "request body must be a JSON object"})
                return
            mode = payload.get("mode")
            source = payload.get("source")
            client_idempotency_key = payload.get("idempotency_key")
            if mode not in ("quick", "standard", "pro"):
                self._send_json(400, {"ok": False, "error": "mode must be one of quick/standard/pro"})
                return
            if not isinstance(source, str) or not source.strip():
                self._send_json(400, {"ok": False, "error": "source is required"})
                return
            # Cheap, fast rejection only - see MAX_RAW_SOURCE_BYTES's own
            # comment on why the authoritative maxEffectiveLoc/
            # maxSourceFiles check happens inside the worker, not here.
            if len(source.encode("utf-8")) > MAX_RAW_SOURCE_BYTES:
                self._send_json(413, {"ok": False, "error": "source exceeds the maximum submission size"})
                return
            if client_idempotency_key is not None and (not isinstance(client_idempotency_key, str) or not (1 <= len(client_idempotency_key) <= 200)):
                self._send_json(400, {"ok": False, "error": "idempotency_key must be a string of 1-200 characters"})
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
                entitlement = repo.get_entitlement_by_workspace(conn, workspace_id)
                if entitlement is None or entitlement["status"] not in ("active", "trialing"):
                    self._send_json(402, {"ok": False, "error": "this workspace has no active subscription"})
                    return
                idempotency_key = client_idempotency_key or repo.new_id()
                existing = repo.get_job_by_idempotency_key(conn, idempotency_key)
                if existing is not None:
                    self._send_json(200, {"ok": True, "job_id": existing["id"], "status": existing["status"], "duplicate": True})
                    return
                content_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
                # A fresh id for the storage OBJECT only - decoupled from
                # the contract row's own id (create_contract() generates
                # that itself and needs storage_ref as an input, so the
                # two cannot be the same value chosen up front).
                storage_ref = object_storage.workspace_key(workspace_id, "sources", repo.new_id())
                storage.put_object(storage_ref, source.encode("utf-8"), content_type="text/plain")
                contract_id = repo.create_contract(conn, workspace_id, storage_ref, content_hash, payload.get("filename") or "contract.sol")
                try:
                    job_id = repo.enqueue_job(conn, workspace_id, contract_id, current_user_id, mode, idempotency_key=idempotency_key)
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
                self._send_json(200, {"ok": True, "job_id": job_id, "status": "queued"})
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
                if existing is not None and existing["status"] in ("active", "trialing"):
                    self._send_json(409, {"ok": False, "error": "this workspace already has an active subscription"})
                    return
                scheme = "https" if secure_cookies else "http"
                success_path = auth.validate_redirect_path(payload.get("success_path") if isinstance(payload, dict) else None)
                cancel_path = auth.validate_redirect_path(payload.get("cancel_path") if isinstance(payload, dict) else None)
                try:
                    session = billing.create_checkout_session(
                        plan=plan,
                        workspace_id=workspace_id,
                        success_url="%s://%s%s" % (scheme, host, success_path),
                        cancel_url="%s://%s%s" % (scheme, host, cancel_path),
                        customer_id=existing["stripe_customer_id"] if existing is not None else None,
                    )
                except billing_module.PriceNotAllowedError:
                    self._send_json(400, {"ok": False, "error": "unknown plan"})
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
                    _apply_webhook_event(conn, event_type, obj, event_created_at)
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
                    self._send_json(500, {"ok": False, "error": "internal error processing webhook"})
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
    billing: Optional["billing_module.StripeBilling"] = None,
    storage: Optional["object_storage.ObjectStorage"] = None,
) -> ThreadingHTTPServer:
    handler_cls = make_handler(connect_fn, email_sender, host_allowlist, secure_cookies, billing, storage)
    return ThreadingHTTPServer((host, port), handler_cls)
