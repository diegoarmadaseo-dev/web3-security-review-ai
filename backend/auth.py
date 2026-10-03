#!/usr/bin/env python3
"""Passwordless magic-link authentication and session management (Phase 2
identity/access, docs/decisiones.md D-077/D-078 follow-up).

Two secrets, same discipline for both: a raw one-time login token
(auth_tokens) and a raw session token (sessions) are each generated with
os.urandom(32) + base64url and ONLY their SHA-256 hash is ever stored or
looked up by - the raw value exists only in the HTTP response (a Set-
Cookie header, or the link emailed out) and is never written to a
database column, a log line, or an audit_events row.

SCANNER/PREFETCHER SAFETY (the reason this module exposes peek_token()
and consume_token_and_create_session() as two separate, differently-
gated operations instead of one): a bare GET on a magic link is
routinely issued automatically by email security gateways and client
prefetchers, before the human ever clicks anything. peek_token() is
read-only - it NEVER marks a token consumed, no matter how many times or
how quickly it is called, so it is safe to call from a GET handler.
consume_token_and_create_session() performs the actual one-time
consumption and must only ever be reachable from the confirmation POST a
human's own click submits (see backend/http_app.py) - never from GET.

RATE LIMITING is deliberately not a new subsystem: check_rate_limit()
queries auth_tokens itself (the row already being written for the token)
by email and by requested_ip within a sliding window, rather than adding
a dedicated counters table. requested_ip is always the immediate TCP
peer address the HTTP layer observed, never a client-supplied
X-Forwarded-For header (same rule website/server.py's own rate limiter
already documents - trusting a spoofable header lets an attacker defeat
the limit by varying it per request); a deployment behind a reverse
proxy that wants the true client IP must supply it via that proxy's own
trusted mechanism, which is that deployment's responsibility, not
something guessed at here.

REDIRECT SAFETY: validate_redirect_path() only ever accepts an internal,
site-relative path - never an absolute URL, a protocol-relative
"//host/path", or a backslash - so a captured/forwarded magic link can
never be turned into an open redirect to an attacker-controlled site.

Session fixation is structurally prevented, not merely mitigated:
create_session() always generates a brand-new random token and never
accepts or extends a client-supplied session id - there is no code path
anywhere in this module that turns an existing cookie value into a valid
session, logged in or not.

Uses backend/db.py for all SQL (dialect-agnostic) and
backend/repository.py for user/workspace identity operations it reuses
rather than duplicates. Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import backend.db as db
import backend.repository as repo

TOKEN_TTL_SECONDS = 15 * 60  # 15 minutes - short-lived by design.
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days.

RATE_LIMIT_WINDOW_SECONDS = 15 * 60
RATE_LIMIT_MAX_PER_EMAIL = 5  # per email, per window - caps spamming one victim's inbox.
RATE_LIMIT_MAX_PER_IP = 20  # per IP, per window - caps one source enumerating many emails.

DEFAULT_REDIRECT_PATH = "/"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    """Raised only for malformed input this module validates itself
    before touching the database - never for "token not found/expired",
    which is an expected, normal outcome reported by return value, not an
    exception (same philosophy as repository.record_webhook_event)."""


class RateLimitExceeded(AuthError):
    pass


def normalize_email(email: Any) -> str:
    if not isinstance(email, str):
        raise AuthError("email must be a string")
    normalized = email.strip().lower()
    if not _EMAIL_RE.match(normalized):
        raise AuthError("invalid email address")
    return normalized


def validate_redirect_path(path: Optional[str]) -> str:
    """Only a site-relative path is ever accepted - see module docstring.
    Falls back to DEFAULT_REDIRECT_PATH for anything absent or
    suspicious, never raises (a bad redirect hint is never fatal to the
    login itself)."""
    if not isinstance(path, str) or not path:
        return DEFAULT_REDIRECT_PATH
    if not path.startswith("/") or path.startswith("//"):
        return DEFAULT_REDIRECT_PATH
    if "://" in path or "\\" in path or "\n" in path or "\r" in path:
        return DEFAULT_REDIRECT_PATH
    return path


def _generate_opaque_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def check_rate_limit(conn: Any, email: str, ip: Optional[str]) -> None:
    """Raises RateLimitExceeded if either the per-email or per-IP window
    is already at its cap - see module docstring for why this queries
    auth_tokens itself rather than a dedicated counters table."""
    cutoff = (_now() - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)).isoformat()
    cur = db.execute(conn, "SELECT COUNT(*) AS n FROM auth_tokens WHERE email = ? AND created_at > ?", (email, cutoff))
    if db.normalize_row(cur.fetchone())["n"] >= RATE_LIMIT_MAX_PER_EMAIL:
        raise RateLimitExceeded("too many login requests for this email - try again later")
    if ip:
        cur = db.execute(conn, "SELECT COUNT(*) AS n FROM auth_tokens WHERE requested_ip = ? AND created_at > ?", (ip, cutoff))
        if db.normalize_row(cur.fetchone())["n"] >= RATE_LIMIT_MAX_PER_IP:
            raise RateLimitExceeded("too many login requests from this address - try again later")


TOKEN_PURPOSES = ("login", "signup")   # D-112: verifying a "signup" link is what grants the free Trial


def request_magic_link(conn: Any, email: Any, ip: Optional[str] = None, purpose: str = "login") -> str:
    """Normalizes, rate-limits, then always creates a token row and
    returns the RAW token - regardless of whether an account with this
    email exists yet (anti-enumeration: identical work and identical
    return shape either way; the HTTP layer must send the same generic
    response whether or not this raises for a bad address, never
    revealing account existence - see backend/http_app.py). The caller
    (HTTP layer) is responsible for emailing the raw token inside a
    verify link; this function never logs or persists it anywhere.

    purpose (D-112) is "login" (default, every existing caller) or
    "signup"; the same per-email/per-IP limit covers both, so re-sending a
    sign-up verification is rate limited exactly like a login link."""
    if purpose not in TOKEN_PURPOSES:
        raise AuthError("unknown token purpose")
    normalized = normalize_email(email)
    check_rate_limit(conn, normalized, ip)
    token = _generate_opaque_token()
    token_hash = _hash_token(token)
    now = _now()
    expires_at = (now + timedelta(seconds=TOKEN_TTL_SECONDS)).isoformat()
    db.execute(
        conn,
        "INSERT INTO auth_tokens (id, email, token_hash, requested_ip, created_at, expires_at, purpose) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (repo.new_id(), normalized, token_hash, ip, now.isoformat(), expires_at, purpose),
    )
    conn.commit()
    return token


TOKEN_VALID = "valid"
TOKEN_INVALID_OR_EXPIRED = "invalid_or_expired"


def peek_token(conn: Any, token: str) -> str:
    """Read-only: existence + not-consumed + not-expired. NEVER marks
    anything consumed, no matter how many times called - see module
    docstring. Safe for a GET handler a scanner/prefetcher might hit any
    number of times."""
    if not isinstance(token, str) or not token:
        return TOKEN_INVALID_OR_EXPIRED
    cur = db.execute(conn, "SELECT expires_at, consumed_at FROM auth_tokens WHERE token_hash = ?", (_hash_token(token),))
    row = db.normalize_row(cur.fetchone())
    if row is None or row["consumed_at"] is not None:
        return TOKEN_INVALID_OR_EXPIRED
    if row["expires_at"] <= _now().isoformat():
        return TOKEN_INVALID_OR_EXPIRED
    return TOKEN_VALID


def consume_token_and_create_session(conn: Any, token: str) -> Optional[Dict[str, Any]]:
    """The ONLY function that actually consumes a token - must only ever
    be reachable from a human-submitted confirmation POST, never GET
    (see module docstring). Atomic single-use consume via the same
    conditional-UPDATE-plus-rowcount pattern already verified in
    repository.claim_next_job/transition_job_status: the UPDATE's WHERE
    clause (consumed_at IS NULL AND expires_at > now) is what makes a
    second, concurrent, or replayed call see rowcount=0 and get nothing,
    even if it races the winning call exactly. Returns None (never
    raises) for an unknown/already-consumed/expired token - an expected,
    normal outcome. On ANY failure after the token is marked consumed
    (e.g. user/session creation), the whole operation rolls back
    together, so a transient failure never permanently burns a token the
    user could otherwise still retry before it expires."""
    if not isinstance(token, str) or not token:
        return None
    token_hash = _hash_token(token)
    now = _now()
    try:
        cur = db.execute(
            conn,
            "UPDATE auth_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
            (now.isoformat(), token_hash, now.isoformat()),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return None
        cur = db.execute(conn, "SELECT email, purpose FROM auth_tokens WHERE token_hash = ?", (token_hash,))
        token_row = db.normalize_row(cur.fetchone())
        email = token_row["email"]
        user = repo.get_user_by_email(conn, email)
        user_id = user["id"] if user is not None else repo.create_user(conn, email)
        repo.mark_email_verified(conn, user_id)
        session = create_session(conn, user_id)
        conn.commit()
        # D-112: who verified and why - the HTTP layer grants the Trial for a
        # verified "signup" link. Never the raw token.
        session.update({"email": email, "purpose": token_row["purpose"]})
        return session
    except Exception:
        conn.rollback()
        raise


def create_session(conn: Any, user_id: str) -> Dict[str, str]:
    """Always a brand-new random session - see module docstring on
    fixation. Caller (consume_token_and_create_session, or this module's
    own tests) is responsible for the surrounding transaction/commit;
    this function itself never commits, so it can be composed inside a
    larger atomic operation."""
    token = _generate_opaque_token()
    token_hash = _hash_token(token)
    session_id = repo.new_id()
    now = repo.utcnow_iso()
    expires_at = (_now() + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
    db.execute(
        conn,
        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (session_id, user_id, token_hash, now, expires_at),
    )
    return {"session_token": token, "session_id": session_id, "user_id": user_id, "expires_at": expires_at}


def validate_session(conn: Any, session_token: str) -> Optional[Dict[str, str]]:
    """Returns {"user_id", "session_id"} or None (never raises) for
    missing/expired/revoked - an expected, normal outcome for a stale or
    forged cookie. Touches last_seen_at on success (activity tracking for
    audit purposes only - see module docstring; this is NOT a second,
    independent expiry check, only the fixed expires_at set at creation
    is authoritative, to avoid two different notions of "still valid")."""
    if not isinstance(session_token, str) or not session_token:
        return None
    cur = db.execute(conn, "SELECT id, user_id, expires_at, revoked_at FROM sessions WHERE token_hash = ?", (_hash_token(session_token),))
    row = db.normalize_row(cur.fetchone())
    if row is None or row["revoked_at"] is not None:
        return None
    if row["expires_at"] <= repo.utcnow_iso():
        return None
    db.execute(conn, "UPDATE sessions SET last_seen_at = ? WHERE id = ?", (repo.utcnow_iso(), row["id"]))
    conn.commit()
    return {"user_id": row["user_id"], "session_id": row["id"]}


def revoke_session(conn: Any, session_token: str) -> bool:
    """Returns True if an active session was revoked, False if the token
    was unknown or already revoked (idempotent, never raises - a logout
    on an already-logged-out session is not an error)."""
    if not isinstance(session_token, str) or not session_token:
        return False
    cur = db.execute(
        conn,
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        (repo.utcnow_iso(), _hash_token(session_token)),
    )
    conn.commit()
    return cur.rowcount > 0


def revoke_all_sessions_for_user(conn: Any, user_id: str) -> int:
    """Phase 6A (docs/decisiones.md D-077 follow-up) - backend/
    retention.py's delete_workspace_data() is the one caller, for a
    member left with zero remaining workspace memberships after a
    workspace deletion (see that function's own docstring on why it is
    scoped that narrowly rather than a broader "delete this account
    everywhere" operation this module has no way to know is actually
    wanted). Returns the number of sessions actually revoked - 0 for a
    user with none active, never raises, same idempotent-by-WHERE-clause
    shape as revoke_session() above; calling this twice in a row is
    always safe (the second call revokes nothing further)."""
    cur = db.execute(conn, "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (repo.utcnow_iso(), user_id))
    conn.commit()
    return cur.rowcount
