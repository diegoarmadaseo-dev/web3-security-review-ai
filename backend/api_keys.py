#!/usr/bin/env python3
"""Private API keys (docs/decisiones.md D-113) - format, hashing and parsing.

A key is `vcx_<prefix>_<secret>`:
- prefix: 12 lowercase hex characters (48 random bits) - a public, NON-secret
  lookup id, also shown in key listings so a user can tell keys apart;
- secret: 43 URL-safe base64 characters = 32 bytes from `secrets` (256 bits).

Only SHA-256(full key) is stored (backend/migrations/0014_api_keys.sql). With
256 bits of entropy a fast hash is the right tool (a slow password hash only
helps for guessable secrets); the stored hash is compared in constant time
(hmac.compare_digest). The full key is returned exactly once, by the create
endpoint, and never logged, listed, stored in job metadata or reports.

Stdlib only. No database access here: backend/repository.py stores and looks
keys up, backend/http_app.py authenticates requests with them.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import List, Optional, Tuple

KEY_LITERAL = "vcx_"
_KEY_RE = re.compile(r"^vcx_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$")
# "Bearer <key>": scheme case-insensitive (RFC 7235), exactly one space, one
# token, nothing else - anything looser is refused as malformed.
_BEARER_RE = re.compile(r"^[Bb][Ee][Aa][Rr][Ee][Rr] ([!-~]+)$")

MAX_NAME_LENGTH = 100
# Abuse-safety ceiling on ACTIVE keys per workspace (a technical bound, not a
# plan limit - identical for Quick/Standard/Pro). Revoked keys do not count.
MAX_ACTIVE_KEYS_PER_WORKSPACE = 25
# last_used_at is written at most once per this many seconds per key, so an
# API client polling a job does not turn every GET into a database write.
LAST_USED_RESOLUTION_SECONDS = 60

AUTH_MISSING = "missing"
AUTH_MALFORMED = "malformed"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate() -> Tuple[str, str, str]:
    """(full key, prefix, SHA-256 hex of the full key)."""
    prefix = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    key = "%s%s_%s" % (KEY_LITERAL, prefix, secret)
    assert _KEY_RE.match(key), "generated key does not match its own format"
    return key, prefix, hash_key(key)


def parse_prefix(key: str) -> Optional[str]:
    """The lookup prefix of a well-formed key, or None."""
    match = _KEY_RE.match(key) if isinstance(key, str) else None
    return match.group(1) if match else None


def matches(key: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented key against a stored hash."""
    if not isinstance(key, str) or not isinstance(stored_hash, str):
        return False
    return hmac.compare_digest(hash_key(key), stored_hash)


def parse_authorization(values: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """(key, None) for exactly one well-formed `Authorization: Bearer
    vcx_...` header, else (None, AUTH_MISSING | AUTH_MALFORMED). The key's
    own format is checked here too, so a malformed key never reaches the
    database."""
    if not values:
        return None, AUTH_MISSING
    if len(values) != 1:
        return None, AUTH_MALFORMED
    match = _BEARER_RE.match(values[0] or "")
    if not match or parse_prefix(match.group(1)) is None:
        return None, AUTH_MALFORMED
    return match.group(1), None


def validate_name(name: object) -> Optional[str]:
    """The stripped key name, or None when it is not a 1-100 character
    string without control characters."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > MAX_NAME_LENGTH or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return None
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return name
