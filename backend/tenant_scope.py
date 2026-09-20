#!/usr/bin/env python3
"""Tenant-scope resolution - the one rule this entire backend depends on
(Phase 1 data foundation, docs/decisiones.md D-077).

NEVER trust a client-supplied workspace_id without resolving it against the
AUTHENTICATED user's actual membership first. Every data-access function in
repository.py that takes a workspace_id assumes its caller already did this
- it is the application layer's job (a later phase: the HTTP layer that
reads the session, per sessions.user_id) to call resolve_workspace_role()
(or require_workspace_role()) and reject the request on a None/denied
result, BEFORE ever passing that workspace_id into a repository function.

This module makes no assumption about auth/session verification itself
(out of scope this phase - see backend/migrations/0001_initial_schema.sql's
`sessions` table, structure only) - it only answers the one question "is
this already-authenticated user_id actually a member of this workspace_id,
and with what role", which is a pure database fact, never guessed.

Works against both SQLite and PostgreSQL connections via backend/db.py's
adapter (placeholder translation only - the row-shape difference doesn't
apply here, `role` is always a plain TEXT column on both backends).
Imports no driver itself, so it stays usable with no extra dependency for
a SQLite-only caller; see backend/db.py.
"""
from __future__ import annotations

from typing import Any, Optional, Sequence

import backend.db as db

_ALL_ROLES = ("owner", "admin", "member")


class TenantScopeError(Exception):
    """Raised only by require_workspace_role() when the user is not a
    member of the workspace with an allowed role - never for a query that
    simply found no rows to return, a normal, expected result elsewhere."""


def resolve_workspace_role(conn: Any, user_id: str, workspace_id: str) -> Optional[str]:
    """Returns the caller's role ('owner'/'admin'/'member') in
    workspace_id, or None if the user is not a member of that workspace
    (including a workspace_id that does not exist at all - a non-existent
    workspace and "not a member of a real one" are deliberately
    indistinguishable to the caller, so this can never leak which
    workspace IDs exist to someone who isn't a member of them). Pure
    lookup; never mutates anything, never raises for "not a member"."""
    cur = db.execute(
        conn,
        "SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
        (workspace_id, user_id),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return row[0] if not hasattr(row, "keys") else row["role"]


def require_workspace_role(
    conn: Any,
    user_id: str,
    workspace_id: str,
    allowed_roles: Sequence[str] = _ALL_ROLES,
) -> str:
    """Same lookup as resolve_workspace_role(), but raises
    TenantScopeError instead of returning None/an insufficient role - for
    call sites that want a hard failure rather than an if-check. Returns
    the resolved role on success."""
    role = resolve_workspace_role(conn, user_id, workspace_id)
    if role is None or role not in allowed_roles:
        raise TenantScopeError(
            "user %r is not a member of workspace %r with an allowed role %r" % (user_id, workspace_id, tuple(allowed_roles))
        )
    return role
