#!/usr/bin/env python3
"""The smallest email-sending abstraction Phase 2 needs (docs/decisiones.md
D-077/D-078 follow-up) - deliberately NOT a choice of real provider: no
SMTP/API credentials exist anywhere in this codebase, and none should be
added without an explicit deployment decision (same "no new dependency/
provider without being asked for explicitly" rule this project has
applied throughout - see backend/db.py's own psycopg boundary for the
same shape of decision made differently, once actually asked for).

EmailSender is a structural (duck-typed) contract, not a base class a
real implementation must inherit from - see typing.Protocol. Any object
with a matching send() method satisfies it. backend/http_app.py depends
on this Protocol, never on a concrete class, so swapping in a real
provider later (SES, Postgres-backed outbox, whatever gets chosen when
there is a real deployment target) never requires changing any caller -
same boundary discipline as backend/db.py's dialect adapter.

LoggingEmailSender is the ONLY implementation this phase ships: it never
makes a network call, never stores a credential, and is exactly enough
to develop and test the request-link flow end-to-end today. It logs the
full message it "sent" - acceptable ONLY because this is an explicitly
non-production stand-in; a real provider implementation must never log a
message body that could contain a live magic-link token.

Standard library only. No network access, no credentials.
"""
from __future__ import annotations

import logging
from typing import Protocol

logger = logging.getLogger("backend.email_sender")


class EmailSender(Protocol):
    def send(self, to_email: str, subject: str, body: str) -> None: ...


class LoggingEmailSender:
    """Dev/test stand-in - see module docstring. Never use in production;
    nothing about this implementation is a security or delivery
    guarantee of any kind."""

    def send(self, to_email: str, subject: str, body: str) -> None:
        logger.info("EMAIL to=%s subject=%r body=%r", to_email, subject, body)
