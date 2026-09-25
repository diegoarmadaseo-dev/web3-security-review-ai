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

LoggingEmailSender remains the dev/test stand-in: it never makes a
network call, never stores a credential, and is exactly enough to
develop and test the request-link flow end-to-end today. It logs the
full message it "sent" - acceptable ONLY because this is an explicitly
non-production choice; a real provider implementation must never log a
message body that could contain a live magic-link token.

SMTPEmailSender (Phase 6B, docs/decisiones.md D-077 follow-up) is that
explicit deployment decision, made the same provider-neutral way
backend/alerting.WebhookAlertSender was: SMTP is a PROTOCOL, not a
vendor, so this works unmodified against any provider that exposes an
SMTP relay (SES, Postmark, SendGrid, Mailgun, a real mail server, ...)
without this codebase picking or importing a vendor-specific SDK.
Standard library only (smtplib + email.message). Never logs the
password - the constructor stores it privately and it is used only
inside smtplib's own login() call; a send() failure is logged with the
exception TYPE NAME only, matching backend/alerting.WebhookAlertSender's
own discipline (some SMTP error messages echo back the auth attempt).
Unlike LoggingEmailSender, a send() failure here DOES raise (this
module has no "safe" wrapper of its own - see backend/http_app.py's
_handle_request_link(), the one caller, for how that failure currently
surfaces) - swallowing a real delivery failure silently would be worse
than the caller finding out the email never sent.

Standard library only.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
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


class SMTPEmailSender:
    """Production SMTP adapter - see module docstring. Never reads
    os.environ itself (backend/main.py is the one place allowed to);
    every value is an explicit constructor argument, same discipline as
    backend/billing.StripeBilling."""

    def __init__(
        self, host: str, port: int, username: str, password: str, from_address: str,
        use_tls: bool = True, timeout_seconds: float = 10.0,
    ) -> None:
        if not host:
            raise ValueError("host is required")
        if not username:
            raise ValueError("username is required")
        if not password:
            raise ValueError("password is required")
        if not from_address:
            raise ValueError("from_address is required")
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._from_address = from_address
        self._use_tls = use_tls
        self._timeout_seconds = timeout_seconds

    def send(self, to_email: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._from_address
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)
        try:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout_seconds) as client:
                if self._use_tls:
                    client.starttls()
                client.login(self._username, self._password)
                client.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            # TYPE NAME only, never str(exc) - an SMTP server's own error
            # text can echo back the username/credentials it rejected -
            # same discipline backend/alerting.WebhookAlertSender applies
            # for its own delivery failures.
            logger.error("SMTPEmailSender delivery failed: %s", type(exc).__name__)
            raise
