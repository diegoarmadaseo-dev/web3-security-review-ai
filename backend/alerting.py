#!/usr/bin/env python3
"""Minimal, provider-neutral alert/event abstraction (Phase 6A production
hardening, docs/decisiones.md D-077 follow-up).

AlertSender is a structural (duck-typed) Protocol, not a base class a
real implementation must inherit from - same boundary discipline as
backend/email_sender.py's EmailSender Protocol: any object with a
matching emit() method satisfies it, so swapping in a real provider
(PagerDuty, a Slack/Discord webhook, OpsGenie, whatever gets chosen when
there is a real deployment target) never requires changing any caller.

LoggingAlertSender is the dev/test stand-in - it logs a structured event
via the stdlib logging module and makes no delivery guarantee of any
kind. Acceptable ONLY as an explicitly non-production choice (same
caveat backend/email_sender.LoggingEmailSender already carries) - a real
deployment needs its stdlib logging actually shipped somewhere that
pages a human, which remains this phase's own explicit non-goal ("do not
add a full observability vendor yet").

WebhookAlertSender (Phase 6B, docs/decisiones.md D-077 follow-up) is the
production-neutral REAL channel: POSTs the same structured event as one
JSON body to a single configured URL, using only the standard library
(urllib.request) - no vendor SDK, so it works unmodified with anything
that accepts an incoming webhook (Slack, Discord, PagerDuty, OpsGenie, a
custom endpoint, ...). It never raises to its own caller either (see
emit_safe() below, and this class's own internal try/except) - a
delivery failure (network error, non-2xx response, timeout) is logged
locally and swallowed, never allowed to fail the job/request that
triggered the alert.

STRUCTURED EVENTS ONLY: emit()'s `detail` dict is caller-supplied
structured data - job/workspace ids, counts, exception TYPE NAMES, a
truncated/generic error description - never raw source code, a Stripe/
LLM/S3 API key, a session/auth token, or a raw exception message that
could embed any of those. This module does not scrub `detail` itself
(there is nothing generic it could safely strip without risking hiding a
real value) - every call site is responsible for only ever passing
already-safe-to-log values, the same discipline backend/http_app.py's
log_message()/_redact_query_string() already apply to the access log.

emit_safe() is the one function every call site should actually use: it
NEVER raises and NEVER blocks the caller's own control flow, even if
alert_sender is None (alerting not configured) or its own emit()
implementation is itself broken - an alert failing to send must never be
the reason a job fails, a webhook 500s, or a request is rejected.

Standard library only (urllib.request for WebhookAlertSender - no vendor
SDK). The webhook URL itself may be a secret-bearing endpoint (some
providers embed a token in the URL path) - this module never logs the
URL itself, only the fact that a send attempt failed.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Protocol

logger = logging.getLogger("backend.alerting")

SEVERITIES = ("info", "warning", "error")

# Event types this phase's call sites actually emit - documented here as
# the single source of truth for what a real provider integration needs
# to eventually handle, never duplicated as a second hand-typed list
# anywhere else.
#
# No separate EVENT_LLM_PROVIDER_FAILURE exists: an LLM call happens
# INSIDE the isolated worker container (backend/worker_entrypoint.py),
# which has no network route to anything except the LLM API through the
# egress proxy - it cannot reach an alert provider itself. An LLM
# failure instead surfaces as an ordinary EVENT_WORKER_JOB_FAILED (see
# backend/worker_supervisor.py's claim_and_run_one_job()), with the
# underlying reason in that event's own `error` detail - a deliberate
# scoping decision, not an oversight.
EVENT_WORKER_JOB_FAILED = "worker.job_failed"
EVENT_WORKER_REPEATED_RETRY = "worker.repeated_retry"
EVENT_STRIPE_WEBHOOK_FAILURE = "stripe.webhook_failure"
EVENT_STORAGE_FAILURE = "storage.failure"
EVENT_AUTH_RATE_LIMIT = "auth.rate_limit_exceeded"
EVENT_READINESS_FAILURE = "readiness.failure"
EVENT_RETENTION_PURGE = "retention.purge"  # Phase 6B - informational only (severity "info"), emitted only when a scheduled purge actually deleted something.
EVENT_EMAIL_DELIVERY_FAILURE = "email.delivery_failure"  # Phase 6B email hardening (D-083) - emitted when email_sender.send() raises; the request-link HTTP response is unchanged either way, see backend/http_app.py's _handle_request_link().


class AlertSender(Protocol):
    def emit(self, event_type: str, severity: str, detail: Dict[str, Any]) -> None: ...


class LoggingAlertSender:
    """Dev/test/initial-production stand-in - see module docstring."""

    def emit(self, event_type: str, severity: str, detail: Dict[str, Any]) -> None:
        log_fn = {"info": logger.info, "warning": logger.warning, "error": logger.error}.get(severity, logger.warning)
        log_fn("ALERT type=%s severity=%s detail=%r", event_type, severity, detail)


class WebhookAlertSender:
    """Production-neutral real alert channel - see module docstring.
    Never reads os.environ itself (backend/main.py is the one place
    allowed to - see that module's own docstring); the URL/timeout are
    always explicit constructor arguments."""

    def __init__(self, webhook_url: str, timeout_seconds: float = 5.0) -> None:
        if not webhook_url:
            raise ValueError("webhook_url is required")
        self._webhook_url = webhook_url
        self._timeout_seconds = timeout_seconds

    def emit(self, event_type: str, severity: str, detail: Dict[str, Any]) -> None:
        payload = json.dumps({"event_type": event_type, "severity": severity, "detail": detail}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self._webhook_url, data=payload, method="POST",
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds):
                pass
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # TYPE NAME only, never str(exc) - some URLError/OSError
            # subtypes can echo back the target host/URL in their own
            # message, and the webhook URL may itself be secret-bearing
            # (see module docstring) - same "exception type name only"
            # discipline backend/llm_client.py already applies for the
            # same reason around its own provider call.
            logger.warning("WebhookAlertSender delivery failed: %s", type(exc).__name__)


def emit_safe(alert_sender: Optional[AlertSender], event_type: str, severity: str, detail: Dict[str, Any]) -> None:
    """See module docstring - the one function call sites should use."""
    if alert_sender is None:
        return
    try:
        alert_sender.emit(event_type, severity, detail)
    except Exception:
        pass
