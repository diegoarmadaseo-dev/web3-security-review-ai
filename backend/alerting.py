#!/usr/bin/env python3
"""Minimal, provider-neutral alert/event abstraction (Phase 6A production
hardening, docs/decisiones.md D-077 follow-up).

AlertSender is a structural (duck-typed) Protocol, not a base class a
real implementation must inherit from - same boundary discipline as
backend/email_sender.py's EmailSender Protocol: any object with a
matching emit() method satisfies it, so swapping in a real provider
(PagerDuty, a Slack/Discord webhook, OpsGenie, whatever gets chosen when
there is a real deployment target) never requires changing any caller.

LoggingAlertSender is the ONLY implementation this phase ships - it logs
a structured event via the stdlib logging module and makes no delivery
guarantee of any kind. Acceptable ONLY as an explicitly non-production
stand-in (same caveat backend/email_sender.LoggingEmailSender already
carries) - a real deployment needs its stdlib logging actually shipped
somewhere that pages a human, which is this phase's own explicit
non-goal ("do not add a full observability vendor yet").

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

Standard library only. No network access, no credentials.
"""
from __future__ import annotations

import logging
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


class AlertSender(Protocol):
    def emit(self, event_type: str, severity: str, detail: Dict[str, Any]) -> None: ...


class LoggingAlertSender:
    """Dev/test/initial-production stand-in - see module docstring."""

    def emit(self, event_type: str, severity: str, detail: Dict[str, Any]) -> None:
        log_fn = {"info": logger.info, "warning": logger.warning, "error": logger.error}.get(severity, logger.warning)
        log_fn("ALERT type=%s severity=%s detail=%r", event_type, severity, detail)


def emit_safe(alert_sender: Optional[AlertSender], event_type: str, severity: str, detail: Dict[str, Any]) -> None:
    """See module docstring - the one function call sites should use."""
    if alert_sender is None:
        return
    try:
        alert_sender.emit(event_type, severity, detail)
    except Exception:
        pass
