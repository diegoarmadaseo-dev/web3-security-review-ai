"""Tests for backend/alerting.py (Phase 6A production hardening, docs/
decisiones.md D-077 follow-up).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import unittest

import backend.alerting as alerting


class _CapturingAlertSender:
    def __init__(self):
        self.events = []

    def emit(self, event_type, severity, detail):
        self.events.append((event_type, severity, detail))


class _BrokenAlertSender:
    def emit(self, event_type, severity, detail):
        raise RuntimeError("this sender is broken on purpose")


class EmitSafeTests(unittest.TestCase):
    def test_emit_safe_delivers_to_a_working_sender(self):
        sender = _CapturingAlertSender()
        alerting.emit_safe(sender, "worker.job_failed", "warning", {"job_id": "abc"})
        self.assertEqual(sender.events, [("worker.job_failed", "warning", {"job_id": "abc"})])

    def test_emit_safe_is_a_no_op_when_sender_is_none(self):
        # Must not raise - every call site in this codebase relies on this.
        alerting.emit_safe(None, "worker.job_failed", "warning", {})

    def test_emit_safe_never_raises_even_if_the_sender_itself_is_broken(self):
        sender = _BrokenAlertSender()
        try:
            alerting.emit_safe(sender, "storage.failure", "error", {"phase": "fetch_source"})
        except Exception as exc:  # pragma: no cover - the assertion below is what actually matters.
            self.fail("emit_safe raised %r - alerting must never crash its caller" % (exc,))

    def test_event_type_constants_are_distinct_strings(self):
        values = [
            alerting.EVENT_WORKER_JOB_FAILED, alerting.EVENT_WORKER_REPEATED_RETRY,
            alerting.EVENT_STRIPE_WEBHOOK_FAILURE, alerting.EVENT_STORAGE_FAILURE,
            alerting.EVENT_AUTH_RATE_LIMIT, alerting.EVENT_READINESS_FAILURE,
        ]
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue(all(isinstance(v, str) and v for v in values))


class LoggingAlertSenderTests(unittest.TestCase):
    def test_emit_logs_without_raising_for_every_declared_severity(self):
        sender = alerting.LoggingAlertSender()
        for severity in alerting.SEVERITIES:
            sender.emit("worker.job_failed", severity, {"job_id": "xyz"})

    def test_emit_never_raises_for_an_unrecognized_severity(self):
        # Degrades to the "warning" log level rather than crashing the caller.
        sender = alerting.LoggingAlertSender()
        sender.emit("worker.job_failed", "not-a-real-severity", {})


if __name__ == "__main__":
    unittest.main()
