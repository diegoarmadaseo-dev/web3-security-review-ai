"""Tests for backend/alerting.py (Phase 6A production hardening, docs/
decisiones.md D-077 follow-up).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
            alerting.EVENT_RETENTION_PURGE, alerting.EVENT_EMAIL_DELIVERY_FAILURE,
            alerting.EVENT_TECHNICAL_BUDGET_EXHAUSTED,
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


# ---------------------------------------------------------------------------
# Phase 6B (docs/decisiones.md D-077 follow-up): WebhookAlertSender.
# ---------------------------------------------------------------------------

class _RecordingWebhookHandler(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.__class__.received.append(json.loads(body.decode("utf-8")))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence test output.
        pass


class _FailingWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(500)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


class WebhookAlertSenderTests(unittest.TestCase):
    def _start_server(self, handler_cls):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return "http://127.0.0.1:%d" % server.server_address[1]

    def test_requires_a_webhook_url(self):
        with self.assertRaises(ValueError):
            alerting.WebhookAlertSender("")

    def test_successful_delivery_posts_the_structured_event_as_json(self):
        _RecordingWebhookHandler.received = []
        url = self._start_server(_RecordingWebhookHandler)
        sender = alerting.WebhookAlertSender(url, timeout_seconds=5)

        sender.emit(alerting.EVENT_WORKER_JOB_FAILED, "warning", {"job_id": "abc-123"})

        self.assertEqual(len(_RecordingWebhookHandler.received), 1)
        received = _RecordingWebhookHandler.received[0]
        self.assertEqual(received, {"event_type": alerting.EVENT_WORKER_JOB_FAILED, "severity": "warning", "detail": {"job_id": "abc-123"}})

    def test_delivery_failure_never_raises(self):
        url = self._start_server(_FailingWebhookHandler)
        sender = alerting.WebhookAlertSender(url, timeout_seconds=5)
        sender.emit(alerting.EVENT_STORAGE_FAILURE, "error", {"phase": "fetch_source"})  # must not raise.

    def test_unreachable_url_never_raises(self):
        # Port 1 on loopback: nothing is listening there in this test environment.
        sender = alerting.WebhookAlertSender("http://127.0.0.1:1/hook", timeout_seconds=1)
        sender.emit(alerting.EVENT_READINESS_FAILURE, "error", {"checks": {"database": False}})  # must not raise.

    def test_emit_safe_still_works_as_the_outer_safety_net(self):
        sender = alerting.WebhookAlertSender("http://127.0.0.1:1/hook", timeout_seconds=1)
        alerting.emit_safe(sender, alerting.EVENT_READINESS_FAILURE, "error", {})  # belt-and-suspenders, must not raise either.

    def test_no_secret_shaped_value_leaks_into_the_posted_payload(self):
        # This is a property of the CALLER's own detail dict (see module
        # docstring - this class never scrubs it), proven here by
        # confirming the payload is EXACTLY the structured event passed
        # in, nothing added, nothing from this process's own environment.
        _RecordingWebhookHandler.received = []
        url = self._start_server(_RecordingWebhookHandler)
        sender = alerting.WebhookAlertSender(url, timeout_seconds=5)
        sender.emit(alerting.EVENT_STRIPE_WEBHOOK_FAILURE, "error", {"event_type": "customer.subscription.updated", "error_type": "KeyError"})
        received = _RecordingWebhookHandler.received[0]
        self.assertEqual(set(received.keys()), {"event_type", "severity", "detail"})
        self.assertEqual(set(received["detail"].keys()), {"event_type", "error_type"})


if __name__ == "__main__":
    unittest.main()
