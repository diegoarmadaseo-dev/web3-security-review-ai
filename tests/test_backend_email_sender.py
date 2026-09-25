"""Tests for backend/email_sender.py (Phase 6B, docs/decisiones.md D-077
follow-up): LoggingEmailSender (unchanged, kept for dev/tests) and the
new SMTPEmailSender production adapter - mocked smtplib.SMTP throughout,
never a real network connection.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import smtplib
import unittest
from unittest.mock import MagicMock, patch

import backend.email_sender as email_sender


def _fake_smtp_client():
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


class LoggingEmailSenderTests(unittest.TestCase):
    def test_send_never_raises(self):
        sender = email_sender.LoggingEmailSender()
        sender.send("user@example.com", "Subject", "Body")


class SMTPEmailSenderConstructionTests(unittest.TestCase):
    _BASE = dict(host="smtp.example.com", port=587, username="u", password="p", from_address="from@example.com")

    def test_requires_every_field(self):
        for missing in ("host", "username", "password", "from_address"):
            kwargs = dict(self._BASE)
            kwargs[missing] = ""
            with self.assertRaises(ValueError, msg="missing=%s" % missing):
                email_sender.SMTPEmailSender(**kwargs)

    def test_constructs_successfully_with_complete_config(self):
        sender = email_sender.SMTPEmailSender(**self._BASE)
        self.assertIsNotNone(sender)

    def test_never_reads_os_environ_itself(self):
        # Explicit-config discipline (same as backend/billing.StripeBilling) -
        # a caller who never sets any real SMTP_* env var must still be able
        # to construct this with plain, explicit arguments.
        with patch.dict("os.environ", {}, clear=True):
            sender = email_sender.SMTPEmailSender(**self._BASE)
        self.assertIsNotNone(sender)


class SMTPEmailSenderSendTests(unittest.TestCase):
    def test_send_starts_tls_logs_in_and_sends_by_default(self):
        sender = email_sender.SMTPEmailSender(host="smtp.example.com", port=587, username="u", password="secret-pw", from_address="from@example.com")
        fake_client = _fake_smtp_client()
        with patch("smtplib.SMTP", return_value=fake_client) as mock_smtp:
            sender.send("to@example.com", "Subject", "Body text")
        mock_smtp.assert_called_once_with("smtp.example.com", 587, timeout=10.0)
        fake_client.starttls.assert_called_once()
        fake_client.login.assert_called_once_with("u", "secret-pw")
        fake_client.send_message.assert_called_once()
        sent_message = fake_client.send_message.call_args[0][0]
        self.assertEqual(sent_message["To"], "to@example.com")
        self.assertEqual(sent_message["From"], "from@example.com")
        self.assertEqual(sent_message["Subject"], "Subject")
        self.assertEqual(sent_message.get_content().strip(), "Body text")

    def test_use_tls_false_skips_starttls(self):
        sender = email_sender.SMTPEmailSender(host="smtp.example.com", port=25, username="u", password="p", from_address="from@example.com", use_tls=False)
        fake_client = _fake_smtp_client()
        with patch("smtplib.SMTP", return_value=fake_client):
            sender.send("to@example.com", "Subject", "Body")
        fake_client.starttls.assert_not_called()
        fake_client.login.assert_called_once()

    def test_smtp_failure_propagates_and_never_logs_the_password(self):
        sender = email_sender.SMTPEmailSender(host="smtp.example.com", port=587, username="u", password="SUPER-SECRET-PW", from_address="from@example.com")
        fake_client = _fake_smtp_client()
        fake_client.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad credentials")
        with self.assertLogs("backend.email_sender", level="ERROR") as log_ctx:
            with patch("smtplib.SMTP", return_value=fake_client):
                with self.assertRaises(smtplib.SMTPAuthenticationError):
                    sender.send("to@example.com", "Subject", "Body")
        logged_text = " ".join(log_ctx.output)
        self.assertNotIn("SUPER-SECRET-PW", logged_text)
        self.assertIn("SMTPAuthenticationError", logged_text)

    def test_connection_error_propagates_and_never_logs_the_password(self):
        sender = email_sender.SMTPEmailSender(host="smtp.example.com", port=587, username="u", password="ANOTHER-SECRET", from_address="from@example.com")
        with self.assertLogs("backend.email_sender", level="ERROR") as log_ctx:
            with patch("smtplib.SMTP", side_effect=ConnectionRefusedError("refused")):
                with self.assertRaises(ConnectionRefusedError):
                    sender.send("to@example.com", "Subject", "Body")
        logged_text = " ".join(log_ctx.output)
        self.assertNotIn("ANOTHER-SECRET", logged_text)


if __name__ == "__main__":
    unittest.main()
