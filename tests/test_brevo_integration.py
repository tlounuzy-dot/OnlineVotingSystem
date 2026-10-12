"""Offline tests: no provider credentials, network calls or local database writes."""
import json
from unittest.mock import patch
from urllib.error import HTTPError

from django.core.mail import send_mail
from django.test import SimpleTestCase, TestCase, override_settings
from django.contrib.auth import get_user_model

from accounts.email_backends import EmailDeliveryError
from accounts.otp import _send_email_otp, issue_code, DeliveryUnavailable
from accounts.models import ContactVerificationCode, Role


@override_settings(EMAIL_BACKEND="accounts.email_backends.BrevoEmailBackend",
                   DEFAULT_FROM_EMAIL="verified-sender@example.test",
                   BREVO_API_KEY="dummy-offline-key", EMAIL_TIMEOUT=10)
class BrevoIntegrationTests(SimpleTestCase):
    @patch("accounts.email_backends.build_opener")
    def test_registration_and_reset_use_configured_sender_key_and_transport(self, opener):
        opener.return_value.open.return_value.__enter__.return_value.status = 201
        for purpose in ("registration_verification", "password_reset"):
            _send_email_otp("recipient@example.test", "123456", purpose)
            request = opener.return_value.open.call_args.args[0]
            payload = json.loads(request.data)
            self.assertEqual(payload["sender"]["email"], "verified-sender@example.test")
            self.assertEqual(payload["to"], [{"email": "recipient@example.test"}])
            self.assertEqual(request.get_header("Api-key"), "dummy-offline-key")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.full_url, "https://api.brevo.com/v3/smtp/email")
            self.assertIn("123456", payload["textContent"])

    @patch("accounts.email_backends.build_opener")
    def test_invalid_credentials_rejection_rate_limit_and_server_errors(self, opener):
        for status in (400, 401, 403, 422, 429, 500, 503):
            opener.return_value.open.side_effect = HTTPError(
                "https://api.brevo.com/v3/smtp/email", status,
                "dummy-offline-key recipient@example.test 123456", {}, None)
            with self.subTest(status=status):
                with self.assertRaises(EmailDeliveryError) as caught:
                    _send_email_otp("recipient@example.test", "123456", "password_reset")
                self.assertEqual(str(caught.exception), "Email delivery is temporarily unavailable.")
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(send_mail("Test", "Harmless", None, ["recipient@example.test"], fail_silently=True), 0)

    @patch("accounts.email_backends.build_opener")
    def test_only_created_response_counts_as_provider_acceptance(self, opener):
        for status in (200, 202, 204, 302):
            opener.return_value.open.return_value.__enter__.return_value.status = status
            with self.subTest(status=status), self.assertRaises(EmailDeliveryError):
                send_mail("Test", "Harmless", None, ["recipient@example.test"])
        opener.return_value.open.return_value.__enter__.return_value.status = 201
        self.assertEqual(send_mail("Test", "Harmless", None, ["recipient@example.test"]), 1)
        # This is transport acceptance only; no inbox/delivery event is asserted.


@override_settings(EMAIL_BACKEND="accounts.email_backends.BrevoEmailBackend",
                   DEFAULT_FROM_EMAIL="verified-sender@example.test", BREVO_API_KEY="dummy-offline-key",
                   EMAIL_TIMEOUT=10, PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class BrevoOTPFailureTests(TestCase):
    @patch("accounts.email_backends.build_opener")
    @patch("accounts.otp._new_code", return_value="123456")
    def test_provider_failure_invalidates_each_purpose_without_sensitive_logs(self, new_code, opener):
        role = Role.objects.create(name="Voter")
        user = get_user_model().objects.create_user(
            email="recipient@example.test", password="SyntheticPassword!42", full_name="Synthetic Test", role=role)
        opener.return_value.open.side_effect = HTTPError(
            "https://api.brevo.com/v3/smtp/email", 401,
            "dummy-offline-key recipient@example.test 123456", {}, None)
        for purpose in (ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION,
                        ContactVerificationCode.Purpose.PASSWORD_RESET):
            with self.subTest(purpose=purpose), self.assertLogs("accounts.otp", level="WARNING") as logs:
                with self.assertRaises(DeliveryUnavailable):
                    issue_code(user, purpose, ContactVerificationCode.Channel.EMAIL)
            record = ContactVerificationCode.objects.get(user=user, purpose=purpose)
            self.assertIsNotNone(record.invalidated_at)
            self.assertIsNone(record.used_at)
            for sensitive in ("123456", "recipient@example.test", "dummy-offline-key", "SyntheticPassword!42"):
                self.assertNotIn(sensitive, " ".join(logs.output))
