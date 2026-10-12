import copy
import ssl
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMultiAlternatives, send_mail
from django.test import SimpleTestCase, override_settings

from accounts.email_backends import BrevoEmailBackend, EmailDeliveryError, NoRedirects
from online_voting_system.production import configure


@override_settings(EMAIL_BACKEND="accounts.email_backends.BrevoEmailBackend",
                   BREVO_API_KEY="dummy-test-key", EMAIL_TIMEOUT=10)
class BrevoTests(SimpleTestCase):
    def test_redirects_are_rejected(self):
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, "redirect", {}, "https://other.example.test"))

    @patch("accounts.email_backends.build_opener")
    def test_send_mail_and_html_payload(self, opener):
        import json
        opener.return_value.open.return_value.__enter__.return_value.status = 201
        self.assertEqual(send_mail("Subject", "123456", "sender@example.test", ["recipient@example.test"]), 1)
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(json.loads(request.data)["textContent"], "123456")
        self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 10)
        message = EmailMultiAlternatives("Subject", "text", "sender@example.test", ["recipient@example.test"])
        message.attach_alternative("<b>text</b>", "text/html")
        self.assertEqual(BrevoEmailBackend().send_messages([message]), 1)
        self.assertEqual(json.loads(opener.return_value.open.call_args.args[0].data)["htmlContent"], "<b>text</b>")

    @patch("accounts.email_backends.build_opener")
    def test_provider_failures_are_sanitized_and_silent_mode_counts_zero(self, opener):
        for error in [HTTPError("https://example.test", 429, "secret 123456", {}, None),
                      URLError("secret 123456"), TimeoutError("secret 123456")]:
            opener.return_value.open.side_effect = error
            with self.assertRaisesMessage(EmailDeliveryError, "Email delivery is temporarily unavailable.") as caught:
                send_mail("Subject", "123456", "sender@example.test", ["recipient@example.test"])
            self.assertNotIn("123456", str(caught.exception))
            self.assertEqual(send_mail("Subject", "123456", "sender@example.test", ["recipient@example.test"], fail_silently=True), 0)

    @override_settings(BREVO_API_KEY="")
    def test_missing_key_and_empty_messages(self):
        self.assertEqual(BrevoEmailBackend().send_messages([]), 0)
        with self.assertRaises(EmailDeliveryError):
            send_mail("Subject", "text", "sender@example.test", ["recipient@example.test"])


class ProductionTests(SimpleTestCase):
    def setUp(self):
        self.env = {"DJANGO_SECRET_KEY": "dummy-testing-only-" * 4,
                    "VOTE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                    "WEBAUTHN_ORIGIN": "https://securevote.onrender.com", "WEBAUTHN_RP_ID": "securevote.onrender.com",
                    "DJANGO_ALLOWED_HOSTS": "securevote.onrender.com", "DJANGO_CSRF_TRUSTED_ORIGINS": "https://securevote.onrender.com",
                    "AIVEN_MYSQL_SSL_CA": "dummy-ca.pem", "AIVEN_MYSQL_PORT": "12345", "AIVEN_MYSQL_DATABASE": "test",
                    "AIVEN_MYSQL_USER": "test", "AIVEN_MYSQL_PASSWORD": "dummy", "AIVEN_MYSQL_HOST": "mysql.example.test",
                    "DJANGO_EMAIL_BACKEND": "accounts.email_backends.BrevoEmailBackend", "BREVO_API_KEY": "dummy",
                    "DJANGO_DEFAULT_FROM_EMAIL": "sender@example.test"}
        self.config = {"MIDDLEWARE": ["django.middleware.security.SecurityMiddleware"],
                       "OTP_EXPIRY_SECONDS": 300, "OTP_MAX_ATTEMPTS": 5, "OTP_RESEND_COOLDOWN_SECONDS": 60}

    @patch("online_voting_system.production.ssl.create_default_context")
    def test_verified_tls_secure_cookies_proxy_and_static_storage(self, context):
        configure(self.config, self.env)
        options = self.config["DATABASES"]["default"]["OPTIONS"]
        self.assertTrue(options["ssl_verify_cert"])
        self.assertTrue(options["ssl_verify_identity"])
        self.assertTrue(self.config["SESSION_COOKIE_SECURE"])
        self.assertTrue(self.config["SECURE_SSL_REDIRECT"])
        self.assertIn("whitenoise.middleware.WhiteNoiseMiddleware", self.config["MIDDLEWARE"])

    @patch("online_voting_system.production.ssl.create_default_context")
    def test_missing_required_values_and_insecure_options_fail_closed(self, context):
        for name in self.env:
            env = self.env.copy()
            del env[name]
            with self.subTest(missing=name), self.assertRaises(ImproperlyConfigured):
                configure(copy.deepcopy(self.config), env)
        for name, value in [("DJANGO_DEBUG", "True"), ("WEBAUTHN_ORIGIN", "http://securevote.onrender.com"),
                            ("DJANGO_ALLOWED_HOSTS", "*"), ("DJANGO_SECURE_COOKIES", "False"),
                            ("DJANGO_TRUST_X_FORWARDED_PROTO", "False"), ("DJANGO_SECURE_SSL_REDIRECT", "False"),
                            ("DJANGO_EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"),
                            ("VOTE_ENCRYPTION_KEY", "invalid"), ("EMAIL_TIMEOUT", "0")]:
            with self.subTest(setting=name), self.assertRaises(ImproperlyConfigured):
                configure(copy.deepcopy(self.config), dict(self.env, **{name: value}))

    @patch("online_voting_system.production.ssl.create_default_context", side_effect=ssl.SSLError("invalid"))
    def test_invalid_ca_fails(self, context):
        with self.assertRaises(ImproperlyConfigured):
            configure(self.config, self.env)
