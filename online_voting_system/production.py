"""Validated hosted settings, separate from the existing local workflow."""
from pathlib import Path
from urllib.parse import urlsplit
import ssl

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


def configure(config, env):
    def require(name):
        value = env.get(name, "").strip()
        if not value:
            raise ImproperlyConfigured(f"{name} is required in production.")
        return value

    def boolean(name, default=True):
        value = env.get(name, str(default)).lower()
        if value not in {"true", "false"}:
            raise ImproperlyConfigured(f"{name} must be True or False.")
        return value == "true"

    if boolean("DJANGO_DEBUG", False):
        raise ImproperlyConfigured("DJANGO_DEBUG must be False in production.")
    secret = require("DJANGO_SECRET_KEY")
    if len(secret) < 50 or len(set(secret)) < 5 or secret.startswith("django-insecure-"):
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be a strong independent secret.")
    try:
        Fernet(require("VOTE_ENCRYPTION_KEY").encode())
    except (ValueError, TypeError):
        raise ImproperlyConfigured("VOTE_ENCRYPTION_KEY must be a valid Fernet key.") from None
    origin = require("WEBAUTHN_ORIGIN")
    parsed = urlsplit(origin)
    rp = require("WEBAUTHN_RP_ID")
    if (parsed.scheme != "https" or parsed.hostname != rp or parsed.netloc != rp
            or parsed.path or parsed.query or parsed.fragment or rp in {"localhost", "127.0.0.1"}):
        raise ImproperlyConfigured("WebAuthn requires the exact final HTTPS origin and matching RP hostname.")
    hosts = [v.strip() for v in require("DJANGO_ALLOWED_HOSTS").split(",")]
    origins = [v.strip() for v in require("DJANGO_CSRF_TRUSTED_ORIGINS").split(",")]
    if rp not in hosts or any(not h or "*" in h or "/" in h or ":" in h or h.startswith(".") for h in hosts):
        raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS requires explicit hostnames including the RP ID.")
    if origin not in origins or any(urlsplit(o).scheme != "https" or "*" in o or urlsplit(o).netloc not in hosts or urlsplit(o).path or urlsplit(o).query or urlsplit(o).fragment for o in origins):
        raise ImproperlyConfigured("CSRF origins must be exact HTTPS origins for allowed hosts.")
    ca = Path(require("AIVEN_MYSQL_SSL_CA"))
    try:
        ssl.create_default_context(cafile=str(ca))
    except (OSError, ssl.SSLError):
        raise ImproperlyConfigured("AIVEN_MYSQL_SSL_CA must identify a readable valid CA certificate.") from None
    try:
        port = int(require("AIVEN_MYSQL_PORT"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ImproperlyConfigured("AIVEN_MYSQL_PORT must be a valid port.") from None
    database = {"ENGINE": "django.db.backends.mysql", "NAME": require("AIVEN_MYSQL_DATABASE"),
                "USER": require("AIVEN_MYSQL_USER"), "PASSWORD": require("AIVEN_MYSQL_PASSWORD"),
                "HOST": require("AIVEN_MYSQL_HOST"), "PORT": port,
                "CONN_MAX_AGE": 60, "CONN_HEALTH_CHECKS": True,
                "OPTIONS": {"ssl_ca": str(ca), "ssl_verify_cert": True, "ssl_verify_identity": True,
                            "charset": "utf8mb4"}}
    backend = require("DJANGO_EMAIL_BACKEND")
    if backend != "accounts.email_backends.BrevoEmailBackend":
        raise ImproperlyConfigured("Production requires accounts.email_backends.BrevoEmailBackend.")
    require("BREVO_API_KEY")
    sender = require("DJANGO_DEFAULT_FROM_EMAIL")
    try:
        validate_email(sender)
    except ValidationError:
        raise ImproperlyConfigured("DJANGO_DEFAULT_FROM_EMAIL must be a valid sender address.") from None
    if sender.endswith(".local"):
        raise ImproperlyConfigured("Production requires a verified public sender.")
    for name in ("DJANGO_SECURE_COOKIES", "DJANGO_SECURE_SSL_REDIRECT", "DJANGO_TRUST_X_FORWARDED_PROTO"):
        if not boolean(name):
            raise ImproperlyConfigured(f"{name} must be True in production.")
    try:
        hsts = int(env.get("DJANGO_SECURE_HSTS_SECONDS", "3600"))
        timeout = int(env.get("EMAIL_TIMEOUT", "10"))
        if hsts < 0 or not 1 <= timeout <= 60:
            raise ValueError
        if any(int(config[n]) < 1 for n in ("OTP_EXPIRY_SECONDS", "OTP_MAX_ATTEMPTS", "OTP_RESEND_COOLDOWN_SECONDS")):
            raise ValueError
    except ValueError:
        raise ImproperlyConfigured("Security durations and email timeout must be valid positive values (HSTS may be zero).") from None
    config.update(DEBUG=False, SECRET_KEY=secret, ALLOWED_HOSTS=hosts, CSRF_TRUSTED_ORIGINS=origins,
                  DATABASES={"default": database}, EMAIL_BACKEND=backend, DEFAULT_FROM_EMAIL=sender,
                  BREVO_API_KEY=env["BREVO_API_KEY"], EMAIL_TIMEOUT=timeout,
                  SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True, SECURE_SSL_REDIRECT=True,
                  SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
                  SECURE_HSTS_SECONDS=hsts, SECURE_HSTS_INCLUDE_SUBDOMAINS=False, SECURE_HSTS_PRELOAD=False,
                  SECURE_CONTENT_TYPE_NOSNIFF=True)
    config["MIDDLEWARE"].insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")
    config["STORAGES"] = {"default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
                          "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"}}
    # Exception reports can contain POST bodies and personal records. Keep hosted
    # request diagnostics status-only; provider failures have their own safe log.
    config["LOGGING"] = {"version": 1, "disable_existing_loggers": False,
                         "handlers": {"null": {"class": "logging.NullHandler"}},
                         "loggers": {"django.request": {"handlers": ["null"], "propagate": False},
                                     "django.security": {"handlers": ["null"], "propagate": False}}}
