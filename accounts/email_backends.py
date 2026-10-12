"""Brevo HTTPS transport. Never expose provider response bodies or credentials."""
import json
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from email.utils import parseaddr

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend
from django.core.exceptions import ImproperlyConfigured


class EmailDeliveryError(Exception):
    """Sanitized provider failure suitable for the OTP service."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BrevoEmailBackend(BaseEmailBackend):
    def send_messages(self, email_messages):
        sent = 0
        for message in email_messages or []:
            if not message.recipients():
                continue
            try:
                key = getattr(settings, "BREVO_API_KEY", "")
                if not key:
                    raise ImproperlyConfigured("BREVO_API_KEY is required.")
                if message.attachments:
                    raise EmailDeliveryError("Attachments are unsupported by this transport.")
                name, address = parseaddr(message.from_email)
                payload = {"sender": {"email": address}, "subject": message.subject,
                           "textContent": message.body}
                if name:
                    payload["sender"]["name"] = name
                for field in ("to", "cc", "bcc", "reply_to"):
                    addresses = getattr(message, field)
                    if addresses:
                        entries = [{"email": parseaddr(a)[1]} for a in addresses]
                        payload["replyTo" if field == "reply_to" else field] = entries[0] if field == "reply_to" else entries
                for alternative in getattr(message, "alternatives", []):
                    if alternative.mimetype == "text/html":
                        payload["htmlContent"] = alternative.content
                request = Request("https://api.brevo.com/v3/smtp/email",
                                  data=json.dumps(payload).encode(), method="POST",
                                  headers={"api-key": key, "Content-Type": "application/json", "Accept": "application/json"})
                with build_opener(NoRedirects()).open(request, timeout=settings.EMAIL_TIMEOUT) as response:
                    if response.status != 201:
                        raise EmailDeliveryError("Email provider did not accept the message.")
                sent += 1
            except (HTTPError, URLError, OSError, EmailDeliveryError, ImproperlyConfigured):
                if not self.fail_silently:
                    raise EmailDeliveryError("Email delivery is temporarily unavailable.") from None
        return sent
