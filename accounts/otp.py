"""Secure, reusable delivery and verification services for contact OTPs."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import socket
import ssl
from dataclasses import dataclass
from datetime import timedelta
from json import JSONDecodeError, dumps, loads
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import ContactVerificationCode, SMSDeliveryMetadata


logger = logging.getLogger(__name__)


class OTPError(Exception):
    """Base class for safe, user-facing OTP workflow errors."""


class DeliveryUnavailable(OTPError):
    pass


class ResendCooldown(OTPError):
    pass


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str = ""


@dataclass(frozen=True)
class SMSDeliverySubmission:
    """Safe Infobip submission fields retained separately from the OTP hash."""

    provider_message_id: str
    status_group: str = ""
    status_name: str = ""
    status_description: str = ""


def normalize_phone_number(phone: str) -> str:
    """Return a South African local or E.164 number as E.164 without changing stored data."""
    compact = re.sub(r"[\s().-]", "", phone or "")
    if compact.startswith("+27") and compact[1:].isdigit() and len(compact) == 12:
        return compact
    if compact.startswith("27") and compact.isdigit() and len(compact) == 11:
        return f"+{compact}"
    if compact.startswith("0") and compact.isdigit() and len(compact) == 10:
        return f"+27{compact[1:]}"
    raise DeliveryUnavailable("The selected phone contact is not in a supported format.")


def available_channels(user) -> dict[str, str]:
    """Return destinations available to a user, without mutating stored contact data."""
    channels = {ContactVerificationCode.Channel.EMAIL: user.email} if user.email else {}
    voter = getattr(user, "voter_profile", None)
    if voter and voter.phone:
        try:
            normalized = normalize_phone_number(voter.phone)
        except DeliveryUnavailable:
            normalized = None
        if normalized:
            channels[ContactVerificationCode.Channel.SMS] = normalized
            channels[ContactVerificationCode.Channel.WHATSAPP] = normalized
    return channels


def mask_destination(channel: str, destination: str) -> str:
    if channel == ContactVerificationCode.Channel.EMAIL:
        local, _, domain = destination.partition("@")
        return f"{local[:1]}***@{domain}" if domain else "***"
    return f"{destination[:3]} ****** {destination[-3:]}" if len(destination) > 6 else "***"


def _contact_digest(destination: str) -> str:
    return hashlib.sha256(destination.strip().lower().encode("utf-8")).hexdigest()


def _new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _send_email_otp(destination: str, code: str, purpose: str) -> None:
    subject = "Your SecureVote verification code"
    send_mail(
        subject,
        "SecureVote\n\n"
        f"Your verification code is:\n\n{code}\n\n"
        "This code expires in 5 minutes.\n\n"
        "If you did not request this code, you can ignore this message.",
        settings.DEFAULT_FROM_EMAIL,
        [destination],
        fail_silently=False,
    )


def _infobip_api_base_url() -> str:
    """Return a validated Infobip HTTPS base URL."""
    base_url = getattr(settings, "INFOBIP_API_BASE_URL", "").strip().rstrip("/")
    parsed = urlsplit(base_url)
    if not base_url:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=missing_base_url")
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=invalid_base_url")
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    return base_url


def _infobip_sms_url() -> str:
    """Build the documented Infobip SMS v3 endpoint from a HTTPS base URL."""
    return f"{_infobip_api_base_url()}/sms/3/messages"


def _infobip_error_code(payload: bytes) -> str | None:
    """Extract only a provider error identifier, never an error message/body."""
    try:
        response = loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, JSONDecodeError):
        return None
    if not isinstance(response, dict):
        return None
    request_error = response.get("requestError")
    if not isinstance(request_error, dict):
        return None
    for error_type in ("serviceException", "policyException"):
        detail = request_error.get(error_type)
        if isinstance(detail, dict) and isinstance(detail.get("messageId"), str):
            return detail["messageId"]
    return None


def _safe_provider_text(value: object, limit: int) -> str:
    """Keep short provider status labels only; never retain arbitrary payload data."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _submission_from_infobip_response(response_data: object) -> SMSDeliverySubmission:
    if not isinstance(response_data, dict):
        raise ValueError("response is not an object")
    messages = response_data.get("messages")
    if not isinstance(messages, list) or not messages or not isinstance(messages[0], dict):
        raise ValueError("response does not contain a message")
    message = messages[0]
    message_id = message.get("messageId")
    if not isinstance(message_id, str) or not message_id.strip() or len(message_id) > 128:
        raise ValueError("response does not contain a valid message identifier")
    status = message.get("status") if isinstance(message.get("status"), dict) else {}
    return SMSDeliverySubmission(
        provider_message_id=message_id.strip(),
        status_group=_safe_provider_text(status.get("groupName"), 64),
        status_name=_safe_provider_text(status.get("name"), 100),
        status_description=_safe_provider_text(status.get("description"), 255),
    )


def _send_infobip_sms_otp(destination: str, code: str, purpose: str) -> SMSDeliverySubmission:
    """Send an existing SecureVote OTP through Infobip without persisting provider data."""
    api_key = getattr(settings, "INFOBIP_API_KEY", "")
    sender = getattr(settings, "INFOBIP_SMS_SENDER", "")
    if not api_key:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=missing_api_key")
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    if not sender:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=missing_sender")
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")

    payload = {
        "messages": [{
            "sender": sender,
            "destinations": [{"to": destination}],
            "content": {"text": f"SecureVote: Your verification code is {code}. It expires in 5 minutes."},
        }],
    }
    request = Request(
        _infobip_sms_url(),
        data=dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"App {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=settings.INFOBIP_SMS_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            response_body = response.read()
    except HTTPError as exc:
        provider_code = _infobip_error_code(exc.read())
        logger.warning(
            "OTP provider failure: provider=infobip channel=sms http_status=%s provider_code=%s",
            exc.code,
            provider_code,
        )
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.") from exc
    except (URLError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
        logger.warning(
            "OTP provider failure: provider=infobip channel=sms error_type=%s",
            _infobip_network_error_type(exc),
        )
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.") from exc

    if not 200 <= status < 300:
        logger.warning(
            "OTP provider failure: provider=infobip channel=sms http_status=%s provider_code=%s",
            status,
            _infobip_error_code(response_body),
        )
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.")


    try:
        response_data = loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=malformed_response")
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.") from exc
    try:
        return _submission_from_infobip_response(response_data)
    except ValueError as exc:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=unexpected_response")
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.") from exc


def _infobip_network_error_type(exc: Exception) -> str:
    """Classify transport failures without logging endpoints, credentials, or payloads."""
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, socket.gaierror):
        return "dns_failure"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "connection_timeout"
    if isinstance(reason, ssl.SSLError):
        return "tls_failure"
    proxy_environment = any(os.environ.get(name) for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
    ))
    if proxy_environment and isinstance(reason, ConnectionRefusedError):
        return "proxy_failure"
    return "connection_failure"


def _twilio_client():
    sid = getattr(settings, "TWILIO_ACCOUNT_SID", "")
    token = getattr(settings, "TWILIO_AUTH_TOKEN", "")
    if not sid or not token:
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    try:
        from twilio.rest import Client
    except ImportError as exc:
        raise DeliveryUnavailable("This delivery channel is not installed in this environment.") from exc
    return Client(sid, token)


def _send_twilio_otp(channel: str, destination: str, code: str, purpose: str) -> None:
    client = _twilio_client()
    if channel != ContactVerificationCode.Channel.WHATSAPP:
        raise DeliveryUnavailable("The selected delivery channel is unavailable.")
    sender = getattr(settings, "TWILIO_WHATSAPP_FROM_NUMBER", "")
    recipient = f"whatsapp:{destination}"
    if not sender:
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    client.messages.create(
        body=f"SecureVote: Your verification code is {code}. It expires in 5 minutes.",
        from_=sender,
        to=recipient,
    )


def send_otp(channel: str, destination: str, code: str, purpose: str) -> SMSDeliverySubmission | None:
    """Dispatch through one provider boundary; never log provider secrets or the code."""
    if channel == ContactVerificationCode.Channel.EMAIL:
        _send_email_otp(destination, code, purpose)
        return
    if channel == ContactVerificationCode.Channel.SMS:
        return _send_infobip_sms_otp(destination, code, purpose)
    if channel == ContactVerificationCode.Channel.WHATSAPP:
        _send_twilio_otp(channel, destination, code, purpose)
        return
    raise DeliveryUnavailable("The selected delivery channel is unavailable.")


def _store_sms_delivery_submission(
    contact_code: ContactVerificationCode, submission: SMSDeliverySubmission,
) -> None:
    """Persist safe delivery metadata without changing OTP validity if diagnostics fail."""
    try:
        SMSDeliveryMetadata.objects.create(
            contact_code=contact_code,
            provider=SMSDeliveryMetadata.Provider.INFOBIP,
            provider_message_id=submission.provider_message_id,
            initial_status_group=submission.status_group,
            initial_status_name=submission.status_name,
            initial_status_description=submission.status_description,
            last_status_group=submission.status_group,
            last_status_name=submission.status_name,
            last_status_description=submission.status_description,
        )
    except Exception as exc:  # A message was accepted; do not invalidate its usable OTP.
        logger.error(
            "OTP delivery metadata persistence failed: provider=infobip channel=sms error_type=%s",
            type(exc).__name__,
        )


def fetch_infobip_delivery_report(delivery: SMSDeliveryMetadata) -> SMSDeliveryMetadata:
    """Fetch one Infobip report using its stored identifier; never make an unfiltered query."""
    if delivery.provider != SMSDeliveryMetadata.Provider.INFOBIP or not delivery.provider_message_id:
        raise DeliveryUnavailable("The requested delivery report is unavailable.")
    api_key = getattr(settings, "INFOBIP_API_KEY", "")
    if not api_key:
        logger.warning("OTP provider failure: provider=infobip channel=sms error_type=missing_api_key")
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    report_url = f"{_infobip_api_base_url()}/sms/3/reports?{urlencode({'messageId': delivery.provider_message_id})}"
    request = Request(
        report_url,
        headers={"Authorization": f"App {api_key}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=settings.INFOBIP_SMS_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            response_body = response.read()
    except HTTPError as exc:
        logger.warning(
            "OTP delivery report failure: provider=infobip channel=sms http_status=%s provider_code=%s",
            exc.code,
            _infobip_error_code(exc.read()),
        )
        raise DeliveryUnavailable("The requested delivery report is unavailable.") from exc
    except (URLError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
        logger.warning(
            "OTP delivery report failure: provider=infobip channel=sms error_type=%s",
            _infobip_network_error_type(exc),
        )
        raise DeliveryUnavailable("The requested delivery report is unavailable.") from exc
    if not 200 <= status < 300:
        logger.warning("OTP delivery report failure: provider=infobip channel=sms http_status=%s", status)
        raise DeliveryUnavailable("The requested delivery report is unavailable.")
    try:
        payload = loads(response_body.decode("utf-8"))
        results = payload.get("results") if isinstance(payload, dict) else None
        report = results[0] if isinstance(results, list) and results and isinstance(results[0], dict) else None
    except (UnicodeDecodeError, JSONDecodeError):
        report = None
    delivery.last_checked_at = timezone.now()
    if report:
        status_data = report.get("status") if isinstance(report.get("status"), dict) else {}
        error_data = report.get("error") if isinstance(report.get("error"), dict) else {}
        delivery.last_status_group = _safe_provider_text(status_data.get("groupName"), 64)
        delivery.last_status_name = _safe_provider_text(status_data.get("name"), 100)
        delivery.last_status_description = _safe_provider_text(status_data.get("description"), 255)
        delivery.last_error_group = _safe_provider_text(error_data.get("groupName"), 64)
        delivery.last_error_name = _safe_provider_text(error_data.get("name"), 100)
        delivery.last_error_description = _safe_provider_text(error_data.get("description"), 255)
        if delivery.last_status_group in {"DELIVERED", "UNDELIVERABLE", "REJECTED", "EXPIRED"}:
            delivery.finalized_at = delivery.last_checked_at
    delivery.save()
    return delivery


def issue_code(user, purpose: str, channel: str) -> tuple[ContactVerificationCode, str]:
    """Create and deliver a new code, invalidating all prior unconsumed codes for its purpose."""
    destinations = available_channels(user)
    destination = destinations.get(channel)
    if not destination:
        raise DeliveryUnavailable("The selected delivery channel is unavailable for this account.")
    now = timezone.now()
    cooldown = timedelta(seconds=settings.OTP_RESEND_COOLDOWN_SECONDS)
    with transaction.atomic():
        # Serialise issuance per user so concurrent resend requests cannot leave
        # two active codes for the same purpose.
        user.__class__.objects.select_for_update().get(pk=user.pk)
        recent = ContactVerificationCode.objects.select_for_update().filter(
            user=user, purpose=purpose, used_at__isnull=True, invalidated_at__isnull=True,
            created_at__gt=now - cooldown,
        ).exists()
        if recent:
            raise ResendCooldown("Please wait before requesting another code.")
        ContactVerificationCode.objects.filter(
            user=user, purpose=purpose, used_at__isnull=True, invalidated_at__isnull=True,
        ).update(invalidated_at=now)
        code = _new_code()
        record = ContactVerificationCode.objects.create(
            user=user,
            purpose=purpose,
            channel=channel,
            contact_digest=_contact_digest(destination),
            code_hash=make_password(code),
            expires_at=now + timedelta(seconds=settings.OTP_EXPIRY_SECONDS),
        )
    try:
        submission = send_otp(channel, destination, code, purpose)
    except Exception as exc:
        # Keep operational diagnostics useful without logging the recipient,
        # OTP, provider request URL, or credential material.
        logger.warning(
            "OTP delivery provider failure: channel=%s error_type=%s error_code=%s http_status=%s",
            channel,
            type(exc).__name__,
            getattr(exc, "code", None),
            getattr(exc, "status", None),
        )
        ContactVerificationCode.objects.filter(pk=record.pk, used_at__isnull=True).update(invalidated_at=timezone.now())
        if isinstance(exc, DeliveryUnavailable):
            raise
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.") from exc
    if isinstance(submission, SMSDeliverySubmission):
        _store_sms_delivery_submission(record, submission)
    return record, mask_destination(channel, destination)


def verify_code(user, purpose: str, submitted_code: str) -> VerificationResult:
    """Verify exactly one current code atomically and consume it on success or lockout."""
    now = timezone.now()
    with transaction.atomic():
        record = ContactVerificationCode.objects.select_for_update().filter(
            user=user, purpose=purpose, used_at__isnull=True, invalidated_at__isnull=True,
        ).first()
        if not record:
            return VerificationResult(False, "No active code is available. Request a new code.")
        if record.expires_at <= now:
            record.invalidated_at = now
            record.save(update_fields=["invalidated_at"])
            return VerificationResult(False, "This code has expired. Request a new code.")
        if record.attempts >= settings.OTP_MAX_ATTEMPTS:
            record.invalidated_at = now
            record.save(update_fields=["invalidated_at"])
            return VerificationResult(False, "Too many attempts. Request a new code.")
        if not re.fullmatch(r"\d{6}", submitted_code or "") or not check_password(submitted_code, record.code_hash):
            record.attempts += 1
            fields = ["attempts"]
            if record.attempts >= settings.OTP_MAX_ATTEMPTS:
                record.invalidated_at = now
                fields.append("invalidated_at")
            record.save(update_fields=fields)
            return VerificationResult(False, "The verification code is invalid.")
        record.used_at = now
        record.save(update_fields=["used_at"])
        return VerificationResult(True)
