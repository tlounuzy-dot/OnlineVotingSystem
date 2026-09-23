"""Secure, reusable delivery and verification services for contact OTPs."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import ContactVerificationCode


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
    if channel == ContactVerificationCode.Channel.SMS:
        sender = getattr(settings, "TWILIO_SMS_FROM_NUMBER", "")
        recipient = destination
    else:
        sender = getattr(settings, "TWILIO_WHATSAPP_FROM_NUMBER", "")
        recipient = f"whatsapp:{destination}"
    if not sender:
        raise DeliveryUnavailable("This delivery channel is not configured in this environment.")
    client.messages.create(
        body=f"SecureVote: Your verification code is {code}. It expires in 5 minutes.",
        from_=sender,
        to=recipient,
    )


def send_otp(channel: str, destination: str, code: str, purpose: str) -> None:
    """Dispatch through one provider boundary; never log provider secrets or the code."""
    if channel == ContactVerificationCode.Channel.EMAIL:
        _send_email_otp(destination, code, purpose)
        return
    if channel in {ContactVerificationCode.Channel.SMS, ContactVerificationCode.Channel.WHATSAPP}:
        _send_twilio_otp(channel, destination, code, purpose)
        return
    raise DeliveryUnavailable("The selected delivery channel is unavailable.")


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
        send_otp(channel, destination, code, purpose)
    except Exception as exc:
        ContactVerificationCode.objects.filter(pk=record.pk, used_at__isnull=True).update(invalidated_at=timezone.now())
        if isinstance(exc, DeliveryUnavailable):
            raise
        raise DeliveryUnavailable("The verification code could not be delivered. Please try again.") from exc
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
