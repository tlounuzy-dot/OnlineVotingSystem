from datetime import date
import uuid

from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from .fields import WebAuthnCredentialIDField
from .eligibility import validate_voter_age

from .managers import UserManager


class Role(models.Model):
    """Access level from the Phase 3 ROLE entity."""

    name = models.CharField(max_length=50, unique=True)
    description = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class User(AbstractUser):
    """Phase 3 USER entity, using email rather than a separate username."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        PENDING = "pending", "Pending"

    username = None
    first_name = None
    last_name = None
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=100)
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="users")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    # Superusers always receive the application Admin role in UserManager;
    # exposing a ForeignKey here makes createsuperuser prompt for a raw ID.
    REQUIRED_FIELDS = ["full_name"]
    objects = UserManager()

    class Meta:
        ordering = ["full_name", "email"]

    def __str__(self):
        return self.full_name or self.email


class Voter(models.Model):
    """Voter eligibility details linked one-to-one with a user account."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        VERIFIED = "verified", "Verified"
        REJECTED = "rejected", "Rejected"

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="voter_profile")
    id_number = models.CharField(max_length=20, unique=True)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    address = models.CharField(max_length=255, blank=True)
    registration_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.VERIFIED)

    class Meta:
        ordering = ["user__full_name"]

    def clean(self):
        if self.date_of_birth:
            try:
                validate_voter_age(self.date_of_birth)
            except ValidationError as error:
                raise ValidationError({"date_of_birth": error.messages})

    def __str__(self):
        return f"{self.user.full_name} ({self.id_number})"


class Biometric(models.Model):
    """Safe prototype record: no raw fingerprint, face image, or template is stored."""

    class BiometricType(models.TextChoices):
        FINGERPRINT = "fingerprint", "Fingerprint"
        FACE = "face", "Face"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        EXPIRED = "expired", "Expired"

    voter = models.ForeignKey(Voter, on_delete=models.CASCADE, related_name="biometrics")
    biometric_type = models.CharField(
        max_length=20, choices=BiometricType.choices, default=BiometricType.FINGERPRINT
    )
    template_reference = models.CharField(
        max_length=255,
        unique=True,
        help_text="Opaque reference or salted verification token; never raw biometric data.",
    )
    captured_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)

    class Meta:
        ordering = ["biometric_type"]
        constraints = [
            models.UniqueConstraint(
                fields=["voter", "biometric_type"],
                name="one_biometric_type_per_voter",
            ),
        ]

    def __str__(self):
        return f"{self.voter} - {self.get_biometric_type_display()}"


class BiometricVerification(models.Model):
    """A device capability and verification record for the student-project workflow.

    Browser-provided capabilities are recorded as a claim only. A later WebAuthn or
    passkey step must perform the actual device-authenticator verification.
    """

    class Status(models.TextChoices):
        AVAILABLE = "available", "Available"
        REGISTERED = "registered", "Registered"
        VERIFIED = "verified", "Verified"
        UNAVAILABLE = "unavailable", "Unavailable"
        FAILED = "failed", "Failed"

    voter = models.ForeignKey(
        Voter, on_delete=models.CASCADE, related_name="biometric_verifications"
    )
    biometric = models.ForeignKey(
        Biometric,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="verification_attempts",
    )
    requested_method = models.CharField(
        max_length=20,
        choices=Biometric.BiometricType.choices,
        blank=True,
        help_text="Method selected from the browser-reported supported methods.",
    )
    device_capabilities = models.JSONField(
        default=list,
        help_text="Browser-reported methods, for example [\"face\", \"fingerprint\"].",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.AVAILABLE)
    verification_reference = models.CharField(
        max_length=255,
        blank=True,
        help_text="Opaque WebAuthn/passkey or provider response reference; never raw biometric data.",
    )
    failure_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["voter", "status"])]

    def clean(self):
        allowed_methods = {choice for choice, _ in Biometric.BiometricType.choices}
        capabilities = self.device_capabilities or []

        if not isinstance(capabilities, list) or not set(capabilities).issubset(allowed_methods):
            raise ValidationError({"device_capabilities": "Use a list of supported biometric methods."})
        if self.requested_method and self.requested_method not in capabilities:
            raise ValidationError({"requested_method": "The selected method is not available on this device."})
        if self.biometric_id:
            if self.biometric.voter_id != self.voter_id:
                raise ValidationError({"biometric": "The biometric record belongs to another voter."})
            if self.biometric.biometric_type != self.requested_method:
                raise ValidationError({"biometric": "The biometric type must match the selected method."})

    def __str__(self):
        method = self.requested_method or "no supported method"
        return f"{self.voter} - {method}: {self.get_status_display()}"


class WebAuthnCredential(models.Model):
    """Public-key credential registered with a voter's WebAuthn authenticator.

    This model deliberately contains only public WebAuthn credential material and
    non-sensitive device metadata. Biometric samples, authenticator private keys,
    and assertion payloads never belong in the application database.
    """

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"

    voter = models.ForeignKey(
        Voter,
        on_delete=models.CASCADE,
        related_name="webauthn_credentials",
    )
    credential_id = WebAuthnCredentialIDField(
        max_length=1023,
        unique=True,
        help_text="Opaque byte identifier from the authenticator.",
    )
    public_key = models.BinaryField(
        help_text="COSE-encoded public key used to verify WebAuthn assertions."
    )
    signature_counter = models.PositiveBigIntegerField(
        default=0,
        help_text="Authenticator signature counter used for cloned-credential detection where supported.",
    )
    transports = models.JSONField(
        default=list,
        help_text="Authenticator-reported transports, such as internal, usb, ble, nfc, or hybrid.",
    )
    backup_eligible = models.BooleanField(
        default=False,
        help_text="Whether the authenticator reported that this credential may be backed up.",
    )
    backup_state = models.BooleanField(
        default=False,
        help_text="Whether the authenticator reported that this credential is currently backed up.",
    )
    device_name = models.CharField(
        max_length=100,
        blank=True,
        help_text="Optional user-facing label; it must not contain biometric information.",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["voter", "status"])]

    def __str__(self):
        return f"WebAuthn credential for {self.voter} ({self.get_status_display()})"

    def revoke(self):
        """Deactivate this credential while preserving it and its future audit history."""
        self.status = self.Status.REVOKED
        self.revoked_at = timezone.now()
        self.save(update_fields=["status", "revoked_at"])


class WebAuthnChallenge(models.Model):
    """Single-use server-side WebAuthn ceremony state; never stores a raw challenge."""
    class Ceremony(models.TextChoices):
        REGISTRATION = "registration", "Registration"

    voter = models.ForeignKey(Voter, on_delete=models.CASCADE, related_name="webauthn_challenges")
    challenge_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    ceremony = models.CharField(max_length=20, choices=Ceremony.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["voter", "ceremony", "expires_at"])]


class LoginAttempt(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    user = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="login_attempts"
    )
    attempt_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices)
    failure_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-attempt_time"]

    def __str__(self):
        user_label = self.user.email if self.user else "Unknown user"
        return f"{user_label}: {self.get_status_display()}"


class ContactVerificationCode(models.Model):
    """Single-use, hashed contact-verification code.

    The raw six-digit value is intentionally never persisted.  A consumed record
    is retained as a minimal audit trail that a particular contact channel was
    verified; it does not alter voter approval or WebAuthn state.
    """

    class Purpose(models.TextChoices):
        REGISTRATION_VERIFICATION = "registration", "Registration verification"
        PASSWORD_RESET = "password_reset", "Password reset"

    class Channel(models.TextChoices):
        EMAIL = "email", "Email"
        SMS = "sms", "SMS"
        WHATSAPP = "whatsapp", "WhatsApp"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="contact_codes")
    purpose = models.CharField(max_length=32, choices=Purpose.choices)
    channel = models.CharField(max_length=16, choices=Channel.choices)
    contact_digest = models.CharField(
        max_length=64,
        help_text="SHA-256 digest of the normalized delivery destination; never the OTP.",
    )
    code_hash = models.CharField(max_length=255, help_text="Salted password-style hash of the OTP.")
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    invalidated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "purpose", "created_at"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return f"{self.get_purpose_display()} via email for user {self.user_id}"


class SMSDeliveryMetadata(models.Model):
    """Non-secret Infobip delivery state associated with one SMS OTP submission.

    This deliberately lives apart from ContactVerificationCode so provider
    identifiers and delivery states cannot be mistaken for verification secrets.
    It never stores the recipient, message body, OTP, API key, or headers.
    """

    class Provider(models.TextChoices):
        INFOBIP = "infobip", "Infobip"

    contact_code = models.OneToOneField(
        ContactVerificationCode,
        on_delete=models.CASCADE,
        related_name="sms_delivery_metadata",
    )
    provider = models.CharField(max_length=32, choices=Provider.choices)
    provider_message_id = models.CharField(max_length=128, unique=True)
    initial_status_group = models.CharField(max_length=64, blank=True)
    initial_status_name = models.CharField(max_length=100, blank=True)
    initial_status_description = models.CharField(max_length=255, blank=True)
    last_status_group = models.CharField(max_length=64, blank=True)
    last_status_name = models.CharField(max_length=100, blank=True)
    last_status_description = models.CharField(max_length=255, blank=True)
    last_error_group = models.CharField(max_length=64, blank=True)
    last_error_name = models.CharField(max_length=100, blank=True)
    last_error_description = models.CharField(max_length=255, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    finalized_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-submitted_at"]
        indexes = [models.Index(fields=["provider", "last_status_group"])]

    def __str__(self):
        return f"{self.get_provider_display()} SMS delivery metadata ({self.initial_status_name or 'submitted'})"


class AuditLog(models.Model):
    user = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_logs"
    )
    action = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.action} at {self.created_at:%Y-%m-%d %H:%M}"


class SystemSetting(models.Model):
    setting_key = models.CharField(max_length=100, unique=True)
    setting_value = models.CharField(max_length=255, blank=True)
    description = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["setting_key"]

    def __str__(self):
        return self.setting_key
