import base64
import hashlib
import json
import re
from datetime import date, timedelta
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth import authenticate, get_user_model
from django.core import mail
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from elections.models import Candidate, Election
from voting.models import Vote

from .models import (AuditLog, ContactVerificationCode, LoginAttempt, Role,
                     Voter, WebAuthnChallenge,
                     WebAuthnCredential)
from .otp import DeliveryUnavailable, issue_code, verify_code
from .eligibility import calculate_age


class RoleInitializationTests(TestCase):
    def test_seed_roles_creates_roles_once(self):
        call_command("seed_roles")
        call_command("seed_roles")

        self.assertEqual(Role.objects.filter(name="Admin").count(), 1)
        self.assertEqual(Role.objects.filter(name="Voter").count(), 1)


class SuperuserCreationTests(TestCase):
    def test_create_superuser_resolves_one_admin_role_and_authenticates(self):
        admin_role = Role.objects.create(name="Admin", description="Existing admin role.")

        user = get_user_model().objects.create_superuser(
            email="superuser@example.test", password="SuperuserPassword!42",
            full_name="SecureVote Administrator",
        )

        self.assertEqual(user.role, admin_role)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertEqual(user.status, get_user_model().Status.ACTIVE)
        self.assertNotEqual(user.password, "SuperuserPassword!42")
        self.assertTrue(user.check_password("SuperuserPassword!42"))
        self.assertEqual(Role.objects.filter(name="Admin").count(), 1)
        self.assertEqual(
            authenticate(email=user.email, password="SuperuserPassword!42"), user
        )

        response = self.client.post(reverse("accounts:login"), {
            "email": user.email, "password": "SuperuserPassword!42",
        })
        self.assertRedirects(response, reverse("elections:dashboard"))

    def test_create_superuser_creates_admin_role_when_roles_are_not_seeded(self):
        user = get_user_model().objects.create_superuser(
            email="first-superuser@example.test", password="SuperuserPassword!42",
            full_name="First Administrator",
        )

        self.assertEqual(user.role.name, "Admin")
        self.assertEqual(Role.objects.filter(name="Admin").count(), 1)
        self.assertEqual(get_user_model().REQUIRED_FIELDS, ["full_name"])


class VoterRegistrationTests(TestCase):
    def setUp(self):
        Role.objects.create(name="Voter", description="Registered voter access.")
        self.url = reverse("accounts:register")
        self.data = {
            "full_name": "Test Voter",
            "email": "voter@example.test",
            "id_number": "TEST-1001",
            "date_of_birth": "2000-01-01",
            "gender": "",
            "phone": "",
            "address": "",
            "password": "CorrectHorse!42Car",
            "password_confirmation": "CorrectHorse!42Car",
        }

    def test_successful_registration_creates_pending_voter_account(self):
        response = self.client.post(self.url, self.data)

        self.assertRedirects(response, reverse("accounts:registration_verification_method"))
        user = get_user_model().objects.get(email=self.data["email"])
        voter = Voter.objects.get(user=user)
        self.assertEqual(user.role.name, "Voter")
        self.assertEqual(user.status, get_user_model().Status.PENDING)
        self.assertEqual(voter.status, Voter.Status.PENDING)
        self.assertFalse(user.is_active)
        self.assertEqual(voter.id_number, self.data["id_number"])
        self.assertNotEqual(user.password, self.data["password"])
        self.assertTrue(user.check_password(self.data["password"]))

    def test_registration_uses_shared_password_visibility_control_without_unmasking_fields(self):
        response = self.client.get(self.url)

        self.assertContains(response, "js/password-visibility.js")
        self.assertEqual(response.content.count(b'type="password"'), 2)

    def test_duplicate_email_is_rejected(self):
        self.client.post(self.url, self.data)
        duplicate_data = self.data | {"id_number": "TEST-1002"}

        response = self.client.post(self.url, duplicate_data)

        self.assertContains(response, "An account with this email address already exists.")
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_duplicate_id_number_is_rejected(self):
        self.client.post(self.url, self.data)
        duplicate_data = self.data | {"email": "another@example.test"}

        response = self.client.post(self.url, duplicate_data)

        self.assertContains(response, "A voter with this ID number already exists.")
        self.assertEqual(Voter.objects.count(), 1)

    def test_password_mismatch_is_rejected(self):
        response = self.client.post(self.url, self.data | {"password_confirmation": "Different!42"})

        self.assertContains(response, "Passwords do not match.")
        self.assertEqual(get_user_model().objects.count(), 0)
        self.assertEqual(Voter.objects.count(), 0)

    def test_voter_save_failure_rolls_back_user_creation(self):
        with patch("accounts.forms.Voter.save", side_effect=IntegrityError("test failure")):
            response = self.client.post(self.url, self.data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_user_model().objects.count(), 0)
        self.assertEqual(Voter.objects.count(), 0)


class PublicWorkflowSessionTests(TestCase):
    def setUp(self):
        self.admin_role = Role.objects.create(name="Admin")
        self.voter_role = Role.objects.create(name="Voter")
        self.admin = get_user_model().objects.create_user(
            email="workflow-admin@example.test", password="CorrectHorse!42Car", full_name="Workflow Admin",
            role=self.admin_role, status=get_user_model().Status.ACTIVE, is_staff=True,
        )
        self.voter = get_user_model().objects.create_user(
            email="workflow-voter@example.test", password="CorrectHorse!42Car", full_name="Workflow Voter",
            role=self.voter_role, status=get_user_model().Status.PENDING, is_active=False,
        )
        Voter.objects.create(
            user=self.voter, id_number="WORKFLOW-1", date_of_birth="2000-01-01", status=Voter.Status.PENDING,
        )

    def test_logged_in_admin_must_log_out_before_registration_and_public_nav_has_no_admin_links(self):
        self.client.force_login(self.admin)
        response = self.client.get(reverse("accounts:register"))
        self.assertEqual(response.status_code, 409)
        self.assertContains(response, "Log out to continue", status_code=409)
        self.assertNotContains(response, "Audit logs", status_code=409)
        self.assertNotContains(response, "Elections", status_code=409)
        before = get_user_model().objects.count()
        response = self.client.post(reverse("accounts:register"), {
            "full_name": "Attempted Voter", "email": "attempt@example.test", "id_number": "WORKFLOW-2",
            "date_of_birth": "2000-01-01", "gender": "", "phone": "", "address": "",
            "password": "CorrectHorse!42Car", "password_confirmation": "CorrectHorse!42Car",
        })
        self.assertEqual(response.status_code, 409)
        self.assertEqual(get_user_model().objects.count(), before)

    def test_registration_otp_cannot_inherit_admin_session_or_grant_admin_role(self):
        self.client.force_login(self.admin)
        session = self.client.session
        session["registration_verification_user_id"] = self.voter.pk
        session.save()
        response = self.client.get(reverse("accounts:registration_verification_code"))
        self.assertEqual(response.status_code, 409)
        self.assertNotContains(response, "Admin", status_code=409)
        self.voter.refresh_from_db()
        self.assertEqual(self.voter.role.name, "Voter")
        self.assertFalse(self.voter.is_staff)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.admin.pk))
        self.assertNotEqual(self.client.session["_auth_user_id"], str(self.voter.pk))

    def test_anonymous_registration_and_normal_admin_dashboard_remain_available(self):
        anonymous = self.client_class()
        self.assertEqual(anonymous.get(reverse("accounts:register")).status_code, 200)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse("elections:dashboard")).status_code, 200)

    def test_voter_cannot_access_admin_management_routes(self):
        self.voter.status = get_user_model().Status.ACTIVE
        self.voter.is_active = True
        self.voter.save(update_fields=["status", "is_active"])
        self.voter.voter_profile.status = Voter.Status.VERIFIED
        self.voter.voter_profile.save(update_fields=["status"])
        self.client.force_login(self.voter)
        self.assertEqual(self.client.get(reverse("accounts:voter_list")).status_code, 403)


class LoginAuthenticationTests(TestCase):
    def setUp(self):
        self.role = Role.objects.create(name="Voter", description="Registered voter access.")
        self.user = get_user_model().objects.create_user(
            email="login-voter@example.test",
            password="CorrectHorse!42Car",
            full_name="Login Test Voter",
            role=self.role,
            status=get_user_model().Status.ACTIVE,
        )
        self.voter = Voter.objects.create(
            user=self.user,
            id_number="LOGIN-TEST-1",
            date_of_birth="2000-01-01",
            status=Voter.Status.VERIFIED,
        )
        self.url = reverse("accounts:login")
        self.data = {"email": self.user.email, "password": "CorrectHorse!42Car"}

    def test_login_page_loads(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Login")
        self.assertContains(response, "js/password-visibility.js")
        self.assertContains(response, 'type="password"')

    def test_successful_login_creates_session_and_redirects_to_biometric_entry(self):
        response = self.client.post(self.url, self.data)

        self.assertRedirects(response, reverse("accounts:biometric_entry"))
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))
        attempt = self.user.login_attempts.get()
        self.assertEqual(attempt.status, attempt.Status.SUCCESS)

    def test_eligible_voter_without_a_credential_is_sent_to_device_registration(self):
        self.client.post(self.url, self.data)

        response = self.client.get(reverse("accounts:biometric_entry"))

        self.assertContains(response, reverse("accounts:webauthn_registration"))
        self.assertNotContains(response, reverse("accounts:webauthn_authentication"))

    def test_invalid_password_is_rejected_and_logged(self):
        response = self.client.post(self.url, self.data | {"password": "WrongPassword!99"})

        self.assertContains(response, "Invalid email or password.")
        attempt = self.user.login_attempts.get()
        self.assertEqual(attempt.status, attempt.Status.FAILED)

    def test_nonexistent_email_is_rejected_and_logged_without_user(self):
        response = self.client.post(
            self.url, {"email": "unknown@example.test", "password": "WrongPassword!99"}
        )

        self.assertContains(response, "Invalid email or password.")
        attempt = LoginAttempt.objects.get()
        self.assertEqual(attempt.status, attempt.Status.FAILED)
        self.assertIsNone(attempt.user)

    def test_inactive_account_cannot_log_in(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.post(self.url, self.data)

        self.assertContains(response, "Invalid email or password.")
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(self.user.login_attempts.get().status, LoginAttempt.Status.FAILED)

    def test_login_attempt_never_contains_password(self):
        self.client.post(self.url, self.data | {"password": "WrongPassword!99"})

        attempt = self.user.login_attempts.get()
        self.assertFalse(hasattr(attempt, "password"))
        self.assertNotIn("WrongPassword!99", attempt.failure_reason)

    def test_logout_ends_the_authenticated_session(self):
        self.client.force_login(self.user)

        response = self.client.post(reverse("accounts:logout"))

        self.assertRedirects(response, self.url)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_biometric_entry_requires_authenticated_session(self):
        response = self.client.get(reverse("accounts:biometric_entry"))

        self.assertRedirects(response, f"{self.url}?next={reverse('accounts:biometric_entry')}")

    def test_invalid_email_is_rejected(self):
        response = self.client.post(self.url, self.data | {"email": "not-an-email"})

        self.assertContains(response, "Enter a valid email address.")
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_required_fields_are_validated(self):
        response = self.client.post(self.url, {"email": "", "password": ""})

        self.assertContains(response, "This field is required.")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_password_is_hashed(self):
        self.client.post(self.url, self.data)

        user = get_user_model().objects.get(email=self.data["email"])
        self.assertNotEqual(user.password, self.data["password"])
        self.assertTrue(user.check_password(self.data["password"]))

    def test_admin_login_routes_to_admin_dashboard_not_voter_biometric_page(self):
        admin_role = Role.objects.create(name="Admin")
        admin = get_user_model().objects.create_user(
            email="admin-login@example.test", password="CorrectHorse!42Car",
            full_name="Admin Login", role=admin_role,
            status=get_user_model().Status.ACTIVE, is_staff=True,
        )

        response = self.client.post(self.url, {"email": admin.email, "password": "CorrectHorse!42Car"})

        self.assertRedirects(response, reverse("elections:dashboard"))

    def test_pending_voter_with_correct_password_sees_clear_pending_message(self):
        self.user.status = get_user_model().Status.PENDING
        self.user.save(update_fields=["status"])
        self.voter.status = Voter.Status.PENDING
        self.voter.save(update_fields=["status"])

        response = self.client.post(self.url, self.data)

        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "pending approval", status_code=403)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(self.user.login_attempts.get().status, LoginAttempt.Status.SUCCESS)
        self.assertEqual(self.client.get(reverse("elections:voter_dashboard")).status_code, 302)


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    OTP_RESEND_COOLDOWN_SECONDS=0,
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class ContactVerificationTests(TestCase):
    def setUp(self):
        self.role = Role.objects.create(name="Voter")
        self.user = get_user_model().objects.create_user(
            email="reset-voter@example.test", password="OldPassword!42",
            full_name="Reset Voter", role=self.role, status=get_user_model().Status.PENDING,
        )
        self.voter = Voter.objects.create(
            user=self.user, id_number="RESET-1", date_of_birth="2000-01-01",
            status=Voter.Status.PENDING,
        )

    def _issue(self, purpose, channel="email", code="123456"):
        with patch("accounts.otp._new_code", return_value=code):
            return issue_code(self.user, purpose, channel)

    def test_new_password_page_keeps_fields_masked_and_loads_shared_visibility_control(self):
        session = self.client.session
        session["password_reset_verified_user_id"] = self.user.pk
        session.save()

        response = self.client.get(reverse("accounts:password_reset_new_password"))

        self.assertContains(response, "js/password-visibility.js")
        self.assertEqual(response.content.count(b'type="password"'), 2)

    def test_registration_code_is_hashed_valid_and_does_not_approve_voter(self):
        record, _ = self._issue(ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION)
        self.assertNotEqual(record.code_hash, "123456")
        self.assertNotIn("123456", record.code_hash)
        self.assertTrue(verify_code(self.user, record.purpose, "123456").valid)
        record.refresh_from_db()
        self.assertIsNotNone(record.used_at)
        self.user.refresh_from_db(); self.voter.refresh_from_db()
        self.assertEqual(self.user.status, get_user_model().Status.PENDING)
        self.assertEqual(self.voter.status, Voter.Status.PENDING)

    def test_invalid_expired_reused_and_attempt_limited_codes_are_rejected(self):
        record, _ = self._issue(ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION)
        self.assertFalse(verify_code(self.user, record.purpose, "000000").valid)
        self.assertTrue(verify_code(self.user, record.purpose, "123456").valid)
        self.assertFalse(verify_code(self.user, record.purpose, "123456").valid)
        expired, _ = self._issue(ContactVerificationCode.Purpose.PASSWORD_RESET)
        ContactVerificationCode.objects.filter(pk=expired.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertIn("expired", verify_code(self.user, expired.purpose, "123456").reason)
        locked, _ = self._issue(ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION)
        for _ in range(5):
            verify_code(self.user, locked.purpose, "000000")
        self.assertIn("No active", verify_code(self.user, locked.purpose, "123456").reason)

    def test_resend_invalidates_previous_code_and_email_is_delivered(self):
        first, _ = self._issue(ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION, code="111111")
        second, _ = self._issue(ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION, code="222222")
        first.refresh_from_db()
        self.assertIsNotNone(first.invalidated_at)
        self.assertTrue(verify_code(self.user, second.purpose, "222222").valid)
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("222222", mail.outbox[-1].body)
        self.assertIn("This code expires in 5 minutes.", mail.outbox[-1].body)
        self.assertIn("If you did not request this code", mail.outbox[-1].body)

    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
        DEFAULT_FROM_EMAIL="securevote@example.test",
    )
    def test_email_otp_uses_configured_django_backend_without_exposing_credentials(self):
        with patch("accounts.otp.send_mail", return_value=1) as send:
            self._issue(ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION, code="333333")
        args, kwargs = send.call_args
        self.assertEqual(args[0], "Your SecureVote verification code")
        self.assertEqual(args[2], "securevote@example.test")
        self.assertEqual(args[3], [self.user.email])
        self.assertFalse(kwargs["fail_silently"])
        self.assertNotIn("EMAIL_HOST_PASSWORD", " ".join(str(value) for value in args))

    def test_registration_flow_activates_after_contact_verification_but_still_requires_webauthn(self):
        self.client.post(reverse("accounts:register"), {
            "full_name": "OTP Voter", "email": "otp-register@example.test", "id_number": "OTP-REGISTER-1",
            "date_of_birth": "2000-01-01", "gender": "", "phone": "", "address": "",
            "password": "CorrectHorse!42Car", "password_confirmation": "CorrectHorse!42Car",
        })
        user = get_user_model().objects.get(email="otp-register@example.test")
        with patch("accounts.otp._new_code", return_value="123456"):
            response = self.client.post(reverse("accounts:registration_verification_method"), {"channel": "email"})
        self.assertRedirects(response, reverse("accounts:registration_verification_code"))
        response = self.client.post(reverse("accounts:registration_verification_code"), {"code": "123456"})
        self.assertRedirects(response, reverse("accounts:registration_success"))
        user.refresh_from_db()
        self.assertEqual(user.status, get_user_model().Status.ACTIVE)
        self.assertTrue(user.is_active)
        self.assertEqual(user.voter_profile.status, Voter.Status.VERIFIED)
        login_response = self.client.post(reverse("accounts:login"), {
            "email": user.email, "password": "CorrectHorse!42Car",
        })
        self.assertRedirects(login_response, reverse("accounts:biometric_entry"))
        self.assertRedirects(
            self.client.get(reverse("elections:voter_dashboard")),
            reverse("accounts:biometric_entry"),
        )
        audit_text = " ".join(AuditLog.objects.filter(user=user).values_list("description", flat=True))
        self.assertNotIn("123456", audit_text)
        self.assertTrue(AuditLog.objects.filter(user=user, action="registration_contact_code_sent").exists())
        self.assertTrue(AuditLog.objects.filter(user=user, action="voter_auto_activated").exists())

    def test_pending_registration_email_correction_invalidates_old_code_and_sends_new_email(self):
        self.client.post(reverse("accounts:register"), {
            "full_name": "Correction Voter", "email": "wrong@example.test", "id_number": "CORRECT-1",
            "date_of_birth": "2000-01-01", "gender": "", "phone": "", "address": "",
            "password": "CorrectHorse!42Car", "password_confirmation": "CorrectHorse!42Car",
        })
        user = get_user_model().objects.get(email="wrong@example.test")
        with patch("accounts.otp._new_code", return_value="111111"):
            old, _ = issue_code(user, ContactVerificationCode.Purpose.REGISTRATION_VERIFICATION, "email")
        page = self.client.get(reverse("accounts:registration_verification_code"))
        self.assertContains(page, "Change email address")
        with patch("accounts.otp._new_code", return_value="222222"):
            response = self.client.post(reverse("accounts:registration_email_change"), {"email": "right@example.test"})
        self.assertRedirects(response, reverse("accounts:registration_verification_code"))
        user.refresh_from_db()
        self.assertEqual(user.email, "right@example.test")
        self.assertEqual(Voter.objects.filter(id_number="CORRECT-1").count(), 1)
        self.assertEqual(get_user_model().objects.count(), 2)
        old.refresh_from_db()
        self.assertIsNotNone(old.invalidated_at)
        self.assertFalse(verify_code(user, old.purpose, "111111").valid)
        fresh = ContactVerificationCode.objects.filter(user=user, invalidated_at__isnull=True).get()
        self.assertTrue(verify_code(user, fresh.purpose, "222222").valid)
        self.assertEqual(mail.outbox[-1].to, ["right@example.test"])

    def test_email_correction_requires_existing_session_and_rejects_duplicate_id_or_email(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        denied = self.client.post(reverse("accounts:registration_email_change"), {"id_number": "RESET-1", "email": "takeover@example.test"})
        self.assertRedirects(denied, reverse("accounts:register"))
        self.assertFalse(get_user_model().objects.filter(email="takeover@example.test").exists())
        session = self.client.session
        session["registration_verification_user_id"] = self.user.pk
        session.save()
        other = get_user_model().objects.create_user(email="already-used@example.test", password="CorrectHorse!42Car", full_name="Other", role=self.role, status=get_user_model().Status.PENDING)
        response = self.client.post(reverse("accounts:registration_email_change"), {"email": other.email})
        self.assertContains(response, "That email address cannot be used")
        self.assertEqual(get_user_model().objects.filter(email="reset-voter@example.test").count(), 1)
        self.assertEqual(self.client.post(reverse("accounts:register"), {
            "full_name": "Duplicate ID", "email": "different@example.test", "id_number": "RESET-1",
            "date_of_birth": "2000-01-01", "gender": "", "phone": "", "address": "",
            "password": "CorrectHorse!42Car", "password_confirmation": "CorrectHorse!42Car",
        }).status_code, 200)
        self.assertFalse(get_user_model().objects.filter(email="different@example.test").exists())

    def test_email_correction_denied_for_nonpending_user_states(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        session = self.client.session
        session["registration_verification_user_id"] = self.user.pk
        session.save()
        for user_status, voter_status in ((get_user_model().Status.ACTIVE, Voter.Status.VERIFIED),
                                          (get_user_model().Status.SUSPENDED, Voter.Status.VERIFIED),
                                          (get_user_model().Status.PENDING, Voter.Status.REJECTED)):
            self.user.status = user_status
            self.user.save(update_fields=["status"])
            self.voter.status = voter_status
            self.voter.save(update_fields=["status"])
            response = self.client.post(reverse("accounts:registration_email_change"), {"email": f"new{user_status}{voter_status}@example.test"})
            self.assertRedirects(response, reverse("accounts:register"))
            self.user.refresh_from_db()
            self.assertEqual(self.user.email, "reset-voter@example.test")
            self.user.status = get_user_model().Status.PENDING
            self.user.save(update_fields=["status"])
            self.voter.status = Voter.Status.PENDING
            self.voter.save(update_fields=["status"])
            session = self.client.session
            session["registration_verification_user_id"] = self.user.pk
            session.save()

    def test_password_recovery_request_does_not_enumerate_accounts(self):
        known = self.client.post(reverse("accounts:password_reset"), {"email": self.user.email})
        self.assertRedirects(known, reverse("accounts:password_reset_method"))
        known_page = self.client.get(reverse("accounts:password_reset_method"))
        self.assertEqual(known_page.status_code, 200)
        other = self.client_class()
        unknown = other.post(reverse("accounts:password_reset"), {"email": "unknown@example.test"})
        self.assertRedirects(unknown, reverse("accounts:password_reset_method"))
        unknown_page = other.get(reverse("accounts:password_reset_method"))
        self.assertContains(unknown_page, "Choose a recovery method")
        self.assertContains(known_page, "Choose a recovery method")

    def test_valid_password_reset_otp_changes_only_password_and_preserves_security_state(self):
        self.user.is_active = True
        self.user.save(update_fields=["is_active"])
        self.client.post(reverse("accounts:password_reset"), {"email": self.user.email})
        with patch("accounts.otp._new_code", return_value="123456"):
            response = self.client.post(reverse("accounts:password_reset_method"), {"channel": "email"})
        self.assertRedirects(response, reverse("accounts:password_reset_code"))
        response = self.client.post(reverse("accounts:password_reset_code"), {"code": "123456"})
        self.assertRedirects(response, reverse("accounts:password_reset_new_password"))
        response = self.client.post(reverse("accounts:password_reset_new_password"), {
            "new_password1": "NewPassword!42", "new_password2": "NewPassword!42",
        })
        self.assertRedirects(response, reverse("accounts:password_reset_complete"))
        self.user.refresh_from_db()
        self.voter.refresh_from_db()
        self.assertIsNone(authenticate(email=self.user.email, password="OldPassword!42"))
        self.assertEqual(authenticate(email=self.user.email, password="NewPassword!42"), self.user)
        self.assertEqual(self.user.role, self.role)
        self.assertEqual(self.user.status, get_user_model().Status.PENDING)
        self.assertEqual(self.voter.status, Voter.Status.PENDING)
        self.assertEqual(self.client.get(reverse("elections:voter_dashboard")).status_code, 302)

    def test_non_email_channel_is_rejected_by_service_and_endpoints(self):
        with self.assertRaises(DeliveryUnavailable):
            self._issue(ContactVerificationCode.Purpose.PASSWORD_RESET, "sms")
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        session = self.client.session
        session["registration_verification_user_id"] = self.user.pk
        session.save()
        response = self.client.post(reverse("accounts:registration_verification_method"), {"channel": "whatsapp"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ContactVerificationCode.objects.filter(channel__in=["sms", "whatsapp"]).exists())
        self.assertContains(response, "Email")
        self.assertNotContains(response, "SMS")
        self.assertNotContains(response, "WhatsApp")
        self.client.post(reverse("accounts:password_reset"), {"email": self.user.email})
        reset_response = self.client.post(reverse("accounts:password_reset_method"), {"channel": "sms"})
        self.assertEqual(reset_response.status_code, 200)
        self.assertFalse(ContactVerificationCode.objects.filter(purpose=ContactVerificationCode.Purpose.PASSWORD_RESET).exists())

    def test_email_only_reset_screen_and_delivery(self):
        self.client.post(reverse("accounts:password_reset"), {"email": self.user.email})
        screen = self.client.get(reverse("accounts:password_reset_method"))
        self.assertContains(screen, "Email")
        self.assertNotContains(screen, "SMS")
        self.assertNotContains(screen, "WhatsApp")
        with patch("accounts.otp._new_code", return_value="123456"):
            response = self.client.post(reverse("accounts:password_reset_method"), {"channel": "email"})
        self.assertRedirects(response, reverse("accounts:password_reset_code"))
        self.assertEqual(mail.outbox[-1].to, [self.user.email])
        self.assertEqual(ContactVerificationCode.objects.get().channel, ContactVerificationCode.Channel.EMAIL)


class VoterAgeEligibilityTests(TestCase):
    def setUp(self):
        Role.objects.create(name="Voter")
        self.url = reverse("accounts:register")

    @staticmethod
    def _years_ago(years):
        today = date.today()
        try:
            return today.replace(year=today.year - years)
        except ValueError:  # 29 February in a non-leap target year
            return today.replace(year=today.year - years, day=28)

    def _data(self, dob, *, email="age-voter@example.test", id_number="AGE-1001"):
        return {
            "full_name": "Age Test Voter", "email": email, "id_number": id_number,
            "date_of_birth": dob.isoformat() if isinstance(dob, date) else dob,
            "gender": "", "phone": "", "address": "",
            "password": "CorrectHorse!42Car", "password_confirmation": "CorrectHorse!42Car",
        }

    def test_exactly_eighteen_today_is_eligible_and_proceeds_to_contact_verification(self):
        dob = self._years_ago(18)
        self.assertEqual(calculate_age(dob), 18)
        response = self.client.post(self.url, self._data(dob))
        self.assertRedirects(response, reverse("accounts:registration_verification_method"))
        user = get_user_model().objects.get(email="age-voter@example.test")
        self.assertEqual(user.status, get_user_model().Status.PENDING)
        self.assertFalse(user.is_active)

    def test_eighteenth_birthday_tomorrow_and_obvious_underage_dates_are_rejected_without_records(self):
        almost_eighteen = self._years_ago(18) + timedelta(days=1)
        response = self.client.post(self.url, self._data(almost_eighteen))
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Registration not eligible", status_code=400)
        self.assertEqual(get_user_model().objects.count(), 0)
        response = self.client.post(self.url, self._data(self._years_ago(12), email="young@example.test", id_number="AGE-1002"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(get_user_model().objects.count(), 0)
        self.assertEqual(Voter.objects.count(), 0)

    def test_older_voter_is_eligible_and_future_or_malformed_dates_are_rejected(self):
        response = self.client.post(self.url, self._data(self._years_ago(30)))
        self.assertRedirects(response, reverse("accounts:registration_verification_method"))
        future = self.client.post(self.url, self._data(date.today() + timedelta(days=1), email="future@example.test", id_number="AGE-1003"))
        self.assertContains(future, "Date of birth must be in the past.")
        malformed = self.client.post(self.url, self._data("not-a-date", email="bad@example.test", id_number="AGE-1004"))
        self.assertContains(malformed, "Enter a valid date.")
        self.assertEqual(get_user_model().objects.count(), 1)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", OTP_RESEND_COOLDOWN_SECONDS=0)
    def test_suspended_voter_cannot_be_automatically_reactivated_by_contact_code(self):
        response = self.client.post(self.url, self._data(self._years_ago(24)))
        self.assertRedirects(response, reverse("accounts:registration_verification_method"))
        user = get_user_model().objects.get(email="age-voter@example.test")
        with patch("accounts.otp._new_code", return_value="123456"):
            self.client.post(reverse("accounts:registration_verification_method"), {"channel": "email"})
        user.status = get_user_model().Status.SUSPENDED; user.is_active = False
        user.save(update_fields=["status", "is_active"])
        user.voter_profile.status = Voter.Status.VERIFIED; user.voter_profile.save(update_fields=["status"])
        response = self.client.post(reverse("accounts:registration_verification_code"), {"code": "123456"})
        self.assertRedirects(response, reverse("accounts:register"))
        user.refresh_from_db(); user.voter_profile.refresh_from_db()
        self.assertEqual(user.status, get_user_model().Status.SUSPENDED)
        self.assertEqual(user.voter_profile.status, Voter.Status.VERIFIED)

    def test_administrator_can_still_manage_voter_status(self):
        voter_role = Role.objects.get(name="Voter")
        voter_user = get_user_model().objects.create_user(
            email="managed-voter@example.test", password="CorrectHorse!42Car", full_name="Managed Voter",
            role=voter_role, status=get_user_model().Status.PENDING, is_active=False,
        )
        voter = Voter.objects.create(
            user=voter_user, id_number="AGE-MANAGED-1", date_of_birth=self._years_ago(25),
            status=Voter.Status.PENDING,
        )
        admin_role = Role.objects.create(name="Admin")
        admin = get_user_model().objects.create_user(
            email="status-admin@example.test", password="CorrectHorse!42Car", full_name="Status Admin",
            role=admin_role, status=get_user_model().Status.ACTIVE, is_active=True, is_staff=True,
        )
        self.client.force_login(admin)
        response = self.client.post(reverse("accounts:voter_status", args=[voter.pk]), {"status": Voter.Status.VERIFIED})
        self.assertRedirects(response, reverse("accounts:voter_list"))
        voter.refresh_from_db(); voter_user.refresh_from_db()
        self.assertEqual(voter.status, Voter.Status.VERIFIED)
        self.assertEqual(voter_user.status, get_user_model().Status.ACTIVE)
        self.assertTrue(voter_user.is_active)


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class VoterSuspensionLifecycleTests(TestCase):
    def setUp(self):
        admin_role = Role.objects.create(name="Admin")
        voter_role = Role.objects.create(name="Voter")
        self.admin = get_user_model().objects.create_user(
            email="suspension-admin@example.test", password="ValidPass!42", full_name="Suspension Admin",
            role=admin_role, status=get_user_model().Status.ACTIVE, is_active=True, is_staff=True,
        )
        self.user = get_user_model().objects.create_user(
            email="suspension-voter@example.test", password="ValidPass!42", full_name="Suspension Voter",
            role=voter_role, status=get_user_model().Status.ACTIVE, is_active=True,
        )
        self.voter = Voter.objects.create(
            user=self.user, id_number="SUSPEND-1", date_of_birth="2000-01-01", status=Voter.Status.VERIFIED,
        )
        self.credential = WebAuthnCredential.objects.create(
            voter=self.voter, credential_id=b"suspension-credential", public_key=b"example-cose-key",
        )
        self.election = Election.objects.create(
            title="Suspension history", start_date=timezone.now() - timedelta(days=2),
            end_date=timezone.now() - timedelta(days=1), status=Election.Status.CLOSED,
            created_by=self.admin,
        )
        self.candidate = Candidate.objects.create(election=self.election, full_name="Candidate", party="Party")
        self.vote = Vote.objects.create(
            voter=self.voter, election=self.election, candidate=self.candidate, encrypted_choice=b"test-snapshot",
        )
        self.status_url = reverse("accounts:voter_status", args=[self.voter.pk])

    def _suspend(self):
        self.client.force_login(self.admin)
        return self.client.post(self.status_url, {"status": get_user_model().Status.SUSPENDED})

    def _verified_voter_session(self, client):
        client.force_login(self.user)
        session = client.session
        session["webauthn_verified_voter_id"] = self.voter.pk
        session.save()

    def test_verified_voter_is_displayed_as_suspended_after_admin_suspension(self):
        management_page = self.client
        management_page.force_login(self.admin)
        response = management_page.get(reverse("accounts:voter_list"))
        self.assertContains(response, reverse("accounts:voter_status", args=[self.voter.pk]))
        self.assertContains(response, 'name="status" value="suspended"')
        self.assertContains(response, "csrfmiddlewaretoken")
        self.assertContains(response, "Suspend")

        self.assertRedirects(self._suspend(), reverse("accounts:voter_list"))
        self.user.refresh_from_db(); self.voter.refresh_from_db()

        self.assertEqual(self.user.status, get_user_model().Status.SUSPENDED)
        self.assertFalse(self.user.is_active)
        self.assertEqual(self.voter.status, Voter.Status.VERIFIED)
        page = self.client.get(reverse("accounts:voter_list"))
        self.assertContains(page, "Suspended")
        self.assertContains(page, "Reactivate")

    def test_suspension_blocks_new_logins_and_existing_protected_voter_sessions(self):
        existing_session = self.client_class()
        self._verified_voter_session(existing_session)
        self._suspend()

        login_client = self.client_class()
        response = login_client.post(reverse("accounts:login"), {
            "email": self.user.email, "password": "ValidPass!42",
        })
        self.assertContains(response, "Invalid email or password.")
        self.assertNotIn("_auth_user_id", login_client.session)
        for url in (
            reverse("elections:voter_dashboard"),
            reverse("reports:voter_results"),
            reverse("accounts:biometric_entry"),
        ):
            self.assertRedirects(existing_session.get(url), f"{reverse('accounts:login')}?next={url}")

    def test_password_reset_cannot_reactivate_a_suspended_voter(self):
        self._suspend()
        reset_client = self.client_class()
        session = reset_client.session
        session["password_reset_verified_user_id"] = self.user.pk
        session.save()

        response = reset_client.post(reverse("accounts:password_reset_new_password"), {
            "new_password1": "ReplacementPassword!42", "new_password2": "ReplacementPassword!42",
        })
        self.assertRedirects(response, reverse("accounts:password_reset_complete"))
        self.user.refresh_from_db(); self.voter.refresh_from_db()
        self.assertTrue(self.user.check_password("ReplacementPassword!42"))
        self.assertEqual(self.user.status, get_user_model().Status.SUSPENDED)
        self.assertFalse(self.user.is_active)
        self.assertEqual(self.voter.status, Voter.Status.VERIFIED)

    def test_admin_reactivation_preserves_web_authn_credentials_and_vote_history(self):
        self._suspend()
        self.client.force_login(self.admin)
        self.assertRedirects(self.client.post(self.status_url, {"status": Voter.Status.VERIFIED}), reverse("accounts:voter_list"))
        self.user.refresh_from_db(); self.voter.refresh_from_db()

        self.assertEqual(self.user.status, get_user_model().Status.ACTIVE)
        self.assertTrue(self.user.is_active)
        self.assertEqual(self.voter.status, Voter.Status.VERIFIED)
        self.assertTrue(WebAuthnCredential.objects.filter(pk=self.credential.pk).exists())
        self.assertTrue(Vote.objects.filter(pk=self.vote.pk).exists())
        login_client = self.client_class()
        response = login_client.post(reverse("accounts:login"), {
            "email": self.user.email, "password": "ValidPass!42",
        })
        self.assertRedirects(response, reverse("accounts:biometric_entry"))

    def test_pending_suspended_and_rejected_states_remain_distinct(self):
        voter_role = Role.objects.get(name="Voter")
        pending_user = get_user_model().objects.create_user(
            email="pending-voter@example.test", password="ValidPass!42", full_name="Pending Voter",
            role=voter_role, status=get_user_model().Status.PENDING, is_active=False,
        )
        Voter.objects.create(user=pending_user, id_number="SUSPEND-2", date_of_birth="2000-01-01", status=Voter.Status.PENDING)
        rejected_user = get_user_model().objects.create_user(
            email="rejected-voter@example.test", password="ValidPass!42", full_name="Rejected Voter",
            role=voter_role, status=get_user_model().Status.SUSPENDED, is_active=False,
        )
        Voter.objects.create(user=rejected_user, id_number="SUSPEND-3", date_of_birth="2000-01-01", status=Voter.Status.REJECTED)
        self._suspend()

        page = self.client.get(reverse("accounts:voter_list"))
        self.assertContains(page, "Pending")
        self.assertContains(page, "Activate")
        self.assertContains(page, "Suspended")
        self.assertContains(page, "Reactivate")
        self.assertContains(page, "Rejected")
        self.assertContains(page, "Reinstate")


class WebAuthnCredentialModelTests(TestCase):
    def setUp(self):
        role = Role.objects.create(name="Voter")
        user = get_user_model().objects.create_user(
            email="credential-voter@example.test",
            password="CorrectHorse!42Car",
            full_name="Credential Test Voter",
            role=role,
            status=get_user_model().Status.ACTIVE,
        )
        self.voter = Voter.objects.create(
            user=user,
            id_number="CREDENTIAL-1001",
            date_of_birth="2000-01-01",
        )

    def create_credential(self, credential_id=b"credential-id-1"):
        return WebAuthnCredential.objects.create(
            voter=self.voter,
            credential_id=credential_id,
            public_key=b"example-cose-public-key",
            transports=["internal"],
            device_name="Personal device",
        )

    def test_voter_can_have_multiple_credentials(self):
        self.create_credential(b"credential-id-1")
        self.create_credential(b"credential-id-2")

        self.assertEqual(self.voter.webauthn_credentials.count(), 2)

    def test_credential_id_is_unique(self):
        self.create_credential()

        with self.assertRaises(IntegrityError):
            self.create_credential()

    def test_credential_belongs_to_the_correct_voter(self):
        credential = self.create_credential()

        self.assertEqual(credential.voter, self.voter)

    def test_credential_can_be_revoked_without_being_deleted(self):
        credential = self.create_credential()
        credential.revoke()

        self.assertTrue(WebAuthnCredential.objects.filter(pk=credential.pk).exists())
        revoked_credential = WebAuthnCredential.objects.get(pk=credential.pk)
        self.assertEqual(revoked_credential.status, WebAuthnCredential.Status.REVOKED)
        self.assertIsNotNone(revoked_credential.revoked_at)

    def test_credential_requires_public_key(self):
        credential = WebAuthnCredential(
            voter=self.voter,
            credential_id=b"missing-public-key",
            public_key=b"",
        )

        with self.assertRaisesMessage(ValidationError, "This field cannot be blank."):
            credential.full_clean()

    def test_credential_model_contains_no_sensitive_biometric_fields(self):
        field_names = {field.name.lower() for field in WebAuthnCredential._meta.fields}

        self.assertFalse(field_names & {"fingerprint", "face", "template", "password", "private_key"})


class WebAuthnRegistrationUXTests(TestCase):
    def setUp(self):
        role = Role.objects.create(name="Voter")
        self.user = get_user_model().objects.create_user(
            email="registration-ux@example.test", password="CorrectHorse!42Car",
            full_name="Registration UX Voter", role=role,
            status=get_user_model().Status.ACTIVE,
        )
        self.voter = Voter.objects.create(
            user=self.user, id_number="REG-UX-1", date_of_birth="2000-01-01",
            status=Voter.Status.VERIFIED,
        )
        self.url = reverse("accounts:webauthn_registration")
        self.client.force_login(self.user)

    def test_registration_page_shows_primary_action_before_a_credential_exists(self):
        response = self.client.get(self.url)

        self.assertContains(response, "Register this device")
        self.assertFalse(response.context["registration_complete"])

    def test_registered_credential_renders_persistent_success_state(self):
        WebAuthnCredential.objects.create(
            voter=self.voter, credential_id=b"registration-ux-device", public_key=b"example-cose-key",
        )

        response = self.client.get(self.url)

        self.assertContains(response, "Device security registered successfully")
        self.assertContains(response, "This device is now registered. Verify your device to continue securely.")
        self.assertContains(response, "Verify device and continue")
        self.assertContains(response, reverse("accounts:webauthn_authentication"))
        self.assertContains(response, "Register another device")
        self.assertNotContains(response, "Register this device")

    def test_registered_credential_without_a_verified_session_is_redirected_to_device_verification(self):
        WebAuthnCredential.objects.create(
            voter=self.voter, credential_id=b"registration-ux-device", public_key=b"example-cose-key",
        )

        response = self.client.get(reverse("elections:voter_dashboard"))

        self.assertRedirects(response, reverse("accounts:biometric_entry"))
        self.assertNotIn("webauthn_verified_voter_id", self.client.session)
        biometric_entry = self.client.get(reverse("accounts:biometric_entry"))
        self.assertContains(biometric_entry, reverse("accounts:webauthn_authentication"))

    def test_add_another_device_uses_existing_multiple_credential_support(self):
        WebAuthnCredential.objects.create(
            voter=self.voter, credential_id=b"registration-ux-device", public_key=b"example-cose-key",
        )

        response = self.client.get(f"{self.url}?add=1")

        self.assertContains(response, "Register this device")
        self.assertFalse(response.context["registration_complete"])


class WebAuthnAuthenticationTests(TestCase):
    def setUp(self):
        role = Role.objects.create(name="Voter")
        self.user = get_user_model().objects.create_user(
            email="assertion-voter@example.test", password="CorrectHorse!42Car",
            full_name="Assertion Voter", role=role, status=get_user_model().Status.ACTIVE,
        )
        self.voter = Voter.objects.create(user=self.user, id_number="ASSERT-1001", date_of_birth="2000-01-01")
        self.credential = WebAuthnCredential.objects.create(
            voter=self.voter, credential_id=b"credential-id", public_key=b"not-a-real-cose-key"
        )
        self.options_url = reverse("accounts:webauthn_authentication_options")
        self.verify_url = reverse("accounts:webauthn_authentication_verify")

    def _options(self):
        response = self.client.post(self.options_url)
        self.assertEqual(response.status_code, 200)
        return response.json()["challenge_id"]

    def test_unauthenticated_user_cannot_start_authentication(self):
        response = self.client.post(self.options_url)
        self.assertEqual(response.status_code, 302)

    def test_authenticated_voter_can_request_a_session_bound_challenge(self):
        self.client.force_login(self.user)
        challenge_id = self._options()
        challenge = WebAuthnChallenge.objects.get(challenge_id=challenge_id)
        self.assertEqual(challenge.voter, self.voter)
        self.assertEqual(challenge.ceremony, "authentication")
        self.assertEqual(self.client.session["webauthn_auth_challenge_id"], challenge_id)

    def test_challenge_from_another_session_is_rejected(self):
        self.client.force_login(self.user)
        challenge_id = self._options()
        other_client = self.client_class()
        other_client.force_login(self.user)
        response = other_client.post(self.verify_url, data=json.dumps({"challenge_id": challenge_id, "credential": {"id": "Y3JlZGVudGlhbC1pZA"}}), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_expired_challenge_is_rejected(self):
        self.client.force_login(self.user)
        challenge_id = self._options()
        WebAuthnChallenge.objects.filter(challenge_id=challenge_id).update(expires_at=timezone.now() - timedelta(seconds=1))
        response = self.client.post(self.verify_url, data=json.dumps({"challenge_id": challenge_id, "credential": {"id": "Y3JlZGVudGlhbC1pZA"}}), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_invalid_assertion_is_consumed_and_does_not_verify_session(self):
        self.client.force_login(self.user)
        challenge_id = self._options()
        payload = {"challenge_id": challenge_id, "credential": {"id": "Y3JlZGVudGlhbC1pZA", "response": {}}}
        response = self.client.post(self.verify_url, data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIsNotNone(WebAuthnChallenge.objects.get(challenge_id=challenge_id).consumed_at)
        self.assertNotIn("webauthn_verified_voter_id", self.client.session)
        self.assertFalse(AuditLog.objects.filter(description__contains="Y3JlZGVudGlhbC1pZA").exists())


@override_settings(WEBAUTHN_RP_ID="localhost", WEBAUTHN_ORIGIN="http://localhost:8000")
class WebAuthnAuthenticationSecurityTests(TestCase):
    """Exercise the production assertion verifier with an ephemeral test authenticator."""

    def setUp(self):
        role = Role.objects.create(name="Voter")
        self.user = get_user_model().objects.create_user(
            email="cryptographic-voter@example.test", password="CorrectHorse!42Car",
            full_name="Cryptographic Voter", role=role, status=get_user_model().Status.ACTIVE,
        )
        self.voter = Voter.objects.create(
            user=self.user, id_number="CRYPTO-1001", date_of_birth="2000-01-01"
        )
        self.options_url = reverse("accounts:webauthn_authentication_options")
        self.verify_url = reverse("accounts:webauthn_authentication_verify")

    @staticmethod
    def _b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    def _credential(self, credential_id=b"test-credential", counter=0):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_numbers = private_key.public_key().public_numbers()
        cose_public_key = cbor2.dumps({
            1: 2, 3: -7, -1: 1,
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        })
        credential = WebAuthnCredential.objects.create(
            voter=self.voter, credential_id=credential_id, public_key=cose_public_key,
            signature_counter=counter, transports=["internal"],
        )
        return credential, private_key

    def _start(self, client=None):
        client = client or self.client
        response = client.post(self.options_url)
        self.assertEqual(response.status_code, 200)
        return response.json()["challenge_id"]

    def _assertion(self, challenge_id, credential, private_key, *, rp_id="localhost",
                   origin="http://localhost:8000", counter=1, uv=True, challenge=None,
                   signature_valid=True, malformed_client_data=False, malformed_auth_data=False):
        challenge_record = WebAuthnChallenge.objects.get(challenge_id=challenge_id)
        challenge_value = challenge if challenge is not None else __import__("accounts.views", fromlist=["_challenge_bytes"])._challenge_bytes(challenge_record)
        client_data = b"not-json" if malformed_client_data else json.dumps({
            "type": "webauthn.get", "challenge": self._b64(challenge_value),
            "origin": origin, "crossOrigin": False,
        }, separators=(",", ":")).encode()
        flags = 0x01 | (0x04 if uv else 0)
        authenticator_data = b"bad" if malformed_auth_data else (
            hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
        )
        signature = private_key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        ) if not malformed_auth_data else b"invalid"
        if not signature_valid:
            signature = b"\x00" * len(signature)
        credential_id = bytes(credential.credential_id)
        return {
            "challenge_id": str(challenge_id),
            "credential": {
                "id": self._b64(credential_id), "rawId": self._b64(credential_id), "type": "public-key",
                "response": {
                    "clientDataJSON": self._b64(client_data),
                    "authenticatorData": self._b64(authenticator_data), "signature": self._b64(signature),
                },
            },
        }

    def _verify(self, payload, client=None):
        return (client or self.client).post(
            self.verify_url, data=json.dumps(payload), content_type="application/json"
        )

    @override_settings(
        WEBAUTHN_RP_ID="mobile-test.trycloudflare.com",
        WEBAUTHN_ORIGIN="https://mobile-test.trycloudflare.com",
    )
    def test_https_tunnel_configuration_is_used_for_options_and_assertion_verification(self):
        self.client.force_login(self.user)
        registration_options = self.client.post(reverse("accounts:webauthn_registration_options"))
        self.assertEqual(registration_options.status_code, 200)
        self.assertEqual(registration_options.json()["publicKey"]["rp"]["id"], "mobile-test.trycloudflare.com")

        credential, key = self._credential()
        authentication_options = self.client.post(self.options_url)
        self.assertEqual(authentication_options.status_code, 200)
        self.assertEqual(authentication_options.json()["publicKey"]["rpId"], "mobile-test.trycloudflare.com")
        challenge_id = authentication_options.json()["challenge_id"]
        response = self._verify(self._assertion(
            challenge_id, credential, key,
            rp_id="mobile-test.trycloudflare.com",
            origin="https://mobile-test.trycloudflare.com",
        ))
        self.assertEqual(response.status_code, 200)

    def test_valid_cryptographic_assertion_verifies_and_rotates_session(self):
        credential, private_key = self._credential(counter=4)
        self.client.force_login(self.user)
        session_key = self.client.session.session_key
        challenge_id = self._start()
        response = self._verify(self._assertion(challenge_id, credential, private_key, counter=5))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["next"], reverse("accounts:biometric_entry"))
        self.assertEqual(self.client.session["webauthn_verified_voter_id"], self.voter.pk)
        self.assertNotEqual(self.client.session.session_key, session_key)
        self.assertEqual(self.client.get(reverse("elections:voter_dashboard")).status_code, 200)
        challenge = WebAuthnChallenge.objects.get(challenge_id=challenge_id)
        credential.refresh_from_db()
        self.assertIsNotNone(challenge.consumed_at)
        self.assertEqual(credential.signature_counter, 5)
        self.assertIsNotNone(credential.last_used_at)

    def test_wrong_rp_id_is_rejected_by_real_verifier(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        challenge_id = self._start()
        response = self._verify(self._assertion(challenge_id, credential, key, rp_id="example.test"))
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("webauthn_verified_voter_id", self.client.session)

    def test_wrong_origin_is_rejected_by_real_verifier(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        challenge_id = self._start()
        self.assertEqual(self._verify(self._assertion(challenge_id, credential, key, origin="https://example.test")).status_code, 400)

    def test_wrong_challenge_is_rejected_by_real_verifier(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        challenge_id = self._start()
        self.assertEqual(self._verify(self._assertion(challenge_id, credential, key, challenge=b"wrong-challenge")).status_code, 400)

    def test_invalid_signature_is_rejected_by_real_verifier(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        challenge_id = self._start()
        self.assertEqual(self._verify(self._assertion(challenge_id, credential, key, signature_valid=False)).status_code, 400)

    def test_missing_user_verification_is_rejected_by_real_verifier(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        challenge_id = self._start()
        self.assertEqual(self._verify(self._assertion(challenge_id, credential, key, uv=False)).status_code, 400)

    def test_malformed_client_and_authenticator_data_are_rejected(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        first = self._start()
        self.assertEqual(self._verify(self._assertion(first, credential, key, malformed_client_data=True)).status_code, 400)
        second = self._start()
        self.assertEqual(self._verify(self._assertion(second, credential, key, malformed_auth_data=True)).status_code, 400)

    def test_reused_consumed_challenge_is_rejected(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        challenge_id = self._start()
        payload = self._assertion(challenge_id, credential, key)
        self.assertEqual(self._verify(payload).status_code, 200)
        self.assertEqual(self._verify(payload).status_code, 400)

    def test_unknown_and_revoked_credentials_are_rejected(self):
        credential, key = self._credential()
        self.client.force_login(self.user)
        unknown_challenge = self._start()
        payload = self._assertion(unknown_challenge, credential, key)
        payload["credential"]["id"] = payload["credential"]["rawId"] = self._b64(b"unknown")
        self.assertEqual(self._verify(payload).status_code, 400)
        credential.revoke()
        self._credential(b"other-active-credential")
        revoked_challenge = self._start()
        self.assertEqual(self._verify(self._assertion(revoked_challenge, credential, key)).status_code, 400)

    def test_inactive_and_pending_voters_cannot_start_authentication(self):
        self._credential()
        self.client.force_login(self.user)
        self.user.status = get_user_model().Status.SUSPENDED
        self.user.save(update_fields=["status"])
        self.assertEqual(self.client.post(self.options_url).status_code, 403)
        self.user.status = get_user_model().Status.ACTIVE
        self.user.save(update_fields=["status"])
        self.voter.status = Voter.Status.PENDING
        self.voter.save(update_fields=["status"])
        self.assertEqual(self.client.post(self.options_url).status_code, 403)

    def test_rejected_voter_cannot_start_authentication(self):
        self._credential()
        self.client.force_login(self.user)
        self.voter.status = Voter.Status.REJECTED
        self.voter.save(update_fields=["status"])
        self.assertEqual(self.client.post(self.options_url).status_code, 403)

    def test_multiple_credentials_authenticate_independently_and_counter_rollback_fails(self):
        first, first_key = self._credential(b"first", counter=1)
        second, second_key = self._credential(b"second", counter=3)
        self.client.force_login(self.user)
        first_challenge = self._start()
        self.assertEqual(self._verify(self._assertion(first_challenge, first, first_key, counter=2)).status_code, 200)
        second_challenge = self._start()
        self.assertEqual(self._verify(self._assertion(second_challenge, second, second_key, counter=4)).status_code, 200)
        rollback_challenge = self._start()
        self.assertEqual(self._verify(self._assertion(rollback_challenge, second, second_key, counter=4)).status_code, 400)

    def test_audit_log_omits_sensitive_assertion_material_and_cancellation_does_not_verify(self):
        credential, key = self._credential(b"audit-marker")
        self.client.force_login(self.user)
        challenge_id = self._start()
        payload = self._assertion(challenge_id, credential, key, malformed_client_data=True)
        self.assertEqual(self._verify(payload).status_code, 400)
        self.assertNotIn("webauthn_verified_voter_id", self.client.session)
        audit_text = " ".join(AuditLog.objects.values_list("description", flat=True))
        self.assertNotIn(payload["credential"]["id"], audit_text)
        self.assertNotIn(payload["credential"]["response"]["clientDataJSON"], audit_text)

    def test_browser_cancellation_without_submission_never_verifies_session(self):
        self._credential()
        self.client.force_login(self.user)
        self._start()  # Browser cancellation means no assertion is submitted.
        self.assertNotIn("webauthn_verified_voter_id", self.client.session)
