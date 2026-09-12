import base64
import hashlib
import json
import re
from datetime import timedelta
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

from .models import AuditLog, LoginAttempt, Role, Voter, WebAuthnChallenge, WebAuthnCredential


class RoleInitializationTests(TestCase):
    def test_seed_roles_creates_roles_once(self):
        call_command("seed_roles")
        call_command("seed_roles")

        self.assertEqual(Role.objects.filter(name="Admin").count(), 1)
        self.assertEqual(Role.objects.filter(name="Voter").count(), 1)


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

        self.assertRedirects(response, reverse("accounts:registration_success"))
        user = get_user_model().objects.get(email=self.data["email"])
        voter = Voter.objects.get(user=user)
        self.assertEqual(user.role.name, "Voter")
        self.assertEqual(user.status, get_user_model().Status.PENDING)
        self.assertEqual(voter.status, Voter.Status.PENDING)
        self.assertEqual(voter.id_number, self.data["id_number"])
        self.assertNotEqual(user.password, self.data["password"])
        self.assertTrue(user.check_password(self.data["password"]))

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


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class PasswordResetTests(TestCase):
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

    def test_reset_request_page_loads_without_email_enumeration(self):
        url = reverse("accounts:password_reset")
        self.assertEqual(self.client.get(url).status_code, 200)
        known = self.client.post(url, {"email": self.user.email})
        self.assertRedirects(known, reverse("accounts:password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)
        unknown = self.client.post(url, {"email": "unknown@example.test"})
        self.assertRedirects(unknown, reverse("accounts:password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)

    def test_valid_reset_changes_only_password_and_preserves_voter_security_state(self):
        self.client.post(reverse("accounts:password_reset"), {"email": self.user.email})
        match = re.search(r"http://testserver(/reset/[^\s]+)", mail.outbox[0].body)
        self.assertIsNotNone(match)
        reset_url = match.group(1)
        reset_page = self.client.get(reset_url, follow=True)
        self.assertEqual(reset_page.status_code, 200)
        response = self.client.post(reset_page.wsgi_request.path, {
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

    def test_invalid_reset_token_is_rejected_safely(self):
        response = self.client.get(reverse("accounts:password_reset_confirm", args=["invalid", "invalid-token"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "invalid or has already been used")


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

    def test_valid_cryptographic_assertion_verifies_and_rotates_session(self):
        credential, private_key = self._credential(counter=4)
        self.client.force_login(self.user)
        session_key = self.client.session.session_key
        challenge_id = self._start()
        response = self._verify(self._assertion(challenge_id, credential, private_key, counter=5))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.session["webauthn_verified_voter_id"], self.voter.pk)
        self.assertNotEqual(self.client.session.session_key, session_key)
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
