from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import hashlib
import hmac
import json
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from webauthn import (base64url_to_bytes, generate_authentication_options,
                      generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers.structs import AuthenticatorAttachment, AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, UserVerificationRequirement

from .forms import EmailLoginForm, VoterRegistrationForm
from .models import AuditLog, LoginAttempt, User, Voter, WebAuthnChallenge, WebAuthnCredential
from .permissions import admin_required


def register(request):
    if request.method == "POST":
        form = VoterRegistrationForm(request.POST)
        if form.is_valid():
            try:
                form.save()
            except IntegrityError:
                form.add_error(None, "Registration could not be completed. Please try again.")
            else:
                return redirect("accounts:registration_success")
    else:
        form = VoterRegistrationForm()

    return render(request, "accounts/register.html", {"form": form})


def registration_success(request):
    return render(request, "accounts/registration_success.html")


def home(request):
    """Render the public landing page without changing authentication state."""
    if request.user.is_authenticated:
        if request.user.is_staff or request.user.role.name == "Admin":
            dashboard_url = "elections:dashboard"
        else:
            # The biometric entry view keeps the existing server-side WebAuthn
            # gate in place and redirects verified voters to their dashboard.
            dashboard_url = "accounts:biometric_entry"
    else:
        dashboard_url = None
    return render(request, "accounts/home.html", {"dashboard_url": dashboard_url})


def get_client_ip(request):
    """Return the client IP address without trusting more than the first proxy value."""
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def login_view(request):
    if request.method == "POST":
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].lower()
            password = form.cleaned_data["password"]
            identified_user = User.objects.filter(email__iexact=email).first()
            authenticated_user = authenticate(request, email=email, password=password)

            if authenticated_user is not None and authenticated_user.is_active:
                if authenticated_user.status == User.Status.PENDING:
                    LoginAttempt.objects.create(
                        user=authenticated_user, ip_address=get_client_ip(request),
                        status=LoginAttempt.Status.SUCCESS,
                        failure_reason="Account is pending approval.",
                    )
                    return render(request, "accounts/account_pending.html", status=403)

                if authenticated_user.status != User.Status.ACTIVE:
                    LoginAttempt.objects.create(
                        user=authenticated_user, ip_address=get_client_ip(request),
                        status=LoginAttempt.Status.FAILED,
                        failure_reason="Account is unavailable.",
                    )
                    form.add_error(None, "This account is unavailable.")
                    return render(request, "accounts/login.html", {"form": form})

                login(request, authenticated_user)
                LoginAttempt.objects.create(
                    user=authenticated_user,
                    ip_address=get_client_ip(request),
                    status=LoginAttempt.Status.SUCCESS,
                )
                if authenticated_user.is_staff or authenticated_user.role.name == "Admin":
                    return redirect("elections:dashboard")
                return redirect("accounts:biometric_entry")

            LoginAttempt.objects.create(
                user=identified_user,
                ip_address=get_client_ip(request),
                status=LoginAttempt.Status.FAILED,
                failure_reason="Invalid credentials or account unavailable.",
            )
            form.add_error(None, "Invalid email or password.")
    else:
        form = EmailLoginForm()

    return render(request, "accounts/login.html", {"form": form})


@login_required(login_url="accounts:login")
def biometric_entry(request):
    voter_id = Voter.objects.filter(user=request.user).values_list("pk", flat=True).first()
    if voter_id is None:
        if request.user.is_staff or request.user.role.name == "Admin":
            return redirect("elections:dashboard")
        return redirect("accounts:login")
    if voter_id is not None and request.session.get("webauthn_verified_voter_id") == voter_id:
        return redirect("elections:voter_dashboard")
    has_active_credential = WebAuthnCredential.objects.filter(
        voter_id=voter_id, status=WebAuthnCredential.Status.ACTIVE
    ).exists()
    return render(request, "accounts/biometric_entry.html", {
        "webauthn_verified": request.session.get("webauthn_verified_voter_id") == voter_id,
        "has_active_credential": has_active_credential,
    })


def _eligible_voter(request):
    voter = get_object_or_404(Voter, user=request.user)
    if request.user.status != User.Status.ACTIVE or voter.status != Voter.Status.VERIFIED:
        return None
    return voter


def _challenge_bytes(challenge):
    return hmac.new(settings.SECRET_KEY.encode(), challenge.challenge_id.bytes, hashlib.sha256).digest()


def _audit(voter, action, description):
    AuditLog.objects.create(user=voter.user, action=action, description=description)


@login_required(login_url="accounts:login")
def webauthn_registration(request):
    if not _eligible_voter(request):
        return render(request, "accounts/biometric_registration.html", {"registration_allowed": False}, status=403)
    return render(request, "accounts/biometric_registration.html", {"registration_allowed": True})


@login_required(login_url="accounts:login")
@require_POST
def webauthn_registration_options(request):
    voter = _eligible_voter(request)
    if not voter:
        return JsonResponse({"error": "Credential registration is unavailable for this account."}, status=403)
    challenge = WebAuthnChallenge.objects.create(
        voter=voter, ceremony=WebAuthnChallenge.Ceremony.REGISTRATION,
        expires_at=timezone.now() + timedelta(seconds=settings.WEBAUTHN_REGISTRATION_TIMEOUT_SECONDS),
    )
    excluded = [PublicKeyCredentialDescriptor(id=bytes(c.credential_id)) for c in voter.webauthn_credentials.filter(status=WebAuthnCredential.Status.ACTIVE)]
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID, rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=voter.user_id.to_bytes(8, "big"), user_name=f"voter-{voter.pk}",
        user_display_name="Registered voter", challenge=_challenge_bytes(challenge),
        timeout=settings.WEBAUTHN_REGISTRATION_TIMEOUT_SECONDS * 1000,
        exclude_credentials=excluded,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    return JsonResponse({"challenge_id": str(challenge.challenge_id), "publicKey": json.loads(options_to_json(options))})


@login_required(login_url="accounts:login")
@require_POST
def webauthn_registration_verify(request):
    voter = _eligible_voter(request)
    if not voter:
        return JsonResponse({"error": "Credential registration is unavailable for this account."}, status=403)
    try:
        data = json.loads(request.body)
        challenge = WebAuthnChallenge.objects.get(challenge_id=data["challenge_id"], voter=voter, ceremony=WebAuthnChallenge.Ceremony.REGISTRATION, consumed_at__isnull=True)
    except (ValueError, KeyError, WebAuthnChallenge.DoesNotExist):
        return JsonResponse({"error": "This registration request is invalid or already used."}, status=400)
    if challenge.expires_at <= timezone.now():
        _audit(voter, "webauthn_registration_failed", "Registration challenge expired.")
        return JsonResponse({"error": "This registration request has expired. Please try again."}, status=400)
    try:
        verified = verify_registration_response(
            credential=data["credential"], expected_challenge=_challenge_bytes(challenge),
            expected_rp_id=settings.WEBAUTHN_RP_ID, expected_origin=settings.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
        credential_id = base64url_to_bytes(data["credential"]["id"])
        if WebAuthnCredential.objects.filter(credential_id=credential_id).exists():
            raise ValueError("duplicate credential")
        with transaction.atomic():
            challenge.consumed_at = timezone.now()
            challenge.save(update_fields=["consumed_at"])
            WebAuthnCredential.objects.create(voter=voter, credential_id=credential_id, public_key=verified.credential_public_key, signature_counter=verified.sign_count, transports=data["credential"].get("response", {}).get("transports", []), backup_eligible=verified.credential_device_type.value == "multi_device", backup_state=verified.credential_backed_up)
        _audit(voter, "webauthn_registration_succeeded", "Platform credential registered.")
    except Exception:
        _audit(voter, "webauthn_registration_failed", "Registration verification failed.")
        return JsonResponse({"error": "The device credential could not be verified."}, status=400)
    return JsonResponse({"ok": True}, status=201)


@login_required(login_url="accounts:login")
def webauthn_authentication(request):
    voter = _eligible_voter(request)
    has_credentials = voter and voter.webauthn_credentials.filter(
        status=WebAuthnCredential.Status.ACTIVE
    ).exists()
    return render(request, "accounts/webauthn_authentication.html", {
        "authentication_allowed": bool(has_credentials),
    }, status=200 if has_credentials else 403)


@login_required(login_url="accounts:login")
@require_POST
def webauthn_authentication_options(request):
    voter = _eligible_voter(request)
    if not voter:
        return JsonResponse({"error": "Device verification is unavailable for this account."}, status=403)
    credentials = list(voter.webauthn_credentials.filter(status=WebAuthnCredential.Status.ACTIVE))
    if not credentials:
        return JsonResponse({"error": "No active device credential is registered."}, status=400)
    challenge = WebAuthnChallenge.objects.create(
        voter=voter,
        ceremony="authentication",
        expires_at=timezone.now() + timedelta(seconds=settings.WEBAUTHN_REGISTRATION_TIMEOUT_SECONDS),
    )
    request.session["webauthn_auth_challenge_id"] = str(challenge.challenge_id)
    request.session.modified = True
    _audit(voter, "webauthn_authentication_started", "Device verification started.")
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        challenge=_challenge_bytes(challenge),
        timeout=settings.WEBAUTHN_REGISTRATION_TIMEOUT_SECONDS * 1000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(c.credential_id)) for c in credentials],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return JsonResponse({"challenge_id": str(challenge.challenge_id), "publicKey": json.loads(options_to_json(options))})


@login_required(login_url="accounts:login")
@require_POST
def webauthn_authentication_verify(request):
    voter = _eligible_voter(request)
    if not voter:
        return JsonResponse({"error": "Device verification is unavailable for this account."}, status=403)
    try:
        data = json.loads(request.body)
        challenge_id = str(data["challenge_id"])
        if request.session.get("webauthn_auth_challenge_id") != challenge_id:
            raise ValueError("challenge is not bound to this session")
        challenge = WebAuthnChallenge.objects.get(
            challenge_id=challenge_id, voter=voter, ceremony="authentication", consumed_at__isnull=True
        )
        if challenge.expires_at <= timezone.now():
            _audit(voter, "webauthn_challenge_expired", "Device verification challenge expired.")
            return JsonResponse({"error": "This verification request has expired. Please try again."}, status=400)
        # Consume before processing assertion material so malformed or rejected
        # assertions cannot be retried against the same server challenge.
        if not WebAuthnChallenge.objects.filter(pk=challenge.pk, consumed_at__isnull=True).update(consumed_at=timezone.now()):
            return JsonResponse({"error": "This verification request is invalid or already used."}, status=400)
        request.session.pop("webauthn_auth_challenge_id", None)
        credential_id = base64url_to_bytes(data["credential"]["id"])
        credential = WebAuthnCredential.objects.get(
            voter=voter, credential_id=credential_id, status=WebAuthnCredential.Status.ACTIVE
        )
    except (ValueError, KeyError, WebAuthnChallenge.DoesNotExist, WebAuthnCredential.DoesNotExist):
        _audit(voter, "webauthn_credential_rejected", "Device credential or verification request was rejected.")
        return JsonResponse({"error": "The device credential could not be verified."}, status=400)

    try:
        verified = verify_authentication_response(
            credential=data["credential"], expected_challenge=_challenge_bytes(challenge),
            expected_rp_id=settings.WEBAUTHN_RP_ID, expected_origin=settings.WEBAUTHN_ORIGIN,
            credential_public_key=bytes(credential.public_key),
            credential_current_sign_count=credential.signature_counter,
            require_user_verification=True,
        )
    except Exception:
        _audit(voter, "webauthn_authentication_failed", "Device verification failed.")
        return JsonResponse({"error": "The device credential could not be verified."}, status=400)

    updates = ["last_used_at"]
    credential.last_used_at = timezone.now()
    # Zero means the authenticator does not implement a counter. A newer positive
    # counter is retained; the library rejects a rollback where it is meaningful.
    if verified.new_sign_count > credential.signature_counter:
        credential.signature_counter = verified.new_sign_count
        updates.append("signature_counter")
    credential.save(update_fields=updates)
    request.session.cycle_key()
    request.session["webauthn_verified_voter_id"] = voter.pk
    request.session["webauthn_verified_at"] = timezone.now().isoformat()
    _audit(voter, "webauthn_authentication_succeeded", "Device verification succeeded.")
    return JsonResponse({"ok": True, "next": "/accounts/biometric/"})


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        AuditLog.objects.create(user=request.user, action="logout", description="User logged out.", ip_address=get_client_ip(request))
    logout(request)
    return redirect("accounts:login")


@admin_required
def voter_list(request):
    query = request.GET.get("q", "").strip()
    voters = Voter.objects.select_related("user")
    if query:
        voters = voters.filter(user__full_name__icontains=query) | voters.filter(user__email__icontains=query) | voters.filter(id_number__icontains=query)
    return render(request, "accounts/voter_list.html", {"voters": voters, "query": query})


@admin_required
@require_POST
def voter_status(request, pk):
    voter = get_object_or_404(Voter.objects.select_related("user"), pk=pk); status = request.POST.get("status")
    if status not in {Voter.Status.VERIFIED, Voter.Status.PENDING, Voter.Status.REJECTED}: return redirect("accounts:voter_list")
    with transaction.atomic():
        voter.status = status; voter.user.status = User.Status.ACTIVE if status == Voter.Status.VERIFIED else User.Status.SUSPENDED; voter.user.is_active = status == Voter.Status.VERIFIED
        voter.save(update_fields=["status"]); voter.user.save(update_fields=["status", "is_active"])
        AuditLog.objects.create(user=request.user, action="voter_status_changed", description="Voter eligibility status changed.", ip_address=get_client_ip(request))
    return redirect("accounts:voter_list")
