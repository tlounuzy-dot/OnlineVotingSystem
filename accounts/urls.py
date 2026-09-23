from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("register/success/", views.registration_success, name="registration_success"),
    path("register/verify/", views.registration_verification_method, name="registration_verification_method"),
    path("register/verify/code/", views.registration_verification_code, name="registration_verification_code"),
    path("register/verify/resend/", views.registration_verification_resend, name="registration_verification_resend"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("password-reset/", views.password_reset_request, name="password_reset"),
    path("password-reset/method/", views.password_reset_method, name="password_reset_method"),
    path("password-reset/code/", views.password_reset_code, name="password_reset_code"),
    path("password-reset/resend/", views.password_reset_resend, name="password_reset_resend"),
    path("password-reset/new-password/", views.password_reset_new_password, name="password_reset_new_password"),
    path("password-reset/done/", auth_views.PasswordResetDoneView.as_view(template_name="accounts/password_reset_done.html"), name="password_reset_done"),
    path("reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view(
        template_name="accounts/password_reset_confirm.html",
        success_url=reverse_lazy("accounts:password_reset_complete"),
    ), name="password_reset_confirm"),
    path("reset/done/", auth_views.PasswordResetCompleteView.as_view(
        template_name="accounts/password_reset_complete.html",
    ), name="password_reset_complete"),
    path("biometric/", views.biometric_entry, name="biometric_entry"),
    path("biometric/register/", views.webauthn_registration, name="webauthn_registration"),
    path("biometric/register/options/", views.webauthn_registration_options, name="webauthn_registration_options"),
    path("biometric/register/verify/", views.webauthn_registration_verify, name="webauthn_registration_verify"),
    path("biometric/authenticate/", views.webauthn_authentication, name="webauthn_authentication"),
    path("biometric/authenticate/options/", views.webauthn_authentication_options, name="webauthn_authentication_options"),
    path("biometric/authenticate/verify/", views.webauthn_authentication_verify, name="webauthn_authentication_verify"),
    path("admin/voters/", views.voter_list, name="voter_list"),
    path("admin/voters/<int:pk>/status/", views.voter_status, name="voter_status"),
]
