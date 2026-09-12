from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("register/success/", views.registration_success, name="registration_success"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
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
