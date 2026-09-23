"""Template context for safe public-account workflow navigation."""


PUBLIC_AUTH_ROUTE_NAMES = {
    "register", "registration_success", "registration_verification_method",
    "registration_verification_code", "registration_verification_resend", "login",
    "password_reset", "password_reset_method", "password_reset_code",
    "password_reset_resend", "password_reset_new_password", "password_reset_done",
    "password_reset_confirm", "password_reset_complete",
}


def navigation_mode(request):
    match = getattr(request, "resolver_match", None)
    is_public_auth_route = bool(
        match and match.namespace == "accounts" and match.url_name in PUBLIC_AUTH_ROUTE_NAMES
    )
    return {"public_navigation": is_public_auth_route}
