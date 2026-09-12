from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from .models import User, Voter


def admin_required(view):
    @login_required(login_url="accounts:login")
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_staff and request.user.role.name != "Admin":
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped


def verified_voter_required(view):
    @login_required(login_url="accounts:login")
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        voter = Voter.objects.filter(user=request.user).first()
        if not voter or request.user.status != User.Status.ACTIVE or voter.status != Voter.Status.VERIFIED:
            raise PermissionDenied
        if request.session.get("webauthn_verified_voter_id") != voter.pk:
            raise PermissionDenied
        request.voter = voter
        return view(request, *args, **kwargs)
    return wrapped
