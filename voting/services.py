"""Small, server-only services for the vote recording transaction."""

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _cipher():
    key = settings.VOTE_ENCRYPTION_KEY
    if not key:
        raise ImproperlyConfigured("VOTE_ENCRYPTION_KEY must be configured before votes can be recorded.")
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured("VOTE_ENCRYPTION_KEY is not a valid Fernet key.") from exc


def encrypt_choice(candidate_id: int) -> bytes:
    """Authenticated encryption; plaintext is never logged or rendered."""
    return _cipher().encrypt(str(candidate_id).encode("ascii"))


def decrypt_choice(value: bytes) -> int:
    """Available only for controlled administrative/recovery uses."""
    try:
        return int(_cipher().decrypt(bytes(value)).decode("ascii"))
    except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Stored vote choice cannot be decrypted.") from exc
