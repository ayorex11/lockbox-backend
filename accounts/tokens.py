import hashlib
from urllib.parse import unquote

from django.conf import settings
from django.core import signing

_SALT = "lockbox.email-verification"


def make_verification_token(user):
    return signing.dumps({"uid": user.pk, "email": user.email}, salt=_SALT)


def read_verification_token(token):
    """Return the payload dict, or None if the token is invalid or expired."""
    # The emailed link URL-encodes the token (":" -> "%3A"). Accept a token that was
    # copied from the raw URL as well as an already-decoded one.
    token = unquote((token or "").strip())
    try:
        return signing.loads(
            token, salt=_SALT, max_age=settings.EMAIL_VERIFICATION_MAX_AGE_SECONDS
        )
    except signing.BadSignature:  # SignatureExpired is a subclass
        return None


# ------------------------------------------------------------------ password reset
_RESET_SALT = "lockbox.password-reset"


def _password_fingerprint(user):
    """Changes whenever the password does, which makes a reset link single-use."""
    return hashlib.sha256((user.password or "").encode()).hexdigest()[:24]


def make_reset_token(user):
    return signing.dumps({"uid": user.pk, "fp": _password_fingerprint(user)}, salt=_RESET_SALT)


def read_reset_token(token):
    """Return the payload dict, or None if the token is invalid or expired."""
    token = unquote((token or "").strip())
    try:
        return signing.loads(token, salt=_RESET_SALT, max_age=settings.PASSWORD_RESET_MAX_AGE_SECONDS)
    except signing.BadSignature:
        return None


def reset_token_matches(user, payload):
    import hmac

    return hmac.compare_digest(payload.get("fp", ""), _password_fingerprint(user))

