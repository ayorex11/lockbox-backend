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