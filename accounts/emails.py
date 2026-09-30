import logging
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail

from .tokens import make_verification_token

logger = logging.getLogger(__name__)


def send_verification_email(user):
    """Send the verification email. Never raises: callers return a generic response
    either way, so SMTP problems must not leak whether an address is registered."""
    token = make_verification_token(user)
    url = f"{settings.FRONTEND_URL}/verify-email?token={quote(token)}"
    hours = settings.EMAIL_VERIFICATION_MAX_AGE_SECONDS // 3600
    body = (
        "Welcome to Lockbox.\n\n"
        f"Confirm your email to start sending files:\n{url}\n\n"
        f"This link expires in {hours} hours. If you didn't create an account, "
        "you can ignore this email."
    )
    try:
        send_mail("Confirm your email", body, settings.DEFAULT_FROM_EMAIL, [user.email])
    except Exception:  # noqa: BLE001 - deliberately broad, see docstring
        logger.exception("Failed to send verification email to user id=%s", user.pk)
